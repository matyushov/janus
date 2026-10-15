//! Dispatcher: (NBSS packet, state) → reply bytes ready to send
//! (with credits and signatures filled in). The whole transition table is tested
//! without sockets; sockets live only in `server`.
//!
//! J1: NEGOTIATE 3.1.1 → SESSION_SETUP (SPNEGO/NTLMv2, 2 steps) → TREE_CONNECT /
//! TREE_DISCONNECT / LOGOFF / ECHO. The remaining commands get `STATUS_NOT_IMPLEMENTED`
//! (signed). Signing is mandatory: after SESSION_SETUP, frames without a valid
//! signature are rejected and replies are signed.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use janus_lib::profile::CompatCaps;
use smb_wire::auth::{self, OID_NTLMSSP, SpnegoToken};
use smb_wire::bytes::{Reader, Writer};
use smb_wire::create::{
    ACTION_OPENED, ATTR_DIRECTORY, CreateContext, CreateReq, CreateResp, FILE_ID_RELATED,
    disposition,
};
use smb_wire::crypto;
use smb_wire::fileinfo::{
    CloseReq, QueryDirectoryReq, QueryInfoReq, VolumeInfo, encode_close_resp,
    encode_query_info_resp, fs_info, info_type, root_dir_info,
};
use smb_wire::header::{Header, SMB2_TRANSFORM_MAGIC, flags};
use smb_wire::messages::{
    ACCESS_ALL, HASH_SHA512, NegotiateReq, NegotiateResp, SessionSetupReq, SessionSetupResp,
    TreeConnectReq, TreeConnectResp, decode_simple_req, encode_simple_resp, security_mode,
    session_setup_flags, share_flags, share_type,
};
use smb_wire::ntlm::{ChallengeParams, Credentials, NtlmServer};
use smb_wire::{Command, Message, WireError};

use crate::conn::{ConnState, MAX_AUTH_FAILURES, MAX_PENDING_SESSIONS};
use crate::session::{PendingAuth, Session, SessionState};

/// Result of handling a packet.
pub enum Reply {
    /// Ready reply bytes (a whole NBSS packet, possibly compound); the write loop
    /// sends them as is.
    Now(Vec<u8>),
    /// Long operation: the interim STATUS_PENDING has already been sent, the final reply comes later.
    /// UPGRADE: enable together with AsyncOpRegistry (FLUSH sync-through, CHANGE_NOTIFY).
    Async { async_id: u64 },
    /// No reply (for example, an ack without a response).
    None,
}

/// NTSTATUS constants.
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const NOT_IMPLEMENTED: u32 = 0xC000_0002;
    pub const INVALID_INFO_CLASS: u32 = 0xC000_0003;
    pub const INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
    pub const NO_SUCH_FILE: u32 = 0xC000_000F;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
    pub const FILE_CLOSED: u32 = 0xC000_0128;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const LOGON_FAILURE: u32 = 0xC000_006D;
    pub const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
    pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
    pub const USER_SESSION_DELETED: u32 = 0xC000_0203;
    pub const NO_PREAUTH_HASH_OVERLAP: u32 = 0xC05D_0000;
}

/// Server context, immutable while a packet is being handled.
pub struct ServerCtx<'a> {
    pub server_guid: [u8; 16],
    /// NetBIOS name (NTLM TargetName/AV pairs).
    pub server_name: &'a str,
    /// Name of the only share (case-insensitive).
    pub share_name: &'a str,
    pub caps: CompatCaps,
    /// The only permitted user; `None` means logon is impossible.
    pub credentials: Option<Credentials>,
    /// SessionId generator (shared across the server).
    pub next_session_id: &'a AtomicU64,
    /// Current time, FILETIME.
    pub filetime: u64,
    /// Server start time, FILETIME (volume/root creation).
    pub started_filetime: u64,
    /// Volume size in bytes as the client sees it (share quota).
    pub volume_bytes: u64,
    pub now: Instant,
    /// Source of randomness (server challenge, salt); replaced in tests.
    pub random: fn(&mut [u8]),
}

/// System source of randomness for `ServerCtx::random`.
pub fn system_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("system random number generator unavailable");
}

/// One reply before assembly: header + body + the key to sign with.
struct Element {
    header: Header,
    body: Vec<u8>,
    sign_key: Option<[u8; 16]>,
}

impl Element {
    /// Bytes exactly as on the wire, without signature or alignment (for the preauth hash).
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.header.encode(&mut w);
        w.bytes(&self.body);
        w.into_vec()
    }
}

/// CreateOptions: FILE_NON_DIRECTORY_FILE.
const OPT_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// Maximum number of elements in a compound chain.
const MAX_COMPOUND: usize = 32;

pub struct Dispatcher;

impl Dispatcher {
    /// Handle one NBSS packet (a single message or a compound chain).
    ///
    /// Platform switches (once we get to CREATE/QUERY_INFO) go ONLY
    /// through CompatCaps (janus_lib::profile): name case semantics, AAPL/
    /// F_FULLFSYNC, POSIX-ext, ADS probes. The dispatcher does not branch on "platforms".
    ///
    /// `Err` is a protocol violation; the connection is closed without a reply.
    pub fn handle(
        payload: &[u8],
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
    ) -> Result<Reply, WireError> {
        if smb_wire::messages::is_smb1(payload) {
            return Self::smb1_negotiate(payload, conn, ctx);
        }
        if payload.len() >= 4 && payload[..4] == SMB2_TRANSFORM_MAGIC {
            return Err(WireError::Malformed("encryption not negotiated"));
        }
        let parts = split_compound(payload)?;
        let compound = parts.len() > 1;

        let mut elements: Vec<Element> = Vec::with_capacity(parts.len());
        let (mut prev_session, mut prev_tree) = (0u64, 0u32);
        conn.compound_file = None;
        for raw in parts {
            let mut msg = Message::decode_single(raw)?;
            if msg.header.flags & flags::SERVER_TO_REDIR != 0 {
                return Err(WireError::Malformed("response instead of request"));
            }
            // Related operations: identifiers are inherited from the previous request.
            if msg.header.flags & flags::RELATED_OPERATIONS != 0 {
                if msg.header.session_id == u64::MAX {
                    msg.header.session_id = prev_session;
                }
                if msg.header.tree_id == u32::MAX {
                    msg.header.tree_id = prev_tree;
                }
            }
            (prev_session, prev_tree) = (msg.header.session_id, msg.header.tree_id);
            let related_failed = (msg.header.flags & flags::RELATED_OPERATIONS != 0)
                .then(|| elements.last().map(|e| e.header.status))
                .flatten()
                .filter(|&st| st != status::SUCCESS);

            if conn.credits.charge(msg.header.credit_charge).is_err() {
                return Err(WireError::Malformed("insufficient credits"));
            }
            let element = match msg.header.command {
                Command::Negotiate | Command::SessionSetup if compound => {
                    return Err(WireError::Malformed("NEGOTIATE/SESSION_SETUP in compound"));
                }
                Command::Negotiate => Self::negotiate(raw, &msg, conn, ctx)?,
                _ if conn.dialect.is_none() => {
                    return Err(WireError::Malformed("command before NEGOTIATE"));
                }
                Command::SessionSetup => Self::session_setup(raw, &msg, conn, ctx)?,
                _ => Self::authenticated(raw, &msg, conn, ctx, related_failed)?,
            };
            elements.push(element);
        }
        Ok(Reply::Now(assemble(elements)))
    }

    // --- SMB1 multi-protocol NEGOTIATE ---------------------------------------

    /// macOS (and other clients) open the connection with an SMB1 NEGOTIATE offering
    /// "SMB 2.???". Per MS-SMB2 §3.3.5.3.1 we reply with an SMB2 NEGOTIATE response with
    /// DialectRevision 0x02FF (or 0x0202), after which the client sends the real SMB2
    /// NEGOTIATE. SMB1 as a protocol is not served; this exchange is not part of the preauth hash.
    fn smb1_negotiate(
        payload: &[u8],
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
    ) -> Result<Reply, WireError> {
        if conn.dialect.is_some() || conn.smb1_negotiated {
            return Err(WireError::Malformed("SMB1 after NEGOTIATE"));
        }
        let dialects = smb_wire::messages::smb1_negotiate_dialects(payload)?;
        let Some(revision) = smb_wire::messages::smb1_wildcard_revision(&dialects) else {
            return Err(WireError::Malformed("SMB1 client without SMB 2.x"));
        };
        conn.smb1_negotiated = true;

        let resp = NegotiateResp {
            dialect_revision: revision,
            server_guid: ctx.server_guid,
            security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: ctx.filetime,
            security_buffer: auth::neg_token_init_ntlm(),
            preauth_salt: Vec::new(),
        };
        let mut body = Writer::new();
        resp.encode(&mut body);
        // MessageId 0; we leave the credit window alone: the single initial credit
        // goes to the next (real) SMB2 NEGOTIATE.
        let mut header = Header::response_to(
            &Header {
                credit_charge: 0,
                status: 0,
                command: Command::Negotiate,
                credit_req_grant: 1,
                flags: 0,
                next_command: 0,
                message_id: 0,
                tree_id: 0,
                async_id: 0,
                session_id: 0,
                signature: [0; 16],
            },
            status::SUCCESS,
        );
        header.credit_req_grant = 1;
        Ok(Reply::Now(assemble(vec![Element {
            header,
            body: body.into_vec(),
            sign_key: None,
        }])))
    }

    // --- NEGOTIATE ----------------------------------------------------------

    fn negotiate(
        raw: &[u8],
        msg: &Message,
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
    ) -> Result<Element, WireError> {
        let h = &msg.header;
        if conn.dialect.is_some() {
            // MS-SMB2 §3.3.5.4: a repeated NEGOTIATE on a connection means disconnect.
            return Err(WireError::Malformed("repeated NEGOTIATE"));
        }
        let req = NegotiateReq::decode(&mut Reader::new(&msg.body))?;
        let Some(dialect) = req.select_dialect() else {
            // No 3.1.1: refuse (the dialect is 3.1.1 only).
            return Ok(error_reply(h, conn, status::NOT_SUPPORTED, None));
        };
        let sha512_offered = req
            .contexts
            .preauth
            .as_ref()
            .is_some_and(|p| p.hash_algorithms.contains(&HASH_SHA512));
        if !sha512_offered {
            return Ok(error_reply(h, conn, status::NO_PREAUTH_HASH_OVERLAP, None));
        }

        conn.dialect = Some(dialect);
        conn.preauth_hash = crypto::preauth_chain(&[0; 64], raw);

        let mut salt = vec![0u8; 32];
        (ctx.random)(&mut salt);
        let resp = NegotiateResp {
            dialect_revision: dialect as u16,
            server_guid: ctx.server_guid,
            security_mode: security_mode::SIGNING_ENABLED | security_mode::SIGNING_REQUIRED,
            // Minimal capabilities: no DFS and no leasing (J4 will add them), no LARGE_MTU
            // (J2 together with READ/WRITE), hence sizes of at most 64 KiB.
            capabilities: 0,
            max_transact_size: 65536,
            max_read_size: 65536,
            max_write_size: 65536,
            system_time: ctx.filetime,
            security_buffer: auth::neg_token_init_ntlm(),
            preauth_salt: salt,
        };
        let mut w = Writer::new();
        resp.encode(&mut w);
        let elem = reply(h, conn, status::SUCCESS, w.into_vec(), None);
        conn.preauth_hash = crypto::preauth_chain(&conn.preauth_hash, &elem.encode_unsigned());
        Ok(elem)
    }

    // --- SESSION_SETUP ------------------------------------------------------

    fn session_setup(
        raw: &[u8],
        msg: &Message,
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
    ) -> Result<Element, WireError> {
        let h = &msg.header;
        let req = SessionSetupReq::decode(&mut Reader::new(&msg.body))?;
        if req.flags & session_setup_flags::BINDING != 0 {
            // multichannel is not supported
            return Ok(error_reply(h, conn, status::INVALID_PARAMETER, None));
        }
        conn.purge_expired_auth(ctx.now);

        let sid = if h.session_id == 0 {
            if conn.pending_auth_count() >= MAX_PENDING_SESSIONS {
                return Ok(error_reply(h, conn, status::INSUFFICIENT_RESOURCES, None));
            }
            let id = ctx.next_session_id.fetch_add(1, Ordering::Relaxed);
            conn.sessions.insert(
                id,
                Session::new(
                    id,
                    SessionState::Authenticating(Box::new(PendingAuth {
                        ntlm: None,
                        preauth_hash: conn.preauth_hash,
                        started: ctx.now,
                    })),
                ),
            );
            id
        } else {
            match conn.sessions.get(&h.session_id).map(|s| &s.state) {
                Some(SessionState::Authenticating(_)) => h.session_id,
                // re-authentication of a live session is not supported
                Some(SessionState::Active { .. }) => {
                    return Ok(error_reply(h, conn, status::INVALID_PARAMETER, None));
                }
                None => return Ok(error_reply(h, conn, status::USER_SESSION_DELETED, None)),
            }
        };

        let pending = pending_mut(conn, sid);
        pending.preauth_hash = crypto::preauth_chain(&pending.preauth_hash, raw);

        let Ok(token) = SpnegoToken::parse(&req.security_buffer) else {
            conn.sessions.remove(&sid);
            return Ok(error_reply(h, conn, status::INVALID_PARAMETER, None));
        };

        match Self::auth_step(&token, sid, conn, ctx) {
            AuthStep::SendToken(spnego) => {
                let mut w = Writer::new();
                SessionSetupResp {
                    session_flags: 0,
                    security_buffer: spnego,
                }
                .encode(&mut w);
                let mut elem = reply(
                    h,
                    conn,
                    status::MORE_PROCESSING_REQUIRED,
                    w.into_vec(),
                    None,
                );
                elem.header.session_id = sid;
                let pending = pending_mut(conn, sid);
                pending.preauth_hash =
                    crypto::preauth_chain(&pending.preauth_hash, &elem.encode_unsigned());
                Ok(elem)
            }
            AuthStep::Done { user, session_key } => {
                let pending = pending_mut(conn, sid);
                let signing_key = crypto::signing_key_311(&session_key, &pending.preauth_hash);
                if let Some(s) = conn.sessions.get_mut(&sid) {
                    s.state = SessionState::Active { user, signing_key };
                }
                let mut w = Writer::new();
                SessionSetupResp {
                    session_flags: 0,
                    security_buffer: auth::neg_token_resp_completed(),
                }
                .encode(&mut w);
                let mut elem = reply(h, conn, status::SUCCESS, w.into_vec(), Some(signing_key));
                elem.header.session_id = sid;
                Ok(elem)
            }
            AuthStep::Fail => {
                // The reason for the refusal is not disclosed to the client (user/password/format).
                conn.sessions.remove(&sid);
                conn.auth_failures += 1;
                if conn.auth_failures >= MAX_AUTH_FAILURES {
                    conn.close_after_reply = true;
                }
                Ok(error_reply(h, conn, status::LOGON_FAILURE, None))
            }
        }
    }

    /// One SPNEGO/NTLM step for session `sid` (in the Authenticating state).
    fn auth_step(
        token: &SpnegoToken,
        sid: u64,
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
    ) -> AuthStep {
        let Some(creds) = ctx.credentials.as_ref() else {
            return AuthStep::Fail; // no credentials means no guest logon either
        };
        let ntlm = token.ntlm_token();
        let first_is_ntlm = match token {
            SpnegoToken::NegTokenInit { mech_types, .. } => {
                if !mech_types.iter().any(|m| m == OID_NTLMSSP) {
                    return AuthStep::Fail;
                }
                mech_types.first().is_some_and(|m| m == OID_NTLMSSP)
            }
            SpnegoToken::NegTokenResp { .. } => true,
        };
        if ntlm.is_empty() || !first_is_ntlm {
            // The client preferred another mechanism (or there is no token): offer NTLM.
            return match token {
                SpnegoToken::NegTokenInit { .. } => AuthStep::SendToken(
                    SpnegoToken::NegTokenResp {
                        neg_state: Some(auth::NegState::AcceptIncomplete),
                        supported_mech: Some(OID_NTLMSSP.to_vec()),
                        response_token: Vec::new(),
                    }
                    .build(),
                ),
                SpnegoToken::NegTokenResp { .. } => AuthStep::Fail,
            };
        }
        // The NTLM message type sits at offset 8 (after the "NTLMSSP\0" signature).
        let msg_type = ntlm
            .get(8..12)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
        match msg_type {
            Some(1) => {
                let mut challenge = [0u8; 8];
                (ctx.random)(&mut challenge);
                let params = ChallengeParams {
                    server_challenge: challenge,
                    timestamp: ctx.filetime,
                    server_name: ctx.server_name,
                };
                match NtlmServer::accept_negotiate(ntlm, &params) {
                    Ok((srv, challenge_msg)) => {
                        pending_mut(conn, sid).ntlm = Some(srv);
                        AuthStep::SendToken(auth::neg_token_resp_challenge(&challenge_msg))
                    }
                    Err(_) => AuthStep::Fail,
                }
            }
            Some(3) => {
                let Some(srv) = pending_mut(conn, sid).ntlm.take() else {
                    return AuthStep::Fail;
                };
                match srv.authenticate(ntlm, creds) {
                    Ok(out) => AuthStep::Done {
                        user: out.user,
                        session_key: out.session_key,
                    },
                    Err(_) => AuthStep::Fail,
                }
            }
            _ => AuthStep::Fail,
        }
    }

    // --- Commands of an established session -------------------------------

    fn authenticated(
        raw: &[u8],
        msg: &Message,
        conn: &mut ConnState,
        ctx: &ServerCtx<'_>,
        related_failed: Option<u32>,
    ) -> Result<Element, WireError> {
        let h = &msg.header;
        let key = conn
            .sessions
            .get(&h.session_id)
            .and_then(Session::signing_key);
        let Some(key) = key else {
            return Ok(error_reply(h, conn, status::USER_SESSION_DELETED, None));
        };

        // Signing is mandatory: without SIGNED and a valid signature the command is not executed.
        let signed_ok = h.flags & flags::SIGNED != 0 && crypto::verify(&key, raw, &h.signature);
        if !signed_ok {
            return Ok(error_reply(h, conn, status::ACCESS_DENIED, Some(key)));
        }
        // A related operation after a failed predecessor inherits its error (MS-SMB2 §3.3.5.2.7.2).
        if let Some(st) = related_failed {
            return Ok(error_reply(h, conn, st, Some(key)));
        }

        let compound_file = conn.compound_file;
        let session = conn
            .sessions
            .get_mut(&h.session_id)
            .expect("session found above");
        let out = match h.command {
            Command::Echo | Command::Logoff => {
                decode_simple_req(&mut Reader::new(&msg.body))?;
                Out::ok(simple_body())
            }
            Command::TreeConnect => {
                let req = TreeConnectReq::decode(&mut Reader::new(&msg.body))?;
                match share_of(&req.path) {
                    Some(share) if share.to_lowercase() == ctx.share_name.to_lowercase() => {
                        let tree_id = session.add_tree(ctx.share_name);
                        let mut w = Writer::new();
                        tree_connect_resp(&ctx.caps).encode(&mut w);
                        Out {
                            new_tree: Some(tree_id),
                            ..Out::ok(w.into_vec())
                        }
                    }
                    _ => Out::err(status::BAD_NETWORK_NAME),
                }
            }
            Command::TreeDisconnect => {
                decode_simple_req(&mut Reader::new(&msg.body))?;
                if session.trees.remove(&h.tree_id).is_some() {
                    session.opens.retain(|_, o| o.tree_id != h.tree_id);
                    Out::ok(simple_body())
                } else {
                    Out::err(status::NETWORK_NAME_DELETED)
                }
            }
            Command::Create => {
                let req = CreateReq::decode(&mut Reader::new(&msg.body))?;
                Self::create(&req, h.tree_id, session, ctx)
            }
            Command::QueryInfo => {
                let req = QueryInfoReq::decode(&mut Reader::new(&msg.body))?;
                let fid = resolve_file_id(req.file_id, compound_file);
                match session.open_mut(&fid, h.tree_id) {
                    Some(_) => Self::query_info(&req, ctx),
                    None => Out::err(status::FILE_CLOSED),
                }
            }
            Command::QueryDirectory => {
                let req = QueryDirectoryReq::decode(&mut Reader::new(&msg.body))?;
                let fid = resolve_file_id(req.file_id, compound_file);
                match session.open_mut(&fid, h.tree_id) {
                    // The root is empty: the first query finds no matches, then the enumeration is over.
                    Some(open) if !open.enumerated => {
                        open.enumerated = true;
                        Out::err(status::NO_SUCH_FILE)
                    }
                    Some(_) => Out::err(status::NO_MORE_FILES),
                    None => Out::err(status::FILE_CLOSED),
                }
            }
            Command::Close => {
                let req = CloseReq::decode(&mut Reader::new(&msg.body))?;
                let fid = resolve_file_id(req.file_id, compound_file);
                if session.close(&fid, h.tree_id) {
                    let mut w = Writer::new();
                    encode_close_resp(&mut w);
                    Out::ok(w.into_vec())
                } else {
                    Out::err(status::FILE_CLOSED)
                }
            }
            // READ/WRITE/FLUSH/IOCTL/... — J2.
            _ => Out::err(status::NOT_IMPLEMENTED),
        };

        let mut elem = reply(h, conn, out.status, out.body, Some(key));
        if let Some(tree_id) = out.new_tree {
            elem.header.tree_id = tree_id;
        }
        if let Some(fid) = out.created_file {
            conn.compound_file = Some(fid);
        }
        if h.command == Command::Logoff && out.status == status::SUCCESS {
            // The reply is signed with the session key (already in the Element); we delete the session itself.
            conn.sessions.remove(&h.session_id);
        }
        Ok(elem)
    }

    /// CREATE: only the share root (empty path) is served for now, as a virtual empty directory.
    fn create(req: &CreateReq, tree_id: u32, session: &mut Session, ctx: &ServerCtx<'_>) -> Out {
        if !session.trees.contains_key(&tree_id) {
            return Out::err(status::NETWORK_NAME_DELETED);
        }
        let is_root = req.path.trim_matches('\\').is_empty();
        if !is_root {
            return match req.create_disposition {
                disposition::OPEN | disposition::OVERWRITE => {
                    Out::err(status::OBJECT_NAME_NOT_FOUND)
                }
                _ => Out::err(status::NOT_IMPLEMENTED), // file creation is J2
            };
        }
        match req.create_disposition {
            disposition::OPEN | disposition::OPEN_IF => {}
            disposition::CREATE => return Out::err(status::OBJECT_NAME_COLLISION),
            _ => return Out::err(status::ACCESS_DENIED),
        }
        if req.create_options & OPT_NON_DIRECTORY_FILE != 0 {
            return Out::err(status::FILE_IS_A_DIRECTORY);
        }
        let file_id = session.open_root(tree_id);
        let v = volume_info(ctx);
        let mut w = Writer::new();
        CreateResp {
            create_action: ACTION_OPENED,
            creation_time: v.created,
            last_access_time: v.now,
            last_write_time: v.now,
            change_time: v.created,
            allocation_size: 0,
            end_of_file: 0,
            file_attributes: ATTR_DIRECTORY,
            file_id,
            maximal_access: req
                .contexts
                .iter()
                .any(|c| matches!(c, CreateContext::QueryMaximalAccess))
                .then_some(ACCESS_ALL),
        }
        .encode(&mut w);
        Out {
            created_file: Some(file_id),
            ..Out::ok(w.into_vec())
        }
    }

    fn query_info(req: &QueryInfoReq, ctx: &ServerCtx<'_>) -> Out {
        let v = volume_info(ctx);
        let data = match req.info_type {
            info_type::FILESYSTEM => fs_info(req.class, &v),
            info_type::FILE => root_dir_info(req.class, &v),
            _ => return Out::err(status::NOT_SUPPORTED),
        };
        match data {
            None => Out::err(status::INVALID_INFO_CLASS),
            Some(d) if d.len() > req.output_buffer_length as usize => {
                Out::err(status::INFO_LENGTH_MISMATCH)
            }
            Some(d) => {
                let mut w = Writer::new();
                encode_query_info_resp(&mut w, &d);
                Out::ok(w.into_vec())
            }
        }
    }
}

/// Result of handling a command, before the header is assembled.
struct Out {
    status: u32,
    body: Vec<u8>,
    new_tree: Option<u32>,
    created_file: Option<[u8; 16]>,
}

impl Out {
    fn ok(body: Vec<u8>) -> Out {
        Out {
            status: status::SUCCESS,
            body,
            new_tree: None,
            created_file: None,
        }
    }

    fn err(status: u32) -> Out {
        Out {
            status,
            body: error_body(),
            new_tree: None,
            created_file: None,
        }
    }
}

fn simple_body() -> Vec<u8> {
    let mut w = Writer::new();
    encode_simple_resp(&mut w);
    w.into_vec()
}

/// 0xFF…FF in a related request means "the file of the previous CREATE in the chain".
fn resolve_file_id(requested: [u8; 16], compound_file: Option<[u8; 16]>) -> [u8; 16] {
    if requested == FILE_ID_RELATED {
        compound_file.unwrap_or(FILE_ID_RELATED)
    } else {
        requested
    }
}

fn volume_info(ctx: &ServerCtx<'_>) -> VolumeInfo {
    VolumeInfo {
        total_bytes: ctx.volume_bytes,
        free_bytes: ctx.volume_bytes, // the root is empty
        created: ctx.started_filetime,
        now: ctx.filetime,
        case_sensitive_names: ctx.caps.case_sensitive_names,
    }
}

enum AuthStep {
    /// Send an SPNEGO token to the client and wait for the next step (MORE_PROCESSING).
    SendToken(Vec<u8>),
    Done {
        user: String,
        session_key: [u8; 16],
    },
    Fail,
}

fn pending_mut(conn: &mut ConnState, sid: u64) -> &mut PendingAuth {
    match &mut conn
        .sessions
        .get_mut(&sid)
        .expect("session in Authenticating state")
        .state
    {
        SessionState::Authenticating(p) => p,
        SessionState::Active { .. } => unreachable!("expected Authenticating"),
    }
}

/// `\\host\share` → `share`. Any other form gives `None`.
fn share_of(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("\\\\")?;
    let (host, share) = rest.split_once('\\')?;
    (!host.is_empty() && !share.is_empty() && !share.contains('\\')).then_some(share)
}

/// TREE_CONNECT reply parameters by profile.
/// In J1 no flag depends on the profile: a backup share is not cached on the client
/// under any profile. The parameter is an extension point (J2+: profile capabilities).
fn tree_connect_resp(_caps: &CompatCaps) -> TreeConnectResp {
    TreeConnectResp {
        share_type: share_type::DISK,
        share_flags: share_flags::NO_CACHING,
        capabilities: 0,
        maximal_access: ACCESS_ALL,
    }
}

/// Splits an NBSS packet by NextCommand into the elements of a compound chain.
fn split_compound(payload: &[u8]) -> Result<Vec<&[u8]>, WireError> {
    let mut out = Vec::new();
    let mut rest = payload;
    loop {
        if rest.len() < smb_wire::header::HEADER_LEN {
            return Err(WireError::Truncated);
        }
        let next = u32::from_le_bytes([rest[20], rest[21], rest[22], rest[23]]) as usize;
        if next == 0 {
            out.push(rest);
            return Ok(out);
        }
        if next < smb_wire::header::HEADER_LEN || !next.is_multiple_of(8) || next > rest.len() {
            return Err(WireError::Malformed("NextCommand outside the packet"));
        }
        out.push(&rest[..next]);
        rest = &rest[next..];
        if out.len() >= MAX_COMPOUND {
            return Err(WireError::Malformed("compound chain too long"));
        }
    }
}

/// Assemble the reply: align the elements, set NextCommand, sign each one.
fn assemble(elements: Vec<Element>) -> Vec<u8> {
    let n = elements.len();
    let mut out = Vec::new();
    for (i, mut e) in elements.into_iter().enumerate() {
        let last = i + 1 == n;
        if e.sign_key.is_some() {
            e.header.flags |= flags::SIGNED;
        }
        let unpadded = smb_wire::header::HEADER_LEN + e.body.len();
        let padded = if last {
            unpadded
        } else {
            unpadded.next_multiple_of(8)
        };
        e.header.next_command = if last { 0 } else { padded as u32 };
        e.header.signature = [0; 16];

        let mut w = Writer::new();
        e.header.encode(&mut w);
        w.bytes(&e.body);
        w.zeros(padded - unpadded);
        let mut bytes = w.into_vec();
        if let Some(key) = e.sign_key {
            let sig = crypto::sign_cmac(&key, &bytes);
            bytes[48..64].copy_from_slice(&sig);
        }
        out.extend_from_slice(&bytes);
    }
    out
}

/// Reply: a header with status, granted credits and (optionally) the signing key.
fn reply(
    req: &Header,
    conn: &mut ConnState,
    status: u32,
    body: Vec<u8>,
    sign_key: Option<[u8; 16]>,
) -> Element {
    let mut header = Header::response_to(req, status);
    header.credit_req_grant = conn.credits.grant(req.credit_req_grant);
    Element {
        header,
        body,
        sign_key,
    }
}

fn error_reply(
    req: &Header,
    conn: &mut ConnState,
    status: u32,
    sign_key: Option<[u8; 16]>,
) -> Element {
    reply(req, conn, status, error_body(), sign_key)
}

/// Error reply body: StructureSize=9, ByteCount=0 (MS-SMB2 §2.2.2).
fn error_body() -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(9); // StructureSize
    w.u8(0); // ErrorContextCount
    w.u8(0); // Reserved
    w.u32(0); // ByteCount
    w.into_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::AUTH_TIMEOUT;
    use janus_lib::profile::ClientProfile;
    use smb_wire::auth::NegState;
    use smb_wire::testclient::{
        Client, Response, close_body, create_body, frame, negotiate_body, query_directory_body,
        query_info_body, request_header, session_setup_body, sign_frame, simple_body,
        smb1_negotiate, split_compound, tree_connect_body,
    };
    use std::time::Duration;

    const USER: &str = "janus";
    const PASSWORD: &str = "correct horse battery staple";

    fn det_random(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = 0x30 + (i % 7) as u8;
        }
    }

    struct Fixture {
        next_session: AtomicU64,
        conn: ConnState,
        creds: Option<Credentials>,
        now: Instant,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                next_session: AtomicU64::new(0x1_0000_0001),
                conn: ConnState::default(),
                creds: Some(Credentials::from_password(USER, PASSWORD)),
                now: Instant::now(),
            }
        }

        fn send(&mut self, payload: &[u8]) -> Result<Vec<u8>, WireError> {
            let ctx = ServerCtx {
                server_guid: [9; 16],
                server_name: "JANUS",
                share_name: "backup",
                caps: ClientProfile::TimeMachine.caps(),
                credentials: self.creds.clone(),
                next_session_id: &self.next_session,
                filetime: 133_000_000_000_000_000,
                started_filetime: 132_000_000_000_000_000,
                volume_bytes: 1 << 40,
                now: self.now,
                random: det_random,
            };
            match Dispatcher::handle(payload, &mut self.conn, &ctx)? {
                Reply::Now(b) => Ok(b),
                _ => panic!("expected Reply::Now"),
            }
        }

        fn negotiate(&mut self, c: &mut Client) -> Response {
            let req = c.negotiate_request();
            let resp = self.send(&req).unwrap();
            c.on_negotiate_response(&resp);
            Response::parse(&resp).unwrap()
        }

        /// Full handshake; returns the reply to the last SESSION_SETUP.
        fn login(&mut self, c: &mut Client) -> Response {
            self.negotiate(c);
            let r1 = self.send(&c.session_setup_1()).unwrap();
            let req2 = c.session_setup_2(&r1).unwrap();
            let r2 = self.send(&req2).unwrap();
            Response::parse(&r2).unwrap()
        }
    }

    fn ok_client() -> Client {
        Client::new(USER, PASSWORD)
    }

    // --- NEGOTIATE ---

    #[test]
    fn negotiate_selects_311_and_requires_signing() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        let r = fx.negotiate(&mut c);
        assert_eq!(r.status(), status::SUCCESS);
        let b = &r.message.body;
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 65);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 0x0003, "ENABLED|REQUIRED");
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 0x0311);
        assert_eq!(
            u16::from_le_bytes([b[6], b[7]]),
            1,
            "single negotiate context"
        );
        assert_eq!(&b[8..24], &[9; 16], "ServerGuid");
        assert_eq!(
            u32::from_le_bytes(b[24..28].try_into().unwrap()),
            0,
            "capabilities"
        );
        let t = u64::from_le_bytes(b[40..48].try_into().unwrap());
        assert_eq!(t, 133_000_000_000_000_000, "real FILETIME from ctx");
        assert_eq!(
            u64::from_le_bytes(b[48..56].try_into().unwrap()),
            0,
            "ServerStartTime"
        );
        assert_eq!(fx.conn.dialect, Some(smb_wire::Dialect::Smb311));
        // The reply carries SPNEGO with NTLM, handed to the client for mechanism selection.
        let sec_len = u16::from_le_bytes([b[58], b[59]]) as usize;
        let tok = SpnegoToken::parse(&b[64..64 + sec_len]).unwrap();
        assert!(matches!(tok, SpnegoToken::NegTokenInit { .. }));
        // The server's preauth hash matched the client's (both computed from the wire).
        assert_eq!(fx.conn.preauth_hash, c.preauth_hash);
    }

    #[test]
    fn negotiate_without_311_is_not_supported() {
        let mut fx = Fixture::new();
        let h = request_header(Command::Negotiate, 0, 0, 0);
        let req = frame(
            &h,
            &negotiate_body(&[0x0202, 0x0210, 0x0300, 0x0302], false, &[]),
        );
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::NOT_SUPPORTED);
        assert_eq!(fx.conn.dialect, None);
    }

    #[test]
    fn negotiate_311_without_preauth_context_is_rejected() {
        let mut fx = Fixture::new();
        let h = request_header(Command::Negotiate, 0, 0, 0);
        let req = frame(&h, &negotiate_body(&[0x0311], false, &[]));
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::NO_PREAUTH_HASH_OVERLAP);
        assert_eq!(fx.conn.dialect, None);
    }

    #[test]
    fn repeated_negotiate_and_early_commands_close_the_connection() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let again = c.negotiate_request();
        assert!(fx.send(&again).is_err());

        let mut fx = Fixture::new();
        let h = request_header(Command::Echo, 0, 0, 0);
        assert!(fx.send(&frame(&h, &simple_body())).is_err());
        let h = request_header(Command::SessionSetup, 0, 0, 0);
        assert!(
            fx.send(&frame(&h, &session_setup_body(&[0x60, 0], 0)))
                .is_err()
        );
    }

    #[test]
    fn garbage_and_truncated_packets_are_errors_not_panics() {
        let mut fx = Fixture::new();
        assert!(fx.send(&[]).is_err());
        assert!(fx.send(&[0xFE, b'S', b'M', b'B']).is_err());
        assert!(fx.send(&[0xFF, b'S', b'M', b'B', 0, 0, 0, 0]).is_err()); // SMB1, not NEGOTIATE
        assert!(fx.send(&[0xFD, b'S', b'M', b'B', 0, 0, 0, 0]).is_err()); // transform
        let mut c = ok_client();
        let req = c.negotiate_request();
        for n in 0..req.len() {
            let mut fx = Fixture::new();
            let _ = fx.send(&req[..n]); // not a single panic
        }
    }

    // --- SMB1 multi-protocol NEGOTIATE ---

    #[test]
    fn smb1_multiprotocol_negotiate_gets_wildcard_then_real_negotiate_works() {
        let mut fx = Fixture::new();
        let r = fx
            .send(&smb1_negotiate(&["NT LM 0.12", "SMB 2.002", "SMB 2.???"]))
            .unwrap();
        let p = Response::parse(&r).unwrap();
        assert_eq!(p.status(), status::SUCCESS);
        assert_eq!(p.header().message_id, 0);
        let b = &p.message.body;
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 0x0003, "signing required");
        assert_eq!(u16::from_le_bytes([b[4], b[5]]), 0x02FF, "wildcard dialect");
        assert_eq!(fx.conn.dialect, None, "dialect not chosen yet");
        assert_eq!(
            fx.conn.preauth_hash, [0; 64],
            "SMB1 exchange is not part of the preauth hash"
        );
        // The real SMB2 NEGOTIATE after the wildcard goes through as usual, the hash is computed from scratch.
        let mut c = ok_client();
        let r = fx.negotiate(&mut c);
        assert_eq!(r.status(), status::SUCCESS);
        assert_eq!(fx.conn.dialect, Some(smb_wire::Dialect::Smb311));
        assert_eq!(fx.conn.preauth_hash, c.preauth_hash);
    }

    #[test]
    fn smb1_only_old_dialects_and_repeats_are_refused() {
        let mut fx = Fixture::new();
        assert!(fx.send(&smb1_negotiate(&["NT LM 0.12"])).is_err());
        // "SMB 2.002" without the wildcard → revision 0x0202
        let r = fx.send(&smb1_negotiate(&["SMB 2.002"])).unwrap();
        let p = Response::parse(&r).unwrap();
        assert_eq!(
            u16::from_le_bytes([p.message.body[4], p.message.body[5]]),
            0x0202
        );
        // a second SMB1 NEGOTIATE on the same connection is a violation
        assert!(fx.send(&smb1_negotiate(&["SMB 2.???"])).is_err());
        // SMB1 after SMB2 NEGOTIATE is a violation too
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        assert!(fx.send(&smb1_negotiate(&["SMB 2.???"])).is_err());
    }

    #[test]
    fn smb1_wildcard_does_not_spend_the_initial_credit() {
        let mut fx = Fixture::new();
        fx.send(&smb1_negotiate(&["SMB 2.???"])).unwrap();
        assert_eq!(fx.conn.credits.outstanding(), 1);
        let mut c = ok_client();
        assert_eq!(fx.negotiate(&mut c).status(), status::SUCCESS);
    }

    // --- SESSION_SETUP ---

    #[test]
    fn full_handshake_establishes_signed_session() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        let r = fx.login(&mut c);
        assert_eq!(r.status(), status::SUCCESS);
        // The reply is signed with a key derived by the client independently of the server.
        assert!(
            c.verify_response(&r.raw),
            "signature of the final SESSION_SETUP response"
        );
        assert_eq!(r.header().session_id, c.session_id);
        assert_ne!(c.session_id, 0);
        // SPNEGO accept-completed
        let tok = SpnegoToken::parse(&r.session_setup_token()).unwrap();
        assert!(matches!(
            tok,
            SpnegoToken::NegTokenResp {
                neg_state: Some(NegState::AcceptCompleted),
                ..
            }
        ));
        let s = &fx.conn.sessions[&c.session_id];
        assert_eq!(s.signing_key(), c.signing_key);
    }

    #[test]
    fn challenge_step_is_more_processing_and_unsigned() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let r1 = Response::parse(&fx.send(&c.session_setup_1()).unwrap()).unwrap();
        assert_eq!(r1.status(), status::MORE_PROCESSING_REQUIRED);
        assert_eq!(r1.header().flags & flags::SIGNED, 0);
        assert_eq!(r1.header().signature, [0; 16]);
        assert_ne!(r1.header().session_id, 0);
        assert!(fx.conn.has_pending_auth());
    }

    #[test]
    fn wrong_password_is_logon_failure_without_details() {
        let mut fx = Fixture::new();
        let mut c = Client::new(USER, "wrong password");
        fx.negotiate(&mut c);
        let r1 = fx.send(&c.session_setup_1()).unwrap();
        let req2 = c.session_setup_2(&r1).unwrap();
        let r = Response::parse(&fx.send(&req2).unwrap()).unwrap();
        assert_eq!(r.status(), status::LOGON_FAILURE);
        assert_eq!(
            r.header().flags & flags::SIGNED,
            0,
            "logon failure is not signed"
        );
        assert_eq!(
            r.message.body,
            error_body(),
            "no failure reason in the body"
        );
        assert!(fx.conn.sessions.is_empty(), "session removed");
        assert_eq!(fx.conn.auth_failures, 1);
        assert!(!fx.conn.close_after_reply);
    }

    #[test]
    fn unknown_user_gets_same_logon_failure() {
        let mut fx = Fixture::new();
        let mut c = Client::new("mallory", PASSWORD);
        fx.negotiate(&mut c);
        let r1 = fx.send(&c.session_setup_1()).unwrap();
        let req2 = c.session_setup_2(&r1).unwrap();
        let r = Response::parse(&fx.send(&req2).unwrap()).unwrap();
        assert_eq!(r.status(), status::LOGON_FAILURE);
    }

    #[test]
    fn repeated_failures_close_the_connection() {
        let mut fx = Fixture::new();
        let mut c0 = ok_client();
        fx.negotiate(&mut c0);
        for i in 0..MAX_AUTH_FAILURES {
            let mut c = Client::new(USER, "nope");
            let r1 = fx.send(&c.session_setup_1()).unwrap();
            let req2 = c.session_setup_2(&r1).unwrap();
            let r = Response::parse(&fx.send(&req2).unwrap()).unwrap();
            assert_eq!(r.status(), status::LOGON_FAILURE);
            assert_eq!(fx.conn.close_after_reply, i + 1 == MAX_AUTH_FAILURES);
        }
    }

    #[test]
    fn no_credentials_configured_means_no_login_and_no_guest() {
        let mut fx = Fixture::new();
        fx.creds = None;
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let r = Response::parse(&fx.send(&c.session_setup_1()).unwrap()).unwrap();
        assert_eq!(r.status(), status::LOGON_FAILURE);
        assert!(fx.conn.sessions.is_empty());
    }

    #[test]
    fn session_binding_is_not_supported() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let h = request_header(Command::SessionSetup, 1, 0, 0);
        let token = SpnegoToken::NegTokenInit {
            mech_types: vec![OID_NTLMSSP.to_vec()],
            mech_token: smb_wire::testclient::ntlm_negotiate_message(),
        }
        .build();
        let req = frame(
            &h,
            &session_setup_body(&token, session_setup_flags::BINDING),
        );
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::INVALID_PARAMETER);
        assert!(fx.conn.sessions.is_empty());
    }

    #[test]
    fn second_leg_for_unknown_session_is_user_session_deleted() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let h = request_header(Command::SessionSetup, 1, 0xDEAD, 0);
        let req = frame(&h, &session_setup_body(&[0xA1, 0x00], 0));
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::USER_SESSION_DELETED);
    }

    #[test]
    fn garbage_spnego_is_invalid_parameter_and_leaves_no_session() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let h = request_header(Command::SessionSetup, 1, 0, 0);
        let req = frame(&h, &session_setup_body(&[0x42, 0x42, 0x42], 0));
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::INVALID_PARAMETER);
        assert!(fx.conn.sessions.is_empty());
    }

    #[test]
    fn kerberos_first_then_ntlm_fallback() {
        // The client offers [KRB5, NTLM] with a Kerberos token → the server asks for NTLM,
        // the client sends the NTLM NEGOTIATE in a NegTokenResp, the exchange completes.
        const OID_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let init = SpnegoToken::NegTokenInit {
            mech_types: vec![OID_KRB5.to_vec(), OID_NTLMSSP.to_vec()],
            mech_token: vec![0x60, 0x03, 0x01, 0x02, 0x03],
        }
        .build();
        let f1 = frame(
            &request_header(Command::SessionSetup, c.next_message_id(), 0, 0),
            &session_setup_body(&init, 0),
        );
        c.preauth_hash = crypto::preauth_chain(&c.preauth_hash, &f1);
        let r1 = fx.send(&f1).unwrap();
        let p1 = Response::parse(&r1).unwrap();
        assert_eq!(p1.status(), status::MORE_PROCESSING_REQUIRED);
        let tok = SpnegoToken::parse(&p1.session_setup_token()).unwrap();
        match tok {
            SpnegoToken::NegTokenResp {
                supported_mech,
                response_token,
                ..
            } => {
                assert_eq!(supported_mech.as_deref(), Some(OID_NTLMSSP));
                assert!(response_token.is_empty());
            }
            other => panic!("{other:?}"),
        }
        c.preauth_hash = crypto::preauth_chain(&c.preauth_hash, &r1);
        c.session_id = p1.header().session_id;
        // Then it is plain NTLM inside NegTokenResp.
        let neg = smb_wire::testclient::ntlm_negotiate_message();
        let resp_tok = SpnegoToken::NegTokenResp {
            neg_state: None,
            supported_mech: None,
            response_token: neg,
        }
        .build();
        let f2 = frame(
            &request_header(Command::SessionSetup, c.next_message_id(), c.session_id, 0),
            &session_setup_body(&resp_tok, 0),
        );
        c.preauth_hash = crypto::preauth_chain(&c.preauth_hash, &f2);
        let r2 = fx.send(&f2).unwrap();
        assert_eq!(
            Response::parse(&r2).unwrap().status(),
            status::MORE_PROCESSING_REQUIRED
        );
    }

    #[test]
    fn mechanism_list_without_ntlm_is_logon_failure() {
        const OID_KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        let init = SpnegoToken::NegTokenInit {
            mech_types: vec![OID_KRB5.to_vec()],
            mech_token: vec![1, 2, 3],
        }
        .build();
        let req = frame(
            &request_header(Command::SessionSetup, 1, 0, 0),
            &session_setup_body(&init, 0),
        );
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::LOGON_FAILURE);
    }

    #[test]
    fn stale_pending_sessions_expire_and_are_limited() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        for _ in 0..MAX_PENDING_SESSIONS {
            let mut ci = ok_client();
            ci.message_id = 1;
            let r = Response::parse(&fx.send(&ci.session_setup_1()).unwrap()).unwrap();
            assert_eq!(r.status(), status::MORE_PROCESSING_REQUIRED);
        }
        // the next one is refused because of the limit
        let mut extra = ok_client();
        extra.message_id = 1;
        let r = Response::parse(&fx.send(&extra.session_setup_1()).unwrap()).unwrap();
        assert_eq!(r.status(), status::INSUFFICIENT_RESOURCES);
        // after the timeout, unfinished sessions are purged
        fx.now += AUTH_TIMEOUT + Duration::from_secs(1);
        extra.message_id = 1;
        let r = Response::parse(&fx.send(&extra.session_setup_1()).unwrap()).unwrap();
        assert_eq!(r.status(), status::MORE_PROCESSING_REQUIRED);
        assert_eq!(fx.conn.pending_auth_count(), 1);
    }

    // --- signature ---

    fn logged_in() -> (Fixture, Client) {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        assert_eq!(fx.login(&mut c).status(), status::SUCCESS);
        (fx, c)
    }

    #[test]
    fn signed_echo_gets_signed_response() {
        let (mut fx, mut c) = logged_in();
        let r = fx
            .send(&c.signed_request(Command::Echo, 0, &simple_body()))
            .unwrap();
        assert!(c.verify_response(&r));
        assert_eq!(Response::parse(&r).unwrap().status(), status::SUCCESS);
    }

    #[test]
    fn unsigned_request_after_login_is_denied() {
        let (mut fx, mut c) = logged_in();
        let h = request_header(Command::TreeConnect, c.next_message_id(), c.session_id, 0);
        let req = frame(&h, &tree_connect_body("\\\\127.0.0.1\\backup"));
        let r = fx.send(&req).unwrap();
        let p = Response::parse(&r).unwrap();
        assert_eq!(p.status(), status::ACCESS_DENIED);
        assert!(c.verify_response(&r), "the rejection is signed too");
        assert!(
            fx.conn.sessions[&c.session_id].trees.is_empty(),
            "command not executed"
        );
    }

    #[test]
    fn bad_signature_is_denied_for_every_kind_of_tampering() {
        let (mut fx, mut c) = logged_in();
        let good = c.signed_request(Command::TreeConnect, 0, &tree_connect_body("\\\\h\\backup"));
        // corrupted signature
        let mut bad = good.clone();
        bad[50] ^= 0x01;
        assert_eq!(
            Response::parse(&fx.send(&bad).unwrap()).unwrap().status(),
            status::ACCESS_DENIED
        );
        // corrupted body with a correct signature
        let mut bad = good.clone();
        let n = bad.len() - 1;
        bad[n] ^= 0x01;
        assert_eq!(
            Response::parse(&fx.send(&bad).unwrap()).unwrap().status(),
            status::ACCESS_DENIED
        );
        // signature with someone else's key
        let mut h = request_header(Command::TreeConnect, c.next_message_id(), c.session_id, 0);
        h.credit_req_grant = 1;
        let mut f = frame(&h, &tree_connect_body("\\\\h\\backup"));
        sign_frame(&mut f, &[7; 16]);
        assert_eq!(
            Response::parse(&fx.send(&f).unwrap()).unwrap().status(),
            status::ACCESS_DENIED
        );
        assert!(fx.conn.sessions[&c.session_id].trees.is_empty());
        // and the original passes
        assert_eq!(
            Response::parse(&fx.send(&good).unwrap()).unwrap().status(),
            status::SUCCESS
        );
    }

    #[test]
    fn signed_flag_without_valid_signature_is_denied() {
        let (mut fx, mut c) = logged_in();
        let h = request_header(Command::Echo, c.next_message_id(), c.session_id, 0);
        let mut f = frame(&h, &simple_body());
        f[16] |= flags::SIGNED as u8; // the flag is there, the signature is not (zeros)
        assert_eq!(
            Response::parse(&fx.send(&f).unwrap()).unwrap().status(),
            status::ACCESS_DENIED
        );
    }

    #[test]
    fn commands_for_unknown_or_unfinished_session_are_rejected() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        fx.negotiate(&mut c);
        // A session id that does not exist
        let h = request_header(Command::Echo, 1, 0x1234, 0);
        let r = Response::parse(&fx.send(&frame(&h, &simple_body())).unwrap()).unwrap();
        assert_eq!(r.status(), status::USER_SESSION_DELETED);
        // The session id of an authentication in progress: too early
        let r1 = fx.send(&c.session_setup_1()).unwrap();
        let sid = Response::parse(&r1).unwrap().header().session_id;
        let h = request_header(Command::TreeConnect, 2, sid, 0);
        let f = frame(&h, &tree_connect_body("\\\\h\\backup"));
        let r = Response::parse(&fx.send(&f).unwrap()).unwrap();
        assert_eq!(r.status(), status::USER_SESSION_DELETED);
    }

    // --- TREE_CONNECT / DISCONNECT / LOGOFF ---

    fn tree_connect(fx: &mut Fixture, c: &mut Client, path: &str) -> Response {
        let r = fx
            .send(&c.signed_request(Command::TreeConnect, 0, &tree_connect_body(path)))
            .unwrap();
        assert!(c.verify_response(&r));
        Response::parse(&r).unwrap()
    }

    #[test]
    fn tree_connect_to_the_share_succeeds_case_insensitively() {
        let (mut fx, mut c) = logged_in();
        for path in [
            "\\\\127.0.0.1\\backup",
            "\\\\127.0.0.1\\BACKUP",
            "\\\\localhost\\BaCkUp",
        ] {
            let r = tree_connect(&mut fx, &mut c, path);
            assert_eq!(r.status(), status::SUCCESS, "{path}");
            assert_ne!(r.header().tree_id, 0);
            let b = &r.message.body;
            assert_eq!(u16::from_le_bytes([b[0], b[1]]), 16);
            assert_eq!(b[2], 1, "ShareType = DISK");
            assert_eq!(
                u32::from_le_bytes(b[4..8].try_into().unwrap()),
                smb_wire::messages::share_flags::NO_CACHING
            );
            assert_eq!(
                u32::from_le_bytes(b[12..16].try_into().unwrap()),
                ACCESS_ALL
            );
        }
        assert_eq!(fx.conn.sessions[&c.session_id].trees.len(), 3);
    }

    #[test]
    fn tree_connect_to_unknown_share_is_bad_network_name() {
        let (mut fx, mut c) = logged_in();
        for path in [
            "\\\\127.0.0.1\\other",
            "\\\\127.0.0.1\\IPC$",
            "\\\\127.0.0.1\\",
            "\\\\127.0.0.1",
            "backup",
            "\\\\h\\backup\\sub",
            "",
        ] {
            let r = tree_connect(&mut fx, &mut c, path);
            assert_eq!(r.status(), status::BAD_NETWORK_NAME, "{path:?}");
        }
        assert!(fx.conn.sessions[&c.session_id].trees.is_empty());
    }

    #[test]
    fn tree_disconnect_and_logoff() {
        let (mut fx, mut c) = logged_in();
        let tid = tree_connect(&mut fx, &mut c, "\\\\h\\backup")
            .header()
            .tree_id;

        let r = fx
            .send(&c.signed_request(Command::TreeDisconnect, tid, &simple_body()))
            .unwrap();
        assert!(c.verify_response(&r));
        assert_eq!(Response::parse(&r).unwrap().status(), status::SUCCESS);
        // again: the tree is already gone
        let r = fx
            .send(&c.signed_request(Command::TreeDisconnect, tid, &simple_body()))
            .unwrap();
        assert_eq!(
            Response::parse(&r).unwrap().status(),
            status::NETWORK_NAME_DELETED
        );

        let r = fx
            .send(&c.signed_request(Command::Logoff, 0, &simple_body()))
            .unwrap();
        assert!(
            c.verify_response(&r),
            "LOGOFF response signed with the session key"
        );
        assert_eq!(Response::parse(&r).unwrap().status(), status::SUCCESS);
        assert!(fx.conn.sessions.is_empty());
        // after LOGOFF the session is invalid
        let r = fx
            .send(&c.signed_request(Command::Echo, 0, &simple_body()))
            .unwrap();
        assert_eq!(
            Response::parse(&r).unwrap().status(),
            status::USER_SESSION_DELETED
        );
    }

    #[test]
    fn file_commands_are_not_implemented_but_still_signed() {
        let (mut fx, mut c) = logged_in();
        let r = fx
            .send(&c.signed_request(Command::Read, 1, &[49, 0, 0, 0]))
            .unwrap();
        assert!(c.verify_response(&r));
        assert_eq!(
            Response::parse(&r).unwrap().status(),
            status::NOT_IMPLEMENTED
        );
    }

    // --- compound and credits ---

    /// A signed compound chain. NextCommand and alignment are set BEFORE signing
    /// (the signature covers the whole element, including NextCommand and padding).
    /// Element: (command, body, flags, session_id, tree_id).
    fn signed_chain(c: &mut Client, items: &[(Command, Vec<u8>, u32, u64, u32)]) -> Vec<u8> {
        let mut chain = Vec::new();
        for (i, (cmd, body, fl, sid, tid)) in items.iter().enumerate() {
            let mut h = request_header(*cmd, c.next_message_id(), *sid, *tid);
            h.flags = *fl;
            let mut f = frame(&h, body);
            if i + 1 < items.len() {
                let padded = f.len().next_multiple_of(8);
                f.resize(padded, 0);
                f[20..24].copy_from_slice(&(padded as u32).to_le_bytes());
            }
            sign_frame(&mut f, &c.signing_key.unwrap());
            chain.extend_from_slice(&f);
        }
        chain
    }

    #[test]
    fn compound_request_gets_aligned_chain_with_each_element_signed() {
        let (mut fx, mut c) = logged_in();
        let sid = c.session_id;
        let chain = signed_chain(
            &mut c,
            &[
                (Command::Echo, simple_body(), 0, sid, 0),
                (
                    Command::TreeConnect,
                    tree_connect_body("\\\\h\\backup"),
                    0,
                    sid,
                    0,
                ),
                (Command::Echo, simple_body(), 0, sid, 0),
            ],
        );
        let resp = fx.send(&chain).unwrap();
        let parts = split_compound(&resp);
        assert_eq!(parts.len(), 3);
        for (i, p) in parts.iter().enumerate() {
            assert!(c.verify_response(p), "item {i} is signed and valid");
            if i + 1 < parts.len() {
                assert_eq!(p.len() % 8, 0, "item {i} is aligned");
            }
        }
        let statuses: Vec<u32> = parts
            .iter()
            .map(|p| Response::parse(p).unwrap().status())
            .collect();
        assert_eq!(statuses, vec![status::SUCCESS; 3]);
    }

    #[test]
    fn related_compound_inherits_session_and_tree_ids() {
        let (mut fx, mut c) = logged_in();
        let tid = tree_connect(&mut fx, &mut c, "\\\\h\\backup")
            .header()
            .tree_id;
        let sid = c.session_id;
        // ECHO + TREE_DISCONNECT (related: session and tree = 0xFFFF…)
        let chain = signed_chain(
            &mut c,
            &[
                (Command::Echo, simple_body(), 0, sid, tid),
                (
                    Command::TreeDisconnect,
                    simple_body(),
                    flags::RELATED_OPERATIONS,
                    u64::MAX,
                    u32::MAX,
                ),
            ],
        );
        let resp = fx.send(&chain).unwrap();
        let parts = split_compound(&resp);
        assert_eq!(parts.len(), 2);
        assert_eq!(Response::parse(parts[1]).unwrap().status(), status::SUCCESS);
        assert!(fx.conn.sessions[&c.session_id].trees.is_empty());
    }

    #[test]
    fn bad_next_command_is_protocol_error() {
        let (mut fx, mut c) = logged_in();
        let mut f = c.signed_request(Command::Echo, 0, &simple_body());
        f[20..24].copy_from_slice(&5000u32.to_le_bytes());
        assert!(fx.send(&f).is_err());
        let mut f = c.signed_request(Command::Echo, 0, &simple_body());
        f[20..24].copy_from_slice(&13u32.to_le_bytes());
        assert!(fx.send(&f).is_err());
    }

    #[test]
    fn negotiate_in_compound_is_protocol_error() {
        let mut fx = Fixture::new();
        let mut c = ok_client();
        let mut f = c.negotiate_request();
        let padded = f.len().next_multiple_of(8);
        f.resize(padded, 0);
        f[20..24].copy_from_slice(&(padded as u32).to_le_bytes());
        let echo = frame(&request_header(Command::Echo, 1, 0, 0), &simple_body());
        f.extend_from_slice(&echo);
        assert!(fx.send(&f).is_err());
    }

    #[test]
    fn every_response_grants_credits_and_overspending_closes() {
        let (mut fx, mut c) = logged_in();
        // steady state: credits are granted in every reply
        for _ in 0..20 {
            let r = fx
                .send(&c.signed_request(Command::Echo, 0, &simple_body()))
                .unwrap();
            let granted = Response::parse(&r).unwrap().header().credit_req_grant;
            assert!(granted >= 1);
        }
        // the client asks for 16 credits in every request → the window grows, but is bounded
        assert!(fx.conn.credits.outstanding() <= crate::conn::MAX_OUTSTANDING_CREDITS);
        // a request with CreditCharge above the window is a protocol error
        let mut h = request_header(Command::Echo, c.next_message_id(), c.session_id, 0);
        h.credit_charge = 1000;
        let mut f = frame(&h, &simple_body());
        sign_frame(&mut f, &c.signing_key.unwrap());
        assert!(fx.send(&f).is_err());
    }

    #[test]
    fn credits_are_granted_in_error_responses_too() {
        let mut fx = Fixture::new();
        let h = request_header(Command::Negotiate, 0, 0, 0);
        let req = frame(&h, &negotiate_body(&[0x0202], false, &[]));
        let r = Response::parse(&fx.send(&req).unwrap()).unwrap();
        assert_eq!(r.status(), status::NOT_SUPPORTED);
        assert_eq!(r.header().credit_req_grant, 16);
    }

    // --- virtual share root: CREATE / QUERY_INFO / QUERY_DIRECTORY / CLOSE ---

    /// Bodies from a live macOS `mount_smbfs` exchange (CREATE of the root + related QUERY_INFO + CLOSE).
    const MACOS_CREATE: &str = "39000000020000000000000000000000000000000000000080001000100000000700000001000000010000007800000080000000180000000000000000000000000000001000040000000000000000004d78416300000000";
    const MACOS_QUERY_INFO: &str =
        "290002031800000000000000000000000000000000000000ffffffffffffffffffffffffffffffff";
    const MACOS_CLOSE: &str = "1800000000000000ffffffffffffffffffffffffffffffff";
    const RELATED: [u8; 16] = [0xFF; 16];

    fn connected() -> (Fixture, Client, u32) {
        let (mut fx, mut c) = logged_in();
        let tid = tree_connect(&mut fx, &mut c, "\\\\127.0.0.1\\backup")
            .header()
            .tree_id;
        (fx, c, tid)
    }

    fn statuses(resp: &[u8]) -> Vec<u32> {
        split_compound(resp)
            .iter()
            .map(|p| Response::parse(p).unwrap().status())
            .collect()
    }

    fn create_root(fx: &mut Fixture, c: &mut Client, tid: u32) -> (Response, [u8; 16]) {
        let r = fx
            .send(&c.signed_request(
                Command::Create,
                tid,
                &create_body("", disposition::OPEN, 1, true),
            ))
            .unwrap();
        assert!(c.verify_response(&r));
        let p = Response::parse(&r).unwrap();
        assert_eq!(p.status(), status::SUCCESS);
        let fid: [u8; 16] = p.message.body[64..80].try_into().unwrap();
        (p, fid)
    }

    #[test]
    fn macos_mount_sequence_for_the_root_succeeds_end_to_end() {
        let (mut fx, mut c, tid) = connected();
        let sid = c.session_id;
        let chain = signed_chain(
            &mut c,
            &[
                (Command::Create, unhex_t(MACOS_CREATE), 0, sid, tid),
                (
                    Command::QueryInfo,
                    unhex_t(MACOS_QUERY_INFO),
                    flags::RELATED_OPERATIONS,
                    u64::MAX,
                    u32::MAX,
                ),
                (
                    Command::Close,
                    unhex_t(MACOS_CLOSE),
                    flags::RELATED_OPERATIONS,
                    u64::MAX,
                    u32::MAX,
                ),
            ],
        );
        let resp = fx.send(&chain).unwrap();
        assert_eq!(statuses(&resp), vec![status::SUCCESS; 3]);
        let parts = split_compound(&resp);
        for p in &parts {
            assert!(c.verify_response(p));
        }
        // CREATE: a directory, FILE_OPENED, MxAc with full rights
        let create = Response::parse(parts[0]).unwrap();
        let b = &create.message.body;
        assert_eq!(
            u32::from_le_bytes(b[4..8].try_into().unwrap()),
            1,
            "FILE_OPENED"
        );
        assert_eq!(
            u32::from_le_bytes(b[56..60].try_into().unwrap()),
            0x10,
            "directory"
        );
        assert_eq!(&b[88 + 16..88 + 20], b"MxAc");
        assert_eq!(
            u32::from_le_bytes(b[88 + 28..88 + 32].try_into().unwrap()),
            ACCESS_ALL
        );
        // QUERY_INFO: FileFsSizeInformation for a 1 TiB quota
        let qi = Response::parse(parts[1]).unwrap();
        let len = u32::from_le_bytes(qi.message.body[4..8].try_into().unwrap()) as usize;
        assert_eq!(len, 24);
        let data = &qi.message.body[8..8 + len];
        assert_eq!(
            u64::from_le_bytes(data[0..8].try_into().unwrap()),
            (1u64 << 40) / 4096
        );
        // after CLOSE nothing is open
        assert!(fx.conn.sessions[&c.session_id].opens.is_empty());
    }

    #[test]
    fn related_ops_after_failed_create_inherit_its_error() {
        let (mut fx, mut c, tid) = connected();
        let sid = c.session_id;
        let rel = flags::RELATED_OPERATIONS;
        let chain = signed_chain(
            &mut c,
            &[
                (
                    Command::Create,
                    create_body("nope.txt", disposition::OPEN, 0, false),
                    0,
                    sid,
                    tid,
                ),
                (
                    Command::QueryInfo,
                    query_info_body(2, 3, 24, RELATED),
                    rel,
                    u64::MAX,
                    u32::MAX,
                ),
                (Command::Close, close_body(RELATED), rel, u64::MAX, u32::MAX),
            ],
        );
        let resp = fx.send(&chain).unwrap();
        assert_eq!(statuses(&resp), vec![status::OBJECT_NAME_NOT_FOUND; 3]);
        for p in split_compound(&resp) {
            assert!(c.verify_response(p));
        }
    }

    #[test]
    fn root_create_rules() {
        let (mut fx, mut c, tid) = connected();
        let create = |fx: &mut Fixture, c: &mut Client, tree, body: Vec<u8>| {
            let r = fx
                .send(&c.signed_request(Command::Create, tree, &body))
                .unwrap();
            Response::parse(&r).unwrap().status()
        };
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                tid,
                create_body("\\", disposition::OPEN_IF, 0, false)
            ),
            status::SUCCESS
        );
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                tid,
                create_body("", disposition::CREATE, 0, false)
            ),
            status::OBJECT_NAME_COLLISION
        );
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                tid,
                create_body("", disposition::OVERWRITE_IF, 0, false)
            ),
            status::ACCESS_DENIED
        );
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                tid,
                create_body("", disposition::OPEN, 0x40, false)
            ),
            status::FILE_IS_A_DIRECTORY
        );
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                tid,
                create_body("a/b", disposition::CREATE, 0, false)
            ),
            status::NOT_IMPLEMENTED
        );
        // a tree that does not exist
        assert_eq!(
            create(
                &mut fx,
                &mut c,
                99,
                create_body("", disposition::OPEN, 0, false)
            ),
            status::NETWORK_NAME_DELETED
        );
    }

    #[test]
    fn query_info_variants_and_errors() {
        let (mut fx, mut c, tid) = connected();
        let (_, fid) = create_root(&mut fx, &mut c, tid);
        let mut q = |it: u8, class: u8, len: u32, fid: [u8; 16]| {
            let r = fx
                .send(&c.signed_request(
                    Command::QueryInfo,
                    tid,
                    &query_info_body(it, class, len, fid),
                ))
                .unwrap();
            let p = Response::parse(&r).unwrap();
            (p.status(), p.message.body.len())
        };
        for (it, class, size) in [
            (2, 1, 30),
            (2, 3, 24),
            (2, 4, 8),
            (2, 5, 20),
            (2, 7, 32),
            (1, 4, 40),
            (1, 5, 24),
            (1, 6, 8),
            (1, 18, 100),
            (1, 34, 56),
        ] {
            let (st, body_len) = q(it, class, 4096, fid);
            assert_eq!(st, status::SUCCESS, "type {it} class {class}");
            assert_eq!(body_len, 8 + size, "type {it} class {class}");
        }
        assert_eq!(q(2, 99, 4096, fid).0, status::INVALID_INFO_CLASS);
        assert_eq!(q(2, 3, 8, fid).0, status::INFO_LENGTH_MISMATCH);
        assert_eq!(q(3, 0, 4096, fid).0, status::NOT_SUPPORTED); // security info
        assert_eq!(q(2, 3, 4096, [7; 16]).0, status::FILE_CLOSED);
        assert_eq!(
            q(2, 3, 4096, RELATED).0,
            status::FILE_CLOSED,
            "related outside a chain"
        );
    }

    #[test]
    fn empty_directory_listing_then_no_more_files() {
        let (mut fx, mut c, tid) = connected();
        let (_, fid) = create_root(&mut fx, &mut c, tid);
        let mut list = || {
            let r = fx
                .send(&c.signed_request(Command::QueryDirectory, tid, &query_directory_body(fid)))
                .unwrap();
            Response::parse(&r).unwrap().status()
        };
        assert_eq!(list(), status::NO_SUCH_FILE);
        assert_eq!(list(), status::NO_MORE_FILES);
    }

    #[test]
    fn close_semantics_and_tree_disconnect_drops_opens() {
        let (mut fx, mut c, tid) = connected();
        let (_, fid) = create_root(&mut fx, &mut c, tid);
        // another tree does not see the handle
        let tid2 = tree_connect(&mut fx, &mut c, "\\\\h\\backup")
            .header()
            .tree_id;
        let r = fx
            .send(&c.signed_request(Command::Close, tid2, &close_body(fid)))
            .unwrap();
        assert_eq!(Response::parse(&r).unwrap().status(), status::FILE_CLOSED);
        // close and a repeated close
        let r = fx
            .send(&c.signed_request(Command::Close, tid, &close_body(fid)))
            .unwrap();
        assert_eq!(Response::parse(&r).unwrap().status(), status::SUCCESS);
        assert_eq!(Response::parse(&r).unwrap().message.body.len(), 60);
        let r = fx
            .send(&c.signed_request(Command::Close, tid, &close_body(fid)))
            .unwrap();
        assert_eq!(Response::parse(&r).unwrap().status(), status::FILE_CLOSED);
        // TREE_DISCONNECT closes the remaining opens
        let (_, _fid2) = create_root(&mut fx, &mut c, tid);
        assert_eq!(fx.conn.sessions[&c.session_id].opens.len(), 1);
        fx.send(&c.signed_request(Command::TreeDisconnect, tid, &simple_body()))
            .unwrap();
        assert!(fx.conn.sessions[&c.session_id].opens.is_empty());
    }

    #[test]
    fn file_ids_are_unique_per_open() {
        let (mut fx, mut c, tid) = connected();
        let (_, a) = create_root(&mut fx, &mut c, tid);
        let (_, b) = create_root(&mut fx, &mut c, tid);
        assert_ne!(a, b);
    }

    fn unhex_t(s: &str) -> Vec<u8> {
        smb_wire::ms_vectors::unhex(s)
    }

    #[test]
    fn share_path_parser() {
        assert_eq!(share_of("\\\\127.0.0.1\\backup"), Some("backup"));
        assert_eq!(share_of("\\\\host\\a b"), Some("a b"));
        assert_eq!(share_of("\\\\host\\"), None);
        assert_eq!(share_of("\\\\\\share"), None);
        assert_eq!(share_of("//host/share"), None);
        assert_eq!(share_of("\\\\host\\a\\b"), None);
    }
}
