//! The file model (J2): CREATE, CLOSE, READ, WRITE, FLUSH, QUERY_INFO, QUERY_DIRECTORY and
//! SET_INFO on top of a `StorageBackend`.
//!
//! Every handler gets the decoded request and the session, and returns an `Out`
//! (NTSTATUS + body); the dispatcher wraps it into a signed reply. Nothing here touches the
//! wire format beyond the codec calls, and nothing here knows which backend is behind
//! the trait.

use janus_lib::vfs::{
    BackendError, BackendHandle, Disposition, FileStat, FsStats, Kind, OpenRequest, SetTimes,
    StorageBackend,
};
use smb_wire::bytes::Writer;
use smb_wire::create::{
    ACCESS_APPEND_DATA, ACCESS_DELETE, ACCESS_EXECUTE, ACCESS_READ_DATA, ACCESS_WRITE_DATA,
    ACTION_CREATED, ACTION_OPENED, ACTION_OVERWRITTEN, ACTION_SUPERSEDED, ATTR_ARCHIVE,
    ATTR_DIRECTORY, ATTR_READONLY, CreateContext, CreateReq, CreateResp, LEASE_HANDLE,
    OPT_DELETE_ON_CLOSE, OPT_DIRECTORY_FILE, OPT_NON_DIRECTORY_FILE, access_wants_read,
    access_wants_write, disposition, expand_access,
};
use smb_wire::fileinfo::{
    CLOSE_POSTQUERY_ATTRIB, CloseReq, DirEntry, FileSet, ObjInfo, QueryDirectoryReq, QueryInfoReq,
    SetInfoReq, VolumeInfo, encode_close_resp, encode_close_resp_attrs, encode_dir_entries,
    encode_query_info_resp, encode_set_info_resp, file_info, filetime_from_unix_ns, fs_info,
    info_type, pattern_matches, query_dir_flags, unix_ns_from_filetime,
};
use smb_wire::io::{
    FLUSH_FULLFSYNC, FlushReq, ReadReq, WriteReq, encode_flush_resp, encode_read_resp,
    encode_write_resp, write_flags,
};
use smb_wire::messages::ACCESS_ALL;

use crate::apple::AppleExt;
use crate::dispatch::{Out, ServerCtx, status};
use crate::session::{DirScan, DurableInfo, Open, Session};
use crate::shared::{OpenIntent, ReconnectError, Shared};

/// Largest READ/WRITE payload. With LARGE_MTU one request may carry up to 1 MiB, which
/// the client pays for with multiple credits (see `required_credits`). 1 MiB is also the
/// largest chunk of one gRPC call, so a request maps to exactly one RPC.
pub const MAX_IO: u32 = 1 << 20;
/// One credit covers this many payload bytes (MS-SMB2 §3.3.1.2).
const CREDIT_UNIT: u32 = 65536;

/// Credits a READ/WRITE of `len` payload bytes must be charged (MS-SMB2 §3.3.5.2.5).
fn required_credits(len: u32) -> u32 {
    len.saturating_sub(1) / CREDIT_UNIT + 1
}
/// Open objects per session (a client that leaks handles must not exhaust the server).
pub const MAX_OPENS_PER_SESSION: usize = 16384;
/// Allocation granularity reported to clients.
const ALLOCATION_UNIT: u64 = 4096;

/// NTSTATUS for a backend failure. `NoSpace` → DISK_FULL is the Time Machine thinning signal.
pub fn status_of(e: &BackendError) -> u32 {
    match e {
        BackendError::NotFound => status::OBJECT_NAME_NOT_FOUND,
        BackendError::PathNotFound => status::OBJECT_PATH_NOT_FOUND,
        BackendError::AlreadyExists => status::OBJECT_NAME_COLLISION,
        BackendError::NoSpace => status::DISK_FULL,
        BackendError::NotADirectory => status::NOT_A_DIRECTORY,
        BackendError::IsADirectory => status::FILE_IS_A_DIRECTORY,
        BackendError::DirectoryNotEmpty => status::DIRECTORY_NOT_EMPTY,
        BackendError::AccessDenied => status::ACCESS_DENIED,
        BackendError::BadHandle => status::FILE_CLOSED,
        BackendError::Busy => status::INSUFFICIENT_RESOURCES,
        BackendError::RemoteUnavailable => status::UNEXPECTED_NETWORK_ERROR,
        BackendError::Io(_) => status::UNEXPECTED_IO_ERROR,
    }
}

/// `\a\b` / `/a/b` → `a/b`.
fn backend_path(smb: &str) -> String {
    smb.replace('\\', "/").trim_matches('/').to_owned()
}

/// `a/b` → `\a\b` (the root is the empty string).
fn smb_name(rel: &str) -> String {
    if rel.is_empty() {
        String::new()
    } else {
        format!("\\{}", rel.replace('/', "\\"))
    }
}

fn allocation(st: &FileStat) -> u64 {
    if st.directory {
        0
    } else {
        st.size.next_multiple_of(ALLOCATION_UNIT)
    }
}

fn attributes(st: &FileStat) -> u32 {
    if st.directory {
        ATTR_DIRECTORY
    } else if st.read_only {
        ATTR_ARCHIVE | ATTR_READONLY
    } else {
        ATTR_ARCHIVE
    }
}

fn obj_info(st: &FileStat, access: u32, delete_pending: bool) -> ObjInfo {
    ObjInfo {
        created: filetime_from_unix_ns(st.btime_unix_ns),
        accessed: filetime_from_unix_ns(st.atime_unix_ns),
        written: filetime_from_unix_ns(st.mtime_unix_ns),
        changed: filetime_from_unix_ns(st.ctime_unix_ns),
        end_of_file: st.size,
        allocation_size: allocation(st),
        attributes: attributes(st),
        file_id: st.file_id,
        file_index: 0,
        directory: st.directory,
        delete_pending,
        name: smb_name(&st.rel_path),
        access,
    }
}

pub(crate) async fn create<B: StorageBackend>(
    backend: &B,
    req: &CreateReq,
    tree_id: u32,
    session: &mut Session,
    ctx: &ServerCtx<'_>,
    client_guid: [u8; 16],
) -> Out {
    if !session.trees.contains_key(&tree_id) {
        return Out::err(status::NETWORK_NAME_DELETED);
    }
    let disposition = match req.create_disposition {
        disposition::SUPERSEDE => Disposition::Supersede,
        disposition::OPEN => Disposition::Open,
        disposition::CREATE => Disposition::Create,
        disposition::OPEN_IF => Disposition::OpenOrCreate,
        disposition::OVERWRITE => Disposition::Overwrite,
        disposition::OVERWRITE_IF => Disposition::OverwriteOrCreate,
        _ => return Out::err(status::INVALID_PARAMETER),
    };
    let kind = match (
        req.create_options & OPT_DIRECTORY_FILE != 0,
        req.create_options & OPT_NON_DIRECTORY_FILE != 0,
    ) {
        (true, true) => return Out::err(status::INVALID_PARAMETER),
        (true, false) => Kind::Directory,
        (false, true) => Kind::File,
        (false, false) => Kind::Any,
    };
    let access = expand_access(req.desired_access);
    let path = backend_path(&req.path);
    let delete_on_close = req.create_options & OPT_DELETE_ON_CLOSE != 0;
    if delete_on_close && (access & ACCESS_DELETE == 0 || path.is_empty()) {
        return Out::err(status::ACCESS_DENIED);
    }
    if session.opens.len() >= MAX_OPENS_PER_SESSION {
        return Out::err(status::INSUFFICIENT_RESOURCES);
    }

    if ctx.caps.leasing
        && let Some(CreateContext::DurableHandleReconnectV2 {
            file_id,
            create_guid,
            ..
        }) = req
            .contexts
            .iter()
            .find(|c| matches!(c, CreateContext::DurableHandleReconnectV2 { .. }))
    {
        return reconnect(
            backend,
            (*file_id, *create_guid),
            tree_id,
            session,
            ctx,
            client_guid,
        )
        .await;
    }

    let opened = match backend
        .open(
            &path,
            OpenRequest {
                disposition,
                kind,
                write: access_wants_write(access),
                delete_on_close,
            },
        )
        .await
    {
        Ok(o) => o,
        Err(e) => return Out::err(status_of(&e)),
    };

    let action = if opened.created {
        ACTION_CREATED
    } else if opened.overwritten {
        if disposition == Disposition::Supersede {
            ACTION_SUPERSEDED
        } else {
            ACTION_OVERWRITTEN
        }
    } else {
        ACTION_OPENED
    };
    let st = &opened.stat;
    let mut lease_key = None;
    let mut lease_reply = None;
    let mut durable = None;
    let mut durable_reply = None;
    if ctx.caps.leasing && !st.directory {
        let lease_req = req.contexts.iter().find_map(|c| match c {
            CreateContext::Lease(l) => Some(l),
            _ => None,
        });
        let writes = access_wants_write(access)
            || matches!(
                disposition,
                Disposition::Supersede | Disposition::Overwrite | Disposition::OverwriteOrCreate
            );
        let outcome = ctx.shared.lease_for_open(
            OpenIntent {
                conn: ctx.conn_id,
                path: &path,
                data_access: writes || access & DATA_ACCESS != 0,
                writes,
            },
            lease_req,
        );
        // A conflicting holder on another connection answers first (or is cut off by timeout).
        ctx.shared.wait_breaks(&outcome.wait_for).await;
        if let Some(granted) = outcome.reply {
            lease_key = Some(granted.key);
            // Durable only with handle caching: the client keeps the handle across a drop.
            if granted.state & LEASE_HANDLE != 0
                && let Some(CreateContext::DurableHandleRequestV2 {
                    timeout_ms,
                    create_guid,
                    ..
                }) = req
                    .contexts
                    .iter()
                    .find(|c| matches!(c, CreateContext::DurableHandleRequestV2 { .. }))
            {
                let timeout = Shared::durable_timeout(*timeout_ms);
                durable = Some(DurableInfo {
                    create_guid: *create_guid,
                    timeout,
                });
                durable_reply = Some((timeout.as_millis() as u32, 0));
            }
            lease_reply = Some(granted);
        }
    }
    let mut body = create_response(
        st,
        action,
        req.contexts
            .iter()
            .any(|c| matches!(c, CreateContext::QueryMaximalAccess))
            .then_some(ACCESS_ALL),
        req.contexts.iter().find_map(|c| match c {
            CreateContext::Aapl(q) => AppleExt::reply_to_query(&ctx.caps, q),
            _ => None,
        }),
        durable_reply,
        lease_reply,
    );
    let file_id = session.add_open(Open {
        readahead: Default::default(),
        tree_id,
        rel_path: path,
        handle: opened.handle,
        directory: st.directory,
        access,
        delete_pending: delete_on_close,
        scan: None,
        lease: lease_key,
        durable,
    });
    if let Some(d) = durable {
        register_durable(session, ctx, client_guid, file_id, d);
    }
    // FileId sits at offset 64 of the CREATE response body (§2.2.14).
    body[64..80].copy_from_slice(&file_id);
    Out {
        created_file: Some(file_id),
        ..Out::ok(body)
    }
}

/// Records a durable open in the shared state (and on disk), keyed by its CreateGuid.
fn register_durable(
    session: &Session,
    ctx: &ServerCtx<'_>,
    client_guid: [u8; 16],
    file_id: [u8; 16],
    d: DurableInfo,
) {
    let Some(key) = file_id_key(&file_id) else {
        return;
    };
    let Some(open) = session.opens.get(&key) else {
        return;
    };
    ctx.shared
        .register_durable(janus_lib::journal::ParkedRecord {
            create_guid: d.create_guid,
            file_id,
            client_guid,
            owner: session.user().unwrap_or_default().to_owned(),
            rel_path: open.rel_path.clone(),
            access: open.access,
            delete_pending: open.delete_pending,
            lease_key: open.lease,
            lease_state: 0,
            timeout_ms: d.timeout.as_millis() as u32,
            expires_unix_ms: 0,
        });
}

/// The session-table key of a FileId issued by `Session::add_open` (both halves equal).
fn file_id_key(file_id: &[u8; 16]) -> Option<u64> {
    let a = u64::from_le_bytes(file_id[..8].try_into().ok()?);
    let b = u64::from_le_bytes(file_id[8..].try_into().ok()?);
    (a == b).then_some(a)
}

/// Opens that read or write file data (an attributes-only open breaks no lease).
const DATA_ACCESS: u32 = ACCESS_READ_DATA | ACCESS_WRITE_DATA | ACCESS_APPEND_DATA | ACCESS_EXECUTE;

/// The CREATE response body for `st` (the FileId is patched in by the caller).
fn create_response(
    st: &FileStat,
    action: u32,
    maximal_access: Option<u32>,
    aapl: Option<smb_wire::create::AaplReply>,
    durable: Option<(u32, u32)>,
    lease: Option<smb_wire::create::LeaseReq>,
) -> Vec<u8> {
    let mut w = Writer::new();
    CreateResp {
        create_action: action,
        creation_time: filetime_from_unix_ns(st.btime_unix_ns),
        last_access_time: filetime_from_unix_ns(st.atime_unix_ns),
        last_write_time: filetime_from_unix_ns(st.mtime_unix_ns),
        change_time: filetime_from_unix_ns(st.ctime_unix_ns),
        allocation_size: allocation(st),
        end_of_file: st.size,
        file_attributes: attributes(st),
        file_id: [0; 16],
        maximal_access,
        aapl,
        durable,
        lease,
    }
    .encode(&mut w);
    w.into_vec()
}

/// DH2C: take a parked durable handle back onto this connection.
async fn reconnect<B: StorageBackend>(
    backend: &B,
    (file_id, create_guid): ([u8; 16], [u8; 16]),
    tree_id: u32,
    session: &mut Session,
    ctx: &ServerCtx<'_>,
    client_guid: [u8; 16],
) -> Out {
    let owner = session.user().unwrap_or_default().to_owned();
    let got = match ctx
        .shared
        .reconnect(file_id, create_guid, &owner, client_guid, ctx.conn_id)
    {
        Ok(g) => g,
        Err(ReconnectError::NotFound) => return Out::err(status::OBJECT_NAME_NOT_FOUND),
        Err(ReconnectError::Denied) => return Out::err(status::ACCESS_DENIED),
    };
    let rec = got.record;
    let fail = |e: &BackendError| {
        if let Some(key) = &rec.lease_key {
            ctx.shared.release_lease(key);
        }
        Out::err(status_of(e))
    };
    let handle = match got.handle {
        Some(h) => h,
        // After a daemon restart the backend handle is gone: open the file again by path.
        None => match backend
            .open(
                &rec.rel_path,
                OpenRequest {
                    disposition: Disposition::Open,
                    kind: Kind::File,
                    write: access_wants_write(rec.access),
                    delete_on_close: rec.delete_pending,
                },
            )
            .await
        {
            Ok(o) => o.handle,
            Err(e) => return fail(&e),
        },
    };
    let st = match backend.stat_handle(handle).await {
        Ok(st) => st,
        Err(e) => {
            let _ = backend.close(handle).await;
            return fail(&e);
        }
    };
    let mut body = create_response(&st, ACTION_OPENED, None, None, None, got.lease);
    let new_id = session.add_open(Open {
        readahead: Default::default(),
        tree_id,
        rel_path: rec.rel_path,
        handle,
        directory: false,
        access: rec.access,
        delete_pending: rec.delete_pending,
        scan: None,
        lease: rec.lease_key,
        durable: Some(DurableInfo {
            create_guid,
            timeout: std::time::Duration::from_millis(u64::from(rec.timeout_ms)),
        }),
    });
    register_durable(
        session,
        ctx,
        client_guid,
        new_id,
        DurableInfo {
            create_guid,
            timeout: std::time::Duration::from_millis(u64::from(rec.timeout_ms)),
        },
    );
    body[64..80].copy_from_slice(&new_id);
    Out {
        created_file: Some(new_id),
        ..Out::ok(body)
    }
}

/// A command that may wait for the journal (FLUSH, CLOSE, SET_INFO). `prepare_*` does the
/// session work synchronously, in request order; `SlowOp::run` only talks to the backend, so
/// the connection can answer other packets (and the client's CANCEL) while it waits.
pub(crate) enum SlowOp {
    Flush {
        handle: BackendHandle,
        fullfsync: bool,
    },
    Close {
        handle: BackendHandle,
        /// CLOSE_POSTQUERY_ATTRIB: (access, delete_pending) to report the final attributes with.
        attrs_of: Option<(u32, bool)>,
    },
    SetTimes {
        handle: BackendHandle,
        times: SetTimes,
    },
    Rename {
        from: String,
        to: String,
        replace: bool,
    },
    SetDelete {
        handle: BackendHandle,
        on: bool,
    },
    Truncate {
        handle: BackendHandle,
        len: u64,
    },
    /// Nothing to ask the backend (ignored information classes): a plain SET_INFO success.
    Nothing,
}

/// What a successful job changes in the session table once the backend has agreed.
#[derive(Clone)]
pub(crate) enum Post {
    None,
    Renamed {
        fid: [u8; 16],
        tree_id: u32,
        to: String,
    },
    DeletePending {
        fid: [u8; 16],
        tree_id: u32,
        on: bool,
    },
}

impl Post {
    pub(crate) fn apply(self, out: &Out, session: &mut Session) {
        if out.status != status::SUCCESS {
            return;
        }
        match self {
            Post::None => {}
            Post::Renamed { fid, tree_id, to } => {
                if let Some(open) = session.open_mut(&fid, tree_id) {
                    // Other opens under a renamed directory keep their old path: a known J2 gap.
                    open.rel_path = to;
                }
            }
            Post::DeletePending { fid, tree_id, on } => {
                if let Some(open) = session.open_mut(&fid, tree_id) {
                    open.delete_pending = on;
                }
            }
        }
    }
}

pub(crate) struct SlowJob {
    pub(crate) op: SlowOp,
    pub(crate) post: Post,
}

impl SlowOp {
    pub(crate) async fn run<B: StorageBackend>(self, backend: &B) -> Out {
        let done = |encode: fn(&mut Writer)| {
            let mut w = Writer::new();
            encode(&mut w);
            Out::ok(w.into_vec())
        };
        match self {
            SlowOp::Flush { handle, fullfsync } => match backend.flush(handle, fullfsync).await {
                Ok(()) => done(encode_flush_resp),
                Err(e) => Out::err(status_of(&e)),
            },
            SlowOp::Close { handle, attrs_of } => {
                let attrs = match attrs_of {
                    Some((access, delete_pending)) => backend
                        .stat_handle(handle)
                        .await
                        .ok()
                        .map(|st| obj_info(&st, access, delete_pending)),
                    None => None,
                };
                if let Err(e) = backend.close(handle).await {
                    return Out::err(status_of(&e));
                }
                let mut w = Writer::new();
                match attrs {
                    Some(o) => encode_close_resp_attrs(&mut w, &o),
                    None => encode_close_resp(&mut w),
                }
                Out::ok(w.into_vec())
            }
            SlowOp::SetTimes { handle, times } => {
                finish_set_info(backend.set_times(handle, times).await)
            }
            SlowOp::Rename { from, to, replace } => {
                finish_set_info(backend.rename(&from, &to, replace).await)
            }
            SlowOp::SetDelete { handle, on } => {
                finish_set_info(backend.set_delete_on_close(handle, on).await)
            }
            SlowOp::Truncate { handle, len } => {
                finish_set_info(backend.truncate(handle, len).await)
            }
            SlowOp::Nothing => finish_set_info(Ok(())),
        }
    }
}

fn finish_set_info(result: janus_lib::vfs::Result<()>) -> Out {
    match result {
        Ok(()) => {
            let mut w = Writer::new();
            encode_set_info_resp(&mut w);
            Out::ok(w.into_vec())
        }
        Err(e) => Out::err(status_of(&e)),
    }
}

/// Run a prepared job to completion and apply its session effects (the inline path).
async fn run_inline<B: StorageBackend>(
    backend: &B,
    job: Result<SlowJob, Out>,
    session: &mut Session,
) -> Out {
    match job {
        Ok(SlowJob { op, post }) => {
            let out = op.run(backend).await;
            post.apply(&out, session);
            out
        }
        Err(out) => out,
    }
}

/// `Err` carries a finished reply; the session is untouched in that case.
pub(crate) fn prepare_close(
    req: &CloseReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Result<SlowJob, Out> {
    let Some(open) = session.take_open(&fid, tree_id) else {
        return Err(Out::err(status::FILE_CLOSED));
    };
    Ok(SlowJob {
        op: SlowOp::Close {
            handle: open.handle,
            attrs_of: (req.flags & CLOSE_POSTQUERY_ATTRIB != 0)
                .then_some((open.access, open.delete_pending)),
        },
        post: Post::None,
    })
}

pub(crate) async fn close<B: StorageBackend>(
    backend: &B,
    req: &CloseReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let job = prepare_close(req, fid, tree_id, session);
    run_inline(backend, job, session).await
}

/// A validated READ or WRITE, ready for the backend. Everything that needs the session is
/// done by `prepare_*` (synchronously, in request order); `run` only talks to the backend,
/// so several jobs of one connection may be in flight at once.
pub(crate) enum IoJob {
    Read {
        handle: BackendHandle,
        offset: u64,
        length: u32,
        minimum_count: u32,
        /// The same range already requested by readahead; a failed prefetch falls back to a
        /// direct read.
        prefetched: Option<tokio::task::JoinHandle<janus_lib::vfs::Result<Vec<u8>>>>,
    },
    Write {
        handle: BackendHandle,
        offset: u64,
        data: Vec<u8>,
        /// WRITE_THROUGH / UNBUFFERED: flush before replying.
        flush: bool,
    },
}

impl IoJob {
    pub(crate) async fn run<B: StorageBackend>(self, backend: &B) -> Out {
        match self {
            IoJob::Read {
                handle,
                offset,
                length,
                minimum_count,
                prefetched,
            } => match match prefetched {
                Some(task) => match task.await {
                    Ok(Ok(data)) => Ok(data),
                    _ => backend.read(handle, offset, length).await,
                },
                None => backend.read(handle, offset, length).await,
            } {
                Ok(data) if data.is_empty() || (data.len() as u32) < minimum_count => {
                    Out::err(status::END_OF_FILE)
                }
                Ok(data) => {
                    let mut w = Writer::new();
                    encode_read_resp(&mut w, &data);
                    Out::ok(w.into_vec())
                }
                Err(e) => Out::err(status_of(&e)),
            },
            IoJob::Write {
                handle,
                offset,
                data,
                flush,
            } => {
                if !data.is_empty()
                    && let Err(e) = backend.write(handle, offset, &data).await
                {
                    return Out::err(status_of(&e));
                }
                if flush && let Err(e) = backend.flush(handle, false).await {
                    return Out::err(status_of(&e));
                }
                let mut w = Writer::new();
                encode_write_resp(&mut w, data.len() as u32);
                Out::ok(w.into_vec())
            }
        }
    }
}

/// Chunks kept in flight ahead of a sequential reader, and the smallest read that starts it.
const READAHEAD_DEPTH: usize = 3;
const READAHEAD_MIN_LEN: u32 = 65536;

/// Where readahead may start tasks: the backend to read from and the connection's write epoch.
pub(crate) struct ReadaheadCtx<'a, B> {
    pub backend: &'a std::sync::Arc<B>,
    pub epoch: u64,
}

/// `Err` carries a finished reply (an error, or the empty read that needs no backend call).
pub(crate) fn prepare_read<B: StorageBackend>(
    req: &ReadReq,
    fid: [u8; 16],
    tree_id: u32,
    credit_charge: u16,
    session: &mut Session,
    ra: Option<ReadaheadCtx<'_, B>>,
) -> Result<IoJob, Out> {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Err(Out::err(status::FILE_CLOSED));
    };
    if open.directory {
        return Err(Out::err(status::FILE_IS_A_DIRECTORY));
    }
    if !access_wants_read(open.access) {
        return Err(Out::err(status::ACCESS_DENIED));
    }
    if req.channel != 0
        || req.length > MAX_IO
        || u32::from(credit_charge.max(1)) < required_credits(req.length)
        || req.offset.checked_add(u64::from(req.length)).is_none()
    {
        return Err(Out::err(status::INVALID_PARAMETER));
    }
    if req.length == 0 {
        let mut w = Writer::new();
        encode_read_resp(&mut w, &[]);
        return Err(Out::ok(w.into_vec()));
    }
    let mut prefetched = None;
    if let Some(ra) = ra {
        let state = &mut open.readahead;
        // Take the prefetch for exactly this range, dropping (aborting) older or stale ones.
        while let Some(mut pf) = state.queue.pop_front() {
            if pf.epoch == ra.epoch && pf.offset == req.offset && pf.length == req.length {
                prefetched = pf.task.take();
                break;
            }
        }
        let sequential = state.next_offset == req.offset;
        state.next_offset = req.offset + u64::from(req.length);
        if sequential && req.length >= READAHEAD_MIN_LEN {
            let mut next = state
                .queue
                .back()
                .map_or(state.next_offset, |p| p.offset + u64::from(p.length));
            while state.queue.len() < READAHEAD_DEPTH {
                let (backend, handle, offset, length) = (
                    std::sync::Arc::clone(ra.backend),
                    open.handle,
                    next,
                    req.length,
                );
                state.queue.push_back(crate::session::Prefetch {
                    offset,
                    length,
                    epoch: ra.epoch,
                    task: Some(tokio::spawn(async move {
                        backend.read(handle, offset, length).await
                    })),
                });
                next += u64::from(length);
            }
        }
    }
    Ok(IoJob::Read {
        handle: open.handle,
        offset: req.offset,
        length: req.length,
        minimum_count: req.minimum_count,
        prefetched,
    })
}

pub(crate) fn prepare_write(
    req: WriteReq,
    fid: [u8; 16],
    tree_id: u32,
    credit_charge: u16,
    session: &mut Session,
) -> Result<IoJob, Out> {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Err(Out::err(status::FILE_CLOSED));
    };
    if open.directory {
        return Err(Out::err(status::FILE_IS_A_DIRECTORY));
    }
    if !access_wants_write(open.access) {
        return Err(Out::err(status::ACCESS_DENIED));
    }
    if req.channel != 0
        || req.data.len() as u64 > u64::from(MAX_IO)
        || u32::from(credit_charge.max(1)) < required_credits(req.data.len() as u32)
        || req.offset.checked_add(req.data.len() as u64).is_none()
    {
        return Err(Out::err(status::INVALID_PARAMETER));
    }
    Ok(IoJob::Write {
        handle: open.handle,
        offset: req.offset,
        flush: req.flags & (write_flags::WRITE_THROUGH | write_flags::UNBUFFERED) != 0,
        data: req.data,
    })
}

pub(crate) async fn read<B: StorageBackend>(
    backend: &B,
    req: &ReadReq,
    fid: [u8; 16],
    tree_id: u32,
    credit_charge: u16,
    session: &mut Session,
) -> Out {
    match prepare_read::<B>(req, fid, tree_id, credit_charge, session, None) {
        Ok(job) => job.run(backend).await,
        Err(out) => out,
    }
}

pub(crate) async fn write<B: StorageBackend>(
    backend: &B,
    req: WriteReq,
    fid: [u8; 16],
    tree_id: u32,
    credit_charge: u16,
    session: &mut Session,
) -> Out {
    match prepare_write(req, fid, tree_id, credit_charge, session) {
        Ok(job) => job.run(backend).await,
        Err(out) => out,
    }
}

pub(crate) fn prepare_flush(
    req: &FlushReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
    ctx: &ServerCtx<'_>,
) -> Result<SlowJob, Out> {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Err(Out::err(status::FILE_CLOSED));
    };
    Ok(SlowJob {
        op: SlowOp::Flush {
            handle: open.handle,
            fullfsync: ctx.caps.fullfsync && req.reserved1 == FLUSH_FULLFSYNC,
        },
        post: Post::None,
    })
}

pub(crate) async fn flush<B: StorageBackend>(
    backend: &B,
    req: &FlushReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
    ctx: &ServerCtx<'_>,
) -> Out {
    let job = prepare_flush(req, fid, tree_id, session, ctx);
    run_inline(backend, job, session).await
}

/// Volume numbers for FileFs* replies: the backend's quota and usage when it has them,
/// the configured share size otherwise.
async fn volume_info<B: StorageBackend>(backend: &B, ctx: &ServerCtx<'_>) -> VolumeInfo {
    let (total, free) = match backend.statfs().await {
        Ok(FsStats {
            quota_bytes,
            used_bytes,
        }) if quota_bytes > 0 => (quota_bytes, quota_bytes.saturating_sub(used_bytes)),
        _ => (ctx.volume_bytes, ctx.volume_bytes),
    };
    VolumeInfo {
        total_bytes: total,
        free_bytes: free,
        created: ctx.started_filetime,
        now: ctx.filetime,
        case_sensitive_names: ctx.caps.case_sensitive_names,
    }
}

pub(crate) async fn query_info<B: StorageBackend>(
    backend: &B,
    ctx: &ServerCtx<'_>,
    req: &QueryInfoReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    let data = match req.info_type {
        info_type::FILESYSTEM => fs_info(req.class, &volume_info(backend, ctx).await),
        info_type::FILE => match backend.stat_handle(open.handle).await {
            Ok(st) => file_info(req.class, &obj_info(&st, open.access, open.delete_pending)),
            Err(e) => return Out::err(status_of(&e)),
        },
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

pub(crate) async fn query_directory<B: StorageBackend>(
    backend: &B,
    ctx: &ServerCtx<'_>,
    req: &QueryDirectoryReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    if !open.directory {
        return Out::err(status::NOT_A_DIRECTORY);
    }
    let restart = req.flags & (query_dir_flags::RESTART_SCANS | query_dir_flags::REOPEN) != 0;
    if restart {
        open.scan = None;
    }
    if open.scan.is_none() {
        let own = match backend.stat_handle(open.handle).await {
            Ok(st) => st,
            Err(e) => return Out::err(status_of(&e)),
        };
        let listing = match backend.list(&open.rel_path).await {
            Ok(l) => l,
            Err(e) => return Out::err(status_of(&e)),
        };
        let case_sensitive = ctx.caps.case_sensitive_names;
        let entry = |name: &str, st: &FileStat| DirEntry {
            name: name.to_owned(),
            info: obj_info(st, 0, false),
        };
        let mut entries = vec![entry(".", &own), entry("..", &own)];
        entries.extend(listing.iter().map(|st| entry(&st.name, st)));
        entries.retain(|e| pattern_matches(&req.pattern, &e.name, case_sensitive));
        open.scan = Some(DirScan {
            entries,
            pos: 0,
            returned: false,
        });
    }
    let scan = open.scan.as_mut().expect("scan created above");
    if scan.pos >= scan.entries.len() {
        return Out::err(if scan.returned {
            status::NO_MORE_FILES
        } else {
            status::NO_SUCH_FILE
        });
    }
    let single = req.flags & query_dir_flags::RETURN_SINGLE_ENTRY != 0;
    let Some((buf, n)) = encode_dir_entries(
        req.class,
        &scan.entries[scan.pos..],
        req.output_buffer_length as usize,
        single,
    ) else {
        return Out::err(status::INVALID_INFO_CLASS);
    };
    if n == 0 {
        return Out::err(status::INFO_LENGTH_MISMATCH);
    }
    scan.pos += n;
    scan.returned = true;
    let mut w = Writer::new();
    encode_query_info_resp(&mut w, &buf);
    Out::ok(w.into_vec())
}

pub(crate) fn prepare_set_info(
    req: &SetInfoReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Result<SlowJob, Out> {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Err(Out::err(status::FILE_CLOSED));
    };
    if req.info_type != info_type::FILE {
        return Err(Out::err(status::NOT_SUPPORTED));
    }
    let set = match FileSet::decode(req.class, &req.buffer) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(Out::err(status::INVALID_INFO_CLASS)),
        Err(_) => return Err(Out::err(status::INFO_LENGTH_MISMATCH)),
    };
    let (op, post) = match set {
        FileSet::Basic {
            accessed, written, ..
        } => {
            let times = SetTimes {
                atime_unix_ns: unix_ns_from_filetime(accessed),
                mtime_unix_ns: unix_ns_from_filetime(written),
            };
            if times.atime_unix_ns.is_some() || times.mtime_unix_ns.is_some() {
                (
                    SlowOp::SetTimes {
                        handle: open.handle,
                        times,
                    },
                    Post::None,
                )
            } else {
                (SlowOp::Nothing, Post::None)
            }
        }
        FileSet::Rename { replace, target } => {
            let to = backend_path(&target);
            if open.rel_path.is_empty() || to.is_empty() {
                return Err(Out::err(status::ACCESS_DENIED));
            }
            (
                SlowOp::Rename {
                    from: open.rel_path.clone(),
                    to: to.clone(),
                    replace,
                },
                Post::Renamed { fid, tree_id, to },
            )
        }
        FileSet::Disposition { delete } => {
            if delete && (open.access & ACCESS_DELETE == 0 || open.rel_path.is_empty()) {
                return Err(Out::err(status::ACCESS_DENIED));
            }
            (
                SlowOp::SetDelete {
                    handle: open.handle,
                    on: delete,
                },
                Post::DeletePending {
                    fid,
                    tree_id,
                    on: delete,
                },
            )
        }
        FileSet::EndOfFile(len) => {
            if open.directory {
                return Err(Out::err(status::FILE_IS_A_DIRECTORY));
            }
            if !access_wants_write(open.access) {
                return Err(Out::err(status::ACCESS_DENIED));
            }
            (
                SlowOp::Truncate {
                    handle: open.handle,
                    len,
                },
                Post::None,
            )
        }
        FileSet::Allocation(_) | FileSet::Ignored => (SlowOp::Nothing, Post::None),
    };
    Ok(SlowJob { op, post })
}

pub(crate) async fn set_info<B: StorageBackend>(
    backend: &B,
    req: &SetInfoReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let job = prepare_set_info(req, fid, tree_id, session);
    run_inline(backend, job, session).await
}

/// Close backend handles of opens that are being dropped (TREE_DISCONNECT, LOGOFF,
/// connection loss). Errors are ignored: there is nobody to report them to.
pub(crate) async fn close_all<B: StorageBackend>(backend: &B, opens: Vec<Open>) {
    for o in opens {
        let _ = backend.close(o.handle).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_errors_map_to_ntstatus() {
        assert_eq!(status_of(&BackendError::NoSpace), 0xC000_007F);
        assert_eq!(status_of(&BackendError::NotFound), 0xC000_0034);
        assert_eq!(status_of(&BackendError::PathNotFound), 0xC000_003A);
        assert_eq!(status_of(&BackendError::DirectoryNotEmpty), 0xC000_0101);
        assert_eq!(status_of(&BackendError::NotADirectory), 0xC000_0103);
    }

    #[test]
    fn path_conversions() {
        assert_eq!(backend_path("\\a\\b\\"), "a/b");
        assert_eq!(backend_path(""), "");
        assert_eq!(smb_name("a/b"), "\\a\\b");
        assert_eq!(smb_name(""), "");
    }
}
