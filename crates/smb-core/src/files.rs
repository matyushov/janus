//! The file model (J2): CREATE, CLOSE, READ, WRITE, FLUSH, QUERY_INFO, QUERY_DIRECTORY and
//! SET_INFO on top of a `StorageBackend`.
//!
//! Every handler gets the decoded request and the session, and returns an `Out`
//! (NTSTATUS + body); the dispatcher wraps it into a signed reply. Nothing here touches the
//! wire format beyond the codec calls, and nothing here knows which backend is behind
//! the trait.

use janus_lib::vfs::{
    BackendError, Disposition, FileStat, FsStats, Kind, OpenRequest, SetTimes, StorageBackend,
};
use smb_wire::bytes::Writer;
use smb_wire::create::{
    ACCESS_DELETE, ACTION_CREATED, ACTION_OPENED, ACTION_OVERWRITTEN, ACTION_SUPERSEDED,
    ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_READONLY, CreateContext, CreateReq, CreateResp,
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

use crate::dispatch::{Out, ServerCtx, status};
use crate::session::{DirScan, Open, Session};

/// Largest READ/WRITE payload: no LARGE_MTU, so one credit, 64 KiB.
pub const MAX_IO: u32 = 65536;
/// Open objects per session (a client that leaks handles must not exhaust the server).
pub const MAX_OPENS_PER_SESSION: usize = 16384;
/// Allocation granularity reported to clients.
const ALLOCATION_UNIT: u64 = 4096;

// H1-EXPERIMENT: `JANUS_SMB_DOWN_STATUS` selects the NTSTATUS returned for `RemoteUnavailable`
// (a name from the table below, or a number like 0xC00000C4). The value `DROP` makes the
// server close the TCP connection instead of replying (see `take_drop_request`).
static DOWN_STATUS: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
static DROP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

const DOWN_STATUS_TABLE: &[(&str, u32)] = &[
    ("UNEXPECTED_NETWORK_ERROR", 0xC000_00C4),
    ("IO_DEVICE_ERROR", 0xC000_0185),
    ("DISK_FULL", 0xC000_007F),
    ("INSUFFICIENT_RESOURCES", 0xC000_009A),
    ("CONNECTION_DISCONNECTED", 0xC000_020C),
    ("CONNECTION_RESET", 0xC000_020D),
    ("CONNECTION_ABORTED", 0xC000_0241),
    ("NETWORK_UNREACHABLE", 0xC000_023C),
    ("HOST_UNREACHABLE", 0xC000_023D),
    ("REMOTE_NOT_LISTENING", 0xC000_00BC),
    ("NETWORK_BUSY", 0xC000_00BF),
    ("DEVICE_NOT_READY", 0xC000_00A3),
    ("DEVICE_OFF_LINE", 0xC000_00B5),
    ("BAD_NETWORK_PATH", 0xC000_00BE),
    ("SERVER_DISABLED", 0xC000_0080),
    ("RETRY", 0xC000_022D),
    ("NOT_SUPPORTED", 0xC000_00BB),
    ("NETWORK_NAME_DELETED", 0xC000_00C9),
    ("USER_SESSION_DELETED", 0xC000_0203),
];

fn down_status() -> u32 {
    let chosen = DOWN_STATUS.get_or_init(|| {
        let v = std::env::var("JANUS_SMB_DOWN_STATUS").ok()?;
        let v = v.trim().trim_start_matches("STATUS_").to_ascii_uppercase();
        if v == "DROP" {
            return None;
        }
        if let Some(hex) = v.strip_prefix("0X") {
            return u32::from_str_radix(hex, 16).ok();
        }
        DOWN_STATUS_TABLE
            .iter()
            .find(|(n, _)| *n == v)
            .map(|(_, c)| *c)
    });
    match chosen {
        Some(c) => *c,
        None => {
            if std::env::var("JANUS_SMB_DOWN_STATUS").is_ok_and(|v| v.eq_ignore_ascii_case("drop"))
            {
                DROP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            status::UNEXPECTED_NETWORK_ERROR
        }
    }
}

/// H1-EXPERIMENT: true once if the last handled request asked to drop the connection.
pub fn take_drop_request() -> bool {
    DROP_REQUESTED.swap(false, std::sync::atomic::Ordering::SeqCst)
}

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
        BackendError::RemoteUnavailable => down_status(),
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
        file_id: [0; 16], // patched below, once the table assigns the id
        maximal_access: req
            .contexts
            .iter()
            .any(|c| matches!(c, CreateContext::QueryMaximalAccess))
            .then_some(ACCESS_ALL),
    }
    .encode(&mut w);
    let file_id = session.add_open(Open {
        tree_id,
        rel_path: path,
        handle: opened.handle,
        directory: st.directory,
        access,
        delete_pending: delete_on_close,
        scan: None,
    });
    let mut body = w.into_vec();
    // FileId sits at offset 64 of the CREATE response body (§2.2.14).
    body[64..80].copy_from_slice(&file_id);
    let _ = ctx;
    Out {
        created_file: Some(file_id),
        ..Out::ok(body)
    }
}

pub(crate) async fn close<B: StorageBackend>(
    backend: &B,
    req: &CloseReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.take_open(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    let attrs = if req.flags & CLOSE_POSTQUERY_ATTRIB != 0 {
        backend
            .stat_handle(open.handle)
            .await
            .ok()
            .map(|st| obj_info(&st, open.access, open.delete_pending))
    } else {
        None
    };
    if let Err(e) = backend.close(open.handle).await {
        return Out::err(status_of(&e));
    }
    let mut w = Writer::new();
    match attrs {
        Some(o) => encode_close_resp_attrs(&mut w, &o),
        None => encode_close_resp(&mut w),
    }
    Out::ok(w.into_vec())
}

pub(crate) async fn read<B: StorageBackend>(
    backend: &B,
    req: &ReadReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    if open.directory {
        return Out::err(status::FILE_IS_A_DIRECTORY);
    }
    if !access_wants_read(open.access) {
        return Out::err(status::ACCESS_DENIED);
    }
    if req.channel != 0
        || req.length > MAX_IO
        || req.offset.checked_add(u64::from(req.length)).is_none()
    {
        return Out::err(status::INVALID_PARAMETER);
    }
    if req.length == 0 {
        let mut w = Writer::new();
        encode_read_resp(&mut w, &[]);
        return Out::ok(w.into_vec());
    }
    match backend.read(open.handle, req.offset, req.length).await {
        Ok(data) if data.is_empty() || (data.len() as u32) < req.minimum_count => {
            Out::err(status::END_OF_FILE)
        }
        Ok(data) => {
            let mut w = Writer::new();
            encode_read_resp(&mut w, &data);
            Out::ok(w.into_vec())
        }
        Err(e) => Out::err(status_of(&e)),
    }
}

pub(crate) async fn write<B: StorageBackend>(
    backend: &B,
    req: &WriteReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    if open.directory {
        return Out::err(status::FILE_IS_A_DIRECTORY);
    }
    if !access_wants_write(open.access) {
        return Out::err(status::ACCESS_DENIED);
    }
    if req.channel != 0
        || req.data.len() as u64 > u64::from(MAX_IO)
        || req.offset.checked_add(req.data.len() as u64).is_none()
    {
        return Out::err(status::INVALID_PARAMETER);
    }
    if !req.data.is_empty()
        && let Err(e) = backend.write(open.handle, req.offset, &req.data).await
    {
        return Out::err(status_of(&e));
    }
    if req.flags & (write_flags::WRITE_THROUGH | write_flags::UNBUFFERED) != 0
        && let Err(e) = backend.flush(open.handle, false).await
    {
        return Out::err(status_of(&e));
    }
    let mut w = Writer::new();
    encode_write_resp(&mut w, req.data.len() as u32);
    Out::ok(w.into_vec())
}

pub(crate) async fn flush<B: StorageBackend>(
    backend: &B,
    req: &FlushReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
    ctx: &ServerCtx<'_>,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    let fullfsync = ctx.caps.fullfsync && req.reserved1 == FLUSH_FULLFSYNC;
    match backend.flush(open.handle, fullfsync).await {
        Ok(()) => {
            let mut w = Writer::new();
            encode_flush_resp(&mut w);
            Out::ok(w.into_vec())
        }
        Err(e) => Out::err(status_of(&e)),
    }
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

pub(crate) async fn set_info<B: StorageBackend>(
    backend: &B,
    req: &SetInfoReq,
    fid: [u8; 16],
    tree_id: u32,
    session: &mut Session,
) -> Out {
    let Some(open) = session.open_mut(&fid, tree_id) else {
        return Out::err(status::FILE_CLOSED);
    };
    if req.info_type != info_type::FILE {
        return Out::err(status::NOT_SUPPORTED);
    }
    let set = match FileSet::decode(req.class, &req.buffer) {
        Ok(Some(s)) => s,
        Ok(None) => return Out::err(status::INVALID_INFO_CLASS),
        Err(_) => return Out::err(status::INFO_LENGTH_MISMATCH),
    };
    let result = match set {
        FileSet::Basic {
            accessed, written, ..
        } => {
            let times = SetTimes {
                atime_unix_ns: unix_ns_from_filetime(accessed),
                mtime_unix_ns: unix_ns_from_filetime(written),
            };
            if times.atime_unix_ns.is_some() || times.mtime_unix_ns.is_some() {
                backend.set_times(open.handle, times).await
            } else {
                Ok(())
            }
        }
        FileSet::Rename { replace, target } => {
            let to = backend_path(&target);
            if open.rel_path.is_empty() || to.is_empty() {
                return Out::err(status::ACCESS_DENIED);
            }
            let r = backend.rename(&open.rel_path, &to, replace).await;
            if r.is_ok() {
                // Other opens under a renamed directory keep their old path: a known J2 gap.
                open.rel_path = to;
            }
            r
        }
        FileSet::Disposition { delete } => {
            if delete && (open.access & ACCESS_DELETE == 0 || open.rel_path.is_empty()) {
                return Out::err(status::ACCESS_DENIED);
            }
            let r = backend.set_delete_on_close(open.handle, delete).await;
            if r.is_ok() {
                open.delete_pending = delete;
            }
            r
        }
        FileSet::EndOfFile(len) => {
            if open.directory {
                return Out::err(status::FILE_IS_A_DIRECTORY);
            }
            if !access_wants_write(open.access) {
                return Out::err(status::ACCESS_DENIED);
            }
            backend.truncate(open.handle, len).await
        }
        FileSet::Allocation(_) | FileSet::Ignored => Ok(()),
    };
    match result {
        Ok(()) => {
            let mut w = Writer::new();
            encode_set_info_resp(&mut w);
            Out::ok(w.into_vec())
        }
        Err(e) => Out::err(status_of(&e)),
    }
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
