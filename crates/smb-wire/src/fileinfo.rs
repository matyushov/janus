//! QUERY_INFO / CLOSE / QUERY_DIRECTORY and the information structures of a volume and a directory
//! (MS-SMB2 §2.2.37–2.2.38, 2.2.15–2.2.16, 2.2.33; MS-FSCC §2.4, §2.5).
//! Plus SET_INFO and the per-object information structures used by the file model (J2).

use crate::WireError;
use crate::bytes::{Reader, Writer};
use crate::create::FileId;

/// InfoType of a QUERY_INFO request.
pub mod info_type {
    pub const FILE: u8 = 0x01;
    pub const FILESYSTEM: u8 = 0x02;
    pub const SECURITY: u8 = 0x03;
}

/// FileInfoClass for InfoType FILE (MS-FSCC §2.4).
pub mod file_class {
    pub const DIRECTORY: u8 = 1;
    pub const FULL_DIRECTORY: u8 = 2;
    pub const BOTH_DIRECTORY: u8 = 3;
    pub const BASIC: u8 = 4;
    pub const STANDARD: u8 = 5;
    pub const INTERNAL: u8 = 6;
    pub const EA: u8 = 7;
    pub const ACCESS: u8 = 8;
    pub const NAME: u8 = 9;
    pub const RENAME: u8 = 10;
    pub const NAMES: u8 = 12;
    pub const DISPOSITION: u8 = 13;
    pub const POSITION: u8 = 14;
    pub const MODE: u8 = 16;
    pub const ALIGNMENT: u8 = 17;
    pub const ALL: u8 = 18;
    pub const ALLOCATION: u8 = 19;
    pub const END_OF_FILE: u8 = 20;
    pub const STREAM: u8 = 22;
    pub const NETWORK_OPEN: u8 = 34;
    pub const ATTRIBUTE_TAG: u8 = 35;
    pub const ID_BOTH_DIRECTORY: u8 = 37;
    pub const ID_FULL_DIRECTORY: u8 = 38;
    pub const DISPOSITION_EX: u8 = 64;
}

/// FsInfoClass for InfoType FILESYSTEM (MS-FSCC §2.5).
pub mod fs_class {
    pub const VOLUME: u8 = 1;
    pub const SIZE: u8 = 3;
    pub const DEVICE: u8 = 4;
    pub const ATTRIBUTE: u8 = 5;
    pub const FULL_SIZE: u8 = 7;
}

#[derive(Debug)]
pub struct QueryInfoReq {
    pub info_type: u8,
    pub class: u8,
    pub output_buffer_length: u32,
    pub file_id: FileId,
}

impl QueryInfoReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if r.u16()? != 41 {
            return Err(WireError::Malformed("QUERY_INFO StructureSize != 41"));
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let output_buffer_length = r.u32()?;
        let _input_offset = r.u16()?;
        let _reserved = r.u16()?;
        let _input_length = r.u32()?;
        let _additional = r.u32()?;
        let _flags = r.u32()?;
        let file_id = r.array::<16>()?;
        Ok(QueryInfoReq {
            info_type,
            class,
            output_buffer_length,
            file_id,
        })
    }
}

/// QUERY_INFO reply: StructureSize 9, the buffer right after it (offset 72).
pub fn encode_query_info_resp(w: &mut Writer, buffer: &[u8]) {
    w.u16(9);
    w.u16((crate::header::HEADER_LEN + 8) as u16);
    w.u32(buffer.len() as u32);
    w.bytes(buffer);
}

#[derive(Debug)]
pub struct CloseReq {
    pub flags: u16,
    pub file_id: FileId,
}

impl CloseReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if r.u16()? != 24 {
            return Err(WireError::Malformed("CLOSE StructureSize != 24"));
        }
        let flags = r.u16()?;
        let _reserved = r.u32()?;
        let file_id = r.array::<16>()?;
        Ok(CloseReq { flags, file_id })
    }
}

/// CLOSE flag: return the attributes of the file (SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB).
pub const CLOSE_POSTQUERY_ATTRIB: u16 = 0x0001;

/// CLOSE reply without attributes (the POSTQUERY_ATTRIB flag was not requested).
pub fn encode_close_resp(w: &mut Writer) {
    w.u16(60);
    w.zeros(58);
}

/// CLOSE reply with the attributes of the object (§2.2.16).
pub fn encode_close_resp_attrs(w: &mut Writer, o: &ObjInfo) {
    w.u16(60);
    w.u16(CLOSE_POSTQUERY_ATTRIB);
    w.u32(0);
    w.u64(o.created);
    w.u64(o.accessed);
    w.u64(o.written);
    w.u64(o.changed);
    w.u64(o.allocation_size);
    w.u64(o.end_of_file);
    w.u32(o.attributes);
}

/// QUERY_DIRECTORY flags (§2.2.33).
pub mod query_dir_flags {
    pub const RESTART_SCANS: u8 = 0x01;
    pub const RETURN_SINGLE_ENTRY: u8 = 0x02;
    pub const INDEX_SPECIFIED: u8 = 0x04;
    pub const REOPEN: u8 = 0x10;
}

#[derive(Debug)]
pub struct QueryDirectoryReq {
    pub class: u8,
    pub flags: u8,
    pub file_index: u32,
    pub file_id: FileId,
    /// Search pattern (`*`, a name or a wildcard expression); empty means all.
    pub pattern: String,
    pub output_buffer_length: u32,
}

impl QueryDirectoryReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let body = r.whole();
        if r.u16()? != 33 {
            return Err(WireError::Malformed("QUERY_DIRECTORY StructureSize != 33"));
        }
        let class = r.u8()?;
        let flags = r.u8()?;
        let file_index = r.u32()?;
        let file_id = r.array::<16>()?;
        let name_off = r.u16()? as usize;
        let name_len = r.u16()? as usize;
        let output_buffer_length = r.u32()?;
        let pattern = if name_len == 0 {
            String::new()
        } else {
            if !name_len.is_multiple_of(2) {
                return Err(WireError::Malformed("QUERY_DIRECTORY: odd name length"));
            }
            let start = name_off
                .checked_sub(crate::header::HEADER_LEN)
                .filter(|&s| s >= 32)
                .ok_or(WireError::Malformed("FileNameOffset inside the fixed part"))?;
            let raw = body
                .get(start..start + name_len)
                .ok_or(WireError::Malformed("pattern outside the message"))?;
            decode_utf16(raw)?
        };
        Ok(QueryDirectoryReq {
            class,
            flags,
            file_index,
            file_id,
            pattern,
            output_buffer_length,
        })
    }
}

fn decode_utf16(raw: &[u8]) -> Result<String, WireError> {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| WireError::Malformed("invalid UTF-16"))
}

/// Whether `name` matches an SMB search pattern (MS-FSA 2.1.4.4: `*`, `?`, and the DOS
/// wildcards `<` `>` `"`). The DOS wildcards are approximated: `<` as `*`, `>` as `?`,
/// `"` as `.`. Matching is case-sensitive iff `case_sensitive`.
pub fn pattern_matches(pattern: &str, name: &str, case_sensitive: bool) -> bool {
    if pattern.is_empty() || pattern == "*" || pattern == "*.*" {
        return true;
    }
    let norm = |s: &str| -> Vec<char> {
        if case_sensitive {
            s.chars().collect()
        } else {
            s.chars().flat_map(char::to_lowercase).collect()
        }
    };
    let (p, n) = (norm(pattern), norm(name));
    // Iterative glob with backtracking on the last star.
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        match p.get(pi) {
            Some('*') | Some('<') => {
                star = Some((pi, ni));
                pi += 1;
            }
            Some('?') | Some('>') => {
                pi += 1;
                ni += 1;
            }
            Some('"') if n[ni] == '.' => {
                pi += 1;
                ni += 1;
            }
            Some(&c) if c == n[ni] && c != '"' => {
                pi += 1;
                ni += 1;
            }
            _ => match star {
                Some((sp, sn)) => {
                    pi = sp + 1;
                    ni = sn + 1;
                    star = Some((sp, sn + 1));
                }
                None => return false,
            },
        }
    }
    while matches!(p.get(pi), Some('*') | Some('<')) {
        pi += 1;
    }
    pi == p.len()
}

/// One directory entry, in the form all FILE*_DIRECTORY classes are built from.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub info: ObjInfo,
}

/// Serialise as many entries as fit into `max` bytes, in the requested class.
/// Returns the buffer and how many entries were consumed. `None` means the class is not a
/// directory class. The first entry that does not fit stops the listing; if not even one
/// fits the caller answers STATUS_INFO_LENGTH_MISMATCH (`consumed == 0`).
pub fn encode_dir_entries(
    class: u8,
    entries: &[DirEntry],
    max: usize,
    single: bool,
) -> Option<(Vec<u8>, usize)> {
    if !matches!(
        class,
        file_class::DIRECTORY
            | file_class::FULL_DIRECTORY
            | file_class::BOTH_DIRECTORY
            | file_class::NAMES
            | file_class::ID_BOTH_DIRECTORY
            | file_class::ID_FULL_DIRECTORY
    ) {
        return None;
    }
    let mut out: Vec<u8> = Vec::new();
    let mut consumed = 0;
    let mut last_start = 0usize;
    for e in entries {
        let mut w = Writer::new();
        w.u32(0); // NextEntryOffset (patched when another entry follows)
        w.u32(e.info.file_index);
        let name = utf16(&e.name);
        if class != file_class::NAMES {
            let i = &e.info;
            w.u64(i.created);
            w.u64(i.accessed);
            w.u64(i.written);
            w.u64(i.changed);
            w.u64(i.end_of_file);
            w.u64(i.allocation_size);
            w.u32(i.attributes);
        }
        w.u32(name.len() as u32);
        match class {
            file_class::FULL_DIRECTORY => w.u32(0), // EaSize
            file_class::BOTH_DIRECTORY | file_class::ID_BOTH_DIRECTORY => {
                w.u32(0); // EaSize
                w.u8(0); // ShortNameLength
                w.u8(0); // Reserved
                w.zeros(24); // ShortName
                if class == file_class::ID_BOTH_DIRECTORY {
                    w.u16(0); // Reserved2
                    w.u64(e.info.file_id);
                }
            }
            file_class::ID_FULL_DIRECTORY => {
                w.u32(0); // EaSize
                w.u32(0); // Reserved
                w.u64(e.info.file_id);
            }
            _ => {}
        }
        w.bytes(&name);
        let entry = w.into_vec();
        // Entries are 8-byte aligned except the last one, which needs no padding.
        let aligned = if out.is_empty() {
            0
        } else {
            out.len().next_multiple_of(8) - out.len()
        };
        if out.len() + aligned + entry.len() > max {
            break;
        }
        if !out.is_empty() {
            out.resize(out.len() + aligned, 0);
            let next = (out.len() - last_start) as u32;
            out[last_start..last_start + 4].copy_from_slice(&next.to_le_bytes());
        }
        last_start = out.len();
        out.extend_from_slice(&entry);
        consumed += 1;
        if single {
            break;
        }
    }
    Some((out, consumed))
}

// --- MS-FSCC structures -----------------------------------------------

/// Volume/object parameters for the information replies.
#[derive(Debug, Clone, Copy)]
pub struct VolumeInfo {
    /// Volume size in bytes (by quota).
    pub total_bytes: u64,
    pub free_bytes: u64,
    /// Volume/root creation time, FILETIME.
    pub created: u64,
    /// Current time (last access/write), FILETIME.
    pub now: u64,
    /// Case-sensitive names (from `CompatCaps`).
    pub case_sensitive_names: bool,
}

pub const BYTES_PER_SECTOR: u32 = 512;
pub const SECTORS_PER_UNIT: u32 = 8;
const UNIT_BYTES: u64 = (BYTES_PER_SECTOR * SECTORS_PER_UNIT) as u64;

const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x1;
const FILE_CASE_PRESERVED_NAMES: u32 = 0x2;
const FILE_UNICODE_ON_DISK: u32 = 0x4;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_DEVICE_IS_MOUNTED: u32 = 0x20;

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Volume information (InfoType FILESYSTEM). `None` means the class is not supported.
pub fn fs_info(class: u8, v: &VolumeInfo) -> Option<Vec<u8>> {
    let mut w = Writer::new();
    match class {
        fs_class::VOLUME => {
            let label = utf16("backup");
            w.u64(v.created);
            w.u32(0x4A41_4E55); // volume serial number
            w.u32(label.len() as u32);
            w.u8(0); // SupportsObjects
            w.u8(0);
            w.bytes(&label);
        }
        fs_class::SIZE => {
            w.u64(v.total_bytes / UNIT_BYTES);
            w.u64(v.free_bytes / UNIT_BYTES);
            w.u32(SECTORS_PER_UNIT);
            w.u32(BYTES_PER_SECTOR);
        }
        fs_class::DEVICE => {
            w.u32(FILE_DEVICE_DISK);
            w.u32(FILE_DEVICE_IS_MOUNTED);
        }
        fs_class::ATTRIBUTE => {
            let name = utf16("NTFS");
            let mut attrs = FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK;
            if v.case_sensitive_names {
                attrs |= FILE_CASE_SENSITIVE_SEARCH;
            }
            w.u32(attrs);
            w.u32(255); // MaximumComponentNameLength
            w.u32(name.len() as u32);
            w.bytes(&name);
        }
        fs_class::FULL_SIZE => {
            w.u64(v.total_bytes / UNIT_BYTES);
            w.u64(v.free_bytes / UNIT_BYTES);
            w.u64(v.free_bytes / UNIT_BYTES);
            w.u32(SECTORS_PER_UNIT);
            w.u32(BYTES_PER_SECTOR);
        }
        _ => return None,
    }
    Some(w.into_vec())
}

/// Attributes of any object, FILETIME times.
#[derive(Debug, Clone, Default)]
pub struct ObjInfo {
    pub created: u64,
    pub accessed: u64,
    pub written: u64,
    pub changed: u64,
    pub end_of_file: u64,
    pub allocation_size: u64,
    pub attributes: u32,
    pub file_id: u64,
    pub file_index: u32,
    pub directory: bool,
    pub delete_pending: bool,
    /// Path from the share root with a leading `\` (empty for the root itself).
    pub name: String,
    /// Access granted on the open (FileAccessInformation).
    pub access: u32,
}

/// File information (InfoType FILE). `None` means the class is not supported.
pub fn file_info(class: u8, o: &ObjInfo) -> Option<Vec<u8>> {
    let mut w = Writer::new();
    match class {
        file_class::BASIC => basic(&mut w, o),
        file_class::STANDARD => standard(&mut w, o),
        file_class::INTERNAL => w.u64(o.file_id),
        file_class::EA => w.u32(0),
        file_class::ACCESS => w.u32(o.access),
        file_class::NAME => name_info(&mut w, o),
        file_class::POSITION => w.u64(0),
        file_class::MODE | file_class::ALIGNMENT => w.u32(0),
        file_class::NETWORK_OPEN => {
            w.u64(o.created);
            w.u64(o.accessed);
            w.u64(o.written);
            w.u64(o.changed);
            w.u64(o.allocation_size);
            w.u64(o.end_of_file);
            w.u32(o.attributes);
            w.u32(0);
        }
        file_class::ATTRIBUTE_TAG => {
            w.u32(o.attributes);
            w.u32(0); // ReparseTag
        }
        file_class::STREAM => {
            // A directory has no streams; a file has the single unnamed data stream.
            if !o.directory {
                let name = utf16("::$DATA");
                w.u32(0); // NextEntryOffset
                w.u32(name.len() as u32);
                w.u64(o.end_of_file);
                w.u64(o.allocation_size);
                w.bytes(&name);
            }
        }
        file_class::ALL => {
            basic(&mut w, o);
            standard(&mut w, o);
            w.u64(o.file_id); // InternalInformation
            w.u32(0); // EaInformation
            w.u32(o.access); // AccessInformation
            w.u64(0); // PositionInformation
            w.u32(0); // ModeInformation
            w.u32(0); // AlignmentInformation
            name_info(&mut w, o);
        }
        _ => return None,
    }
    Some(w.into_vec())
}

fn basic(w: &mut Writer, o: &ObjInfo) {
    w.u64(o.created);
    w.u64(o.accessed);
    w.u64(o.written);
    w.u64(o.changed);
    w.u32(o.attributes);
    w.u32(0);
}

fn standard(w: &mut Writer, o: &ObjInfo) {
    w.u64(o.allocation_size);
    w.u64(o.end_of_file);
    w.u32(1); // NumberOfLinks
    w.u8(o.delete_pending as u8);
    w.u8(o.directory as u8);
    w.u16(0);
}

fn name_info(w: &mut Writer, o: &ObjInfo) {
    let name = utf16(&o.name);
    w.u32(name.len() as u32);
    w.bytes(&name);
}

/// Root directory information from the volume parameters (the root is always present).
pub fn root_dir_info(class: u8, v: &VolumeInfo) -> Option<Vec<u8>> {
    file_info(class, &root_obj(v))
}

/// The share root as an object.
pub fn root_obj(v: &VolumeInfo) -> ObjInfo {
    ObjInfo {
        created: v.created,
        accessed: v.now,
        written: v.now,
        changed: v.created,
        attributes: crate::create::ATTR_DIRECTORY,
        file_id: 1,
        directory: true,
        access: 0x001F_01FF,
        ..ObjInfo::default()
    }
}

// --- Times -----------------------------------------------------------------

/// 100 ns intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// Unix nanoseconds → FILETIME (clamped at 0 for dates before 1601).
pub fn filetime_from_unix_ns(ns: i64) -> u64 {
    let ticks = ns.div_euclid(100);
    FILETIME_UNIX_EPOCH.saturating_add_signed(ticks)
}

/// FILETIME → Unix nanoseconds; `None` for 0 and for the "do not change" markers.
pub fn unix_ns_from_filetime(ft: u64) -> Option<i64> {
    if ft == 0 || ft == u64::MAX {
        return None;
    }
    let ticks = i128::from(ft) - i128::from(FILETIME_UNIX_EPOCH);
    i64::try_from(ticks * 100).ok()
}

// --- SET_INFO ---------------------------------------------------------------

#[derive(Debug)]
pub struct SetInfoReq {
    pub info_type: u8,
    pub class: u8,
    pub file_id: FileId,
    pub buffer: Vec<u8>,
}

impl SetInfoReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let body = r.whole();
        if r.u16()? != 33 {
            return Err(WireError::Malformed("SET_INFO StructureSize != 33"));
        }
        let info_type = r.u8()?;
        let class = r.u8()?;
        let len = r.u32()? as usize;
        let off = r.u16()? as usize;
        let _reserved = r.u16()?;
        let _additional = r.u32()?;
        let file_id = r.array::<16>()?;
        let buffer = if len == 0 {
            Vec::new()
        } else {
            let start = off
                .checked_sub(crate::header::HEADER_LEN)
                .filter(|&s| s >= 32)
                .ok_or(WireError::Malformed(
                    "SET_INFO BufferOffset inside the fixed part",
                ))?;
            let end = start
                .checked_add(len)
                .ok_or(WireError::Malformed("SET_INFO length overflow"))?;
            body.get(start..end)
                .ok_or(WireError::Malformed("SET_INFO buffer outside the message"))?
                .to_vec()
        };
        Ok(SetInfoReq {
            info_type,
            class,
            file_id,
            buffer,
        })
    }
}

pub fn encode_set_info_resp(w: &mut Writer) {
    w.u16(2);
}

/// A decoded FILE-type SET_INFO payload.
#[derive(Debug, PartialEq, Eq)]
pub enum FileSet {
    /// FileBasicInformation: times as FILETIME (0 and -1 mean "unchanged"), attributes
    /// (0 means unchanged).
    Basic {
        created: u64,
        accessed: u64,
        written: u64,
        changed: u64,
        attributes: u32,
    },
    /// FileRenameInformation: target path relative to the share, `\`-separated.
    Rename {
        replace: bool,
        target: String,
    },
    /// FileDispositionInformation(+Ex): delete on close.
    Disposition {
        delete: bool,
    },
    EndOfFile(u64),
    /// FileAllocationInformation: a hint only.
    Allocation(u64),
    /// FilePositionInformation / FileModeInformation: accepted and ignored.
    Ignored,
}

impl FileSet {
    /// `Ok(None)` is an unsupported class; `Err` a malformed buffer.
    pub fn decode(class: u8, buf: &[u8]) -> Result<Option<FileSet>, WireError> {
        let mut r = Reader::new(buf);
        Ok(Some(match class {
            file_class::BASIC => FileSet::Basic {
                created: r.u64()?,
                accessed: r.u64()?,
                written: r.u64()?,
                changed: r.u64()?,
                attributes: r.u32()?,
            },
            file_class::RENAME => {
                let replace = r.u8()? != 0;
                r.skip(7)?;
                let _root = r.u64()?;
                let len = r.u32()? as usize;
                let name = r.take(len)?;
                if !len.is_multiple_of(2) {
                    return Err(WireError::Malformed("rename: odd name length"));
                }
                FileSet::Rename {
                    replace,
                    target: decode_utf16(name)?,
                }
            }
            file_class::DISPOSITION => FileSet::Disposition {
                delete: r.u8()? != 0,
            },
            file_class::DISPOSITION_EX => FileSet::Disposition {
                delete: r.u32()? & 1 != 0,
            },
            file_class::END_OF_FILE => FileSet::EndOfFile(r.u64()?),
            file_class::ALLOCATION => FileSet::Allocation(r.u64()?),
            file_class::POSITION | file_class::MODE => FileSet::Ignored,
            _ => return Ok(None),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: VolumeInfo = VolumeInfo {
        total_bytes: 1 << 40,
        free_bytes: 1 << 39,
        created: 100,
        now: 200,
        case_sensitive_names: true,
    };

    // QUERY_INFO and CLOSE from a live macOS exchange (related, FileId = 0xFF…).
    const MACOS_QUERY_INFO: &str =
        "290002031800000000000000000000000000000000000000ffffffffffffffffffffffffffffffff";
    const MACOS_CLOSE: &str = "1800000000000000ffffffffffffffffffffffffffffffff";

    #[test]
    fn decodes_macos_query_info_and_close() {
        let q = crate::ms_vectors::unhex(MACOS_QUERY_INFO);
        let req = QueryInfoReq::decode(&mut Reader::new(&q)).unwrap();
        assert_eq!(req.info_type, info_type::FILESYSTEM);
        assert_eq!(req.class, fs_class::SIZE);
        assert_eq!(req.output_buffer_length, 24);
        assert_eq!(req.file_id, crate::create::FILE_ID_RELATED);
        let c = crate::ms_vectors::unhex(MACOS_CLOSE);
        let req = CloseReq::decode(&mut Reader::new(&c)).unwrap();
        assert_eq!(req.file_id, crate::create::FILE_ID_RELATED);
        assert_eq!(req.flags, 0);
    }

    #[test]
    fn requests_reject_truncation() {
        let q = crate::ms_vectors::unhex(MACOS_QUERY_INFO);
        for n in 0..q.len() {
            assert!(QueryInfoReq::decode(&mut Reader::new(&q[..n])).is_err());
        }
        let c = crate::ms_vectors::unhex(MACOS_CLOSE);
        for n in 0..c.len() {
            assert!(CloseReq::decode(&mut Reader::new(&c[..n])).is_err());
        }
    }

    #[test]
    fn fs_structures_have_msfscc_sizes() {
        assert_eq!(fs_info(fs_class::SIZE, &V).unwrap().len(), 24);
        assert_eq!(fs_info(fs_class::FULL_SIZE, &V).unwrap().len(), 32);
        assert_eq!(fs_info(fs_class::DEVICE, &V).unwrap().len(), 8);
        assert_eq!(fs_info(fs_class::VOLUME, &V).unwrap().len(), 18 + 12);
        assert_eq!(fs_info(fs_class::ATTRIBUTE, &V).unwrap().len(), 12 + 8);
        assert!(fs_info(99, &V).is_none());
    }

    #[test]
    fn size_information_values() {
        let b = fs_info(fs_class::SIZE, &V).unwrap();
        assert_eq!(
            u64::from_le_bytes(b[0..8].try_into().unwrap()),
            (1u64 << 40) / 4096
        );
        assert_eq!(
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            (1u64 << 39) / 4096
        );
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 8);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 512);
    }

    #[test]
    fn attribute_information_follows_case_semantics() {
        let attrs = |cs: bool| {
            let v = VolumeInfo {
                case_sensitive_names: cs,
                ..V
            };
            u32::from_le_bytes(
                fs_info(fs_class::ATTRIBUTE, &v).unwrap()[0..4]
                    .try_into()
                    .unwrap(),
            )
        };
        assert_eq!(attrs(true), 0x7);
        assert_eq!(attrs(false), 0x6);
    }

    #[test]
    fn root_dir_structures_have_msfscc_sizes_and_are_directories() {
        assert_eq!(root_dir_info(file_class::BASIC, &V).unwrap().len(), 40);
        let std = root_dir_info(file_class::STANDARD, &V).unwrap();
        assert_eq!(std.len(), 24);
        assert_eq!(std[21], 1, "Directory");
        assert_eq!(root_dir_info(file_class::INTERNAL, &V).unwrap().len(), 8);
        assert_eq!(
            root_dir_info(file_class::NETWORK_OPEN, &V).unwrap().len(),
            56
        );
        assert_eq!(
            root_dir_info(file_class::ALL, &V).unwrap().len(),
            40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 + 4
        );
        assert!(root_dir_info(99, &V).is_none());
    }

    #[test]
    fn response_encoders() {
        let mut w = Writer::new();
        encode_query_info_resp(&mut w, &[1, 2, 3]);
        let b = w.into_vec();
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 9);
        assert_eq!(u16::from_le_bytes([b[2], b[3]]), 72);
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 3);
        let mut w = Writer::new();
        encode_close_resp(&mut w);
        assert_eq!(w.len(), 60);
    }

    // --- J2: directory entries, SET_INFO, patterns ---

    fn obj(name: &str, size: u64, dir: bool, id: u64) -> DirEntry {
        DirEntry {
            name: name.into(),
            info: ObjInfo {
                created: 1,
                accessed: 2,
                written: 3,
                changed: 4,
                end_of_file: size,
                allocation_size: size.next_multiple_of(4096),
                attributes: if dir { 0x10 } else { 0x20 },
                file_id: id,
                directory: dir,
                ..ObjInfo::default()
            },
        }
    }

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn u64_at(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    /// FileNameOffset per class, from MS-FSCC §2.4.
    #[test]
    fn dir_entry_name_offsets_follow_msfscc() {
        for (class, name_off) in [
            (file_class::DIRECTORY, 64),
            (file_class::FULL_DIRECTORY, 68),
            (file_class::BOTH_DIRECTORY, 94),
            (file_class::ID_FULL_DIRECTORY, 80),
            (file_class::ID_BOTH_DIRECTORY, 104),
            (file_class::NAMES, 12),
        ] {
            let (b, n) =
                encode_dir_entries(class, &[obj("ab", 5, false, 77)], 4096, false).unwrap();
            assert_eq!(n, 1);
            assert_eq!(b.len(), name_off + 4, "class {class}");
            let name_len_at = if class == file_class::NAMES { 8 } else { 60 };
            assert_eq!(u32_at(&b, name_len_at), 4, "FileNameLength, class {class}");
            assert_eq!(&b[name_off..], [b'a', 0, b'b', 0], "class {class}");
            assert_eq!(u32_at(&b, 0), 0, "single entry: NextEntryOffset 0");
        }
    }

    #[test]
    fn id_both_entry_carries_times_size_attrs_and_id() {
        let (b, _) = encode_dir_entries(
            file_class::ID_BOTH_DIRECTORY,
            &[obj("f", 5000, false, 0xABCD)],
            4096,
            false,
        )
        .unwrap();
        assert_eq!(u64_at(&b, 8), 1); // CreationTime
        assert_eq!(u64_at(&b, 16), 2); // LastAccessTime
        assert_eq!(u64_at(&b, 24), 3); // LastWriteTime
        assert_eq!(u64_at(&b, 32), 4); // ChangeTime
        assert_eq!(u64_at(&b, 40), 5000); // EndOfFile
        assert_eq!(u64_at(&b, 48), 8192); // AllocationSize
        assert_eq!(u32_at(&b, 56), 0x20); // FileAttributes
        assert_eq!(u64_at(&b, 96), 0xABCD); // FileId
    }

    #[test]
    fn dir_entries_chain_with_alignment_and_limits() {
        let entries = [
            obj("a", 1, false, 1),
            obj("bb", 2, false, 2),
            obj("ccc", 3, true, 3),
        ];
        let (b, n) = encode_dir_entries(file_class::DIRECTORY, &entries, 4096, false).unwrap();
        assert_eq!(n, 3);
        // entry sizes: 64+2=66, 64+4=68, 64+6=70; offsets are 8-aligned
        assert_eq!(u32_at(&b, 0), 72);
        assert_eq!(u32_at(&b, 72), 72);
        assert_eq!(u32_at(&b, 144), 0, "last entry");
        assert_eq!(b.len(), 144 + 70, "no padding after the last entry");
        // a buffer that holds only the first two entries
        let (b, n) = encode_dir_entries(file_class::DIRECTORY, &entries, 72 + 68, false).unwrap();
        assert_eq!((n, b.len()), (2, 140));
        assert_eq!(u32_at(&b, 72), 0, "last of the returned entries");
        // not even one fits
        let (b, n) = encode_dir_entries(file_class::DIRECTORY, &entries, 65, false).unwrap();
        assert_eq!((n, b.len()), (0, 0));
        // RETURN_SINGLE_ENTRY
        let (_, n) = encode_dir_entries(file_class::DIRECTORY, &entries, 4096, true).unwrap();
        assert_eq!(n, 1);
        assert!(encode_dir_entries(99, &entries, 4096, false).is_none());
    }

    #[test]
    fn patterns() {
        for (p, n, cs, want) in [
            ("*", "anything", true, true),
            ("", "x", true, true),
            ("a*", "abc", true, true),
            ("a*", "Abc", true, false),
            ("a*", "Abc", false, true),
            ("*.txt", "f.txt", true, true),
            ("*.txt", "f.txt.bak", true, false),
            ("f?.c", "fa.c", true, true),
            ("f?.c", "fab.c", true, false),
            ("exact", "exact", true, true),
            ("exact", "exacts", true, false),
            ("*a*b*", "xxaxxbxx", true, true),
            ("*a*b*", "xxbxxaxx", true, false),
            ("*", "", true, true),
        ] {
            assert_eq!(pattern_matches(p, n, cs), want, "{p} vs {n} cs={cs}");
        }
    }

    #[test]
    fn query_directory_request_decodes_pattern() {
        let mut w = Writer::new();
        w.u16(33);
        w.u8(file_class::ID_BOTH_DIRECTORY);
        w.u8(query_dir_flags::RESTART_SCANS);
        w.u32(0);
        w.bytes(&[5; 16]);
        w.u16(96);
        w.u16(2);
        w.u32(65536);
        w.bytes(&utf16("*"));
        let b = w.into_vec();
        let q = QueryDirectoryReq::decode(&mut Reader::new(&b)).unwrap();
        assert_eq!(
            (q.class, q.flags, q.pattern.as_str(), q.output_buffer_length),
            (37, 1, "*", 65536)
        );
        for n in 0..b.len() {
            assert!(
                QueryDirectoryReq::decode(&mut Reader::new(&b[..n])).is_err(),
                "{n}"
            );
        }
    }

    #[test]
    fn set_info_request_and_payloads() {
        // FileEndOfFileInformation
        let mut w = Writer::new();
        w.u16(33);
        w.u8(info_type::FILE);
        w.u8(file_class::END_OF_FILE);
        w.u32(8);
        w.u16(96);
        w.u16(0);
        w.u32(0);
        w.bytes(&[1; 16]);
        w.u64(4096);
        let b = w.into_vec();
        let r = SetInfoReq::decode(&mut Reader::new(&b)).unwrap();
        assert_eq!(
            FileSet::decode(r.class, &r.buffer).unwrap(),
            Some(FileSet::EndOfFile(4096))
        );
        for n in 0..b.len() {
            assert!(
                SetInfoReq::decode(&mut Reader::new(&b[..n])).is_err(),
                "{n}"
            );
        }

        // FileRenameInformation (type 2 layout: 20 fixed bytes + name)
        let name = utf16("dir\\new.txt");
        let mut p = vec![1u8];
        p.extend_from_slice(&[0; 7]);
        p.extend_from_slice(&0u64.to_le_bytes());
        p.extend_from_slice(&(name.len() as u32).to_le_bytes());
        p.extend_from_slice(&name);
        assert_eq!(
            FileSet::decode(file_class::RENAME, &p).unwrap(),
            Some(FileSet::Rename {
                replace: true,
                target: "dir\\new.txt".into()
            })
        );
        assert!(FileSet::decode(file_class::RENAME, &p[..p.len() - 1]).is_err());

        assert_eq!(
            FileSet::decode(file_class::DISPOSITION, &[1]).unwrap(),
            Some(FileSet::Disposition { delete: true })
        );
        assert_eq!(
            FileSet::decode(file_class::DISPOSITION_EX, &[1, 0, 0, 0]).unwrap(),
            Some(FileSet::Disposition { delete: true })
        );
        assert_eq!(
            FileSet::decode(file_class::DISPOSITION_EX, &[0x10, 0, 0, 0]).unwrap(),
            Some(FileSet::Disposition { delete: false })
        );
        assert!(FileSet::decode(99, &[]).unwrap().is_none());
        assert!(FileSet::decode(file_class::BASIC, &[0; 35]).is_err());
        let mut basic = vec![0u8; 40];
        basic[8..16].copy_from_slice(&5u64.to_le_bytes());
        basic[32..36].copy_from_slice(&0x21u32.to_le_bytes());
        assert_eq!(
            FileSet::decode(file_class::BASIC, &basic).unwrap(),
            Some(FileSet::Basic {
                created: 0,
                accessed: 5,
                written: 0,
                changed: 0,
                attributes: 0x21
            })
        );
    }

    #[test]
    fn filetime_conversion() {
        // 1970-01-01 is 116444736000000000 in FILETIME (MS-DTYP).
        assert_eq!(filetime_from_unix_ns(0), 116_444_736_000_000_000);
        assert_eq!(unix_ns_from_filetime(116_444_736_000_000_000), Some(0));
        assert_eq!(
            unix_ns_from_filetime(filetime_from_unix_ns(1_600_000_000_123_456_700)),
            Some(1_600_000_000_123_456_700)
        );
        assert_eq!(unix_ns_from_filetime(0), None);
        assert_eq!(unix_ns_from_filetime(u64::MAX), None);
        assert_eq!(
            filetime_from_unix_ns(i64::MIN),
            116_444_736_000_000_000 - 92_233_720_368_547_759,
            "1677 is representable"
        );
    }

    #[test]
    fn file_info_for_a_regular_file() {
        let o = ObjInfo {
            end_of_file: 10,
            allocation_size: 4096,
            attributes: 0x20,
            file_id: 9,
            name: "\\a\\b".into(),
            access: 0x1F01FF,
            ..ObjInfo::default()
        };
        let std = file_info(file_class::STANDARD, &o).unwrap();
        assert_eq!((u64_at(&std, 0), u64_at(&std, 8)), (4096, 10));
        assert_eq!((std[20], std[21]), (0, 0), "not pending, not a directory");
        let name = file_info(file_class::NAME, &o).unwrap();
        assert_eq!(u32_at(&name, 0), 8);
        let all = file_info(file_class::ALL, &o).unwrap();
        assert_eq!(all.len(), 100 + 8);
        assert_eq!(u64_at(&all, 64), 9, "InternalInformation");
        assert_eq!(file_info(file_class::STREAM, &o).unwrap().len(), 24 + 14);
        let dir = ObjInfo {
            directory: true,
            ..o.clone()
        };
        assert!(file_info(file_class::STREAM, &dir).unwrap().is_empty());
        assert_eq!(file_info(file_class::ATTRIBUTE_TAG, &o).unwrap().len(), 8);
        assert_eq!(file_info(file_class::NETWORK_OPEN, &o).unwrap().len(), 56);
        let mut w = Writer::new();
        encode_close_resp_attrs(&mut w, &o);
        let c = w.into_vec();
        assert_eq!(c.len(), 60);
        assert_eq!(u16::from_le_bytes([c[2], c[3]]), 1);
        assert_eq!(u64_at(&c, 48), 10, "EndOfFile");
        assert_eq!(u32_at(&c, 56), 0x20);
    }
}
