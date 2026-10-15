//! QUERY_INFO / CLOSE / QUERY_DIRECTORY and the information structures of a volume and a directory
//! (MS-SMB2 §2.2.37–2.2.38, 2.2.15–2.2.16, 2.2.33; MS-FSCC §2.4, §2.5).
//! For now they serve the virtual empty share root (J1-lite); the file model is J2.

use crate::WireError;
use crate::bytes::{Reader, Writer};
use crate::create::FileId;

/// InfoType of a QUERY_INFO request.
pub mod info_type {
    pub const FILE: u8 = 0x01;
    pub const FILESYSTEM: u8 = 0x02;
}

/// FileInfoClass for InfoType FILE (MS-FSCC §2.4).
pub mod file_class {
    pub const BASIC: u8 = 4;
    pub const STANDARD: u8 = 5;
    pub const INTERNAL: u8 = 6;
    pub const ALL: u8 = 18;
    pub const NETWORK_OPEN: u8 = 34;
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

/// CLOSE reply without attributes (we do not set the POSTQUERY_ATTRIB flag).
pub fn encode_close_resp(w: &mut Writer) {
    w.u16(60);
    w.zeros(58);
}

#[derive(Debug)]
pub struct QueryDirectoryReq {
    pub file_id: FileId,
}

impl QueryDirectoryReq {
    pub fn decode(r: &mut Reader<'_>) -> Result<Self, WireError> {
        if r.u16()? != 33 {
            return Err(WireError::Malformed("QUERY_DIRECTORY StructureSize != 33"));
        }
        let _class = r.u8()?;
        let _flags = r.u8()?;
        let _file_index = r.u32()?;
        let file_id = r.array::<16>()?;
        Ok(QueryDirectoryReq { file_id })
    }
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

fn basic(w: &mut Writer, v: &VolumeInfo, attrs: u32) {
    w.u64(v.created);
    w.u64(v.now);
    w.u64(v.now);
    w.u64(v.created);
    w.u32(attrs);
    w.u32(0);
}

fn standard_dir(w: &mut Writer) {
    w.u64(0); // AllocationSize
    w.u64(0); // EndOfFile
    w.u32(1); // NumberOfLinks
    w.u8(0); // DeletePending
    w.u8(1); // Directory
    w.u16(0);
}

/// Root directory information (InfoType FILE). `None` means the class is not supported.
pub fn root_dir_info(class: u8, v: &VolumeInfo) -> Option<Vec<u8>> {
    use crate::create::ATTR_DIRECTORY as DIR;
    let mut w = Writer::new();
    match class {
        file_class::BASIC => basic(&mut w, v, DIR),
        file_class::STANDARD => standard_dir(&mut w),
        file_class::INTERNAL => w.u64(1),
        file_class::NETWORK_OPEN => {
            w.u64(v.created);
            w.u64(v.now);
            w.u64(v.now);
            w.u64(v.created);
            w.u64(0);
            w.u64(0);
            w.u32(DIR);
            w.u32(0);
        }
        file_class::ALL => {
            basic(&mut w, v, DIR);
            standard_dir(&mut w);
            w.u64(1); // InternalInformation
            w.u32(0); // EaInformation
            w.u32(0x001F_01FF); // AccessInformation
            w.u64(0); // PositionInformation
            w.u32(0); // ModeInformation
            w.u32(0); // AlignmentInformation
            w.u32(0); // NameInformation: FileNameLength = 0 (the root)
        }
        _ => return None,
    }
    Some(w.into_vec())
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
}
