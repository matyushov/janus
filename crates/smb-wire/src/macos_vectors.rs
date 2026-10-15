//! Live macOS (`mount_smbfs`, JANUS_SMB_TRACE=2) request bodies for the J2 commands, captured
//! on 2026-10-15 while running `echo > f`, `cp`, `mv`, `touch -t`, `mkdir` and `rmdir`
//! on a share served by janus. The expectations below come from what the commands did, not from
//! what our encoder produces.

use crate::bytes::Reader;
use crate::create::{CreateContext, CreateReq, disposition};
use crate::fileinfo::{FileSet, QueryDirectoryReq, SetInfoReq, file_class, query_dir_flags};
use crate::io::{ReadReq, WriteReq};
use crate::ms_vectors::unhex;

const CREATE_5: &str = "39000000020000000000000000000000000000000000000087000600a000000007000000050000000000000078000e0088000000300000006f006e0065002e007400780074000000180000001000040000000000000000005146696400000000000000001000040000000000000000004d78416300000000";

const CREATE_2: &str = "39000000020000000000000000000000000000000000000082000000a20000000700000002000000000000007800120090000000180000002e005f006f006e0065002e00740078007400000000000000000000001000040000000000000000004d78416300000000";

const QUERYDIR: &str = "2100250300000000ffffffffffffffffffffffffffffffff60000e00000001006f006e0065002e007400780074000000";

const WRITE_SMALL: &str = "31007000030000000000000000000000070000000000000007000000000000000000000000000000000000000000000068690a";

const READ: &str = "31000000000001000000000000000000c000000000000000c000000000000000010000000000000000000000000000000000000000000000";

const SETINFO_4: &str = "21000104280000006000000000000000ffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000002200000000000000";

const SETINFO_10: &str = "2100010a260000006000000000000000ffffffffffffffffffffffffffffffff000000000000000000000000000000000e00000075006e006f002e00740078007400000000000000";

const SETINFO_13: &str =
    "2100010d010000006000000000000000ffffffffffffffffffffffffffffffff0100000000000000";

const SETINFO_19: &str =
    "210001130800000060000000000000002c000000000000002c0000000000000000a0040000000000";

const SETINFO_20: &str =
    "210001140800000060000000000000001b000000000000001b000000000000000010000000000000";

fn setinfo(hex: &str) -> SetInfoReq {
    SetInfoReq::decode(&mut Reader::new(&unhex(hex))).unwrap()
}

#[test]
fn macos_create_for_echo_redirect_overwrites_one_txt() {
    let req = CreateReq::decode(&mut Reader::new(&unhex(CREATE_5))).unwrap();
    assert_eq!(req.path, "one.txt");
    assert_eq!(req.create_disposition, disposition::OVERWRITE_IF);
    assert_eq!(req.file_attributes, 0xA0, "NORMAL | ARCHIVE");
    assert!(
        req.contexts
            .iter()
            .any(|c| matches!(c, CreateContext::QueryMaximalAccess))
    );
    assert!(
        req.contexts
            .iter()
            .any(|c| matches!(c, CreateContext::Unknown { tag, .. } if tag == b"QFid"))
    );
}

#[test]
fn macos_create_of_the_appledouble_sidecar() {
    let req = CreateReq::decode(&mut Reader::new(&unhex(CREATE_2))).unwrap();
    assert_eq!(req.path, "._one.txt");
    assert_eq!(req.create_disposition, disposition::CREATE);
}

#[test]
fn macos_query_directory_probes_an_exact_name() {
    let q = QueryDirectoryReq::decode(&mut Reader::new(&unhex(QUERYDIR))).unwrap();
    assert_eq!(q.class, file_class::ID_BOTH_DIRECTORY);
    assert_eq!(q.pattern, "one.txt");
    assert_eq!(
        q.flags,
        query_dir_flags::RESTART_SCANS | query_dir_flags::RETURN_SINGLE_ENTRY
    );
    assert_eq!(q.output_buffer_length, 65536);
}

#[test]
fn macos_write_carries_three_bytes_of_echo_output() {
    let w = WriteReq::decode(&mut Reader::new(&unhex(WRITE_SMALL))).unwrap();
    assert_eq!(w.data, b"hi\n");
    assert_eq!(w.offset, 0);
    assert_eq!(w.channel, 0);
}

#[test]
fn macos_read_request() {
    let r = ReadReq::decode(&mut Reader::new(&unhex(READ))).unwrap();
    assert_eq!(r.length, 0x10000);
    assert_eq!(r.channel, 0);
}

#[test]
fn macos_set_info_requests_decode_to_the_operations_performed() {
    // mv one.txt uno.txt
    let r = setinfo(SETINFO_10);
    assert_eq!(
        FileSet::decode(r.class, &r.buffer).unwrap(),
        Some(FileSet::Rename {
            replace: false,
            target: "uno.txt".into()
        })
    );
    // rm / rmdir: delete on close
    let r = setinfo(SETINFO_13);
    assert_eq!(
        FileSet::decode(r.class, &r.buffer).unwrap(),
        Some(FileSet::Disposition { delete: true })
    );
    // the copy pre-sizes the destination: allocation, then end of file
    let r = setinfo(SETINFO_19);
    assert!(matches!(
        FileSet::decode(r.class, &r.buffer).unwrap(),
        Some(FileSet::Allocation(_))
    ));
    let r = setinfo(SETINFO_20);
    assert!(matches!(
        FileSet::decode(r.class, &r.buffer).unwrap(),
        Some(FileSet::EndOfFile(_))
    ));
    // attribute change with no times (all zero = leave unchanged)
    let r = setinfo(SETINFO_4);
    match FileSet::decode(r.class, &r.buffer).unwrap() {
        Some(FileSet::Basic {
            created,
            accessed,
            written,
            changed,
            attributes,
        }) => {
            assert_eq!((created, accessed, written, changed), (0, 0, 0, 0));
            assert_ne!(attributes, 0);
        }
        other => panic!("{other:?}"),
    }
}
