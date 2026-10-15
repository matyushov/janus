//! Contract revision 2: new operations and flags, and the guarantee that rev-1 requests
//! (new fields left at their defaults) behave as before.

use janus_proto::v1::{
    BundleOpRequest, CreateOp, DeleteOp, FileRef, RenameOp, SetTimesOp, StatOp, bundle_op_reply,
    bundle_op_request,
};
use janus_receiverd::testkit::TestServer;
use tonic::Code;

fn file(p: &str) -> Option<FileRef> {
    Some(FileRef { rel_path: p.into() })
}

async fn op(
    srv: &mut TestServer,
    op: bundle_op_request::Op,
) -> Result<bundle_op_reply::Result, tonic::Status> {
    Ok(srv
        .client
        .raw()
        .bundle_op(BundleOpRequest { op: Some(op) })
        .await?
        .into_inner()
        .result
        .expect("result"))
}

fn class(st: &tonic::Status) -> String {
    st.metadata()
        .get("janus-error")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default()
}

#[tokio::test]
async fn ping_reports_rev_2() {
    let mut srv = TestServer::start("rev2-ping", 0).await.unwrap();
    assert_eq!(srv.client.ping().await.unwrap().proto_rev, 2);
}

#[tokio::test]
async fn rev1_create_still_creates_parents_and_is_idempotent() {
    let mut srv = TestServer::start("rev2-compat-create", 0).await.unwrap();
    srv.client.create("a/b/c", true).await.unwrap();
    srv.client.create("a/b/c", true).await.unwrap(); // not exclusive: fine
    srv.client.create("x/y/file", false).await.unwrap();
    assert!(srv.store.exists("x/y/file"));
}

#[tokio::test]
async fn exclusive_directory_and_no_create_parents() {
    let mut srv = TestServer::start("rev2-create", 0).await.unwrap();
    let mk = |p: &str, exclusive, no_parents| {
        bundle_op_request::Op::Create(CreateOp {
            file: file(p),
            directory: true,
            exclusive,
            no_create_parents: no_parents,
        })
    };
    op(&mut srv, mk("d", true, true)).await.unwrap();
    let e = op(&mut srv, mk("d", true, true)).await.unwrap_err();
    assert_eq!(e.code(), Code::AlreadyExists);

    let e = op(&mut srv, mk("missing/d", true, true)).await.unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    assert_eq!(class(&e), "path-not-found");
    assert!(!srv.store.exists("missing"));

    // for files too
    let e = op(
        &mut srv,
        bundle_op_request::Op::Create(CreateOp {
            file: file("missing/f"),
            directory: false,
            exclusive: true,
            no_create_parents: true,
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(class(&e), "path-not-found");
}

#[tokio::test]
async fn non_recursive_delete_refuses_non_empty_directory() {
    let mut srv = TestServer::start("rev2-delete", 0).await.unwrap();
    srv.client.write("d/f", 0, b"x").await.unwrap();
    let del = |non_recursive| {
        bundle_op_request::Op::Delete(DeleteOp {
            file: file("d"),
            non_recursive,
        })
    };
    let e = op(&mut srv, del(true)).await.unwrap_err();
    assert_eq!(e.code(), Code::FailedPrecondition);
    assert_eq!(class(&e), "not-empty");
    assert!(srv.store.exists("d/f"));
    // rev-1 behaviour: recursive
    op(&mut srv, del(false)).await.unwrap();
    assert!(!srv.store.exists("d"));
}

#[tokio::test]
async fn rename_rules() {
    let mut srv = TestServer::start("rev2-rename", 0).await.unwrap();
    srv.client.write("a", 0, b"A").await.unwrap();
    srv.client.write("b", 0, b"B").await.unwrap();
    srv.client.create("dir", true).await.unwrap();
    let ren = |from: &str, to: &str, replace, no_parents| {
        bundle_op_request::Op::Rename(RenameOp {
            from: file(from),
            to: file(to),
            replace,
            no_create_parents: no_parents,
        })
    };
    let e = op(&mut srv, ren("a", "b", false, true)).await.unwrap_err();
    assert_eq!(e.code(), Code::AlreadyExists);
    let e = op(&mut srv, ren("a", "dir", true, true)).await.unwrap_err();
    assert_eq!(
        e.code(),
        Code::PermissionDenied,
        "a directory is never replaced"
    );
    let e = op(&mut srv, ren("nope", "z", false, true))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
    assert_eq!(class(&e), "");
    let e = op(&mut srv, ren("a", "no/z", false, true))
        .await
        .unwrap_err();
    assert_eq!(
        (e.code(), class(&e).as_str()),
        (Code::NotFound, "path-not-found")
    );
    op(&mut srv, ren("a", "b", true, true)).await.unwrap();
    assert_eq!(srv.store.read_file("b").unwrap(), b"A");
}

#[tokio::test]
async fn set_times_and_rich_stat() {
    let mut srv = TestServer::start("rev2-times", 0).await.unwrap();
    srv.client.write("f", 0, b"data").await.unwrap();
    srv.client.create("d", true).await.unwrap();
    let t = 1_600_000_000_000_000_000i64;
    op(
        &mut srv,
        bundle_op_request::Op::SetTimes(SetTimesOp {
            file: file("f"),
            atime_unix_ns: Some(t),
            mtime_unix_ns: Some(t + 1_000),
        }),
    )
    .await
    .unwrap();
    let st = srv.client.stat("f").await.unwrap();
    // 100 ns resolution on Windows; compare at microsecond granularity.
    assert_eq!(st.mtime_unix_ns / 1_000, (t + 1_000) / 1_000);
    assert_eq!(st.size, 4);

    // an unset time stays unchanged
    op(
        &mut srv,
        bundle_op_request::Op::SetTimes(SetTimesOp {
            file: file("f"),
            atime_unix_ns: None,
            mtime_unix_ns: Some(t + 5_000_000),
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        srv.client.stat("f").await.unwrap().mtime_unix_ns / 1_000,
        (t + 5_000_000) / 1_000
    );

    // directories: size 0, no error from set_times
    let d = srv.client.stat("d").await.unwrap();
    assert!(d.directory);
    assert_eq!(d.size, 0);
    #[cfg(unix)]
    assert!(st.file_id != 0 && st.ctime_unix_ns.is_some());
    op(
        &mut srv,
        bundle_op_request::Op::SetTimes(SetTimesOp {
            file: file("d"),
            atime_unix_ns: None,
            mtime_unix_ns: Some(t),
        }),
    )
    .await
    .unwrap();

    let e = op(
        &mut srv,
        bundle_op_request::Op::SetTimes(SetTimesOp {
            file: file("missing"),
            atime_unix_ns: None,
            mtime_unix_ns: Some(t),
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(e.code(), Code::NotFound);
}

#[tokio::test]
async fn stat_of_the_root_works_and_lists() {
    let mut srv = TestServer::start("rev2-root", 0).await.unwrap();
    let r = op(
        &mut srv,
        bundle_op_request::Op::Stat(StatOp { file: file("") }),
    )
    .await
    .unwrap();
    match r {
        bundle_op_reply::Result::Stat(s) => assert!(s.directory),
        other => panic!("{other:?}"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlinks_are_never_followed_or_listed() {
    let mut srv = TestServer::start("rev2-symlink", 0).await.unwrap();
    let outside = srv
        .store
        .path()
        .parent()
        .unwrap()
        .join("janus-outside-target");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret"), b"s").unwrap();
    std::os::unix::fs::symlink(&outside, srv.store.path().join("link")).unwrap();
    let e = srv.client.read("link/secret", 0, 10).await.unwrap_err();
    assert_eq!(e.code(), Code::PermissionDenied);
    assert!(srv.client.list("").await.unwrap().is_empty());
    std::fs::remove_dir_all(&outside).ok();
}

#[tokio::test]
async fn payload_limit_of_1_mib_is_enforced() {
    let mut srv = TestServer::start("rev2-limit", 0).await.unwrap();
    srv.client.write("f", 0, &vec![1u8; 1 << 20]).await.unwrap();
    let e = srv
        .client
        .write("f", 0, &vec![1u8; (1 << 20) + 1])
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    assert_eq!(
        srv.client.read("f", 0, 1 << 20).await.unwrap().len(),
        1 << 20
    );
    let e = srv.client.read("f", 0, (1 << 20) + 1).await.unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
}
