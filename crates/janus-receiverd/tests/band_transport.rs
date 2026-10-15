//! Integration tests of the receiving side.
//!
//! Model: a **real** `janus-receiverd` (not a mock) is started on an ephemeral
//! port in a temporary store; a **mock client** sends commands over gRPC; the result
//! is compared with the files on disk. The temporary store is removed automatically
//! (`TempStore::drop`), including when the test panics.

use janus_receiverd::testkit::TestServer;

#[tokio::test]
async fn ping_returns_server_version() {
    let mut srv = TestServer::start("ping", 0).await.expect("server up");
    let reply = srv.client.ping().await.expect("ping ok");
    assert!(!reply.server_version.is_empty());
    assert_eq!(reply.proto_rev, 1);
}

#[tokio::test]
async fn write_lands_on_disk_and_reads_back() {
    let mut srv = TestServer::start("write", 0).await.expect("server up");

    srv.client
        .write("bands/1a", 0, b"hello ")
        .await
        .expect("write 1");
    srv.client
        .write("bands/1a", 6, b"world")
        .await
        .expect("write 2");

    // verification via gRPC
    let got = srv.client.read("bands/1a", 0, 64).await.expect("read");
    assert_eq!(&got, b"hello world");

    // verification DIRECTLY against the file in the store proves that the data really landed
    let on_disk = srv.store.read_file("bands/1a").expect("file exists");
    assert_eq!(&on_disk, b"hello world");
}

#[tokio::test]
async fn write_is_idempotent_on_retry() {
    let mut srv = TestServer::start("idem", 0).await.expect("server up");
    for _ in 0..3 {
        srv.client
            .write("bands/2", 4, b"abcd")
            .await
            .expect("write retry");
    }
    let on_disk = srv.store.read_file("bands/2").expect("file");
    assert_eq!(on_disk.len(), 8, "офсетная запись не должна дублироваться");
    assert_eq!(&on_disk[4..], b"abcd");
}

#[tokio::test]
async fn read_past_eof_is_short_read() {
    let mut srv = TestServer::start("eof", 0).await.expect("server up");
    srv.client.write("f", 0, b"12345").await.expect("write");
    let got = srv.client.read("f", 3, 100).await.expect("read");
    assert_eq!(&got, b"45");
    let empty = srv.client.read("f", 99, 10).await.expect("read past eof");
    assert!(empty.is_empty());
}

#[tokio::test]
async fn fsync_file_and_all_succeed() {
    let mut srv = TestServer::start("fsync", 0).await.expect("server up");
    srv.client.write("f", 0, b"data").await.expect("write");
    srv.client.fsync_file("f").await.expect("fsync file");
    srv.client.fsync_all().await.expect("fsync all");
}

#[tokio::test]
async fn statfs_reports_quota_and_usage() {
    let mut srv = TestServer::start("statfs", 1024).await.expect("server up");
    srv.client.write("a", 0, &[0u8; 100]).await.expect("write");
    let st = srv.client.statfs().await.expect("statfs");
    assert_eq!(st.quota_bytes, 1024);
    assert_eq!(st.used_bytes, 100);
}

#[tokio::test]
async fn quota_exceeded_is_reported() {
    let mut srv = TestServer::start("quota", 64).await.expect("server up");
    srv.client.write("a", 0, &[1u8; 60]).await.expect("fits");
    let err = srv
        .client
        .write("b", 0, &[1u8; 60])
        .await
        .expect_err("must exceed quota");
    assert_eq!(err.code(), tonic::Code::ResourceExhausted);
}

#[tokio::test]
async fn bundle_ops_create_list_stat_rename_truncate_delete() {
    let mut srv = TestServer::start("bundle", 0).await.expect("server up");

    srv.client.create("bands", true).await.expect("mkdir");
    srv.client.write("bands/1", 0, b"12345").await.expect("w1");
    srv.client.write("bands/2", 0, b"123").await.expect("w2");

    let listing = srv.client.list("bands").await.expect("list");
    assert_eq!(listing.len(), 2);
    assert!(listing.iter().all(|e| !e.directory));

    let st = srv.client.stat("bands/1").await.expect("stat");
    assert_eq!(st.size, 5);

    srv.client
        .rename("bands/1", "bands/renamed", false)
        .await
        .expect("rename");
    assert!(srv.store.exists("bands/renamed"));
    assert!(!srv.store.exists("bands/1"));

    srv.client
        .truncate("bands/renamed", 2)
        .await
        .expect("trunc");
    assert_eq!(srv.store.read_file("bands/renamed").unwrap(), b"12");

    srv.client.delete("bands/renamed").await.expect("delete");
    assert!(!srv.store.exists("bands/renamed"));
}

#[tokio::test]
async fn path_traversal_is_rejected_over_grpc() {
    let mut srv = TestServer::start("traversal", 0).await.expect("server up");
    for bad in ["../escape", "/abs", "a/../../b"] {
        let err = srv
            .client
            .write(bad, 0, b"x")
            .await
            .expect_err("должно быть отклонено");
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "путь {bad} должен отбиваться"
        );
    }
    // and nothing was created outside the store
    assert!(!srv.store.path().parent().unwrap().join("escape").exists());
}

#[tokio::test]
async fn temp_store_is_removed_on_drop() {
    let path = {
        let srv = TestServer::start("cleanup", 0).await.expect("server up");
        let p = srv.store.path().to_path_buf();
        assert!(p.exists(), "store существует пока живёт сервер");
        p
    };
    // after TestServer (and TempStore) is dropped the directory must disappear
    assert!(!path.exists(), "временный store должен удаляться при drop");
}
