//! Contract code generation: proto/janus.proto → Rust (prost types + tonic services)
//! in OUT_DIR. `protoc` comes from the vendored crate so that the build is
//! self-contained (no system protoc required on dev/CI machines).

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Point tonic-build at the vendored protoc.
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // SAFETY: the only point, before the build threads start.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["proto/janus.proto"], &["proto"])?;

    println!("cargo:rerun-if-changed=proto/janus.proto");
    Ok(())
}
