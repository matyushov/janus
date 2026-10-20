//! Generates the C header of the library with cbindgen:
//!
//!   cargo run -p janus-ffi --example gen_header -- <output.h>
//!
//! The header is a build artifact (CMake runs this command and installs the result); it is not
//! committed. Settings live in `cbindgen.toml`, the declarations in `src/lib.rs`.

use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: gen_header <output.h>"),
    );
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bindings = cbindgen::Builder::new()
        .with_crate(&dir)
        .with_config(cbindgen::Config::from_file(dir.join("cbindgen.toml")).expect("cbindgen.toml"))
        .generate()
        .expect("cbindgen failed");
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }
    // Write only on change so that CMake does not rebuild everything for nothing.
    let mut fresh = Vec::new();
    bindings.write(&mut fresh);
    if std::fs::read(&out).ok().as_deref() != Some(&fresh[..]) {
        std::fs::write(&out, fresh).expect("write header");
    }
}
