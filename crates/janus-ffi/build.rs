//! Link settings of the shared library: a relocatable install name and only `janus_*` exported.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=exports.txt");
    match os.as_str() {
        "macos" => {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libjanus.dylib");
            println!("cargo:rustc-cdylib-link-arg=-Wl,-exported_symbols_list,{dir}/exports.txt");
        }
        "linux" => {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libjanus.so");
            println!("cargo:rerun-if-changed=exports.map");
            println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={dir}/exports.map");
        }
        _ => {}
    }
}
