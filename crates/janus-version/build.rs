//! Records the commit and the target the binary is built for.
//!
//! The commit comes from git when the sources are a checkout; a source archive has no git, so
//! `JANUS_BUILD_ID` can set it (a release script, a packager) and the fallback is `unknown`.
//! Only `HEAD` is watched, so a commit rebuilds this crate but plain edits do not.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=JANUS_BUILD_ID");

    let id = std::env::var("JANUS_BUILD_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(git_commit)
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=JANUS_BUILD_ID={}", id.trim());

    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned());
    println!("cargo:rustc-env=JANUS_BUILD_TARGET={target}");

    // Rebuild when the checked-out commit changes (HEAD, or the branch ref it points to).
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let git_dir = root.join(".git");
    let head = git_dir.join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());
        if let Ok(text) = std::fs::read_to_string(&head)
            && let Some(r) = text.trim().strip_prefix("ref: ")
        {
            println!("cargo:rerun-if-changed={}", git_dir.join(r).display());
        }
    }
}

fn git_commit() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}
