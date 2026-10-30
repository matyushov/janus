//! Which janus is this?
//!
//! Every binary and the C library answer from here, so they cannot disagree. The release version
//! is the workspace version (`Cargo.toml`, `[workspace.package]`): to release, change that one
//! line. The commit and the target are added by `build.rs`.

/// The release version, for example `0.1.0`. Semantic Versioning from 1.0.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit this was built from (eight hex digits), `unknown` outside a git checkout unless
/// `JANUS_BUILD_ID` was set when building.
pub const BUILD_ID: &str = env!("JANUS_BUILD_ID");

/// The target triple this was built for, for example `aarch64-apple-darwin`.
pub const TARGET: &str = env!("JANUS_BUILD_TARGET");

/// `janus-smbd 0.1.0 (a8d457e1, aarch64-apple-darwin)`: what `--version` prints.
pub fn long(program: &str) -> String {
    format!("{program} {VERSION} ({BUILD_ID}, {TARGET})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_a_semantic_version() {
        let core = VERSION.split(['-', '+']).next().unwrap();
        let parts: Vec<&str> = core.split('.').collect();
        assert_eq!(parts.len(), 3, "{VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()), "{VERSION}");
    }

    #[test]
    fn long_form_names_program_version_commit_and_target() {
        let s = long("janus-cli");
        assert!(s.starts_with(&format!("janus-cli {VERSION} (")), "{s}");
        assert!(s.contains(BUILD_ID) && s.contains(TARGET), "{s}");
        assert!(!BUILD_ID.is_empty() && !TARGET.is_empty());
    }
}
