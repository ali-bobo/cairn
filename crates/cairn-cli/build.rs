//! Build script: stamp the git commit into the binary as `CAIRN_BUILD_SHA`.
//!
//! The CLI embeds this via `env!("CAIRN_BUILD_SHA")` and records it in the run
//! manifest (`tool.build_sha`, SRS §5.3 / §13 legitimacy). We read the short SHA
//! from git when available; when building outside a git checkout (e.g. from a
//! packaged source tarball) we fall back to "unknown" rather than failing the build.
//! A `CAIRN_BUILD_SHA` already set in the environment wins, so CI/reproducible
//! builds can inject an exact value.

use std::process::Command;

fn main() {
    // Rebuild if HEAD moves, so the stamped SHA stays accurate.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-env-changed=CAIRN_BUILD_SHA");

    let sha = std::env::var("CAIRN_BUILD_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    println!(
        "cargo:rustc-env=CAIRN_BUILD_SHA={}",
        sha.as_deref().unwrap_or("unknown")
    );
}
