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

    let build_sha = sha.as_deref().unwrap_or("unknown").to_string();
    println!("cargo:rustc-env=CAIRN_BUILD_SHA={build_sha}");

    embed_windows_version_resource(&build_sha);
}

/// On Windows, embed a PE version-info resource so the binary self-identifies in file
/// properties and to EDR/SOC tooling (legitimacy, SRS §13): a clear product name and a
/// FileDescription that states the benign, authorized-DFIR intent. This is the opposite
/// of a malware tell — the tool WANTS to be recognized. No-op on non-Windows targets.
#[cfg(windows)]
fn embed_windows_version_resource(build_sha: &str) {
    use winresource::WindowsResource;

    let version = env!("CARGO_PKG_VERSION");
    let mut res = WindowsResource::new();
    res.set("ProductName", "Cairn")
        .set(
            "FileDescription",
            "Cairn — authorized Windows live-forensics triage (DFIR)",
        )
        .set("CompanyName", "Cairn project")
        .set("LegalCopyright", "Apache-2.0 licensed; open source")
        .set("OriginalFilename", "cairn.exe")
        .set("InternalName", "cairn")
        .set("ProductVersion", &format!("{version} ({build_sha})"))
        .set("FileVersion", version)
        // Marker so a SOC inspecting properties sees the build commit too.
        .set(
            "Comments",
            &format!("build {build_sha}; see README intent statement"),
        );
    if let Err(e) = res.compile() {
        // Don't fail the build over resource embedding; log and continue (the binary is
        // still valid, just without the metadata). A signed release should verify it.
        println!("cargo:warning=winresource embed failed: {e}");
    }
}

/// Non-Windows builds carry no PE resource; nothing to embed.
#[cfg(not(windows))]
fn embed_windows_version_resource(_build_sha: &str) {}
