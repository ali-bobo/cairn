//! Build script: on Windows, embed the launcher's PE version info and an application
//! manifest that asks for `highestAvailable`. An administrator who double-clicks the
//! launcher gets the normal UAC prompt, so the scan runs elevated and the raw-volume,
//! per-user-hive and Security-log collectors are not skipped; a standard user is not
//! blocked and gets a degraded scan (graceful degrade, golden rule 8). Asking for
//! elevation through the manifest is the documented, visible way to do it, so the
//! EDR and the user both see the request. No-op on non-Windows targets.

fn main() {
    embed_windows_resources();
}

#[cfg(windows)]
fn embed_windows_resources() {
    use winresource::WindowsResource;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="highestAvailable" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
"#;

    let version = env!("CARGO_PKG_VERSION");
    let mut res = WindowsResource::new();
    res.set("ProductName", "Cairn")
        .set(
            "FileDescription",
            "Cairn launcher — double-click to run an authorized Windows triage scan",
        )
        .set("CompanyName", "Cairn project")
        .set("LegalCopyright", "MIT licensed; open source")
        .set("OriginalFilename", "cairn-launcher.exe")
        .set("InternalName", "cairn-launcher")
        .set("ProductVersion", version)
        .set("FileVersion", version)
        .set_manifest(MANIFEST);
    if let Err(e) = res.compile() {
        // Don't fail the build over resource embedding; the launcher still works, it
        // just won't prompt for elevation.
        println!("cargo:warning=winresource embed failed: {e}");
    }
}

#[cfg(not(windows))]
fn embed_windows_resources() {}
