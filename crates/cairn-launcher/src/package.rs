//! 把掃描結果目錄壓縮成 .zip，並開啟所在資料夾。

use std::path::{Path, PathBuf};

/// 把 `output_dir`（如 `.\output\20260627_143022\`）內的所有檔案（含子資料夾，
/// 例如 `evidence\evtx\`）壓縮成 `.\output\20260627_143022.zip`，並在旁邊寫一個
/// `.zip.sha256`（壓縮檔本身的 SHA-256，可交給資安人員核對）。
/// zip 內的路徑與 manifest.json 的 outputs 一致（`/` 分隔），解壓後可直接
/// `cairn verify manifest.json`。回傳 zip 檔案的路徑。
pub fn zip_output(output_dir: &Path) -> anyhow::Result<PathBuf> {
    let dir_name = output_dir
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("output_dir has no file name"))?
        .to_string_lossy()
        .into_owned();
    let zip_path = output_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("output_dir has no parent"))?
        .join(format!("{dir_name}.zip"));

    let file = std::fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::<()>::default()
        .compression_method(zip::CompressionMethod::Deflated);

    let mut files = Vec::new();
    collect_files(output_dir, "", &mut files)?;
    files.sort();
    for (name, path) in files {
        zip.start_file(&name, options)?;
        std::io::copy(&mut std::fs::File::open(&path)?, &mut zip)?;
    }
    zip.finish()?;

    let digest = sha256_file(&zip_path)?;
    let mut sidecar = zip_path.as_os_str().to_os_string();
    sidecar.push(".sha256");
    std::fs::write(
        PathBuf::from(sidecar),
        format!("{digest}  {dir_name}.zip\n"),
    )?;
    Ok(zip_path)
}

/// Every regular file under `dir`, as (`/`-separated name relative to the root, path).
/// Symlinks are not followed.
fn collect_files(
    dir: &Path,
    prefix: &str,
    out: &mut Vec<(String, PathBuf)>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
        if ft.is_dir() {
            collect_files(&entry.path(), &format!("{name}/"), out)?;
        } else if ft.is_file() {
            out.push((name, entry.path()));
        }
    }
    Ok(())
}

/// Streaming SHA-256 hex of a file.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Windows 上用 explorer.exe 開啟資料夾，或以預設程式開啟檔案（report.html →
/// 預設瀏覽器）。非 Windows 環境下靜默跳過（單元測試環境）。
pub fn open_path(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer.exe").arg(path).spawn();
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zip_output_creates_zip_file() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("20260627_143022");
        std::fs::create_dir(&output_dir).unwrap();
        std::fs::write(output_dir.join("manifest.json"), b"{}").unwrap();
        std::fs::write(output_dir.join("findings.jsonl"), b"").unwrap();

        let zip_path = zip_output(&output_dir).unwrap();
        assert!(zip_path.exists(), "zip file should exist");
        assert!(
            zip_path.metadata().unwrap().len() > 0,
            "zip should not be empty"
        );
        assert_eq!(zip_path.extension().unwrap(), "zip");
    }

    #[test]
    fn zip_output_contains_expected_files() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("20260627_143022");
        std::fs::create_dir(&output_dir).unwrap();
        std::fs::write(output_dir.join("manifest.json"), b"test-manifest").unwrap();
        std::fs::write(output_dir.join("findings.jsonl"), b"test-findings").unwrap();

        let zip_path = zip_output(&output_dir).unwrap();
        let file = std::fs::File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().unwrap().to_string())
            .collect();
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"findings.jsonl".to_string()));
    }

    #[test]
    fn zip_output_includes_subdirs_and_writes_sidecar() {
        let parent = tempfile::TempDir::new().unwrap();
        let output_dir = parent.path().join("20260627_143022");
        std::fs::create_dir_all(output_dir.join("evidence").join("evtx")).unwrap();
        std::fs::write(output_dir.join("manifest.json"), b"{}").unwrap();
        std::fs::write(
            output_dir
                .join("evidence")
                .join("evtx")
                .join("Security.evtx"),
            b"ElfFile",
        )
        .unwrap();
        let zip_path = zip_output(&output_dir).unwrap();
        let mut archive = zip::ZipArchive::new(std::fs::File::open(&zip_path).unwrap()).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().unwrap().to_string())
            .collect();
        assert!(
            names.contains(&"evidence/evtx/Security.evtx".to_string()),
            "{names:?}"
        );
        let sidecar = parent.path().join("20260627_143022.zip.sha256");
        let text = std::fs::read_to_string(sidecar).unwrap();
        assert_eq!(
            text,
            format!("{}  20260627_143022.zip\n", sha256_file(&zip_path).unwrap())
        );
    }
}
