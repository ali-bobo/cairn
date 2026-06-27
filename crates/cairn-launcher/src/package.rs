//! 把掃描結果目錄壓縮成 .zip，並開啟所在資料夾。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 把 `output_dir`（如 `.\output\20260627_143022\`）內的所有檔案
/// 壓縮成 `.\output\20260627_143022.zip`。
/// 回傳 zip 檔案的路徑。
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

    for entry in std::fs::read_dir(output_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            zip.start_file(&name, options)?;
            let content = std::fs::read(&path)?;
            zip.write_all(&content)?;
        }
    }
    zip.finish()?;
    Ok(zip_path)
}

/// Windows 上用 explorer.exe 開啟資料夾。
/// 非 Windows 環境下靜默跳過（單元測試環境）。
pub fn open_folder(path: &Path) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer.exe")
            .arg(path)
            .spawn();
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
        assert!(zip_path.metadata().unwrap().len() > 0, "zip should not be empty");
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
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"manifest.json".to_string()));
        assert!(names.contains(&"findings.jsonl".to_string()));
    }
}
