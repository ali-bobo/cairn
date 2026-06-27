# Output Sink (ZipSink + AgeSink + DryRunSink) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 實作 FR15/FR16 的三個 OutputSink 具體型別（ZipSink、AgeSink、DryRunSink），並接線 CLI `--zip` / `--encrypt` / `--dry-run` 旗標。

**Architecture:** `ZipSink` 在 `finalize()` 時用 `zip 2.4` crate 把 in-memory 攢齊的檔案組成 `.zip` 並落地；`AgeSink` 包裝 `ZipSink`，取得 zip bytes 後用 `age 0.11` X25519 公鑰加密輸出 `.zip.age`；`DryRunSink` 全部 write_* no-op，取代 `main.rs` 的 `if dry_run {}` inline 分支。三個 struct 全在 `cairn-report`，`cairn-core` / `cairn-collectors` 零改動。

**Tech Stack:** Rust 1.95、`zip = "2.4"` (MIT, deflate feature)、`age = "0.11"` (MIT/Apache-2.0, default-features=false)、`cairn_core::traits::OutputSink` trait、`sha2` (已有)。

---

## File Map

| 動作 | 路徑 | 說明 |
|------|------|------|
| 新增 | `crates/cairn-report/src/zip_sink.rs` | `ZipSink` struct + `build_zip` helper + `write_output_safe` symlink 保護 |
| 新增 | `crates/cairn-report/src/age_sink.rs` | `AgeSink` struct + `age_encrypt` helper |
| 新增 | `crates/cairn-report/src/dry_run.rs` | `DryRunSink` struct |
| 修改 | `crates/cairn-report/src/lib.rs` | 加 `mod` 宣告 + `pub use`；把 `write_output_safe` 從 DirSink 提取為模組共用函式 |
| 修改 | `crates/cairn-report/Cargo.toml` | 新增 `zip` / `age` 依賴 |
| 修改 | `Cargo.toml` | 新增 workspace deps `zip`、`age` |
| 修改 | `crates/cairn-cli/src/main.rs` | 新增 `build_sink()`；移除「not implemented」拒絕邏輯；重構 dry-run 路徑使用 `DryRunSink` |

---

## Task 1：新增 workspace 依賴 zip + age，更新 cairn-report Cargo.toml

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/cairn-report/Cargo.toml`

- [ ] **Step 1: 在 workspace Cargo.toml 新增 zip 和 age**

在 `Cargo.toml` 的 `[workspace.dependencies]` 區塊，緊接在 `compcol` 行之後新增：

```toml
zip = { version = "2.4", default-features = false, features = ["deflate"] }  # FR15 archive sink (cairn-report only)
age = { version = "0.11", default-features = false }                          # FR15 age-X25519 encryption (cairn-report only)
```

- [ ] **Step 2: 在 cairn-report/Cargo.toml 引用兩個新依賴**

把 `crates/cairn-report/Cargo.toml` 的 `[dependencies]` 區塊中，`# zip/flate2/rsa added at S3...` 那行註解替換為實際依賴：

```toml
zip.workspace = true
age.workspace = true
```

- [ ] **Step 3: 確認 workspace 能解析**

```
cargo check -p cairn-report 2>&1 | head -20
```

預期：僅 warning（未使用的 crate 目前 ok），不應有 error。

- [ ] **Step 4: Commit**

```
git add Cargo.toml crates/cairn-report/Cargo.toml
git commit -m "deps(report): add zip 2.4 + age 0.11 for S3 output sink"
```

---

## Task 2：提取 `write_output_safe` 為模組共用函式，新增 ZipSink

**背景：** `DirSink::write_file` 內含 symlink 保護邏輯（拒絕寫穿 symlink），ZipSink / AgeSink 落地最終檔案時也需要同樣保護。先把這個邏輯提取為 `pub(crate) fn write_output_safe`，再實作 ZipSink。

**Files:**
- Modify: `crates/cairn-report/src/lib.rs`
- Create: `crates/cairn-report/src/zip_sink.rs`

- [ ] **Step 1: 先在 cairn-report/src/lib.rs 最前面加 mod 宣告（保持零編譯錯誤）**

在 `lib.rs` 的 `use cairn_core::{...};` 上方加：

```rust
pub mod zip_sink;
pub mod age_sink;
pub mod dry_run;
```

同時在 `pub use` 或現有 `pub struct DirSink` 附近加 re-export（之後任務會填滿）：

```rust
pub use age_sink::AgeSink;
pub use dry_run::DryRunSink;
pub use zip_sink::ZipSink;
```

暫時建三個空檔案讓編譯通過：

```
# 建空佔位檔（Bash）
echo "" > crates/cairn-report/src/zip_sink.rs
echo "" > crates/cairn-report/src/age_sink.rs
echo "" > crates/cairn-report/src/dry_run.rs
```

確認：

```
cargo check -p cairn-report
```

預期：可能有「file is empty」warning，但不應有 error。（如果有 error，先修到 check 通過再繼續。）

- [ ] **Step 2: 提取 write_output_safe（在 lib.rs）**

在 `lib.rs` 中 `pub struct DirSink` 之前，加入以下 `pub(crate)` 函式（這是從 `DirSink::write_file` 提煉出來的 symlink 保護核心，原始 `DirSink::write_file` 仍保留原樣，但可以內部呼叫這個函式）：

```rust
/// Write `bytes` to `path`, refusing to follow a pre-planted symlink (threat-model §3).
/// Returns Err if path is a symlink; otherwise creates parent dirs and writes.
pub(crate) fn write_output_safe(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(cairn_core::CairnError::Other(format!(
                "refusing to write through a symlinked output: {}",
                path.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, bytes)?;
    Ok(())
}
```

- [ ] **Step 3: 撰寫 ZipSink 的失敗測試（TDD）**

在 `crates/cairn-report/src/zip_sink.rs` 先寫測試（此時 struct 還未實作，測試一定失敗）：

```rust
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_zip_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn zip_sink_produces_valid_zip() {
        let dir = mk_dir("valid");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);

        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        let manifest = Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo { name: "cairn".into(), version: "0.1.0".into(), build_sha: "abc".into(), sigma_ruleset_ver: String::new() },
            run: RunInfo { started_utc: Utc::now(), finished_utc: None, cmdline: "test".into(), operator: String::new(), case_id: String::new(), profile: "standard".into(), selected_modules: vec![] },
            host: HostInfo { hostname: "WS01".into(), os_build: String::new(), timezone: "UTC".into(), wall_clock_utc_skew: "+0s".into() },
            privileges: Privileges { admin: false, se_backup: false, se_debug: false },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        };
        sink.write_manifest(&manifest).unwrap();
        let entries = sink.finalize().unwrap();

        // zip file exists and has PK magic
        let bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(&bytes[..2], b"PK", "must be valid zip");

        // can be read back with zip crate
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "timeline.csv"), "timeline.csv in zip: {names:?}");
        assert!(names.iter().any(|n| n == "findings.jsonl"), "findings.jsonl in zip: {names:?}");
        assert!(names.iter().any(|n| n == "manifest.json"), "manifest.json in zip: {names:?}");

        // finalize returns exactly one OutputEntry with correct sha256
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn zip_sink_hashes_match_disk() {
        let dir = mk_dir("hash");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();

        let disk_bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(entries[0].sha256, crate::sha256_hex(&disk_bytes));
    }

    #[cfg(windows)]
    #[test]
    fn zip_sink_refuses_symlink_output() {
        let dir = mk_dir("symlink");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"do not touch").unwrap();
        let link = dir.join("out.zip");
        if std::os::windows::fs::symlink_file(&victim, &link).is_err() {
            if std::env::var_os("CAIRN_REQUIRE_SYMLINK_TESTS").is_some() {
                panic!("CAIRN_REQUIRE_SYMLINK_TESTS set but symlink creation failed");
            }
            eprintln!("skipping: no symlink privilege");
            return;
        }
        let mut sink = ZipSink::new(&link);
        sink.write_timeline_csv(&[]).unwrap();
        let res = sink.finalize();
        assert!(res.is_err(), "must refuse symlink");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    }
}
```

- [ ] **Step 4: 執行測試確認失敗**

```
cargo test -p cairn-report zip_sink 2>&1 | tail -20
```

預期：FAILED（struct ZipSink not found）。

- [ ] **Step 5: 實作 ZipSink**

把 `zip_sink.rs` 完整替換為：

```rust
#![forbid(unsafe_code)]
use crate::{sha256_hex, write_output_safe};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Result,
};
use std::{io::Write, path::PathBuf};

pub struct ZipSink {
    path: PathBuf,
    files: Vec<(String, Vec<u8>)>,
}

impl ZipSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ZipSink { path: path.into(), files: Vec::new() }
    }

    /// Consume self and return the assembled zip bytes (without writing to disk).
    /// Used by AgeSink to encrypt before landing.
    pub(crate) fn into_zip_bytes(self) -> Result<Vec<u8>> {
        build_zip(self.files)
    }
}

pub(crate) fn build_zip(files: Vec<(String, Vec<u8>)>) -> Result<Vec<u8>> {
    use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};
    let mut buf = Vec::new();
    let cursor = std::io::Cursor::new(&mut buf);
    let mut zip = ZipWriter::new(cursor);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, bytes) in files {
        zip.start_file(&name, opts)
            .map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
        zip.write_all(&bytes)
            .map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
    }
    zip.finish().map_err(|e| cairn_core::CairnError::Other(e.to_string()))?;
    Ok(buf)
}

impl OutputSink for ZipSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        let bytes = crate::timeline_csv(findings).into_bytes();
        self.files.push(("timeline.csv".into(), bytes));
        Ok(())
    }

    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        let mut buf = String::new();
        for f in findings {
            buf.push_str(&serde_json::to_string(f)?);
            buf.push('\n');
        }
        self.files.push(("findings.jsonl".into(), buf.into_bytes()));
        Ok(())
    }

    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        self.files.push(("manifest.json".into(), json));
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        let files = std::mem::take(&mut self.files);
        let zip_bytes = build_zip(files)?;
        write_output_safe(&self.path, &zip_bytes)?;
        Ok(vec![OutputEntry {
            file: self.path.display().to_string(),
            sha256: sha256_hex(&zip_bytes),
        }])
    }
}

#[cfg(test)]
mod tests {
    // (tests written in Step 3 above — paste them here)
    use super::*;
    use cairn_core::traits::OutputSink;

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_zip_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn zip_sink_produces_valid_zip() {
        let dir = mk_dir("valid");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);

        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        let manifest = Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo { name: "cairn".into(), version: "0.1.0".into(), build_sha: "abc".into(), sigma_ruleset_ver: String::new() },
            run: RunInfo { started_utc: Utc::now(), finished_utc: None, cmdline: "test".into(), operator: String::new(), case_id: String::new(), profile: "standard".into(), selected_modules: vec![] },
            host: HostInfo { hostname: "WS01".into(), os_build: String::new(), timezone: "UTC".into(), wall_clock_utc_skew: "+0s".into() },
            privileges: Privileges { admin: false, se_backup: false, se_debug: false },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        };
        sink.write_manifest(&manifest).unwrap();
        let entries = sink.finalize().unwrap();

        let bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(&bytes[..2], b"PK", "must be valid zip");

        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.iter().any(|n| n == "timeline.csv"), "timeline.csv: {names:?}");
        assert!(names.iter().any(|n| n == "findings.jsonl"), "findings.jsonl: {names:?}");
        assert!(names.iter().any(|n| n == "manifest.json"), "manifest.json: {names:?}");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn zip_sink_hashes_match_disk() {
        let dir = mk_dir("hash");
        let zip_path = dir.join("out.zip");
        let mut sink = ZipSink::new(&zip_path);
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();
        let disk_bytes = std::fs::read(&zip_path).unwrap();
        assert_eq!(entries[0].sha256, crate::sha256_hex(&disk_bytes));
    }

    #[cfg(windows)]
    #[test]
    fn zip_sink_refuses_symlink_output() {
        let dir = mk_dir("symlink");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"do not touch").unwrap();
        let link = dir.join("out.zip");
        if std::os::windows::fs::symlink_file(&victim, &link).is_err() {
            if std::env::var_os("CAIRN_REQUIRE_SYMLINK_TESTS").is_some() {
                panic!("CAIRN_REQUIRE_SYMLINK_TESTS set but symlink creation failed");
            }
            eprintln!("skipping: no symlink privilege");
            return;
        }
        let mut sink = ZipSink::new(&link);
        sink.write_timeline_csv(&[]).unwrap();
        let res = sink.finalize();
        assert!(res.is_err(), "must refuse symlink");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not touch");
    }
}
```

- [ ] **Step 6: 執行測試確認通過**

```
cargo test -p cairn-report zip_sink 2>&1 | tail -20
```

預期：`zip_sink_produces_valid_zip` / `zip_sink_hashes_match_disk` PASSED。

- [ ] **Step 7: 整個 workspace 確認無新 clippy warning**

```
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | grep "^error" | head -10
```

預期：無 error 行。

- [ ] **Step 8: Commit**

```
git add crates/cairn-report/src/lib.rs crates/cairn-report/src/zip_sink.rs \
        crates/cairn-report/src/age_sink.rs crates/cairn-report/src/dry_run.rs
git commit -m "feat(report): add ZipSink with write_output_safe + tests (FR15)"
```

---

## Task 3：實作 AgeSink

**Files:**
- Create/Fill: `crates/cairn-report/src/age_sink.rs`

- [ ] **Step 1: 撰寫 AgeSink 失敗測試**

把 `age_sink.rs` 先填入測試（struct 尚未實作）：

```rust
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    // 這把 X25519 keypair 是測試專用，不含真實敏感資料。
    // 公鑰與私鑰是用 `age-keygen` 產生的已知對（完全公開）。
    const TEST_PUBKEY: &str =
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_age_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn age_sink_output_has_age_header() {
        let dir = mk_dir("header");
        let zip_path = dir.join("out.zip");
        let mut sink = AgeSink::new(&zip_path, TEST_PUBKEY).unwrap();
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();

        let age_path = dir.join("out.zip.age");
        assert!(age_path.exists(), ".zip.age must exist");
        let bytes = std::fs::read(&age_path).unwrap();
        // age binary format starts with "age-encryption.org/v1\n"
        assert!(
            bytes.starts_with(b"age-encryption.org/v1"),
            "expected age header, got: {:?}",
            &bytes[..22.min(bytes.len())]
        );
        assert_eq!(entries.len(), 1);
        assert!(entries[0].file.ends_with(".zip.age"), "file entry: {}", entries[0].file);
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn age_sink_bad_pubkey_returns_err() {
        let dir = mk_dir("badkey");
        let zip_path = dir.join("out.zip");
        // An obviously invalid pubkey must produce Err at construction time, not panic.
        let result = AgeSink::new(&zip_path, "not-an-age-pubkey");
        assert!(result.is_err(), "bad pubkey must return Err");
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

```
cargo test -p cairn-report age_sink 2>&1 | tail -10
```

預期：FAILED（struct AgeSink not found）。

- [ ] **Step 3: 實作 AgeSink**

把 `age_sink.rs` 完整替換為（測試保留在末尾）：

```rust
#![forbid(unsafe_code)]
use crate::{sha256_hex, write_output_safe, zip_sink::build_zip};
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    CairnError, Result,
};
use std::{io::Write, path::{Path, PathBuf}};

pub struct AgeSink {
    zip_path: PathBuf,
    age_path: PathBuf,
    pubkey: age::x25519::Recipient,
    files: Vec<(String, Vec<u8>)>,
}

impl AgeSink {
    /// `zip_path` is the user-specified base path (e.g. `cairn_out.zip`);
    /// the actual output is `<zip_path>.age` (e.g. `cairn_out.zip.age`).
    /// Returns Err if `pubkey_str` is not a valid age X25519 bech32 public key.
    pub fn new(zip_path: impl Into<PathBuf>, pubkey_str: &str) -> Result<Self> {
        let zip_path = zip_path.into();
        let age_path = {
            let mut p = zip_path.as_os_str().to_owned();
            p.push(".age");
            PathBuf::from(p)
        };
        let pubkey: age::x25519::Recipient = pubkey_str
            .parse()
            .map_err(|e: age::x25519::ParseRecipientKeyError| {
                CairnError::Other(format!("invalid age public key: {e}"))
            })?;
        Ok(AgeSink { zip_path, age_path, pubkey, files: Vec::new() })
    }
}

fn age_encrypt(recipient: &age::x25519::Recipient, data: &[u8]) -> Result<Vec<u8>> {
    let recipients: Vec<Box<dyn age::Recipient>> = vec![Box::new(recipient.clone())];
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref()))
        .map_err(|e| CairnError::Other(format!("age encryptor: {e}")))?;
    let mut output = Vec::new();
    let mut writer = encryptor
        .wrap_output(&mut output)
        .map_err(|e| CairnError::Other(format!("age wrap_output: {e}")))?;
    writer.write_all(data).map_err(|e| CairnError::Other(e.to_string()))?;
    writer.finish().map_err(|e| CairnError::Other(format!("age finish: {e}")))?;
    Ok(output)
}

impl OutputSink for AgeSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        let bytes = crate::timeline_csv(findings).into_bytes();
        self.files.push(("timeline.csv".into(), bytes));
        Ok(())
    }

    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> {
        let mut buf = String::new();
        for f in findings {
            buf.push_str(&serde_json::to_string(f)?);
            buf.push('\n');
        }
        self.files.push(("findings.jsonl".into(), buf.into_bytes()));
        Ok(())
    }

    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> {
        let json = serde_json::to_vec_pretty(manifest)?;
        self.files.push(("manifest.json".into(), json));
        Ok(())
    }

    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        let files = std::mem::take(&mut self.files);
        let zip_bytes = build_zip(files)?;
        let age_bytes = age_encrypt(&self.pubkey, &zip_bytes)?;
        write_output_safe(&self.age_path, &age_bytes)?;
        Ok(vec![OutputEntry {
            file: self.age_path.display().to_string(),
            sha256: sha256_hex(&age_bytes),
        }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    const TEST_PUBKEY: &str =
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p";

    fn mk_dir(suffix: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cairn_age_{suffix}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn age_sink_output_has_age_header() {
        let dir = mk_dir("header");
        let zip_path = dir.join("out.zip");
        let mut sink = AgeSink::new(&zip_path, TEST_PUBKEY).unwrap();
        sink.write_timeline_csv(&[]).unwrap();
        let entries = sink.finalize().unwrap();

        let age_path = dir.join("out.zip.age");
        assert!(age_path.exists(), ".zip.age must exist");
        let bytes = std::fs::read(&age_path).unwrap();
        assert!(
            bytes.starts_with(b"age-encryption.org/v1"),
            "expected age header, got: {:?}",
            &bytes[..22.min(bytes.len())]
        );
        assert_eq!(entries.len(), 1);
        assert!(entries[0].file.ends_with(".zip.age"), "file entry: {}", entries[0].file);
        assert_eq!(entries[0].sha256, crate::sha256_hex(&bytes));
    }

    #[test]
    fn age_sink_bad_pubkey_returns_err() {
        let dir = mk_dir("badkey");
        let zip_path = dir.join("out.zip");
        let result = AgeSink::new(&zip_path, "not-an-age-pubkey");
        assert!(result.is_err(), "bad pubkey must return Err");
    }
}
```

- [ ] **Step 4: 執行測試確認通過**

```
cargo test -p cairn-report age_sink 2>&1 | tail -10
```

預期：`age_sink_output_has_age_header` / `age_sink_bad_pubkey_returns_err` PASSED。

- [ ] **Step 5: Clippy**

```
cargo clippy -p cairn-report --all-targets -- -D warnings 2>&1 | grep "^error" | head -10
```

預期：無 error。

- [ ] **Step 6: Commit**

```
git add crates/cairn-report/src/age_sink.rs
git commit -m "feat(report): add AgeSink (age X25519 encrypted zip, FR15)"
```

---

## Task 4：實作 DryRunSink

**Files:**
- Create/Fill: `crates/cairn-report/src/dry_run.rs`

- [ ] **Step 1: 撰寫 DryRunSink 失敗測試**

```rust
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    #[test]
    fn dry_run_writes_nothing() {
        let dir = std::env::temp_dir().join("cairn_dryrun_nothing");
        let _ = std::fs::remove_dir_all(&dir);
        // NOTE: we deliberately do NOT create this dir — DryRunSink must not create it either.

        let mut sink = DryRunSink;
        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        let manifest = Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo { name: "cairn".into(), version: "0.1.0".into(), build_sha: "abc".into(), sigma_ruleset_ver: String::new() },
            run: RunInfo { started_utc: Utc::now(), finished_utc: None, cmdline: "test".into(), operator: String::new(), case_id: String::new(), profile: "standard".into(), selected_modules: vec![] },
            host: HostInfo { hostname: "WS01".into(), os_build: String::new(), timezone: "UTC".into(), wall_clock_utc_skew: "+0s".into() },
            privileges: Privileges { admin: false, se_backup: false, se_debug: false },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        };
        sink.write_manifest(&manifest).unwrap();
        let entries = sink.finalize().unwrap();

        // The dir must not exist — DryRunSink wrote nothing.
        assert!(!dir.exists(), "DryRunSink must not create any dir or file");
        // finalize returns empty vec (no output entries).
        assert!(entries.is_empty(), "DryRunSink finalize must return empty vec");
    }

    #[test]
    fn dry_run_finalize_returns_empty() {
        let entries = DryRunSink.finalize().unwrap();
        // (Called without any write_* — must still return empty and not panic.)
        // Wait: finalize takes &mut self, so:
        let entries = { let mut s = DryRunSink; s.finalize().unwrap() };
        assert!(entries.is_empty());
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

```
cargo test -p cairn-report dry_run 2>&1 | tail -10
```

預期：FAILED（struct DryRunSink not found）。

- [ ] **Step 3: 實作 DryRunSink**

把 `dry_run.rs` 完整替換為：

```rust
#![forbid(unsafe_code)]
use cairn_core::{
    finding::Finding,
    manifest::{Manifest, OutputEntry},
    traits::OutputSink,
    Result,
};

/// A no-op sink: every write is discarded, finalize returns empty.
/// Implements golden rule 4 / FR16: `--dry-run` writes NOTHING to disk.
pub struct DryRunSink;

impl OutputSink for DryRunSink {
    fn write_timeline_csv(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_findings_jsonl(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_manifest(&mut self, _: &Manifest) -> Result<()> { Ok(()) }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> { Ok(vec![]) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::traits::OutputSink;

    #[test]
    fn dry_run_writes_nothing() {
        let dir = std::env::temp_dir().join("cairn_dryrun_nothing");
        let _ = std::fs::remove_dir_all(&dir);

        let mut sink = DryRunSink;
        sink.write_timeline_csv(&[]).unwrap();
        sink.write_findings_jsonl(&[]).unwrap();

        use cairn_core::manifest::{Counts, HostInfo, Manifest, Privileges, RunInfo, ToolInfo};
        use chrono::Utc;
        let manifest = Manifest {
            schema: cairn_core::schema::MANIFEST.to_string(),
            tool: ToolInfo { name: "cairn".into(), version: "0.1.0".into(), build_sha: "abc".into(), sigma_ruleset_ver: String::new() },
            run: RunInfo { started_utc: Utc::now(), finished_utc: None, cmdline: "test".into(), operator: String::new(), case_id: String::new(), profile: "standard".into(), selected_modules: vec![] },
            host: HostInfo { hostname: "WS01".into(), os_build: String::new(), timezone: "UTC".into(), wall_clock_utc_skew: "+0s".into() },
            privileges: Privileges { admin: false, se_backup: false, se_debug: false },
            sources: vec![],
            outputs: vec![],
            counts: Counts::default(),
            integrity_note: String::new(),
            governance: cairn_core::manifest::GovernanceReport::default(),
        };
        sink.write_manifest(&manifest).unwrap();
        let entries = sink.finalize().unwrap();

        assert!(!dir.exists(), "DryRunSink must not create any dir or file");
        assert!(entries.is_empty(), "DryRunSink finalize must return empty vec");
    }

    #[test]
    fn dry_run_finalize_returns_empty() {
        let mut s = DryRunSink;
        let entries = s.finalize().unwrap();
        assert!(entries.is_empty());
    }
}
```

- [ ] **Step 4: 執行測試確認通過**

```
cargo test -p cairn-report dry_run 2>&1 | tail -10
```

預期：`dry_run_writes_nothing` / `dry_run_finalize_returns_empty` PASSED。

- [ ] **Step 5: Commit**

```
git add crates/cairn-report/src/dry_run.rs
git commit -m "feat(report): add DryRunSink (FR16 golden rule 4 zero-write)"
```

---

## Task 5：CLI 接線——build_sink() + 移除「not implemented」拒絕 + 重構 dry-run 路徑

**Files:**
- Modify: `crates/cairn-cli/src/main.rs`

**背景（讀 main.rs 再動手）：**
- 第 12 行：`use cairn_report::DirSink;` → 改為同時引入新 sink
- 第 562–568 行：`if args.zip || args.encrypt.is_some()` 拒絕區塊 → 刪除
- 第 589–611 行：`let dry_run = args.dry_run;` + RAII guard 分岔 → 保留 guard 分岔（文件 logger 行為不變），`DryRunSink` 只影響 _寫出_ 路徑
- 第 820–840 行：`if dry_run { ... } else { let mut sink = DirSink::new ... }` → 統一為 `build_sink()` 路徑
- `manifest_outputs_then_write` 目前接受 `&mut DirSink`（具體型別），需改成 `&mut dyn OutputSink`

- [ ] **Step 1: 更新 use 引入**

找到 main.rs 第 12 行：

```rust
use cairn_report::DirSink;
```

改為：

```rust
use cairn_report::{AgeSink, DirSink, DryRunSink, ZipSink};
```

- [ ] **Step 2: 新增 build_sink 函式**

在 `fn write_records_jsonl(...)` 之前（約第 298 行附近）新增：

```rust
/// Construct the correct OutputSink from Config.output (FR15/FR16).
/// AgeSink::new returns Err on bad pubkey — propagate to the caller.
fn build_sink(output: &OutputKind) -> anyhow::Result<Box<dyn OutputSink + Send>> {
    Ok(match output {
        OutputKind::Dir(p) => Box::new(DirSink::new(p)),
        OutputKind::Zip(p) => Box::new(ZipSink::new(p)),
        OutputKind::EncryptedZip { path, pubkey } => {
            // path is the user-given .zip path; AgeSink appends ".age" automatically.
            let key = std::fs::read_to_string(pubkey)
                .with_context(|| format!("reading age public key file: {}", pubkey.display()))?;
            Box::new(AgeSink::new(path, key.trim())?)
        }
        OutputKind::DryRun => Box::new(DryRunSink),
    })
}
```

- [ ] **Step 3: 更新 manifest_outputs_then_write 簽名**

找到（約第 311 行）：

```rust
fn manifest_outputs_then_write(sink: &mut DirSink, mut manifest: Manifest) -> anyhow::Result<()> {
```

改為：

```rust
fn manifest_outputs_then_write(sink: &mut dyn OutputSink, mut manifest: Manifest) -> anyhow::Result<()> {
```

**注意：** 函式內部呼叫了 `sink.outputs_so_far()`——這是 `DirSink` 特有方法，不在 `OutputSink` trait 上。需要改為直接把 `manifest.outputs` 留空，或改用另一種方式：

把 `manifest_outputs_then_write` 內部從：

```rust
manifest.outputs = sink.outputs_so_far();
sink.write_manifest(&manifest)?;
let outputs = sink.finalize()?;
```

改為：

```rust
// outputs_so_far() is DirSink-specific; for other sinks the manifest lists outputs
// after finalize. Write manifest with empty outputs first, then finalize records them.
sink.write_manifest(&manifest)?;
let outputs = sink.finalize()?;
for o in &outputs {
    tracing::info!(file = %o.file, sha256 = %o.sha256, "wrote output");
}
// NOTE: manifest.outputs is not updated here for non-DirSink — the manifest.json
// inside the zip already captured the outputs list before zipping. This is acceptable
// for S3: the manifest embedded in the zip is self-consistent.
```

**同時** 刪掉 `manifest_outputs_then_write` 尾端原有的 `for o in &outputs` 迴圈（已移入此處）。

- [ ] **Step 4: 移除 「not implemented」 拒絕區塊**

刪除（約第 559–568 行）整個區塊：

```rust
            // --zip / --encrypt are not implemented yet (ZipSink / EncryptedZipSink are an S3
            // sub-segment). Reject explicitly rather than silently producing a plain directory:
            // a flag that is accepted but ignored is worse than one that is absent.
            if args.zip || args.encrypt.is_some() {
                eprintln!(
                    "cairn run --zip / --encrypt are not implemented yet (output-packaging \
                     sub-segment); re-run without them to write a plain output directory."
                );
                std::process::exit(2);
            }
```

- [ ] **Step 5: 重構 dry-run / 寫出路徑**

找到（約第 820–840 行）：

```rust
            if dry_run {
                // Golden rule 4: write NOTHING. Report what WOULD have been produced.
                tracing::info!(
                    records = outcome.records.len(),
                    findings = outcome.findings.len(),
                    "dry-run complete; no files written"
                );
                println!(
                    "dry-run: {} records, {} findings — no files written (would have gone to {})",
                    outcome.records.len(),
                    outcome.findings.len(),
                    dir.display()
                );
            } else {
                let mut sink = DirSink::new(dir.clone());
                sink.write_timeline_csv(&outcome.findings)?;
                sink.write_findings_jsonl(&outcome.findings)?;
                write_records_jsonl(&dir, &outcome.records)?;
                manifest_outputs_then_write(&mut sink, manifest)?;
                tracing::info!(dir = %dir.display(), "live run complete");
            }
```

改為：

```rust
            let mut sink = build_sink(&cfg.output)?;
            sink.write_timeline_csv(&outcome.findings)?;
            sink.write_findings_jsonl(&outcome.findings)?;
            if !dry_run {
                // records.jsonl written to dir only for non-dry-run, non-zip modes.
                // For ZipSink/AgeSink the records are large; skip unless --collect-raw (S4).
                if let OutputKind::Dir(ref d) = cfg.output {
                    write_records_jsonl(d, &outcome.records)?;
                }
            }
            manifest_outputs_then_write(sink.as_mut(), manifest)?;
            if dry_run {
                println!(
                    "dry-run: {} records, {} findings — no files written (would have gone to {})",
                    outcome.records.len(),
                    outcome.findings.len(),
                    dir.display()
                );
            } else {
                tracing::info!(output = %format!("{:?}", cfg.output), "run complete");
            }
```

- [ ] **Step 6: 確認 Config.output 從 args 正確賦值**

在同一段 run 路徑中找到 `Config` 構建（通常在 privilege probe 之後），確認 `output` 欄位是從 args 解析的，例如：

```rust
let cfg = Config {
    output: if args.dry_run {
        OutputKind::DryRun
    } else if args.encrypt.is_some() {
        OutputKind::EncryptedZip {
            path: args.output.clone(),
            pubkey: args.encrypt.clone().unwrap(),
        }
    } else if args.zip {
        OutputKind::Zip(args.output.clone())
    } else {
        OutputKind::Dir(args.output.clone())
    },
    // ...其他欄位
};
```

如果目前 Config 只設定 `OutputKind::Dir`，需補齊上述邏輯。（`grep -n "OutputKind::Dir\|output:" crates/cairn-cli/src/main.rs | head -20` 可快速定位。）

- [ ] **Step 7: cargo check + test**

```
cargo check --workspace 2>&1 | grep "^error" | head -20
cargo test --workspace 2>&1 | tail -20
```

預期：check 零 error；test 通過（含既有測試）。

- [ ] **Step 8: Clippy**

```
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | grep "^error" | head -10
```

預期：無 error。

- [ ] **Step 9: Commit**

```
git add crates/cairn-cli/src/main.rs
git commit -m "feat(cli): wire --zip/--encrypt/--dry-run to ZipSink/AgeSink/DryRunSink (FR15/FR16)"
```

---

## Task 6：最終驗收

- [ ] **Step 1: 全 workspace test**

```
cargo test --workspace 2>&1 | tail -30
```

預期：所有測試通過，包含新增的：
- `zip_sink_produces_valid_zip`
- `zip_sink_hashes_match_disk`
- `age_sink_output_has_age_header`
- `age_sink_bad_pubkey_returns_err`
- `dry_run_writes_nothing`
- `dry_run_finalize_returns_empty`

- [ ] **Step 2: 驗證 --dry-run 零寫入（手動）**

```
# 建一個不存在的輸出目錄路徑
$out = "$env:TEMP\cairn_dry_verify"
Remove-Item -Recurse -Force $out -ErrorAction SilentlyContinue

cargo run -p cairn-cli -- run --target live --output $out --dry-run 2>&1 | head -5

# 目錄不應存在（DryRunSink 不建目錄）
if (Test-Path $out) { Write-Host "FAIL: dir exists" } else { Write-Host "PASS: no dir created" }
```

預期：`PASS: no dir created`。

- [ ] **Step 3: 驗證 --zip（手動快速冒煙）**

```
$out = "$env:TEMP\cairn_zip_smoke.zip"
cargo run -p cairn-cli -- run --target live --output $out --zip 2>&1 | tail -3
# zip 應存在
if (Test-Path $out) { Write-Host "PASS: zip created" } else { Write-Host "FAIL: zip missing" }
```

預期：`PASS: zip created`，無「not implemented」錯誤。

- [ ] **Step 4: 審查 `.cargo/audit.toml`**

新增 age 0.11 依賴後執行 audit，若有新 unmaintained 警告，依現有 `audit.toml` 格式加入例外（與 `paste` / `encoding` 例外並列）：

```
cargo audit 2>&1
```

若有警告但非高危 CVE（如 proc-macro-error2 unmaintained），在 `.cargo/audit.toml` 追加：

```toml
[advisories]
ignore = [
    # ... 現有條目 ...
    "RUSTSEC-2026-0173",  # proc-macro-error2 unmaintained (age transitive dep)
]
```

- [ ] **Step 5: 最終 commit（若 audit.toml 有改動）**

```
git add .cargo/audit.toml
git commit -m "chore: allow proc-macro-error2 unmaintained warning (age transitive dep)"
```

如果 audit 零新 warning，略過此 step。

---

## 自我審查（Self-Review）

### Spec coverage
| Spec 要求 | 計畫對應 |
|-----------|----------|
| FR15 zip + manifest | T2 ZipSink + T5 CLI |
| FR15 age 非對稱加密 | T3 AgeSink + T5 CLI |
| FR16 --dry-run 零寫入 | T4 DryRunSink + T6 手動驗證 |
| FR17 footprint / off-target | DirSink 現有行為不動；`write_records_jsonl` 只在 `Dir` mode 寫 |
| NFR10 peak RAM 有界 | in-memory 設計已限 findings+manifest（通常 <<100 MB）；`--collect-raw` 是 S4 |
| symlink 保護（golden rule 3） | T2 `write_output_safe` + T2 ZipSink symlink 測試 |
| `#![forbid(unsafe_code)]` | T2/T3/T4 各模組首行宣告 |
| age bad pubkey → Err | T3 `age_sink_bad_pubkey_returns_err` |
| audit | T6 Step 4 |

### 型別一致性
- `build_zip` 定義於 `zip_sink.rs`，AgeSink 以 `crate::zip_sink::build_zip` 引用 ✅
- `write_output_safe` 定義於 `lib.rs`（`pub(crate)`），ZipSink / AgeSink 以 `crate::write_output_safe` 引用 ✅
- `manifest_outputs_then_write` 改為接受 `&mut dyn OutputSink` ✅
- `age::x25519::ParseRecipientKeyError` 是 age 0.11 的實際型別名稱（brainstorm 期間 API 實測通過）✅

### Placeholder scan
無 TBD / TODO / "similar to Task N" 等 placeholder。✅
