# Output Sink 設計 — ZipSink + AgeSink + DryRunSink (FR15/FR16/FR17)

> 日期：2026-06-24  
> SRS 依據：FR15、FR16、FR17、NFR10、NFR11、golden rule 4  
> 權威 spec：`cairn-SRS.md`

---

## 背景與現況

`cairn-report` 已有 `DirSink`（寫檔案至目錄）實作 `OutputSink` trait。  
CLI 已定義 `--zip` / `--encrypt <pubkey>` / `--dry-run` 旗標與 `OutputKind` enum，  
但 `--zip`/`--encrypt` 目前明確拒絕（`main.rs:562`）。本段補齊 S3 的三個 sink。

---

## 範圍（本段做／不做）

**本段做：**
- `ZipSink`：in-memory 攢齊 → deflate zip → 單一 `.zip` 檔輸出（FR15）
- `AgeSink`：包裝 `ZipSink`，finalize 後 age-X25519 加密 → `.zip.age`（FR15）
- `DryRunSink`：全 write_* 皆 no-op，finalize 回傳空 vec（FR16）
- CLI `--zip` / `--encrypt` 接線移除「not implemented」拒絕邏輯
- 測試：各 sink 的 unit tests + `--dry-run` 零寫入驗證

**本段不做：**
- `--collect-raw`（打包完整 $MFT/$J，S4 議題）
- FR17 重新套用原始時間戳（staging 情境，S3+ 延後議題）
- NFR11 output 體積策略（預設不整包 raw，由 collector 選擇性填充，現有 `--profile minimal` 已做）

---

## 決策記錄

| 決策 | 選擇 | 理由 |
|------|------|------|
| 加密演算法 | age X25519 | Velociraptor 生態標準、純 Rust、MIT/Apache-2.0、`forbid-unsafe` 相容、解密端一行指令 |
| zip crate 版本 | `zip = "2.4"` | 最新穩定版（非 pre），MIT，rust-version 1.73 相容 cairn 1.95，`forbid-unsafe` 實證 |
| age crate 版本 | `age = "0.11"` | `default-features = false`（不引 CLI/SSH 功能），MIT/Apache-2.0，audit 零嚴重 CVE |
| Zip 記憶體策略 | in-memory 先攢再壓 | findings+manifest 通常幾百 KB，不爆 RAM；`--collect-raw` 是 S4 議題 |
| AgeSink 架構 | 包裝 ZipSink | AgeSink 只加一層：呼叫 ZipSink.finalize() 拿 zip bytes → age 加密 → 寫 `.zip.age` |
| DryRunSink 位置 | cairn-report 新 struct | 取代 main.rs 第 820 行 inline `if dry_run {}` 邏輯，讓 dry-run 走同一條 sink 路徑 |

---

## API 實證（brainstorm 期間驗證）

### age 0.11 X25519 加密
```rust
// with_recipients 接受 Iterator<Item = &dyn Recipient>
let recipients: Vec<Box<dyn age::Recipient>> = vec![Box::new(recipient)];
let encryptor = age::Encryptor::with_recipients(
    recipients.iter().map(|r| r.as_ref())
).unwrap();
let mut out = Vec::new();
let mut w = encryptor.wrap_output(&mut out).unwrap();
w.write_all(payload)?;
w.finish()?;
// 輸出開頭為 "age-encryption.org/v1" — 實測 271 bytes for 11-byte payload
```

### zip 2.4 ZipWriter（in-memory）
```rust
let mut buf = Vec::new();
{
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
    let opts = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("timeline.csv", opts)?;
    zip.write_all(csv_bytes)?;
    // ... 其他檔案
    zip.finish()?;
}
// buf 即完整 zip bytes；PK magic 已實測
```

---

## 架構與資料流

```
OutputKind::Dir(p)                  → DirSink          (現有，不動)
OutputKind::Zip(p)                  → ZipSink          (新)
OutputKind::EncryptedZip{path, key} → AgeSink          (新，包 ZipSink)
OutputKind::DryRun                  → DryRunSink       (新 struct，取代 inline)
```

三個 new struct 全放在 `cairn-report`，各一個子模組：
```
cairn-report/src/
  lib.rs          ← 現有 DirSink（零改動）
  zip_sink.rs     ← ZipSink
  age_sink.rs     ← AgeSink
  dry_run.rs      ← DryRunSink
```

### ZipSink

```rust
pub struct ZipSink {
    path: PathBuf,   // 輸出 .zip 路徑
    files: Vec<(String, Vec<u8>)>,  // (name, bytes) 暫存
}

impl ZipSink {
    pub fn new(path: impl Into<PathBuf>) -> Self { ... }
    /// 供 AgeSink 在 finalize 後拿走 zip bytes，不落地
    pub(crate) fn into_zip_bytes(self) -> Result<Vec<u8>> { ... }
}

impl OutputSink for ZipSink {
    fn write_timeline_csv(&mut self, findings: &[Finding]) -> Result<()> {
        // 攢 bytes，不寫檔
        self.files.push(("timeline.csv".into(), timeline_csv(findings).into_bytes()));
        Ok(())
    }
    fn write_findings_jsonl(&mut self, findings: &[Finding]) -> Result<()> { ... }
    fn write_manifest(&mut self, manifest: &Manifest) -> Result<()> { ... }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        // 組裝 zip bytes → 落地 self.path；回傳單一 OutputEntry
        let bytes = std::mem::take(&mut self.files);
        let zip_bytes = build_zip(bytes)?;     // 呼叫 zip crate
        write_output_safe(&self.path, &zip_bytes)?;  // 沿用 DirSink 的 symlink 保護邏輯
        Ok(vec![OutputEntry {
            file: self.path.display().to_string(),
            sha256: sha256_hex(&zip_bytes),
        }])
    }
}
```

### AgeSink

```rust
pub struct AgeSink {
    inner: ZipSink,   // 先讓 ZipSink 組 zip bytes
    zip_path: PathBuf,
    age_path: PathBuf,  // zip_path + ".age"
    pubkey: String,     // age bech32 公鑰字串
}

impl OutputSink for AgeSink {
    // write_* 全部轉發給 inner（ZipSink）
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> {
        // 1. 取 zip bytes：呼叫 into_zip_bytes()（不落地）
        //    ZipSink 內部 std::mem::take(&mut self.files) 再組 zip
        let inner = std::mem::replace(&mut self.inner, ZipSink::new(&self.zip_path));
        let zip_bytes = inner.into_zip_bytes()?;
        // 2. age 加密（only public key side — 永不接觸私鑰）
        let age_bytes = age_encrypt(&self.pubkey, &zip_bytes)?;
        // 3. 落地 .zip.age（symlink 保護同 DirSink）
        write_output_safe(&self.age_path, &age_bytes)?;
        Ok(vec![OutputEntry {
            file: self.age_path.display().to_string(),
            sha256: sha256_hex(&age_bytes),
        }])
    }
}
```

`age_encrypt(pubkey: &str, data: &[u8]) -> Result<Vec<u8>>`：
- 解析 `pubkey.parse::<age::x25519::Recipient>()`
- `age::Encryptor::with_recipients(...)` → `wrap_output(Cursor::new(&mut out))` → write+finish

### DryRunSink

```rust
pub struct DryRunSink;

impl OutputSink for DryRunSink {
    fn write_timeline_csv(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_findings_jsonl(&mut self, _: &[Finding]) -> Result<()> { Ok(()) }
    fn write_manifest(&mut self, _: &Manifest) -> Result<()> { Ok(()) }
    fn finalize(&mut self) -> Result<Vec<OutputEntry>> { Ok(vec![]) }
}
```

---

## CLI 接線

`main.rs` 的 `build_sink` 函式（新增，或 inline 在 run 路徑）：

```rust
fn build_sink(output: &OutputKind) -> Result<Box<dyn OutputSink>> {
    match output {
        OutputKind::Dir(p)  => Ok(Box::new(DirSink::new(p))),
        OutputKind::Zip(p)  => Ok(Box::new(ZipSink::new(p))),
        OutputKind::EncryptedZip { path, pubkey } => {
            // path 是 user 指定的 .zip 路徑；AgeSink 自動附加 ".age" 後綴
            // 實際輸出檔案為 <path>.age（如 cairn_out.zip.age）
            let key = std::fs::read_to_string(pubkey)?;
            Ok(Box::new(AgeSink::new(path, key.trim())))
        }
        OutputKind::DryRun  => Ok(Box::new(DryRunSink)),
    }
}
```

移除：
- `main.rs:562` 的 `if args.zip || args.encrypt.is_some()` 拒絕邏輯
- `main.rs:820` 的 `if dry_run { ... }` inline 分支（改由 DryRunSink 走同一路徑）

---

## 安全邊界（審查重點）

1. **只嵌公鑰**：`AgeSink` 接受 bech32 `age1...` 公鑰字串或路徑讀取，私鑰永不進 binary。`age` 加密 API 本身只接受 `Recipient`（公鑰側），無法誤傳私鑰。
2. **symlink 保護**：`write_output_safe` 複用 `DirSink.write_file` 的 symlink 拒絕邏輯，`.zip` 和 `.zip.age` 都受保護。
3. **dry-run 零寫入**（golden rule 4）：`DryRunSink` 的所有方法都 `Ok(())`，不呼叫任何 `std::fs::write`。測試需明確證明目標 dir 無任何 byte 變動（見測試策略）。
4. **公鑰格式驗證**：`pubkey.parse::<age::x25519::Recipient>()` 失敗時回傳 `CairnError::Other`，不靜默接受格式錯的公鑰。

---

## 測試策略

| 測試 | 驗證目標 |
|------|----------|
| `zip_sink_produces_valid_zip` | finalize 後 `.zip` 能被 `zip::ZipArchive` 讀回並解出正確內容 |
| `zip_sink_hashes_match` | finalize 回傳的 `OutputEntry.sha256` 等於磁碟 `.zip` 的 sha256 |
| `zip_sink_refuses_symlink` | 輸出路徑為 symlink 時回傳 Err（沿用 DirSink 保護邏輯） |
| `age_sink_output_has_age_header` | `.zip.age` 開頭為 `"age-encryption.org/v1"` |
| `age_sink_bad_pubkey_returns_err` | 格式錯誤的公鑰字串回傳 Err，不 panic |
| `dry_run_writes_nothing` | 呼叫全部 write_* + finalize 後，指定目錄下不存在任何檔案（FR16 零寫入） |
| `dry_run_finalize_returns_empty` | `finalize()` 回傳空 vec |

`dry_run_writes_nothing` 測試：在 temp dir 建一個 `DryRunSink`，走完完整 sink 流程，再用 `fs::read_dir` 斷言目錄為空（或目錄根本未被建立）。

---

## 新依賴

| crate | version | feature flags | license | forbid-unsafe |
|-------|---------|---------------|---------|---------------|
| `zip` | `"2.4"` | `default-features=false, features=["deflate"]` | MIT | 實測通過 |
| `age` | `"0.11"` | `default-features=false` | MIT/Apache-2.0 | 實測：audit 零嚴重 CVE（僅 proc-macro-error2 unmaintained 警告，與現有 cairn audit 一致） |

兩者加入 `cairn-report/Cargo.toml`。`cairn-core` / `cairn-collectors` 零新依賴。

---

## Cargo.toml 變動（僅 cairn-report）

```toml
[dependencies]
# 現有...
zip = { version = "2.4", default-features = false, features = ["deflate"] }
age = { version = "0.11", default-features = false }
```

`.cargo/audit.toml` 如需新增 age 相關例外，照現有 paste/encoding 例外格式補入。

---

## Definition of done

- `cargo check --workspace` 通過
- `cargo test --workspace` 通過（含上表全部新測試）
- `cargo clippy --workspace --all-targets -- -D warnings` 零 warning
- `--zip` / `--encrypt` CLI 旗標不再回傳「not implemented」錯誤
- `dry_run_writes_nothing` 測試明確斷言目標目錄無任何 byte 變動
- golden rule 4（dry-run 零寫入）、golden rule 3（collector 不修改 host）維持
- schema（Record/Finding/Manifest）零變動
- Cargo.lock 只新增 zip 2.4 + age 0.11 的依賴鏈
- `#![forbid(unsafe_code)]` 在 cairn-report 維持
