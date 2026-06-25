# bodyfile/plaso Export (FR20) Design

**Goal:** Export `FileMetaRecord` + `UsnEventRecord` entries as mactime bodyfile format
so investigators can ingest Cairn's NTFS timeline into Autopsy, log2timeline/plaso, or
mactime.

**Architecture:** Pure function `write_bodyfile(records, writer)` in a new
`cairn-report/src/bodyfile.rs` module. The CLI adds `--bodyfile <path>` to `RunArgs`
and writes the file **after** the main sink finishes (separate, additive output).
No new crate dependencies. No schema changes.

**Tech Stack:** Pure Rust `std::fmt::Write` / `std::io::Write`; `chrono` (already in
scope); no new dependencies.

---

## mactime Bodyfile Format (SRS §7, FR20)

One line per record:

```
MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
```

- `MD5`    — fill `0` (no hash available at report time)
- `name`   — full path string from record (`path` field)
- `inode`  — fill `0` (MFT ref not exposed in `FileMetaRecord` at this level)
- `mode`   — fill `0`
- `UID`    — fill `0`
- `GID`    — fill `0`
- `size`   — `FileMetaRecord.size`; `0` for `UsnEventRecord`
- `atime`  — `si_mtime` as Unix timestamp (seconds); `0` if None (FileMetaRecord has no
             explicit atime; closest is si_mtime — see Mapping section below)
- `mtime`  — `si_mtime` as Unix timestamp; `0` if None
- `ctime`  — `fn_mtime` as Unix timestamp; `0` if None
- `crtime` — `si_btime` as Unix timestamp; `0` if None

For `UsnEventRecord`: `ts` → mtime; all others `0`.

---

## MACB → bodyfile column mapping

| bodyfile column | FileMetaRecord source | UsnEventRecord source |
|---|---|---|
| atime | `si_mtime` (proxy; no separate atime) | `0` |
| mtime | `si_mtime` | `ts` |
| ctime | `fn_mtime` | `0` |
| crtime | `si_btime` | `0` |

Rationale: SRS only records SI (Standard Information) mtime + btime and FN (File Name)
mtime + btime. There is no separate atime in the schema. Using `si_mtime` as proxy for
atime is standard in NTFS-targeted bodyfile exports (Autopsy does the same).

---

## Module: `cairn-report/src/bodyfile.rs`

```rust
#![forbid(unsafe_code)]

pub fn write_bodyfile<W: std::io::Write>(records: &[cairn_core::Record], mut w: W)
    -> cairn_core::Result<()>
```

Iterates all records; emits a line only for `Record::FileMeta` and `Record::UsnEvent`.
All other variants are silently skipped (they carry no MACB data).

Helper: `fn ts_unix(dt: Option<DateTime<Utc>>) -> i64` → `dt.map(|d| d.timestamp()).unwrap_or(0)`

---

## CLI integration

`RunArgs` gains one optional field:

```rust
/// Write mactime bodyfile to <PATH> (FR20). Off by default.
#[arg(long)]
bodyfile: Option<PathBuf>,
```

In **both** run paths (evtx and live), after `sink.finalize()`:

```rust
if let Some(bf_path) = &args.bodyfile {
    let f = std::fs::File::create(bf_path)?;
    cairn_report::bodyfile::write_bodyfile(&records, f)?;
    tracing::info!(path = %bf_path.display(), "bodyfile written");
}
```

`--dry-run` constraint: bodyfile write must be skipped when `dry_run` is true (golden
rule 4 — writes nothing).

---

## Tests (`cairn-report/src/bodyfile.rs`, `#[cfg(test)]`)

| Test | Asserts |
|---|---|
| `filemeta_line_format` | A `FileMetaRecord` produces exactly one `\|`-delimited line with 11 fields; mtime column = si_mtime.timestamp() |
| `usn_line_format` | A `UsnEventRecord` produces one line; mtime = ts.timestamp(), crtime = 0 |
| `non_filemeta_records_skipped` | `Record::Event` / `Record::Process` produce zero lines |
| `none_timestamps_become_zero` | `FileMetaRecord` with all-None MACB fields → all time columns are `0` |
| `size_field` | `FileMetaRecord.size = 12345` → size column is `12345` |

---

## Acceptance Gate

- `cargo test --workspace` passes (all new tests green).
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Manual: `cairn run --target live --output /tmp/out --bodyfile /tmp/body.txt` →
  `/tmp/body.txt` exists and each line has exactly 11 `|`-separated fields.
- `--dry-run` with `--bodyfile` → bodyfile NOT written.
