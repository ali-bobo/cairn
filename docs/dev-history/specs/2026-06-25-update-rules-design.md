# update-rules (FR19) Design

**Goal:** Implement `cairn update-rules [--pin <sha>]` — fetch a pinned SigmaHQ rule
subset over HTTPS, DRL 1.1 validate each file, XOR-encode, write to `rules/sigma/`,
and update `rules/sigma/PROVENANCE`.

**Architecture:** New crate `cairn-updater` (pure Rust, `#![forbid(unsafe_code)]`)
containing the fetch + validate + encode + write logic. `cairn-cli` depends on it via
an optional Cargo feature `updater` (default-on). The `UpdateRules` CLI handler
(currently `TODO S4`) calls `cairn_updater::run(pin, rules_dir)`. The rule subset
(relative SigmaHQ paths) and current pin live in `rules/ruleset.toml`; `--pin`
overrides the pin at runtime without editing the toml.

**Tech Stack:**
- `reqwest 0.13` with `features = ["blocking", "rustls-tls-native-roots"]` — sync HTTP
  client, rustls (no OpenSSL link hassle on Windows), native root CA bundle.
- Existing `cairn_sigma::codec::xor` — XOR encode bytes (public, already in scope).
- Existing `cairn_sigma::ruleset::aggregate_hash` — verify post-write integrity.
- `toml` crate for parsing `ruleset.toml`.

---

## Security Design (OWASP / global CLAUDE.md)

### SSRF whitelist
Every fetch URL is constructed as:
```
https://raw.githubusercontent.com/SigmaHQ/sigma/{pin}/rules/{rule_path}
```
The `pin` is a 40-hex SHA1 (validated with regex `^[0-9a-f]{40}$`).
The `rule_path` comes exclusively from `ruleset.toml` (operator-controlled config,
not user input). The base URL prefix is hardcoded: any URL that does not start with
`https://raw.githubusercontent.com/SigmaHQ/sigma/` is rejected before the request.

### DRL 1.1 validation
Each fetched `.yml` must contain a line starting with `author:`. If absent → abort
the whole update (not partial), report which file failed.

### No shell execution
No `subprocess` / `Command` spawning. All logic in pure Rust.

### Supply-chain integrity
After writing, recompute `aggregate_hash` over the written files and log it. The
`PROVENANCE` pin is always written as the validated 40-hex SHA1.

---

## `ruleset.toml` Format

Lives at `rules/ruleset.toml` (committed, operator-editable to add rules):

```toml
[sigma]
pin = "98781da19cf60c48ce6e7f2d3ad11c9ba389191a"

[[rules]]
path = "windows/process_creation/proc_creation_win_hh_chm_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_msxsl_execution.yml"

[[rules]]
path = "windows/process_creation/proc_creation_win_mshta_susp_execution.yml"
```

`cairn update-rules --pin <new-sha>` overrides the pin at runtime; the toml's `pin`
value is NOT rewritten (immutable config; operator updates it manually or via VCS).

---

## New Crate: `cairn-updater`

```
crates/cairn-updater/
  Cargo.toml
  src/
    lib.rs       — public API: run(pin, rules_dir, ruleset_toml)
    fetch.rs     — SSRF-gated HTTPS fetch, DRL 1.1 check
    encode.rs    — XOR encode + write rules/sigma/ + write PROVENANCE
    config.rs    — parse ruleset.toml into RulesetConfig struct
```

### Public API

```rust
pub fn run(
    pin_override: Option<&str>,   // from --pin CLI arg
    rules_dir: &Path,             // path to rules/sigma/
    ruleset_toml: &Path,          // path to rules/ruleset.toml
) -> cairn_core::Result<()>
```

### `config.rs` — `RulesetConfig`

```rust
#[derive(serde::Deserialize)]
pub struct RulesetConfig {
    pub sigma: SigmaSection,
    pub rules: Vec<RuleEntry>,
}

#[derive(serde::Deserialize)]
pub struct SigmaSection {
    pub pin: String,
}

#[derive(serde::Deserialize)]
pub struct RuleEntry {
    pub path: String,
}
```

### `fetch.rs` — `fetch_rule`

```rust
const BASE: &str = "https://raw.githubusercontent.com/SigmaHQ/sigma/";

fn validate_pin(pin: &str) -> cairn_core::Result<()>
fn build_url(pin: &str, rule_path: &str) -> cairn_core::Result<String>
pub fn fetch_rule(pin: &str, rule_path: &str) -> cairn_core::Result<Vec<u8>>
```

- `validate_pin`: regex `^[0-9a-f]{40}$` → `CairnError::Other` if invalid
- `build_url`: constructs URL, asserts it starts with `BASE`
- `fetch_rule`: calls `reqwest::blocking::get`, checks status 200, returns body bytes,
  checks `author:` line (DRL 1.1) — errors abort the whole update

### `encode.rs` — write encoded rules + PROVENANCE

```rust
pub fn write_encoded_rule(rules_dir: &Path, filename: &str, plain_bytes: &[u8]) -> cairn_core::Result<()>
pub fn write_provenance(rules_dir: &Path, pin: &str) -> cairn_core::Result<()>
```

- `write_encoded_rule`: `codec::xor(plain_bytes)` → write to `rules_dir/<filename>`
- `write_provenance`: write the canonical PROVENANCE format matching what
  `fetch-and-encode.sh` produces (so `ruleset_version()` still works)

---

## `cairn-cli` integration

### Cargo feature

```toml
# cairn-cli/Cargo.toml
[features]
default = ["updater"]
updater = ["dep:cairn-updater"]

[dependencies]
cairn-updater = { path = "../cairn-updater", optional = true }
```

### Handler (replaces `TODO S4`)

```rust
Cmd::UpdateRules { pin } => {
    #[cfg(feature = "updater")]
    {
        let rules_dir   = /* path from --rules or default: rules/sigma/ next to binary */;
        let ruleset_toml = /* rules/ruleset.toml */;
        cairn_updater::run(pin.as_deref(), &rules_dir, &ruleset_toml)?;
        tracing::info!("update-rules complete");
    }
    #[cfg(not(feature = "updater"))]
    {
        anyhow::bail!("this build was compiled without network support (updater feature)");
    }
}
```

Default rules dir: `rules/sigma/` relative to the binary's parent directory
(`std::env::current_exe()?.parent()?/../../rules/sigma` in dev;
`rules/sigma` next to the installed binary in release). In practice, use
`std::env::current_dir()?.join("rules/sigma")` as the simplest non-brittle approach
for the CLI — the operator runs `cairn` from the repo root.

---

## Workspace additions

```toml
# Cargo.toml [workspace.dependencies]
reqwest = { version = "0.13", default-features = false, features = ["blocking", "rustls-tls-native-roots"] }
toml    = { version = "0.8",  default-features = false, features = ["parse"] }
```

Add `"crates/cairn-updater"` to `[workspace] members`.

---

## Tests

### Unit tests (no network — `cairn-updater` crate)

| Test | Location | What |
|---|---|---|
| `validate_pin_accepts_40hex` | `fetch.rs` | valid SHA1 passes |
| `validate_pin_rejects_short` | `fetch.rs` | 39-char string errors |
| `validate_pin_rejects_nonhex` | `fetch.rs` | non-hex char errors |
| `build_url_contains_base` | `fetch.rs` | URL starts with BASE |
| `drl11_check_rejects_no_author` | `fetch.rs` | bytes without `author:` → Err |
| `drl11_check_accepts_author` | `fetch.rs` | bytes with `\nauthor: foo` → Ok |
| `write_encoded_round_trips` | `encode.rs` | XOR-encoded file decodes back to original |
| `write_provenance_format` | `encode.rs` | PROVENANCE contains `pin = <sha>` line |
| `parse_ruleset_toml` | `config.rs` | parses pin + rule paths correctly |

### Integration test (network-gated, `#[ignore]`)

```rust
#[test]
#[ignore = "requires network — run manually: cargo test -p cairn-updater -- --ignored"]
fn fetch_real_rule_from_sigmahq() { ... }
```

---

## Acceptance Gate

- `cargo test --workspace` passes (all new unit tests + existing 434 pass; network test `#[ignore]`).
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cairn update-rules` (from repo root, with internet) fetches 3 rules, writes
  `rules/sigma/*.yml`, updates `rules/sigma/PROVENANCE`, prints completion.
- `cairn verify <manifest.json> --rules rules/sigma` still passes after update.
- `--pin` with a non-40-hex string → clear error, no fetch attempted.
- `#![forbid(unsafe_code)]` maintained in `cairn-updater`.
