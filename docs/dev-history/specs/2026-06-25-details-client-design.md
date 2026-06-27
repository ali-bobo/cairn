# details_client (FR18) Design

**Goal:** Fill `Finding.details_client` with plain zh-TW text for every Finding with
severity >= Medium, using a static template dispatch — no LLM, no runtime I/O,
no new dependencies.

**Architecture:** Pure function `fill_details_client(f: &mut Finding)` in a new
`cairn-report/src/client_text.rs` module. The CLI calls it after collecting Findings
and before writing to any OutputSink. Schema is unchanged (`details_client: Option<String>`
already exists in `Finding`).

**Tech Stack:** Pure Rust string formatting; no new crate dependencies.

---

## Constraints (SRS §13 / FR18)

- Only fill for severity `Medium`, `High`, `Critical`. Leave `Low` / `Info` as `None`.
- Language: plain zh-TW, no jargon, no overstatement.
- MUST NOT say "已感染" / "確定為惡意". MUST preserve uncertainty ("可能", "疑似", "建議確認").
- No MITRE tags in client text (technical; analyst-facing only).
- Interpolated fields must be analyst-produced or tool-internal (not external user input):
  `host` (Windows API hostname), `title` (our own bundled Sigma rule title),
  `path` (process path from Windows API). No raw rule content or sample data interpolated.

---

## Module: `cairn-report/src/client_text.rs`

Single public function:

```rust
pub fn fill_details_client(f: &mut Finding)
```

Exposed from `cairn-report/src/lib.rs` as `pub mod client_text;`.

---

## Template Dispatch (first-match, 7 templates)

Evaluated in order. `reason` matching is case-insensitive substring search.

| # | Condition | Template (zh-TW) |
|---|---|---|
| 1 | `Heuristic` + reason contains `parent-child` | 「主機 {host} 上，{path} 以非預期的父行程方式執行，可能為偽裝或橫向移動，建議確認該執行是否屬於正常業務操作。」 |
| 2 | `Heuristic` + reason contains `persist` | 「主機 {host} 上，{path} 疑似建立了持久化機制，建議確認該項目是否為已知且授權的軟體。」 |
| 3 | `Heuristic` + reason contains `netconn` | 「主機 {host} 上，{path} 發起了對外網路連線，建議確認連線目標是否屬於正常業務範疇。」 |
| 4 | `Heuristic` (other) | 「主機 {host} 上偵測到疑似異常行為，建議分析師確認詳情。」 |
| 5 | `Sigma` + severity `Critical` or `High` | 「主機 {host} 上偵測到與「{title}」相關的可疑活動，此類活動具有較高風險，建議盡速進行調查。」 |
| 6 | `Sigma` + severity `Medium` | 「主機 {host} 上偵測到與「{title}」相關的活動，建議分析師評估是否為授權操作。」 |
| 7 | Fallback (any other source) | 「主機 {host} 上偵測到疑似異常事件，建議進行確認。」 |

`path` interpolation: use `f.entity.path` if `Some`, else `"未知程式"`.
`title` interpolation: use `f.title` (always present on Sigma Findings).
`host` interpolation: use `f.host` (always present).

---

## Call Site (cairn-cli/src/main.rs)

Two output paths (run_live and run_evtx), each gets one block inserted **after**
findings are collected and **before** the first `sink.write_*` call:

```rust
for f in &mut findings {
    cairn_report::client_text::fill_details_client(f);
}
```

Severity gate is inside `fill_details_client` (not at call site) so the logic
stays in one place.

---

## Tests (cairn-report/src/client_text.rs, #[cfg(test)])

7 unit tests, one per template + 1 for the severity gate:

| Test | Asserts |
|---|---|
| `parent_child_heuristic_filled` | contains "非預期的父行程", `details_client` is Some |
| `persist_heuristic_filled` | contains "持久化機制" |
| `netconn_heuristic_filled` | contains "對外網路連線" |
| `other_heuristic_filled` | contains "疑似異常行為" |
| `sigma_high_filled` | contains "較高風險", contains rule title |
| `sigma_medium_filled` | contains "評估是否為授權操作" |
| `low_severity_not_filled` | `details_client` remains `None` for Low/Info |

---

## Acceptance Gate

- `cargo test --workspace` passes (all 7 new tests green).
- `cargo clippy --workspace --all-targets -- -D warnings` clean.
- `cargo fmt --all` applied before push.
- Manual spot-check: run `cairn evtx <sample.evtx> --output /tmp/out` and confirm
  `findings.jsonl` contains `details_client` populated for High/Medium findings.
