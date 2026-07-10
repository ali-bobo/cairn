# D — Schema / Serialization Backward-Compatibility Audit

Date: 2026-07-10. Scope: `crates/cairn-core/src/{record,finding,manifest,observation,config}.rs`
on `main`. Read-only review — no code or docs were modified.

Key fact established empirically before reviewing individual fields (see
Methodology): with serde_derive + serde_json (as pinned in this repo,
serde 1.0.228 / serde_json 1.0.150), a struct field of type `Option<T>` is
**already optional on deserialize when the JSON key is absent** — it resolves
to `None` — even with no `#[serde(default)]` attribute. This was verified with
a standalone reproduction (see Methodology). Consequently, "missing
`#[serde(default)]`" is only a real compatibility risk for **non-`Option`**
additive fields (`bool`, `u64`, `usize`, `Vec<T>`, nested structs) — for those,
serde derive has no implicit default and an absent key is a hard deserialize
error without the attribute. The review below applies this corrected model
instead of flagging every bare `Option<T>` field as a violation.

## Methodology

- Enumerated every field of every serde-derived type in the five files.
- Cross-referenced `git log -p --follow` on `record.rs`, `finding.rs`,
  `manifest.rs` to find which fields were NOT present in the initial commit
  (`acbb6ea`) or `T1` characterization commit (`7e0271e`), i.e. were added
  later against an already-shipped schema.
- For each later-added field, checked whether a test exercises "old JSON
  (without this key) deserializes without error" specifically, not just a
  round-trip of a freshly-constructed value.
- Verified the `Option<T>`-is-implicitly-optional claim with an isolated
  cargo project (`serde_check`) using the same serde/serde_json versions
  declared in the workspace `Cargo.toml`, reproduced in scratchpad, run with
  `cargo run`. Output confirmed both a plain `Option<String>` field and one
  annotated `#[serde(default)]` deserialize identically to `None` when the
  key is missing from the input JSON.
- Grepped for all call sites of `cairn_core::schema::{FINDING,MANIFEST,
  OBSERVATION,RECORD}` and for the literal strings `"cairn.finding/1"` etc.
  across the whole repo to check for drift between the constants and their
  consumers.
- Read `crates/cairn-cli/src/main.rs` `run_verify` to confirm `Manifest` JSON
  really is re-parsed by a long-lived external-facing command (`cairn verify`),
  which is the concrete consumer this audit protects.

## 1. Field-by-field backward-compatibility table

### `Record` (record.rs) — internal bus type, no `schema` field by design

| Field / Type | Added when | Default mechanism | Verified by | Conclusion |
|---|---|---|---|---|
| `Record` enum: `Event/Process/NetConn/Persistence/FileMeta/UsnEvent/RegValue/Execution` variants | initial commit (`acbb6ea`) | n/a (baseline) | `event_record_round_trips_with_kind_tag`, `execution_record_kind_tag_is_snake_case` | OK |
| `Record::LogonSession` variant | added later (`ir-snapshot-panels`, 2026-07-03) | n/a — **new enum variants are a compatibility risk only in the other direction**: old JSONL cannot produce a `LogonSession` tag, so no old-file-breaks-new-code risk. New JSONL with `"kind":"logon_session"` sent to an *older* binary would fail — acceptable, not a regression class this repo claims to defend against (Record has no cross-version replay guarantee stated beyond FR1 forward path) | `logon_session_record_kind_tag` | OK, no gap |
| `FileMetaRecord.fn_mtime: Option<DateTime<Utc>>` | added after S2-N (`84df58f` "S2-N' evidence fields") | implicit (`Option`) | `file_meta_fn_mtime_roundtrips_and_old_json_is_none` — explicitly constructs old-shaped JSON missing the key and asserts `None` | OK, and doubly verified (belt-and-suspenders test exists even though implicit default alone would suffice) |
| `FileMetaRecord.path_complete: Option<bool>` | added S2-O (`ce60f61`) | implicit (`Option`) | `file_meta_path_complete_roundtrips_and_old_json_none` — same pattern | OK |
| `LogonSessionRecord.state_active: bool` | added 2026-07-08 (`html-report-filtering`) | **explicit** `#[serde(default)]` (correctly required — `bool` has no implicit optional-on-deserialize) | `logon_session_state_active_defaults_false_on_old_json_and_roundtrips` — deserializes a literal pre-field JSON string and asserts `false` | OK — this is the one field in `record.rs` where the attribute is load-bearing, and it is present and tested |
| `ExecutionRecord.*` (all fields) | initial baseline for the type (added as a whole struct in the raw-NTFS decomposition commit) | n/a — struct introduced complete | none needed (no old JSON predates the struct) | OK |

**Finding-worthy gap in this file: none.** `state_active` — the only
non-`Option` additive field in `record.rs` — is correctly annotated and
tested against literal old-shaped JSON, not just a fresh round-trip.

### `Finding` + `Entity`/`EvidenceItem` (finding.rs)

| Field / Type | Added when | Default mechanism | Verified by | Conclusion |
|---|---|---|---|---|
| `Finding.schema/id/ts/detected_at/severity/title/source/mitre/host/artifact/entity/details` | baseline | n/a | `finding_round_trips_with_schema_and_author` | OK |
| `Finding.rule_id/rule_author/user/event_id/evidence_ref/details_client/reason: Option<T>` | some baseline, some later | implicit (`Option`) + `skip_serializing_if` for compact output | `optional_fields_omitted_when_none_and_reason_round_trips` | OK |
| `Finding.evidence: Vec<EvidenceItem>` | added later (`aafd26b` "add EvidenceItem + Finding.evidence") | **explicit** `#[serde(default, skip_serializing_if = "Vec::is_empty")]` (correctly required — `Vec` has no implicit default) | `evidence_roundtrips_and_old_json_defaults_empty` — asserts old JSON (pre-field) round-trips to an empty vec, and that an empty vec is itself omitted on write (so the omission is symmetric, not just read-side) | OK |
| `EntityFile.si_mtime/fn_mtime: Option<DateTime<Utc>>` | added S2-N′ (`84df58f`) | implicit (`Option`) | `entityfile_old_json_gets_none_mtimes_and_new_roundtrips` | OK |
| `EntityFile.path_complete: Option<bool>` | added S2-O (`ce60f61`) | implicit (`Option`) | `entityfile_path_complete_roundtrips_and_old_json_none` | OK |
| `EvidenceItem.path/ts: Option<T>` | new type, added whole with `evidence` | implicit (`Option`) | covered indirectly by `evidence_roundtrips_and_old_json_defaults_empty` for the containing `Vec`; no direct test deserializes an `EvidenceItem` JSON object missing `path`/`ts` keys specifically | See Finding F-1 below (minor — implicit default makes it safe, but there is no explicit regression test pinning it) |

### `Manifest` and children (manifest.rs)

| Field / Type | Added when | Default mechanism | Verified by | Conclusion |
|---|---|---|---|---|
| `Manifest.governance: GovernanceReport` | added (`c444f9a` "GovernanceReport + Truncation manifest block") | **explicit** `#[serde(default)]` | `manifest_without_governance_field_deserializes` — removes the key from a `serde_json::Value` built from a real `Manifest` (not hand-written JSON) and reparses; strong test | OK |
| `GovernanceReport.effective_threads/low_priority_applied/truncations` | new type, added whole | **explicit** `#[serde(default)]` on all three, plus `#[derive(Default)]` on the struct itself | `governance_report_round_trips_and_old_json_defaults` — parses literal `"{}"` | OK — belt and suspenders (struct-level `Default` derive plus per-field attributes) |
| `Truncation` (nested in `truncations: Vec<Truncation>`) | new type, added whole with `GovernanceReport` | n/a — only reachable via the already-defaulted `Vec`; its own fields (`collector/cap/reason`) are all non-Option and mandatory once a `Truncation` object exists, which is correct (a truncation entry is never partial) | implicit via the above | OK |
| `SourceEntry.errors: Vec<String>` | added post-baseline (diff shows `+ pub errors: Vec<String>` inserted into existing struct) | **explicit** `#[serde(default)]` | `source_entry_errors_defaults_when_absent` — hand-written JSON missing the key | OK |
| `Counts.observations: u64` | added (`9e6e494` "Observation channel... Counts wiring") | **explicit** `#[serde(default)]` | No test deserializes a `Counts` JSON object with the key omitted directly (`manifest_round_trips_with_schema` always constructs `Counts` with the field set); `Counts` also derives `Default` | See Finding F-2 below (minor — same class as F-1: attribute is present and correct, but no test pins the specific "old manifest without `counts.observations`" scenario) |
| `RunInfo.profile/selected_modules` | added S2-L (`1c4a1bf`) | **no default, non-Option, mandatory** | `run_info_round_trips_profile_and_modules` only exercises fresh round-trip, never old-JSON-without-the-field | See Finding F-3 below (real gap — these two fields were added to an existing struct without `#[serde(default)]`, meaning a pre-S2-L manifest JSON with no `profile`/`selected_modules` keys will now hard-fail to deserialize) |

### `Observation` (observation.rs)

Introduced whole in a single commit alongside the `heuristic-gate-redesign`
plan; every field either predates no shipped JSON or was present from the
type's inception. `path: Option<String>` correctly uses `skip_serializing_if`
and benefits from the implicit-`Option`-default. No fields were added to this
struct after its first appearance in `main`. **No findings.**

### `Config` / `Profile` (config.rs)

`Config` is **not** itself persisted/replayed as an external-facing artifact
(it is the in-process run configuration, not `Manifest`/`Finding`); its own
serde derive exists for internal convenience, not for the "external tool
reads this JSON for years" contract this audit is about. Reviewed anyway for
completeness:

- `Governance` (new field group added to `Config`, NFR9): `Config` derives
  `Serialize/Deserialize` but there is no test or code path that deserializes
  an old `Config` JSON blob missing `governance`, `max_mft_records`,
  `max_usn_records`, `timestomp_threshold_hours`, or `resolve_mft_paths`
  (all added after the initial `Config` shape, all non-`Option`, none
  annotated `#[serde(default)]`). This matters far less than `Manifest`/
  `Finding` because nothing in the codebase currently reads a serialized
  `Config` back from disk — grepped `main.rs` and `cairn-cli`, `Config` is
  always constructed fresh from CLI args each run, never loaded from JSON.
  Flagging as informational only (see F-4), not counted in the severity
  totals below, since there is no current external consumer to break.

## 2. Findings

| # | File:Line | Severity | Issue | Suggested fix |
|---|---|---|---|---|
| F-3 | `crates/cairn-core/src/manifest.rs:37-40` (`RunInfo.profile`, `RunInfo.selected_modules`) | **Medium** | Both fields were added to `RunInfo` after S2-A shipped (commit `1c4a1bf`), are non-`Option` (`String`, `Vec<String>`), and carry **no `#[serde(default)]`**. A `manifest.json` produced by a pre-S2-L build (or any manifest hand-edited/truncated to drop these keys) will now fail `serde_json::from_str::<Manifest>` inside `cairn verify` (`crates/cairn-cli/src/main.rs:438`, via `cairn_report::read_manifest`) with a hard deserialize error, not a graceful default. This is the one concrete backward-compat gap in the audited surface with a live external consumer (`cairn verify`) that could hit it. | Add `#[serde(default)]` to both fields (`profile` defaulting to `String::new()`, `selected_modules` to `vec![]`), or explicitly document in `RunInfo`'s doc-comment that manifests older than 2026-06-15 (S2-L) are not supported by `cairn verify` and are out of scope. Either is acceptable; currently neither exists — no attribute and no documented cutoff. |
| F-1 | `crates/cairn-core/src/finding.rs:87-96` (`EvidenceItem.path`, `EvidenceItem.ts`) | **Low** | Safe today only because `Option<T>` deserializes with an implicit `None` on a missing key (verified empirically, see Methodology) — but there is no test that deserializes an `EvidenceItem`-shaped JSON object missing these keys directly; the only coverage is indirect, through `Vec<EvidenceItem>` being empty. If a future refactor changes either field's type away from `Option<T>` (e.g. to satisfy a new invariant) without re-adding `#[serde(default)]`, this would silently become a hard-fail with no test catching it. | Add a small direct test: `serde_json::from_str::<EvidenceItem>(r#"{"artifact":"x","detail":"y"}"#)` and assert `path`/`ts` are `None`. Cheap insurance, not urgent. |
| F-2 | `crates/cairn-core/src/manifest.rs:79-82` (`Counts.observations`) | **Low** | Same class as F-1: the attribute (`#[serde(default)]`) is present and correct, but no test exercises deserializing a `Counts` object with the key physically absent — the existing round-trip test always sets `observations: 0` explicitly rather than omitting the key from the JSON. Functionally safe (attribute is correct), but the "old manifest predates this field" scenario is unverified by test, unlike the parallel and better-tested `manifest_without_governance_field_deserializes`. | Add a `counts_observations_defaults_when_absent` test mirroring `source_entry_errors_defaults_when_absent`'s hand-written-JSON pattern. |
| F-4 | `crates/cairn-core/src/config.rs:92-126` (`Config` struct as a whole, esp. `Governance`, `max_mft_records`, `max_usn_records`, `timestomp_threshold_hours`, `resolve_mft_paths`) | **Info** | `Config` derives `Serialize`/`Deserialize` and has accumulated several non-`Option`, non-defaulted fields since its introduction, but is never round-tripped through JSON anywhere in the current codebase (confirmed by grep — always constructed fresh per run from CLI args). Not an active bug. | No action required unless a future feature persists/replays `Config` from disk (e.g. a "saved run profile" feature) — if that happens, revisit this table first. |

**Severity distribution: 1 Medium, 2 Low, 1 Info. Total: 4 findings.**

## 3. Enum serialization stability

- **`Record` enum** (`#[serde(tag = "kind", rename_all = "snake_case")]`):
  no `#[serde(rename)]` on individual variants. Renaming a Rust variant
  identifier (e.g. `NetConn` → `NetworkConnection`) would silently change the
  wire tag from `"net_conn"` to `"network_connection"` with no compiler error
  and no test failure unless the specific `..._kind_tag` test for that variant
  happens to assert the literal string (which, per-variant, only `Event` and
  `Execution` and `LogonSession` currently do — `Process`, `NetConn`,
  `Persistence`, `FileMeta`, `UsnEvent`, `RegValue` have no such assertion).
  This is the same class of risk as F-1/F-2 (implicit correctness with no
  explicit pin) but for enum tags rather than fields — informational, folded
  into F-1's remediation suggestion rather than a separate finding, since
  fixing it means "add one assertion per variant," not a code change.
- **`Severity`** and **`FindingSource`** (`#[serde(rename_all = "lowercase")]`):
  same absence of per-variant `#[serde(rename)]`, same risk class, lower
  likelihood (these are stable, well-established domain vocabulary, unlike
  `Record` variants which are still being added as new collectors ship).
- **`Severity` comparison/ordering**: `Severity` derives `Debug, Clone, Copy,
  PartialEq, Eq, Serialize, Deserialize` — **no `PartialOrd`/`Ord`**. Ranking
  logic that needs a total order re-implements it independently:
  `crates/cairn-heur/src/persist.rs:334-343` defines a private `sev_rank(s:
  Severity) -> u8` with an explicit comment "Total order over Severity for
  max-selection (Severity itself has no Ord)". This is a **duplicated,
  hand-maintained mapping** parallel to the enum's own variant list. It is
  low-risk in practice because the match is exhaustive (adding a `Severity`
  variant without updating `sev_rank` fails to compile, not silently
  misranks), but it means severity ordering knowledge lives in two places
  (`finding.rs`'s variant list and `persist.rs`'s `sev_rank`) with no single
  source of truth, and any other crate needing severity comparison would
  likely reinvent this mapping a third time. Grepped for other severity
  comparison logic; found none outside `persist.rs`, so no drift exists
  today. **Recommendation (not a hard finding — no bug, but worth flagging
  per the audit's own request for chain-of-custody/ordering stability):**
  consider deriving `PartialOrd, Ord` directly on `Severity` with variants
  declared high-to-low (or explicit discriminants), so there is one
  canonical order instead of a satellite `sev_rank` function that another
  crate could reimplement inconsistently.
- **`Profile`** (`#[serde(rename_all = "lowercase")]`): only three variants,
  stable since introduction, no history of renames. Same theoretical risk,
  negligible practical exposure.

## 4. Schema string constant synchronization

Grepped every occurrence of the literal strings `"cairn.finding/1"`,
`"cairn.manifest/1"`, `"cairn.observation/1"`, `"cairn.record/1"` across the
whole repository (`cairn-SRS.md`, `USER-MANUAL.md`, all crate source, all
`docs/dev-history/plans/*.md`, and the `dist/` build output).

- **All production Rust code** (`cairn-core`, `cairn-report`, `cairn-cli`)
  constructs the `schema` field exclusively via `cairn_core::schema::{FINDING,
  MANIFEST,OBSERVATION}` constants — zero hardcoded schema-string literals
  found in any `.rs` file outside test-assertion strings (which compare
  *against* the constant's known value, e.g. `finding.rs:198`
  `assert_eq!(back.schema, "cairn.finding/1")` — a legitimate use, pinning the
  constant's value rather than duplicating its source).
- Literal occurrences outside `.rs` files (`cairn-SRS.md`, `USER-MANUAL.md`,
  `dist/.../manifest.json`, `dist/.../observations.jsonl`) are documentation
  and generated run output, not independent sources of truth — expected and
  fine.
- `schema::RECORD` (`"cairn.record/1"`) has **zero call sites** anywhere in
  the codebase outside its own definition and doc-comments referencing it.
  `record.rs`'s own doc-comment (lines 6-9) states Records get this tag only
  "when wrapping Records for on-disk interchange" — but no such wrapping code
  currently exists (`Record` is never serialized standalone with this schema
  tag attached; it flows in-process only, per the `#[cfg(test)]` guard
  `record_has_no_inline_schema_field`). This is **not a drift bug** (nothing
  to drift against yet) but is worth noting: `schema::RECORD` is currently
  dead/aspirational — defined for a JSONL replay wrapping feature (FR1) that
  is documented as intended but not yet implemented anywhere in `main`.

**Conclusion: no schema-string drift found.** All four constants are
consumed correctly and exclusively via `cairn_core::schema::*`; `RECORD` is
simply unused pending its wrapping feature, which is a scope gap, not a
compatibility bug.

## Categories with no findings

- `Observation` (observation.rs): no additive fields since introduction, no
  compatibility risk identified.
- `Config`/`Profile` `FromStr` parsing (config.rs): case-insensitive parsing
  (`to_ascii_lowercase()`), tested for both known values (including mixed
  case) and unknown values with a message naming the bad input and the valid
  set (`profile_from_str_parses_known_values_case_insensitively`,
  `profile_from_str_rejects_unknown_value`). This class of issue — CLI-level
  parsing correctness and error-message quality — has no findings.
- `EntityFile`, `EntityProcess`, `EntityNetConn`, `EntityRegistry` (finding.rs):
  reviewed for additive-field-without-default risk; all additive fields
  (`si_mtime`, `fn_mtime`, `path_complete`) are `Option<T>` and correctly
  covered by explicit tests deserializing literal old-shaped JSON, not just
  fresh round-trips. No findings.
- `schema` constant usage in production code (cairn-core, cairn-report,
  cairn-cli): no hardcoded-string drift found (see §3 above).
