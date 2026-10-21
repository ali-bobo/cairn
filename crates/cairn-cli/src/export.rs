//! EVTX evidence export (`--export-evtx`, default on): each live channel the run
//! reads is exported, restricted to the `--since` window, to `evidence/evtx/<channel>.evtx`
//! in the OUTPUT location (dir, or staged beside the zip and archived), then hashed
//! into `manifest.outputs`. Never written to a source path, never under `--dry-run`.
//! A channel that fails (absent, access denied) is recorded in `manifest.sources` and
//! the run goes on (golden rule 8).
use cairn_core::manifest::SourceEntry;
use cairn_report::Sink;
use chrono::{DateTime, Utc};
use std::path::Path;

/// What to export: the channels and the window start.
#[derive(Debug, Clone)]
pub struct ExportPlan {
    pub channels: Vec<String>,
    pub since: DateTime<Utc>,
}

/// The export plan for a live run, or None when export is off or the live EVTX module
/// is not part of this run (e.g. `--profile minimal`, `--only proc`).
pub fn plan(
    enabled: bool,
    selected: &[String],
    channels: Vec<String>,
    since: DateTime<Utc>,
) -> Option<ExportPlan> {
    let evtx_selected = selected
        .iter()
        .any(|s| s == cairn_core::collectors::EVTX_LIVE);
    if !enabled {
        tracing::info!("EVTX export disabled (--no-export-evtx)");
        return None;
    }
    if !evtx_selected {
        tracing::info!("EVTX export skipped: evtx_live module not selected");
        return None;
    }
    Some(ExportPlan { channels, since })
}

/// The `/`-separated output name of a channel's export.
pub fn output_name(channel: &str) -> String {
    format!(
        "evidence/evtx/{}",
        cairn_collectors_win::evtx_export::channel_file_name(channel)
    )
}

fn failure(channel: &str, error: String) -> SourceEntry {
    let name = cairn_collectors_win::evtx_export::NAME;
    SourceEntry {
        collector: name.to_string(),
        artifact: format!("{name}:{channel}"),
        path: format!("live:{name}:{channel}"),
        method: "wevtapi".into(),
        size: 0,
        sha256: String::new(),
        errors: vec![error],
    }
}

/// Export every planned channel through `exporter(channel, xpath, target)` into the
/// sink's evidence location and register each file with the sink. Returns one manifest
/// source entry per failed channel. A dry-run sink has no evidence location, so this
/// does nothing at all.
pub fn export_into(
    sink: &mut Sink,
    plan: &ExportPlan,
    exporter: impl Fn(&str, &str, &Path) -> cairn_core::Result<()>,
) -> Vec<SourceEntry> {
    let query = cairn_collectors_win::evtx_export::since_xpath(plan.since);
    let mut failures = Vec::new();
    for channel in &plan.channels {
        let name = output_name(channel);
        let Some(target) = sink.evidence_path(&name) else {
            return failures; // dry-run: write nothing
        };
        let result = target
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .map_err(cairn_core::CairnError::from)
            .and_then(|()| {
                let target = std::path::absolute(&target).unwrap_or(target.clone());
                exporter(channel, &query, &target)?;
                sink.add_evidence_file(&name, &target)
            });
        match result {
            Ok(()) => tracing::info!(channel = %channel, file = %name, "exported evtx"),
            Err(e) => {
                tracing::warn!(channel = %channel, error = %e, "evtx export failed; skipping");
                failures.push(failure(channel, e.to_string()));
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::OutputKind;

    fn plan_for(channels: &[&str]) -> ExportPlan {
        ExportPlan {
            channels: channels.iter().map(|c| c.to_string()).collect(),
            since: Utc::now(),
        }
    }

    #[test]
    fn plan_requires_flag_and_evtx_live_module() {
        let sel = vec![cairn_core::collectors::EVTX_LIVE.to_string()];
        assert!(plan(true, &sel, vec!["Security".into()], Utc::now()).is_some());
        assert!(plan(false, &sel, vec![], Utc::now()).is_none());
        assert!(plan(true, &["proc".to_string()], vec![], Utc::now()).is_none());
    }

    /// A successful export lands under evidence/evtx in the output dir and is hashed
    /// into the outputs; a failing channel becomes a manifest source error entry.
    #[test]
    fn export_registers_files_and_records_failures() {
        let dir = std::env::temp_dir().join("cairn_cli_export_dir");
        let _ = std::fs::remove_dir_all(&dir);
        let mut sink = Sink::new(&OutputKind::Dir(dir.clone()));
        let fails = export_into(
            &mut sink,
            &plan_for(&["Security", "Microsoft-Windows-Sysmon/Operational"]),
            |ch, q, target| {
                assert!(q.contains("TimeCreated"));
                if ch == "Security" {
                    std::fs::write(target, b"ElfFile\0").map_err(Into::into)
                } else {
                    Err(cairn_core::CairnError::Other("channel not found".into()))
                }
            },
        );
        assert!(dir
            .join("evidence")
            .join("evtx")
            .join("Security.evtx")
            .is_file());
        let outs = sink.outputs_so_far();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].file, "evidence/evtx/Security.evtx");
        assert_eq!(outs[0].size, 8);
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].collector, "evtx_export");
        assert!(fails[0].errors[0].contains("channel not found"));
    }

    /// Dry-run: the exporter is never even called.
    #[test]
    fn dry_run_never_calls_the_exporter() {
        let mut sink = Sink::new(&OutputKind::DryRun);
        let fails = export_into(&mut sink, &plan_for(&["Security"]), |_, _, _| {
            panic!("exporter must not run under --dry-run")
        });
        assert!(fails.is_empty());
    }
}
