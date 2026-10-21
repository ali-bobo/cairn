//! FR14: fill `binary_sha256` on the records behind findings, so each suspicious record
//! carries an IOC hash. In-memory only — nothing is written for `--dry-run`.
use cairn_core::record::Record;
use cairn_core::Finding;

/// Fill `binary_sha256` on the records that produced a finding, using an injected hasher.
///
/// Records are matched to findings by a STABLE KEY (not fragile path comparison):
/// registry-backed persistence finding -> (entity.registry.key, entity.registry.value) matches
/// PersistenceRecord (location, value); startup file finding -> entity.file.path matches the
/// persistence record's binary_path; process finding -> entity.process.pid matches
/// ProcessRecord pid. Only matched records with a binary_path / absolute image are hashed.
/// Findings count is small (triage), so the linear scans are cheap.
pub fn enrich_hashes(
    records: &mut [Record],
    findings: &[Finding],
    hash_fn: impl Fn(&str) -> Option<String>,
) {
    use cairn_collectors::proc::is_absolute_path;
    use std::collections::HashSet;

    let mut reg_keys: HashSet<(String, String)> = HashSet::new();
    let mut file_paths: HashSet<String> = HashSet::new();
    let mut pids: HashSet<u32> = HashSet::new();
    for f in findings {
        if let Some(r) = &f.entity.registry {
            reg_keys.insert((r.key.clone(), r.value.clone()));
        }
        if let Some(fi) = &f.entity.file {
            file_paths.insert(fi.path.clone());
        }
        if let Some(p) = &f.entity.process {
            pids.insert(p.pid);
        }
    }

    for rec in records.iter_mut() {
        match rec {
            Record::Persistence(p) => {
                let value = p.value.clone().unwrap_or_default();
                let matched = reg_keys.contains(&(p.location.clone(), value))
                    || p.binary_path
                        .as_deref()
                        .is_some_and(|bp| file_paths.contains(bp));
                if let Some(bp) = p.binary_path.as_deref().filter(|_| matched) {
                    p.binary_sha256 = hash_fn(bp);
                    if p.binary_sha256.is_none() {
                        // Selected for hashing but unhashable (over the size cap, locked, or
                        // unreadable). Surface it so the skip is auditable, not invisible.
                        tracing::debug!(path = bp, "find-producing binary not hashed");
                    }
                }
            }
            Record::Process(p) if pids.contains(&p.pid) && is_absolute_path(&p.image) => {
                p.binary_sha256 = hash_fn(&p.image);
                if p.binary_sha256.is_none() {
                    tracing::debug!(path = %p.image, "find-producing binary not hashed");
                }
            }
            _ => {}
        }
    }
}

/// The real hasher: streaming SHA-256, capped at DEFAULT_MAX_HASH_BYTES.
pub fn hash_on_disk(path: &str) -> Option<String> {
    cairn_collectors::hash::hash_file_capped(
        path,
        cairn_collectors::hash::DEFAULT_MAX_HASH_BYTES,
        |p| {
            let len = std::fs::metadata(p).ok()?.len();
            let file = std::fs::File::open(p).ok()?;
            Some((len, file))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::finding::EntityRegistry;
    use cairn_core::record::PersistenceRecord;
    use cairn_core::{Entity, FindingSource, Mechanism, Severity};

    #[test]
    fn enrich_hashes_fills_only_find_producing_records() {
        let mk = |value: &str, bin: &str| {
            Record::Persistence(PersistenceRecord {
                mechanism: Mechanism::RunKey,
                location: "HKCU\\Run".into(),
                value: Some(value.into()),
                command: Some(bin.into()),
                binary_path: Some(bin.into()),
                binary_sha256: None,
                signed: None,
                signer: None,
                last_write: None,
                bound: None,
                signer_source: None,
            })
        };
        let mut records = vec![mk("Evil", "C:\\evil.exe"), mk("Benign", "C:\\benign.exe")];

        // A finding whose registry (key,value) matches record[0] only.
        let mut f = Finding::new(Severity::High, "x: evil.exe", FindingSource::Heuristic);
        f.entity = Entity {
            registry: Some(EntityRegistry {
                hive: "HKCU".into(),
                key: "HKCU\\Run".into(),
                value: "Evil".into(),
                data: "C:\\evil.exe".into(),
                last_write: None,
            }),
            ..Entity::default()
        };
        enrich_hashes(&mut records, &[f], |p| Some(format!("hash-of-{p}")));

        let Record::Persistence(p0) = &records[0] else {
            panic!()
        };
        let Record::Persistence(p1) = &records[1] else {
            panic!()
        };
        assert_eq!(p0.binary_sha256.as_deref(), Some("hash-of-C:\\evil.exe"));
        assert_eq!(
            p1.binary_sha256, None,
            "benign record (no finding) not hashed"
        );
    }
}
