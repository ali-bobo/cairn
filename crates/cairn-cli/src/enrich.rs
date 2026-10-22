//! FR14: fill `binary_sha256` on the records behind findings, so each suspicious record
//! carries an IOC hash. In-memory only — nothing is written for `--dry-run`.
use cairn_core::record::Record;
use cairn_core::Finding;

/// Fill `binary_sha256` on every persistence record whose target binary is an absolute
/// path, BEFORE the analyzers run, so heuristics (and their findings) see the hash.
/// Already-hashed records are left alone. Persistence entries are a bounded set (one
/// per ASEP), and the hasher is size-capped, so this stays cheap.
pub fn enrich_persistence_hashes(records: &mut [Record], hash_fn: impl Fn(&str) -> Option<String>) {
    use cairn_collectors::proc::is_absolute_path;
    for rec in records.iter_mut() {
        if let Record::Persistence(p) = rec {
            if p.binary_sha256.is_some() {
                continue;
            }
            if let Some(bp) = p.binary_path.as_deref().filter(|bp| is_absolute_path(bp)) {
                p.binary_sha256 = hash_fn(bp);
                if p.binary_sha256.is_none() {
                    // Unhashable (over the size cap, locked, or unreadable). Surface it
                    // so the skip is auditable, not invisible.
                    tracing::debug!(path = bp, "persistence target not hashed");
                }
            }
        }
    }
}

/// Fill `binary_sha256` on the process records behind findings (matched by pid), after
/// analysis. Only records still lacking a hash are touched, so once the process
/// collector fills hashes itself this is a no-op.
pub fn enrich_process_hashes(
    records: &mut [Record],
    findings: &[Finding],
    hash_fn: impl Fn(&str) -> Option<String>,
) {
    use cairn_collectors::proc::is_absolute_path;
    let pids: std::collections::HashSet<u32> = findings
        .iter()
        .filter_map(|f| f.entity.process.as_ref().map(|p| p.pid))
        .collect();
    for rec in records.iter_mut() {
        match rec {
            Record::Process(p)
                if p.binary_sha256.is_none()
                    && pids.contains(&p.pid)
                    && is_absolute_path(&p.image) =>
            {
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
    cairn_collectors::hash::hash_file_capped(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::record::PersistenceRecord;
    use cairn_core::Mechanism;

    #[test]
    fn persistence_targets_with_absolute_paths_are_hashed() {
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
                service_start: None,
            })
        };
        let mut records = vec![mk("Evil", "C:\\evil.exe"), mk("Rel", "%SystemRoot%\\x.exe")];
        enrich_persistence_hashes(&mut records, |p| Some(format!("hash-of-{p}")));
        let Record::Persistence(p0) = &records[0] else {
            panic!()
        };
        let Record::Persistence(p1) = &records[1] else {
            panic!()
        };
        assert_eq!(p0.binary_sha256.as_deref(), Some("hash-of-C:\\evil.exe"));
        assert_eq!(p1.binary_sha256, None, "unexpanded path is not hashed");

        // Already hashed: left alone.
        enrich_persistence_hashes(&mut records, |_| Some("other".into()));
        let Record::Persistence(p0) = &records[0] else {
            panic!()
        };
        assert_eq!(p0.binary_sha256.as_deref(), Some("hash-of-C:\\evil.exe"));
    }
}
