//! HiveReader: raw-locate a locked hive, read its bytes (+ .LOG1/.LOG2) entirely in
//! memory, and parse it with notatin. Reusable primitive for hive-backed collectors
//! (shimcache now; amcache/userassist later). Mirrors usn.rs: same VolumeReader +
//! ntfs find_child navigation, same catch_unwind third-party-panic containment, same
//! read_value_capped memory ceiling. No temp files (notatin from_file takes a reader).
