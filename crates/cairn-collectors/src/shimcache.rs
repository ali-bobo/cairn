//! ShimCollector: parse the AppCompatCache (shimcache) value from a locked SYSTEM
//! hive into Record::Execution. The version-aware blob parser (parse_appcompatcache)
//! is a pure, never-panic function (bounds-checked readers, like parse_usn_record);
//! the collector is privilege-gated and read-only, using hive_reader to fetch bytes.
