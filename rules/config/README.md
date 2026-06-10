# rules/config

Config maps mirrored from Hayabusa concepts (SRS §9), built/maintained in T5/T6:
- channel_abbreviations.txt  : Channel -> short label (Security->Sec, ...).
- eventkey_alias.txt         : sigma field -> Event.EventData.* path.
- target_event_IDs.txt       : EventIDs worth loading.
- noisy_rules.txt            : rule ids to down-rank.
- exclude_rules.txt          : rule ids to skip.
- level_tuning.txt           : per-rule severity overrides.

Bundled Sigma rules live in ../ (DRL 1.1). They MAY be XOR-encoded on disk to avoid
AV false positives on .yml content — encode the RULES, never the tool (golden rule 2).
