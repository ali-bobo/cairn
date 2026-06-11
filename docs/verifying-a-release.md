# Verifying a Cairn release

Before running Cairn on any host — and before a SOC allow-lists it — confirm the binary
is exactly the published release. This is the integrity half of legitimacy (SRS §13):
the tool is open, hashed, and (once a cert is provisioned) signed.

## 1. Confirm the hash

Every release publishes the SHA-256 of `cairn.exe` (in `cairn.exe.sha256` and the build
log). Recompute it and compare:

```powershell
# Windows
(Get-FileHash .\cairn.exe -Algorithm SHA256).Hash.ToLower()
```
```bash
# Linux/macOS (e.g. verifying a cross-checked copy)
sha256sum cairn.exe
```

The value must match `cairn.exe.sha256` exactly. A mismatch means the binary is not the
published release — do not run it.

## 2. Confirm version + build commit

The binary self-reports the version and the git commit it was built from (stamped by
build.rs into the embedded PE resource and the run manifest):

```
cairn --version
# cairn 0.1.0 (<build_sha>)
```

`<build_sha>` is also written into every run's `manifest.tool.build_sha`, so a report can
be traced back to the exact source commit.

## 3. Confirm the signature

Releases are currently **UNSIGNED** — code signing is wired in `release.yml` but gated
until a signing service is provisioned (SignPath OSS / Azure Trusted Signing; see the
notes in that workflow). Until then:

- Allow-list by **published hash**, not by certificate (there is no certificate yet).
- Once signing is on, verify the Authenticode signature and timestamp:
  ```powershell
  Get-AuthenticodeSignature .\cairn.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
  ```
  `Status` must be `Valid`; record the signer thumbprint in the SOC runbook §1.

## 4. Verify a run's outputs (chain of custody)

After a run, `cairn verify` re-hashes the outputs and re-checks the ruleset against the
manifest (ADR-0003); it exits non-zero on any tamper:

```
cairn verify out/manifest.json --rules rules/sigma
```

See `docs/SOC-runbook-template.md` §1 for where these artifacts (hash, signer, version)
go in the pre-engagement packet.
