# B — Unsafe soundness audit: `cairn-collectors-win`

- **Date:** 2026-07-10
- **Auditor role:** independent (fresh context), review-only. No code or docs changed.
- **Scope:** all 9 files under `crates/cairn-collectors-win/src/` on `main`.
- **`windows` crate:** `0.62.2` (workspace-pinned; verified in `Cargo.lock`).
- **Golden rules reference:** `cairn/CLAUDE.md` §GOLDEN RULES (rule 1 = no evasion; rule 3 = collectors never modify host; rule 8 = graceful degrade).

Verdict up front: **the existing unsafe surface is sound.** No memory-safety
defect, no handle leak, no evasion technique found. Findings below are all
Low/Info — hardening notes and one latent correctness nit, none blocking.

---

## 1. Per-file, per-unsafe-block check results

Legend for check columns:
- **SAFETY** = does the stated invariant actually hold?
- **Handle** = RAII / no leak on any path?
- **Buffer** = in/out length + pointer bounds correct?
- **Cast** = pointer cast / alignment valid?
- **R1** = golden rule 1 (no evasion)?
- **R8** = graceful degrade (no panic on failure)?
- `n/a` = check not applicable to this block.

### `lib.rs`
No unsafe blocks (module declarations + `#![allow(unsafe_code)]` boundary only). The crate-level allow is the documented, intended single FFI boundary (NFR3). **PASS.**

### `host.rs` — `GetComputerNameExW` (2 blocks)
| Loc | Check | Result |
|---|---|---|
| host.rs:26-28 (size probe) | SAFETY / Buffer | PASS — `None` buffer + `&mut size` is the documented probe form; return value intentionally ignored; `size==0` guarded before use. |
| host.rs:37-47 (real call) | Buffer | PASS — `buf` sized to `size` u16; same `size` passed; `map_err`→`Err`. |
| — | R8 | PASS — probe-0 and API error both return `Err`; caller defaults. No panic. |

### `logon.rs` — WTS enumeration (6 blocks)
| Loc | Check | Result |
|---|---|---|
| logon.rs:52-56 `WTSFreeMemory` (SessionInfoBuf drop) | Handle | PASS — frees the exact pointer from `WTSEnumerateSessionsW`, once. |
| logon.rs:68-70 `WTSFreeMemory` (QueryBuf drop) | Handle | PASS — frees the exact `WTSQuerySessionInformationW` buffer, once. |
| logon.rs:83-85 `WTSQuerySessionInformationW` | SAFETY / Buffer | PASS — out-params filled on success; on error no alloc (guard only built after `is_err`/null check). |
| logon.rs:91-92 `guard.0.to_string()` | Buffer | PASS — non-null just verified; API NUL-terminates; `.ok()?` swallows bad UTF-16. |
| logon.rs:108 `WTSEnumerateSessionsW` | SAFETY | PASS — local-server `None`, reserved=0, version=1 per contract; null-checked before use. |
| logon.rs:116 `from_raw_parts(guard.0, count)` | Buffer / Cast | PASS — `count` contiguous entries guaranteed by API; guard non-null; `WTS_SESSION_INFOW` is the correct element type. |
| logon.rs:131-132 `pWinStationName.to_string()` | Buffer | PASS — explicit null check first, then read. Defensive and correct. |
| — | R1 / R8 | PASS — official WTS API, read-only; all failures → empty `Vec`. `client_address` honestly abstained (documented). |

### `net.rs` — extended TCP/UDP tables (8 blocks)
| Loc | Check | Result |
|---|---|---|
| net.rs:62-71 / 112-121 (size probes) | SAFETY | PASS — null-buffer probe form; return ignored intentionally. |
| net.rs:74-83 / 124-133 (real fetch) | Buffer | PASS — `buf` sized to probed `size`; same `size` passed back; `rc!=0`→`Err`. |
| net.rs:92 / 141 `&*(buf.as_ptr() as *const MIB_*TABLE_OWNER_PID)` | Cast | PASS *with caveat* — see **B-2**. Buffer came from the API sized to hold this header; `dwNumEntries` read first. Alignment satisfied because `Vec<u8>` from `vec![0u8; n]` is only guaranteed 1-byte aligned in theory, but in practice the global allocator returns ≥16-byte alignment; the struct's required alignment is 4 (all `u32`/DWORD fields). **Latent, not currently triggerable** — noted as Low. |
| net.rs:95 / 144 `from_raw_parts(table.table.as_ptr(), n)` | Buffer | PASS — flexible-array member with `dwNumEntries` rows immediately following the count, per MIB contract. When `n==0`, `from_raw_parts(ptr, 0)` is sound as long as `ptr` is non-null and aligned (it is — points inside `buf`). |
| — | R1 / R8 | PASS — IpHelper read-only enumeration; `rc!=0`→`Err`. No panic. |

### `priority.rs` — self priority reduction (3 blocks)
| Loc | Check | Result |
|---|---|---|
| priority.rs:45 `GetCurrentProcess()` | SAFETY / Handle | PASS — pseudo-handle; correctly **never** closed. |
| priority.rs:51 `SetPriorityClass(BELOW_NORMAL)` | SAFETY / R8 | PASS — result checked, `map_err`→`Err`. |
| priority.rs:64 `SetPriorityClass(BACKGROUND_BEGIN)` | SAFETY / R8 | PASS — non-idempotent behaviour documented; caller treats `Err` as best-effort. |
| — | R1 | PASS — lowers **own** priority only; no injection, no host artifact touched (rules 3 & 4). |

### `privilege.rs` — token probe (5 blocks)
| Loc | Check | Result |
|---|---|---|
| privilege.rs:58-64 `OpenProcessToken(TOKEN_QUERY)` | Handle | PASS — owned token handle wrapped in `TokenHandle` guard immediately; closed once on drop. |
| privilege.rs:47-51 `CloseHandle` (drop) | Handle | PASS. |
| privilege.rs:76-88 `GetTokenInformation(TokenElevation)` | Buffer | PASS — correctly-sized `TOKEN_ELEVATION`, `size_of` passed, `ret_len` out. |
| privilege.rs:99-105 `LookupPrivilegeValueW` | Buffer | PASS — `wide` is NUL-terminated UTF-16; LUID out-param. |
| privilege.rs:117-122 `PrivilegeCheck` | Buffer | PASS — single-entry `PRIVILEGE_SET`, `PrivilegeCount=1`, `Control=1` (ALL_NECESSARY inlined constant, value correct). |
| — | R8 | PASS — every failure path `map_err`→`Err`, and callers use `.unwrap_or(false)` (privilege.rs:20-22). No panic. |

### `proc.rs` — process enumeration (7 blocks)
| Loc | Check | Result |
|---|---|---|
| proc.rs:52-55 / 64-67 `CloseHandle` (Snapshot/ProcHandle drop) | Handle | PASS — each closes once on drop. |
| proc.rs:78 `OpenProcess(QUERY_LIMITED_INFORMATION)` | Handle | PASS — `.ok()?` on failure (pid 0 / exited / denied → `None`); handle wrapped in `ProcHandle` on the very next line. **No leak on the `?` path** (nothing owned yet when it early-returns). |
| proc.rs:88-95 `QueryFullProcessImageNameW` | **Buffer** | PASS — **the "len is in+out" contract is handled correctly.** `len` starts = `cap`; on success API writes chars-written (excluding NUL) back into `len`, guaranteed `<= cap`, so `&buf[..len]` (proc.rs:98) is in-bounds. Grow-once loop (260 → 32768) covers `ERROR_INSUFFICIENT_BUFFER`. See **B-1** for one theoretical nit. |
| proc.rs:110 `CreateToolhelp32Snapshot` | Handle | PASS — owned handle → `Snapshot` guard; `map_err`→`Err`. |
| proc.rs:125 `Process32FirstW` | Buffer | PASS — `entry.dwSize` set before call (proc.rs:119); empty snapshot → `Ok(empty)`. |
| proc.rs:149 `Process32NextW` | Buffer | PASS — entry reused per Toolhelp iteration contract; loop breaks on `is_err`. |
| — | R1 / R8 | PASS — `QUERY_LIMITED_INFORMATION` is the *least* privileged query right (read-only, cannot modify target); unopenable process falls back to the Toolhelp file name (proc.rs:137). No panic. |

### `signature.rs` — WinTrust + catalog + signer (many blocks)
| Loc | Check | Result |
|---|---|---|
| sig:115-121 `WinVerifyTrust(VERIFY)` embedded | SAFETY | PASS — `wtd`/`file_info`/`wide` all outlive call; union `pFile` written (writing a union field is safe). |
| sig:128-134 `WinVerifyTrust(CLOSE)` | Handle | PASS — provider state always freed; no fallible step between VERIFY and CLOSE (sig:123-125 comment accurate). |
| sig:145-152 `CryptCATAdminReleaseContext` (drop) | Handle | PASS — released once, `dwflags=0`. |
| sig:162-168 `CryptCATAdminReleaseCatalogContext` (drop) | Handle | PASS — **drop order correct**: `CatInfoCtx` declared after `CatAdminCtx` (sig:197 vs 251) so catalog context frees *before* admin (reverse declaration order), and it captures its own copy of the admin handle. |
| sig:173-179 `CloseHandle` FileHandle drop | Handle | PASS. |
| sig:192-193 `CryptCATAdminAcquireContext2` | SAFETY / R8 | PASS — `w!("SHA256")` static; `is_err`→`None`. |
| sig:203-216 `CreateFileW` | Handle / R1 | PASS — `GENERIC_READ`+`SHARE_READ`+`OPEN_EXISTING`, read-only (rule 3); `Err`→`None`, else wrapped in `FileHandle`. |
| sig:221-228 `CalcHashFromFileHandle2` (probe) | Buffer | PASS — `pbhash=None` requests length; `is_err \|\| len==0`→`None`. |
| sig:231-243 `CalcHashFromFileHandle2` (real) | Buffer | PASS — `hash` sized to `hash_len`; in/out len. |
| sig:247 `CryptCATAdminEnumCatalogFromHash` | Buffer | PASS — `0`→genuinely unsigned→`Some(false)`; else wrapped in `CatInfoCtx`. |
| sig:262 `CryptCATCatalogInfoFromContext` | Buffer | PASS — `ci` correctly-sized out-param. |
| sig:294-300 `WinVerifyTrust(CATALOG VERIFY)` + sig:306-312 CLOSE | SAFETY / Handle | PASS — all inputs outlive; provider state freed. `cbCalculatedFileHash=hash_len` matches buffer (sig:273-276 comment accurate). |
| sig:337-351 `CryptQueryObject` | SAFETY | PASS — `pvObject`=NUL-terminated wide path; `store`/`msg` out-params; `is_err`→`None`; guards `StoreGuard`/`MsgGuard` built only after success. |
| sig:360 / 367-379 `CryptMsgGetParam` (probe + real) | Buffer | PASS — two-stage size; `info` sized to `len`. |
| sig:382-391 `CertFindCertificateInStore` | SAFETY / Handle | PASS — encoding flags OR'd correctly; null→`None`; else `CertGuard`. |
| sig:398 / 404-412 `CertGetNameStringW` (probe + real) | Buffer | PASS — `n<=1` (just NUL) → `None`; second call writes into `name[n]`; slices `[..written-1]` to drop NUL. **In-bounds** since `written<=n`. |
| sig:424-451 store/msg/cert guard drops | Handle | PASS — each freed once with the matching free fn. |
| — | R1 / R8 | PASS — this is a *normal* call to the public verification API (WinVerifyTrust / Crypt*), **not** signing, hooking, or trust-provider tampering. Every failure → `None`. No panic (tests at sig:458-553 assert totality). |

### `volume.rs` — raw `\\.\C:` reader (5 blocks)
| Loc | Check | Result |
|---|---|---|
| vol:247-249 `CloseHandle` VolumeHandle drop | Handle | PASS — closes once even on early return/panic. |
| vol:303-317 `CreateFileW(\\.\C:)` | Handle / R1 | PASS — `GENERIC_READ` only, `OPEN_EXISTING`, no write/create/truncate flag; `FILE_FLAG_NO_BUFFERING` is a *footprint-minimising* forensic choice, not evasion (rule 4). Handle wrapped immediately; `map_err`→`Err`. |
| vol:351 `SetFilePointerEx` | SAFETY | PASS — `FILE_BEGIN`, result checked, error mapped. |
| vol:358 `ReadFile(Some(buf), Some(&mut bytes_read))` | Buffer | PASS — `buf` is a valid mutable slice for the call; length bounded by `MAX_READ` (1 MiB < u32::MAX) so the u32 cast is safe; `bytes_read` out. |
| vol:473-484 `DeviceIoControl(GEOMETRY_EX)` | Buffer / Cast | PASS — `DISK_GEOMETRY_EX` output buffer + `size_of` length; `is_err`→`None`; result validated (`>=512 && power_of_two`) before use. |
| — | R8 (overflow) | **PASS — exemplary.** `compute_aligned_window` uses `checked_add`/`align_up_checked`; an adversarial on-disk `pos` near `u64::MAX` returns `None`→`InvalidInput` instead of panicking. Proven by `overflow_*` tests (vol:580-614). Alignment math + partial-read clamping (`extract_subrange`) fully unit-tested (vol:688-916). |

---

## 2. Findings

All findings are **Low / Info**. None blocks the planned PEB/token work.

### B-1 — `QueryFullProcessImageNameW` len underflow-to-None is fine, but the empty-string branch masks a valid corner
- **Location:** `proc.rs:96-99`
- **Severity:** Info
- **Issue:** On success `len` is chars-written; the code slices `&buf[..len]` (correct) then returns `None` if the result is empty. An empty string here is effectively impossible for a real path, so this is harmless — but it means "opened the process, query succeeded, but returned empty" is silently indistinguishable from "couldn't open." Not a soundness bug.
- **Fix suggestion:** None required; optionally log the empty-success case if it ever matters for triage fidelity.

### B-2 — `Vec<u8>` reinterpreted as `MIB_*TABLE_OWNER_PID` relies on allocator alignment
- **Location:** `net.rs:92`, `net.rs:141`
- **Severity:** Low
- **Issue:** `buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID` casts a `Vec<u8>` (element alignment 1) to a struct whose required alignment is 4 (DWORD fields). The global allocator in practice returns ≥16-byte-aligned blocks for `vec![0u8; n]`, so this never faults on Windows x64 — but it is technically alignment-fragile and not guaranteed by the language.
- **Fix suggestion:** Read the header fields via `std::ptr::read_unaligned`, or allocate an over-aligned buffer (e.g. `Vec<MIB_TCPROW_OWNER_PID>` / a `#[repr(align(8))]` wrapper). Low priority; document the assumption if left as-is.

### B-3 — `net.rs` size-probe return value fully ignored
- **Location:** `net.rs:62-71`, `net.rs:112-121`
- **Severity:** Info
- **Issue:** The probe's return code is discarded; if `size` stays 0 (probe failed for a reason other than `ERROR_INSUFFICIENT_BUFFER`), the next call runs against a zero-length `buf`. `GetExtendedTcpTable` would then return a non-zero rc → clean `Err`, so it degrades gracefully, but the failure reason is lost.
- **Fix suggestion:** None required (graceful). Optionally assert `size != 0` before allocation for a clearer error message.

### B-4 — No finding on evasion, handle leaks, or UB
Explicitly recorded: the three highest-risk categories (handle leaks, buffer overrun, evasion) were checked on **every** block and found clean. See §3 and §5.

---

## 3. Golden rule 1 (no evasion) — conclusion

**未發現 evasion 手法 (no evasion technique found).**

Checked every unsafe block against the rule-1 forbidden list (process injection;
syscall-based hook bypass; AMSI/ETW patch; in-memory execution; packing/entropy
reduction; anti-debug/anti-VM; artifact erasure; masquerade naming):

- All process access uses the *least* privilege that works (`PROCESS_QUERY_LIMITED_INFORMATION` in `proc.rs`).
- Priority calls (`priority.rs`) target the tool's **own** process only.
- Signature verification (`signature.rs`) calls the **public** WinTrust/Crypt* verification API — it verifies, it does not sign, hook, or patch a trust provider.
- Raw volume read (`volume.rs`) is `GENERIC_READ` + `OPEN_EXISTING` only; `FILE_FLAG_NO_BUFFERING` reduces forensic footprint (rule 4) — the opposite of hiding.
- No `WriteProcessMemory`, `VirtualAllocEx`, `CreateRemoteThread`, `NtProtectVirtualMemory`, direct-syscall stubs, or ETW/AMSI symbols anywhere in the crate.

The tool is deliberately EDR-visible and benign, as the golden rules require.

---

## 4. Feasibility: PEB cmdline + token integrity additions

**One-line verdict: feasible and low-risk — it reuses `proc.rs`'s existing
`ProcHandle` RAII pattern, and `windows 0.62.2` already ships every symbol
needed (nothing must be hand-defined), but the read-remote-memory path carries
real soundness traps that must be handled explicitly.**

### 4a. RAII reuse
Yes. The plan slots cleanly into the existing pattern:
- `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)` → wrap in `ProcHandle` exactly like `full_image_path` (`proc.rs:78-79`). `Err`→`None` for pid 0 / protected / denied processes preserves graceful degrade (rule 8).
- `OpenProcessToken` → the `privilege.rs` `TokenHandle` guard is the ready-made model (`privilege.rs:44-67`). Consider lifting `TokenHandle` into a shared helper rather than duplicating it.

### 4b. `windows 0.62.2` symbol coverage (verified against the vendored crate source)
All present — **no struct must be hand-defined:**

| Symbol | Location in crate | Feature to enable |
|---|---|---|
| `NtQueryInformationProcess` | `Wdk::System::Threading` (ntdll link) | `Wdk_System_Threading` (→`Wdk_System`) |
| `PROCESSINFOCLASS` / `ProcessBasicInformation` (=0) | `Wdk::System::Threading` | `Wdk_System_Threading` |
| `PROCESS_BASIC_INFORMATION` (has `PebBaseAddress: *mut PEB`) | `Win32::System::Threading` | `Win32_System_Kernel` (gates its `Default` impl + `PEB`) |
| `PEB`, `RTL_USER_PROCESS_PARAMETERS` | `Win32::System::Threading` | `Win32_System_Kernel` |
| `ReadProcessMemory` | `Win32::System::Diagnostics::Debug` | `Win32_System_Diagnostics_Debug` |
| `OpenProcessToken`, `GetTokenInformation`, `TokenIntegrityLevel`, `TOKEN_MANDATORY_LABEL`, `SID_AND_ATTRIBUTES` | `Win32::Security` | `Win32_Security` (**already enabled**, Cargo.toml:19) |

So the only **new** feature flags to add to `Cargo.toml` are:
`Win32_System_Kernel`, `Win32_System_Diagnostics_Debug`, and
`Wdk_System_Threading`. `Win32_Security` and `Win32_System_Threading` are
already on.

**Important layout caveat (verified):** the crate's `PEB` and
`RTL_USER_PROCESS_PARAMETERS` are the *redacted* SDK forms — most PEB fields are
`Reserved1..Reserved12` padding. **However**, `PEB::ProcessParameters` and, inside
`RTL_USER_PROCESS_PARAMETERS`, both `ImagePathName` and `CommandLine`
(`UNICODE_STRING`) **are** exposed as named fields at their correct offsets
(reserved padding preserves layout). So you can read `PEB.ProcessParameters`,
then follow it to `RTL_USER_PROCESS_PARAMETERS.CommandLine` using the crate's own
structs — no hand-rolled offsets required for the 64-bit case. This is the safe
path; do **not** hardcode numeric offsets.

### 4c. Soundness traps for the new code (checklist)
1. **Target process exits mid-read.** Between `OpenProcess` and each `ReadProcessMemory`, the target can die. `ReadProcessMemory` then returns `FALSE` → you must treat every read as fallible and map to `None` (never `unwrap`). Read the PBI first, then the PEB, then the params, then the command-line buffer — any step failing aborts to `None`.
2. **Two pointer indirections into another address space.** `PebBaseAddress` and `ProcessParameters.CommandLine.Buffer` are pointers **in the target's** address space; each must be dereferenced via a *separate* `ReadProcessMemory`, never a local deref. Reading the `UNICODE_STRING` gives you `Length` (bytes) + `Buffer` (remote ptr); then a third `ReadProcessMemory` of `Length` bytes at `Buffer`.
3. **Validate `UNICODE_STRING.Length` before allocating.** It is attacker-influenceable (the target may have rewritten its own PEB). Cap it (e.g. ≤ 32 KiB) before `vec![0u16; len]` to avoid an OOM/DoS — mirror the `MAX_READ` discipline already in `volume.rs:232`.
4. **WOW64 / bitness mismatch.** A 64-bit Cairn reading a 32-bit target (or vice-versa) sees a *different* PEB layout (`PEB32` vs `PEB64`, 4-byte vs 8-byte pointers). The crate's `PEB` is the native-width one. For a 64-bit build reading 32-bit targets you need `NtQueryInformationProcess(ProcessWow64Information)` to detect WOW64 and then the 32-bit param layout, or accept "best-effort, native-width only, abstain on WOW64 mismatch" (consistent with the project's NFR12 "abstain rather than guess" posture already used in `logon.rs` for client_address).
5. **`ReadProcessMemory` partial reads.** Check `lpNumberOfBytesRead` equals the requested size; a short read means the region was partially unmapped — treat as failure, not truncated success.
6. **Token integrity path is simpler and safer.** `OpenProcessToken(PROCESS_QUERY_INFORMATION handle, TOKEN_QUERY)` → `GetTokenInformation(TokenIntegrityLevel, None,0,&len)` size-probe → real call into a `Vec<u8>` → interpret as `TOKEN_MANDATORY_LABEL`, then read the SID's last sub-authority (the RID) via `GetSidSubAuthority`. No cross-process memory reads; same alignment caveat as **B-2** applies to the `Vec<u8>` → `TOKEN_MANDATORY_LABEL` cast (use `read_unaligned` or an aligned buffer). This part is essentially as safe as the existing `privilege.rs` code.
7. **Privilege reality.** `PROCESS_VM_READ` on other users' / elevated / protected (PPL) processes will be denied without `SeDebugPrivilege`; System Idle (pid 0) and some system processes always fail. All of these must degrade to `None` per rule 8 — same graceful pattern the current `full_image_path` already relies on.

---

## 5. Categories explicitly checked and clean ("此類未發現問題")

- **Handle lifecycle / `CloseHandle` leaks:** every WinAPI handle is wrapped in an RAII guard (`Snapshot`, `ProcHandle`, `TokenHandle`, `VolumeHandle`, `FileHandle`, `CatAdminCtx`, `CatInfoCtx`, `SessionInfoBuf`, `QueryBuf`, `StoreGuard`, `MsgGuard`, `CertGuard`) built **after** the success check, so no `?`/early-return path leaks. Pseudo-handles (`GetCurrentProcess`) are correctly never closed. **No leak found.**
- **Buffer / in-out length contracts:** all two-stage (probe-then-fill) calls size the buffer to the probed length and pass it back correctly; `QueryFullProcessImageNameW`'s in/out `len` is handled per contract. **No overrun found.**
- **Uninitialised memory reads:** out-buffers are zero-initialised (`vec![0u8;..]` / `::default()`) before the API fills them; slices are bounded by the API-reported written length. **None found.**
- **Pointer casts / transmute / alignment:** no `transmute`; the only reinterpret casts are the `Vec<u8>`→MIB-table (net.rs) noted as **B-2 (Low, latent)**. No misaligned access is currently reachable. **No active defect.**
- **Golden rule 1 (evasion):** **未發現 evasion 手法.** (§3)
- **Graceful degrade (rule 8):** every fallible FFI call maps failure to `Err`/`None`/empty; totality is asserted by the `#[cfg(windows)]` smoke tests in each module. **No panic-on-failure path found.**
