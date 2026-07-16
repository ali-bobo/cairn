# AV 誤判緩解（合法工程優化）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 `proc.rs` 對同一 pid 分散呼叫的 4 次 `OpenProcess` 合併成 1 次（兩階段 fallback 保留 graceful degrade），並把 PEB/cmdline 讀取邏輯獨立成新檔案 `cmdline_reader.rs`，補 SOC runbook 說明——全部不改變任何被觀察到的行為，只改變呼叫模式與治理透明度。

**Architecture:** `enumerate()` 迴圈對每個 pid 先嘗試一次聯集權限的 `OpenProcess`，成功則把 handle 傳給四個查詢函式（改吃 `HANDLE` 參數而非各自 `OpenProcess`）；失敗則 fallback 到基礎權限再開一次，取三項欄位、cmdline 記 None。`read_cmdline`/`is_wow64`/`read_remote_struct` 搬到新檔案，`proc.rs` 只保留呼叫端。

**Tech Stack:** Rust、`windows` crate（`OpenProcess`/`ReadProcessMemory`/`NtQueryInformationProcess`），`crates/cairn-collectors-win`（`#![allow(unsafe_code)]` 邊界）。

---

## 前置事實（來自完整讀取 proc.rs，任務執行時不需重查）

- **現況 4 個函式**（`crates/cairn-collectors-win/src/proc.rs`）：
  - `full_image_path(pid: u32) -> Option<String>`（行80-110）：`PROCESS_QUERY_LIMITED_INFORMATION`
  - `read_integrity(pid: u32) -> Option<u32>`（行127-197）：`PROCESS_QUERY_LIMITED_INFORMATION` + 內部額外 `OpenProcessToken(TOKEN_QUERY)`
  - `read_start_time(pid: u32) -> Option<DateTime<Utc>>`（行202-218）：`PROCESS_QUERY_LIMITED_INFORMATION`
  - `read_cmdline(pid: u32) -> Option<String>`（行283-368）：`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`

- **`ProcHandle`**（行64-74）：`struct ProcHandle(HANDLE)`，`Drop` 呼叫 `CloseHandle`。目前每個函式各自建立自己的實例。

- **`enumerate()` 主迴圈**（行370-417）：Toolhelp32 快照疊代，對每個 `entry.th32ProcessID` 依序呼叫上述四個函式，組裝 `RawProc`。

- **`read_cmdline` 的完整依賴鏈**（要整包搬到新檔案）：
  - `is_wow64(handle: HANDLE) -> bool`（行234-251）
  - `read_remote_struct<T: Default>(handle: HANDLE, addr: *const c_void) -> Option<T>`（行256-276）
  - `const MAX_CMDLINE_BYTES: usize = 32 * 1024`（行229）
  - import：`NtQueryInformationProcess, ProcessBasicInformation, ProcessWow64Information`（行220-222）、`ReadProcessMemory`（行223）、`PROCESS_BASIC_INFORMATION, PROCESS_VM_READ`（行224）

- **既有 5 個測試**（行420-492）全部透過 `enumerate()` 進入（黑盒），不依賴內部函式簽名，改動後不需修改：`enumerate_includes_current_process`、`current_process_has_absolute_image_path`、`current_process_integrity_resolves`、`current_process_start_time_resolves`、`current_process_cmdline_resolves`。

- **CARGO_TARGET_DIR 與 linker**：
  ```bash
  export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
  export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
  ```
  不寫進 `.cargo/config.toml`。

- **測試分工**：這個 crate 的測試需要 Windows + 能開啟自身行程（`#[cfg(all(test, windows))]`），implementer 在 Windows 機器上跑 `cargo test -p cairn-collectors-win`。

---

## Task 1: 新建 `cmdline_reader.rs`（搬移 cmdline 讀取邏輯）

**Files:**
- Create: `crates/cairn-collectors-win/src/cmdline_reader.rs`
- Modify: `crates/cairn-collectors-win/src/lib.rs`（新增模組宣告）

這個 Task 只做「搬移」，不做「合併 handle」——先讓程式碼移到新檔案且行為完全不變，Task 2 再改造成共用 handle。

- [ ] **Step 1: 建立 `cmdline_reader.rs`**，內容如下（從 `proc.rs` 原樣搬過來，函式簽名暫時不變，仍是 `fn read_cmdline(pid: u32) -> Option<String>` 各自呼叫 `OpenProcess`——Task 2 才改簽名）：

```rust
//! Reads a target process's full command line via its PEB (Process Environment
//! Block), using OpenProcess(PROCESS_VM_READ) + ReadProcessMemory.
//!
//! Why: DFIR triage needs the exact command line an attacker invoked (e.g. full
//! PowerShell -EncodedCommand payload), not just the process image name — this is
//! the single largest source of parentchild/persist heuristic signal (see
//! crates/cairn-heur/src/parentchild.rs).
//!
//! Guarantee: read-only. PROCESS_VM_READ carries no write capability; this module
//! never calls WriteProcessMemory or any handle-modifying API. Failures abstain
//! (return None) rather than guess (NFR12) — see cairn/CLAUDE.md golden rule 8.

use windows::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessBasicInformation, ProcessWow64Information,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

/// RAII guard for a process HANDLE.
/// INVARIANT: holds a valid handle from OpenProcess; closed exactly once on drop.
struct ProcHandle(HANDLE);
impl Drop for ProcHandle {
    fn drop(&mut self) {
        // SAFETY: self.0 is the valid process handle from OpenProcess; closed once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Upper bound on a UNICODE_STRING.Length we will trust before allocating a
/// read buffer — the value lives in the target's (potentially adversarial)
/// memory, so it must be capped before use (mirrors volume.rs::MAX_READ).
const MAX_CMDLINE_BYTES: usize = 32 * 1024;

/// True if `pid` is a WOW64 (32-bit-on-64-bit) process. On query failure,
/// conservatively returns `true` (abstain) rather than risk misreading a
/// 32-bit PEB layout as a 64-bit one.
fn is_wow64(handle: HANDLE) -> bool {
    let mut wow64_peb: usize = 0;
    // SAFETY: handle valid; wow64_peb is a valid out-param; ProcessWow64Information
    // on a 64-bit build returns the WOW64 PEB address (non-zero) or 0 if native.
    let status = unsafe {
        NtQueryInformationProcess(
            handle,
            ProcessWow64Information,
            &mut wow64_peb as *mut usize as *mut core::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status.is_err() {
        return true; // abstain-safe default
    }
    wow64_peb != 0
}

/// Read an entire `T` from `pid`'s address space at `addr` via a single
/// ReadProcessMemory call. Returns None on any failure or short read — never
/// interprets a partial/uninitialized `T`.
fn read_remote_struct<T: Default>(handle: HANDLE, addr: *const core::ffi::c_void) -> Option<T> {
    let mut out = T::default();
    let mut bytes_read: usize = 0;
    let size = std::mem::size_of::<T>();
    // SAFETY: handle valid; `out` is a local T with `size` bytes reserved;
    // bytes_read out-param checked below for a partial-read short-circuit.
    unsafe {
        ReadProcessMemory(
            handle,
            addr,
            &mut out as *mut T as *mut core::ffi::c_void,
            size,
            Some(&mut bytes_read as *mut usize),
        )
    }
    .ok()?;
    if bytes_read != size {
        return None;
    }
    Some(out)
}

/// Best-effort full command line for `pid`, via PEB -> RTL_USER_PROCESS_PARAMETERS
/// -> CommandLine (three chained ReadProcessMemory calls into the target's address
/// space). None on ANY failure at ANY step (target exited mid-read, WOW64 mismatch,
/// oversized/corrupt UNICODE_STRING.Length, partial read) — never guesses from a
/// partial result. Read-only: PROCESS_VM_READ cannot modify the target (rule 1).
pub(crate) fn read_cmdline(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
    }
    .ok()?;
    let guard = ProcHandle(handle);

    if is_wow64(guard.0) {
        return None; // native-width only; abstain on bitness mismatch (NFR12)
    }

    let pbi: PROCESS_BASIC_INFORMATION = {
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: guard.0 valid; pbi is a valid out-param sized correctly.
        let status = unsafe {
            NtQueryInformationProcess(
                guard.0,
                ProcessBasicInformation,
                &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut core::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() {
            return None;
        }
        pbi
    };
    if pbi.PebBaseAddress.is_null() {
        return None;
    }

    // Step 1: read the entire PEB struct (not a hand-computed offset) so
    // ProcessParameters is accessed via the crate's own field layout.
    let peb: windows::Win32::System::Threading::PEB =
        read_remote_struct(guard.0, pbi.PebBaseAddress as *const core::ffi::c_void)?;
    let params_ptr = peb.ProcessParameters;
    if params_ptr.is_null() {
        return None;
    }

    // Step 2: read the entire RTL_USER_PROCESS_PARAMETERS struct, then take
    // its CommandLine field (a UNICODE_STRING: Length in bytes + a remote pointer).
    let params: windows::Win32::System::Threading::RTL_USER_PROCESS_PARAMETERS =
        read_remote_struct(guard.0, params_ptr as *const core::ffi::c_void)?;
    let cmdline_us = params.CommandLine;

    if cmdline_us.Length as usize > MAX_CMDLINE_BYTES {
        return None; // adversarial/corrupt Length; abstain rather than OOM (NFR9)
    }
    if cmdline_us.Length == 0 || cmdline_us.Buffer.is_null() {
        return None;
    }

    // Step 3: read the actual UTF-16LE command-line bytes.
    let byte_len = cmdline_us.Length as usize;
    let mut buf = vec![0u16; byte_len.div_ceil(2)];
    let mut bytes_read: usize = 0;
    // SAFETY: guard.0 valid; buf sized to hold byte_len bytes; bytes_read
    // out-param checked below for a partial-read short-circuit.
    unsafe {
        ReadProcessMemory(
            guard.0,
            cmdline_us.Buffer.0 as *const core::ffi::c_void,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            byte_len,
            Some(&mut bytes_read as *mut usize),
        )
    }
    .ok()?;
    if bytes_read != byte_len {
        return None; // partial read: treat as failure, never truncate-and-guess
    }

    let s = String::from_utf16_lossy(&buf);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
```

- [ ] **Step 2: 在 `crates/cairn-collectors-win/src/lib.rs` 新增模組宣告**

讀取現有 `lib.rs` 確認既有 `mod` 宣告的風格與位置（有 `proc`/`net`/`host`/`logon`/`privilege`/`volume` 等），比照同樣風格新增：

```rust
mod cmdline_reader;
```

（這個模組不需要 `pub`——只有 `proc.rs` 內部使用，`read_cmdline` 用 `pub(crate)` 可見度即可。）

- [ ] **Step 3: 從 `proc.rs` 移除已搬移的程式碼，改為呼叫新模組**

在 `crates/cairn-collectors-win/src/proc.rs` 內：
1. 刪除行220-368（`use windows::Wdk::...` 到 `read_cmdline` 函式結尾，即 `is_wow64`/`read_remote_struct`/`MAX_CMDLINE_BYTES`/`read_cmdline` 全部）。
2. 在檔案頂部（`mod win` 內，其他 `use` 附近）新增：
   ```rust
   use crate::cmdline_reader::read_cmdline;
   ```
3. `enumerate()` 內原本的 `read_cmdline(entry.th32ProcessID)` 呼叫（行405）保持不變（函式簽名這一步還沒變）。

- [ ] **Step 4: 編譯與測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check -p cairn-collectors-win
cargo test -p cairn-collectors-win
```

Expected: 編譯成功；5 個既有測試全部通過（純搬移，行為未變）。

- [ ] **Step 5: Commit**

```bash
git add crates/cairn-collectors-win/src/cmdline_reader.rs crates/cairn-collectors-win/src/proc.rs crates/cairn-collectors-win/src/lib.rs
git commit -m "refactor(collectors-win): isolate PEB/cmdline reading into cmdline_reader.rs"
```

---

## Task 2: 合併 `OpenProcess` 呼叫（兩階段 fallback）

**Files:**
- Modify: `crates/cairn-collectors-win/src/proc.rs`
- Modify: `crates/cairn-collectors-win/src/cmdline_reader.rs`

這個 Task 把四個函式的簽名從「各自呼叫 `OpenProcess(pid)`」改成「吃已開啟的 `HANDLE` 參數」，並在 `enumerate()` 實作兩階段開啟邏輯。

- [ ] **Step 1: 修改 `cmdline_reader.rs` 的 `read_cmdline` 簽名，改吃 `HANDLE`**

```rust
/// Best-effort full command line for an already-open process handle, via PEB ->
/// RTL_USER_PROCESS_PARAMETERS -> CommandLine (three chained ReadProcessMemory calls
/// into the target's address space). None on ANY failure at ANY step (target exited
/// mid-read, WOW64 mismatch, oversized/corrupt UNICODE_STRING.Length, partial read)
/// — never guesses from a partial result. Read-only: PROCESS_VM_READ cannot modify
/// the target (rule 1).
///
/// Caller contract: `handle` MUST have been opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ. This function does not open
/// or close the handle — the caller (proc.rs::enumerate) owns its lifetime.
pub(crate) fn read_cmdline(handle: HANDLE) -> Option<String> {
    if is_wow64(handle) {
        return None; // native-width only; abstain on bitness mismatch (NFR12)
    }

    let pbi: PROCESS_BASIC_INFORMATION = {
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        // SAFETY: handle valid (caller contract); pbi is a valid out-param sized correctly.
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                ProcessBasicInformation,
                &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut core::ffi::c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        };
        if status.is_err() {
            return None;
        }
        pbi
    };
    if pbi.PebBaseAddress.is_null() {
        return None;
    }

    let peb: windows::Win32::System::Threading::PEB =
        read_remote_struct(handle, pbi.PebBaseAddress as *const core::ffi::c_void)?;
    let params_ptr = peb.ProcessParameters;
    if params_ptr.is_null() {
        return None;
    }

    let params: windows::Win32::System::Threading::RTL_USER_PROCESS_PARAMETERS =
        read_remote_struct(handle, params_ptr as *const core::ffi::c_void)?;
    let cmdline_us = params.CommandLine;

    if cmdline_us.Length as usize > MAX_CMDLINE_BYTES {
        return None; // adversarial/corrupt Length; abstain rather than OOM (NFR9)
    }
    if cmdline_us.Length == 0 || cmdline_us.Buffer.is_null() {
        return None;
    }

    let byte_len = cmdline_us.Length as usize;
    let mut buf = vec![0u16; byte_len.div_ceil(2)];
    let mut bytes_read: usize = 0;
    // SAFETY: handle valid (caller contract); buf sized to hold byte_len bytes;
    // bytes_read out-param checked below for a partial-read short-circuit.
    unsafe {
        ReadProcessMemory(
            handle,
            cmdline_us.Buffer.0 as *const core::ffi::c_void,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            byte_len,
            Some(&mut bytes_read as *mut usize),
        )
    }
    .ok()?;
    if bytes_read != byte_len {
        return None; // partial read: treat as failure, never truncate-and-guess
    }

    let s = String::from_utf16_lossy(&buf);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
```

同時移除 `cmdline_reader.rs` 裡不再需要的 `ProcHandle` struct 與 `OpenProcess`/
`PROCESS_QUERY_LIMITED_INFORMATION`/`PROCESS_VM_READ` 的 import（handle 開啟移到
`proc.rs`）；`is_wow64`/`read_remote_struct` 的簽名不變（已經是吃 `HANDLE`）。

檔案開頭的模組說明註解更新最後一段：

```rust
//! Guarantee: read-only. PROCESS_VM_READ carries no write capability; this module
//! never calls WriteProcessMemory or any handle-modifying API. Failures abstain
//! (return None) rather than guess (NFR12) — see cairn/CLAUDE.md golden rule 8.
//! This module does not open or close process handles itself — see
//! proc.rs::enumerate for the shared-handle lifecycle (AV false-positive
//! mitigation: one OpenProcess call per process instead of four).
```

- [ ] **Step 2: 修改 `proc.rs` 的三個函式，改吃 `HANDLE` 參數**

`full_image_path`（原行80-110）改為：

```rust
/// Best-effort full image path for an already-open process handle, via
/// QueryFullProcessImageNameW. Returns None if the query fails.
/// Never panics. Read-only: QUERY_LIMITED_INFORMATION cannot modify the target.
///
/// Caller contract: `handle` MUST have been opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION.
fn full_image_path(handle: HANDLE) -> Option<String> {
    // First attempt with MAX_PATH; grow once on insufficient buffer.
    for cap in [260usize, 32768usize] {
        let mut buf = vec![0u16; cap];
        let mut len = cap as u32;
        // SAFETY: handle valid (caller contract); buf has `cap` u16 slots; len is
        // in/out (capacity in, chars-written out). On success the API guarantees
        // len <= cap (the path + NUL fit), so the `&buf[..len]` slice is in-bounds.
        let r = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        match r {
            Ok(()) => {
                let s = String::from_utf16_lossy(&buf[..len as usize]);
                return if s.is_empty() { None } else { Some(s) };
            }
            Err(_) => continue,
        }
    }
    None
}
```

`read_integrity`（原行127-197）改為（移除自己的 `OpenProcess`，其餘不變）：

```rust
/// Best-effort token integrity RID for an already-open process handle. Returns
/// None on any failure — never panics. Read-only: TOKEN_QUERY cannot modify
/// the target.
///
/// Caller contract: `handle` MUST have been opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION.
fn read_integrity(handle: HANDLE) -> Option<u32> {
    let mut token = HANDLE::default();
    // SAFETY: handle valid (caller contract); token is an out-param written
    // only on success.
    unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) }.ok()?;
    let token_guard = TokenHandle(token);

    let mut len: u32 = 0;
    // SAFETY: null buffer + 0 size is the documented probe form; return value
    // intentionally ignored (probe always "fails" with the required size in `len`).
    unsafe {
        let _ = GetTokenInformation(token_guard.0, TokenIntegrityLevel, None, 0, &mut len);
    }
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: buf sized to the probed `len`; token_guard.0 valid; out len re-passed.
    unsafe {
        GetTokenInformation(
            token_guard.0,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            len,
            &mut len,
        )
    }
    .ok()?;

    if (len as usize) < std::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
        return None;
    }

    // SAFETY: buf is exactly `len` bytes as filled by the API above, and the check
    // just above guarantees len >= size_of::<TOKEN_MANDATORY_LABEL>(); read via
    // read_unaligned because a Vec<u8> only guarantees 1-byte alignment while
    // TOKEN_MANDATORY_LABEL requires pointer alignment.
    let label: TOKEN_MANDATORY_LABEL =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };

    // SAFETY: label.Label.Sid is a valid PSID pointing into `buf`, which is still
    // in scope for the remainder of this unsafe block; GetSidSubAuthorityCount/
    // GetSidSubAuthority are read-only queries against that SID.
    unsafe {
        let count_ptr = GetSidSubAuthorityCount(label.Label.Sid);
        if count_ptr.is_null() {
            return None;
        }
        let count = *count_ptr;
        if count == 0 {
            return None;
        }
        let rid_ptr = GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
        if rid_ptr.is_null() {
            return None;
        }
        Some(*rid_ptr)
    }
}
```

`read_start_time`（原行202-218）改為：

```rust
/// Best-effort process creation time for an already-open process handle, via
/// GetProcessTimes. None on any failure or on an all-zero FILETIME (no real
/// timestamp). Never panics. Read-only.
///
/// Caller contract: `handle` MUST have been opened with at least
/// PROCESS_QUERY_LIMITED_INFORMATION.
fn read_start_time(handle: HANDLE) -> Option<super::DateTime<super::Utc>> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: handle valid (caller contract); all four out-params are valid
    // mutable FILETIME refs owned by this stack frame for the duration of the call.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }.ok()?;

    let ticks = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
    cairn_core::filetime_to_utc(ticks)
}
```

- [ ] **Step 3: 重寫 `enumerate()` 的兩階段開啟邏輯**

```rust
pub fn enumerate() -> Result<Vec<RawProc>> {
    // SAFETY: TH32CS_SNAPPROCESS with pid 0 snapshots all processes; returns an owned
    // handle wrapped immediately in the guard.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
        CairnError::Collector {
            collector: "proc".into(),
            reason: format!("CreateToolhelp32Snapshot: {e}"),
        }
    })?;
    let snap = Snapshot(snap);

    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();

    // SAFETY: snap.0 valid; entry.dwSize set as required by Process32FirstW.
    if unsafe { Process32FirstW(snap.0, &mut entry) }.is_err() {
        return Ok(out); // empty snapshot is not an error
    }
    loop {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        let file_name = String::from_utf16_lossy(&entry.szExeFile[..len]);
        let pid = entry.th32ProcessID;

        // AV false-positive mitigation: open the process ONCE per pid instead of up
        // to 4 times. Try the union of every query's access mask first; if that's
        // denied (e.g. a protected process refusing PROCESS_VM_READ), fall back to
        // the base mask so image/integrity/start_time still resolve — only cmdline
        // is sacrificed. This preserves golden rule 8 (graceful degrade): a denied
        // capability degrades that one field, never the whole pid.
        // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
        let full_handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                false,
                pid,
            )
        }
        .ok();

        let (image, cmdline, integrity_raw, start_time) = if let Some(h) = full_handle {
            let guard = ProcHandle(h);
            let image = full_image_path(guard.0).unwrap_or_else(|| file_name.clone());
            let cmdline = crate::cmdline_reader::read_cmdline(guard.0);
            let integrity_raw = read_integrity(guard.0);
            let start_time = read_start_time(guard.0);
            (image, cmdline, integrity_raw, start_time)
        } else {
            // SAFETY: OpenProcess returns an owned handle or Err; wrapped immediately.
            let base_handle =
                unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok();
            match base_handle {
                Some(h) => {
                    let guard = ProcHandle(h);
                    let image = full_image_path(guard.0).unwrap_or_else(|| file_name.clone());
                    let integrity_raw = read_integrity(guard.0);
                    let start_time = read_start_time(guard.0);
                    (image, None, integrity_raw, start_time)
                }
                None => (file_name.clone(), None, None, None),
            }
        };

        out.push(RawProc {
            pid,
            ppid: entry.th32ParentProcessID,
            image,
            cmdline,
            integrity_raw,
            signed: None,
            user: None,
            start_time,
        });
        // SAFETY: snap.0 valid; entry reused per the Toolhelp iteration contract.
        if unsafe { Process32NextW(snap.0, &mut entry) }.is_err() {
            break;
        }
    }
    Ok(out)
}
```

（`PROCESS_VM_READ` 需要在 `proc.rs` 的 `use windows::Win32::System::Threading::{...}`
區塊補上這個 import，因為原本它只在已刪除的 `cmdline_reader` 相關 import 裡。）

- [ ] **Step 4: 編譯與測試**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cargo test -p cairn-collectors-win
```

Expected: 5 個既有測試全部通過。`current_process_cmdline_resolves` 驗證自身行程
（未受保護）仍能拿到 cmdline，走的是「聯集權限成功」這條路徑。

- [ ] **Step 5: 新增測試驗證 fallback 路徑語意**（無法用真機測試模擬「被拒絕
  PROCESS_VM_READ」的受保護行程，但可以驗證兩階段邏輯本身在正常情況下等價於
  原行為，並用文件/註解明確標註 fallback 路徑目前只有邏輯覆蓋、未被真機測試
  直接觸發過——這是誠實的測試覆蓋缺口，不強行造假測試）：

在 `proc.rs` 的 `#[cfg(all(test, windows))] mod tests` 新增：

```rust
/// Documents the two-stage fallback contract: this test can't force a real
/// PROCESS_VM_READ denial (would need a genuinely protected process), but it
/// confirms the union-mask path is what's actually exercised for an unprotected
/// process — the fallback branch remains logic-reviewed rather than
/// integration-tested against a real protected target. Tracked as a known gap.
#[test]
fn enumerate_uses_union_mask_path_for_unprotected_process() {
    let me = std::process::id();
    let procs = enumerate().expect("enumerate");
    let mine = procs.iter().find(|p| p.pid == me).expect("self in list");
    // If the union-mask OpenProcess had failed and fallen back to the base mask,
    // cmdline would be None. Since our own process is never protected, cmdline
    // resolving proves the primary (non-fallback) path executed.
    assert!(
        mine.cmdline.is_some(),
        "expected the union-mask path (not fallback) for our own unprotected process"
    );
}
```

- [ ] **Step 6: 跑測試確認新測試通過**

```bash
cargo test -p cairn-collectors-win
```

Expected: 6 個測試全部通過。

- [ ] **Step 7: Commit**

```bash
git add crates/cairn-collectors-win/src/proc.rs crates/cairn-collectors-win/src/cmdline_reader.rs
git commit -m "feat(collectors-win): merge per-pid OpenProcess calls with two-stage fallback"
```

---

## Task 3: SOC runbook 補充說明

**Files:**
- Modify: `docs/SOC-runbook-template.md`

- [ ] **Step 1: 讀取現有「Sigma 規則資料前提」章節**（段2剛加的），在其後新增新章節：

```markdown
## 7. Cairn 對每個行程做的記憶體讀取（PEB cmdline 擷取）

Cairn 掃描到的每個 Windows 行程，會嘗試一次 `OpenProcess`
（`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`）+ `ReadProcessMemory`
讀取該行程的 PEB（Process Environment Block），取得完整命令列。

**為什麼需要**：IR 鑑識需要攻擊者實際下達的完整指令（例如完整的
PowerShell `-EncodedCommand` 內容），只有行程名稱不足以判斷是否為惡意。這是
`heur_parentchild`/`heur_persist` 等多個 heuristic 的主要訊號來源。

**保證**：純唯讀。`PROCESS_VM_READ` 不含任何寫入能力，Cairn 不會呼叫
`WriteProcessMemory` 或任何會修改目標行程的 API。程式碼位置：
`crates/cairn-collectors-win/src/cmdline_reader.rs`（供 SOC/資安人員逕行稽核）。

**對 AV/EDR 的影響**：`OpenProcess`+`ReadProcessMemory` 這組 API 組合是多數
EDR/AV 靜態與行為 heuristic 高度關注的訊號（跨行程記憶體讀取是常見的
credential-dumping/infostealer 手法）。這正是本工具最常觸發防禦軟體誤判的
行為之一——SOC 應預期在授權掃描期間看到這個行為，並將其識別為 Cairn 的正常
運作，而非入侵指標。

**已知限制**：受保護行程（PPL、防毒/EDR 自身行程等）會拒絕 `PROCESS_VM_READ`，
此時 Cairn 會 fallback 拿基本身分資訊（image path、integrity、start_time），
`cmdline` 欄位留空——這是預期的優雅降級，不是錯誤。
```

- [ ] **Step 2: Commit**

```bash
git add docs/SOC-runbook-template.md
git commit -m "docs(soc-runbook): explain the PEB cmdline read (OpenProcess+ReadProcessMemory)"
```

---

## Task 4: 全 workspace 驗證收尾

**Files:**
- 無新增修改（純驗證 Task）

- [ ] **Step 1: 全 workspace check/test/clippy/fmt**

```bash
export CARGO_TARGET_DIR=/c/Users/bosen/AppData/Local/cairn-target
export CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER="C:\\Program Files (x86)\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Tools\\MSVC\\14.51.36231\\bin\\Hostx64\\x64\\link.exe"
cd /c/Users/bosen/OneDrive/Desktop/claude_dev/IIR_tool/cairn
cargo check --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

Expected: 全部通過，0 failed，零 clippy 警告。若 `cargo fmt --check` 抓到未格式化
程式碼（歷來每段都會發生），跑 `cargo fmt` 修正後重新確認並補一個 commit。

- [ ] **Step 2: 重新打包驗證(可選但建議)**——這段的動機是使用者實測打包後被
  AV 攔截，值得重新打包一次確認改動有效果（雖然單一次 heuristic 分數變化
  不保證一定解除攔截，這取決於 AV 引擎的具體評分規則，但至少要確認打包流程
  本身沒有壞掉）：

```bash
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/package.ps1
```

Expected: 打包成功，`dist/cairn-forensics/cairn.exe` 產生。**明確告知使用者**：
這次改動能否解除 PC-cillin 的攔截無法在此階段保證（AV heuristic 評分規則不透明,
且信譽分數需要時間累積），改動的目的是降低誤判機率、提高治理透明度，不是
保證消除誤判。

- [ ] **Step 3: 若 Step 1 有 fmt 修正則 commit**

```bash
git add -A
git commit -m "style: cargo fmt on AV false-positive mitigation changes"
```

---

## Self-Review

**1. Spec coverage：**
- 調整1（合併OpenProcess+兩階段fallback）→ Task 2，符合。fallback 邏輯明確
  保留「部分欄位失敗」而非「全部欄位失敗」的 graceful degrade 語意。
- 調整2（cmdline邏輯獨立成新檔案）→ Task 1（先搬移）+ Task 2 Step 1（改簽名），
  分兩步做降低單一 commit 風險，符合 spec 的模組化要求，含誠實的用途說明註解。
- 調整3（SOC runbook）→ Task 3，符合。
- 驗收原則1（不減少任何被觀察到的行為）→ Task 2 逐一比對四個函式的 API 呼叫
  種類與此前完全相同，只是呼叫時機/次數改變。
- 驗收原則2（既有5個測試不需修改）→ Task 1/2 都明確保留這 5 個測試不動，
  Task 2 額外新增第 6 個測試記錄 fallback 路徑的已知測試覆蓋缺口（誠實標註，
  非造假）。
- 驗收原則3（SAFETY註解慣例延續）→ Task 2 每個修改的函式都保留/更新了
  SAFETY 註解，並新增「caller contract」說明共用 handle 的不變量。
- Out of scope（不使用GOLDEN RULE 1例外、不動PE版本資源、不做簽章）→
  本計畫全程未涉及這些項目，符合。

**2. Placeholder 掃描：** 所有 Step 都有完整程式碼，直接複製自 proc.rs 原始碼
並精確修改。Task 2 Step 5 明確標註「fallback 路徑無法被真機測試直接觸發」是
誠實的已知限制，不是偷懶的佔位符——這是因為受保護行程無法在一般開發環境下
穩定重現，測試改為驗證「正常路徑confirmed執行」作為間接證據。

**3. Type 一致性：** `full_image_path`/`read_integrity`/`read_start_time`/
`read_cmdline` 四個函式的簽名從 `fn xxx(pid: u32)` 統一改成 `fn xxx(handle: HANDLE)`，
Task 2 Step 2/3 一致。`ProcHandle` 保留在 `proc.rs`（`enumerate()` 建立與管理），
`cmdline_reader.rs` 不再需要自己的 `ProcHandle`。

**4. 執行順序相依性：** Task 1（搬移，不改簽名）→ Task 2（改簽名+合併handle，
依賴Task1已完成搬移）→ Task 3（文件，獨立可平行但為求簡單序列處理）→
Task 4（全量驗證，依賴前三者完成）。Task 1/2 都改同一組檔案
（proc.rs + cmdline_reader.rs），必須序列處理，不可平行派工。
