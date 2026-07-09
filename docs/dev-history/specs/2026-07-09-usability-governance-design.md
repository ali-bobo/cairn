# Cairn 易用性與治理統整 — 設計規格(段 8)

- 日期:2026-07-09
- 狀態:已審(使用者核准設計 + 安全護欄/YAGNI 二次審視後定稿)
- 基準 commit:`74aefba`(PR #30 HTML 篩選合併後的 main)
- 對應 backlog:本 spec 建立 REMAINING-WORK.md 新段(段 8),不影響既有段 2–7

## 動機

使用者直接執行 `cairn run` 時必須手動帶 `--target`/`--output` 等參數,對非工程師
不友善。盤點後發現基礎其實已存在——`cairn-launcher`(2026-06-27 合併,`683e563`)、
`scripts/package.ps1`、`dist/cairn-forensics/` 都有——真正缺口是:

1. launcher 的「工程師模式」是空殼(選了只印「開發中」);
2. `dist/` 內的 binary 過期(不含 gate 重構、IR 面板、BYOVD、HTML 篩選);
3. `USER-MANUAL.md`(391 行)停在 0.1.0 / commit `1717a19`,缺運作邏輯概念章節;
4. 授權為 Apache-2.0,使用者決定改 MIT;
5. 擴充性/健全性需要一輪混合審計(fresh 審計 + 對照既有 backlog 差距校正)。

## 總覽:五段

| 段 | 內容 | 產出 |
|---|---|---|
| A | Launcher 工程師模式補實 | 程式碼(cairn-launcher) |
| B | 打包流程健全化 + dist 重建 | scripts/package.ps1 + dist/ |
| C | 使用手冊更新 + 概念章節 | USER-MANUAL.md |
| D | 授權 Apache-2.0 → MIT | LICENSE/NOTICE/Cargo.toml/README |
| E | 健全性混合審計 | REMAINING-WORK.md 更新 + 審計摘要 |

執行順序:A → C → D → B → E。理由:C 要寫 A 的新功能;B 打包收攏 A/C/D 全部
產物;E 審計殿後,結果進 backlog,不阻擋前四段。

---

## 段 A — Launcher 工程師模式補實

### 範圍(YAGNI 削減後)

工程師模式子選單只做兩項真需求:

```
[1] 選 profile 掃描      → 再選 minimal / standard / verbose,之後走既有掃描流程
[2] 離線 EVTX 分析       → 輸入 .evtx 檔或目錄路徑,包裝 `cairn evtx` 子指令
[B] 返回主選單
```

**明確排除**(審視後砍掉的冗餘):
- ~~自訂輸出位置~~:預設 `output\` 已符合 golden rule 4(輸出離 target);要改位置
  的人就是會用 CLI 的人。少一個要驗證的輸入入口。
- ~~verify 包裝~~:完整性驗證的真實場景是分析師收到 zip 之後在自己機器做,
  不在受害端點做。
- ~~update-rules~~:launcher 保持零網路(見安全護欄)。
- ~~ratatui 全螢幕 TUI~~:維持純 stdin/stdout 選單。受害端點上跑的工具越簡單
  越好,也少一個重依賴。

profile 值以 `cairn_core::Profile` 為準:`Minimal / Standard / Verbose`
(config.rs:17-21;不是 full——已對源碼查證)。

### 架構(沿既有縫,不開新模式)

現有分層不動:`menu.rs` 純 I/O、`runner.rs` 純參數組裝 + spawn、`summary.rs`
純解析、`main.rs` 流程編排。新增內容全部照同形狀:

1. `runner.rs`:`RunConfig` 加 `profile: Option<&str>` 欄位;`build_args` 對應
   擴充(None 時不帶 `--profile`,沿用 cairn 預設 standard)。**快速掃描與工程師
   掃描共用同一個 `run_scan_flow`**,只差 profile 參數——不複製第二份掃描邏輯。
2. `runner.rs`:新增 `EvtxConfig` + `build_evtx_args` 純函式,與 `build_args`
   對稱(可單元測試):`evtx --input <path> --output <dir> [--rules <dir>]`
   (實際旗標名以 cairn-cli 的 evtx 子指令 clap 定義為準,實作時逐字核對)。
3. `menu.rs`:新增 `read_path_input() -> Option<PathBuf>` 純輸入清理函式
   (去除前後引號與空白 → 空輸入回 None),與新的工程師子選單渲染函式。
4. `main.rs`:`'3' =>` 分支從 stub 換成工程師子選單 loop。

diff 預算:±150 行(含測試)。超過 3 倍停下回報(judgment.md §4)。

### 安全護欄(security.md §2/§3 對照,實作與審查時逐條核)

新增外部輸入只有一個:EVTX 路徑(stdin)。

- **輸入驗證(§3 白名單)**:去引號後驗證(a)路徑存在;(b)是 `.evtx` 副檔名的
  檔案,或是目錄;不符合 → 印錯誤回子選單,不傳給 cairn.exe。
- **免疫指令注入**:沿用 runner.rs 既有 `Command::args(&[...])` 陣列傳參模式,
  參數永不經 shell 字串拼接。新函式禁止改用 `cmd /c` 或字串拼接。
- **零網路**:launcher 不暴露任何會發網路請求的子指令(update-rules 留在 CLI)。
  launcher 能力邊界 = 唯讀收集 + 本地輸出(§6 最小特權)。
- **golden rules 不動**:collector/analyzer 縫、輸出離 target、graceful degrade
  全部不受影響——launcher 只是 cairn.exe 的參數前端。

### 測試

- 單元:`build_args` 含/不含 profile 兩案;`build_evtx_args` 含/不含 rules 兩案;
  `read_path_input` 去引號/空輸入/前後空白三案。
- 真機 e2e(手動):打包後雙擊 launcher → 工程師模式 → verbose profile 掃描一次
  + 對一個真實 .evtx 跑離線分析一次,確認摘要框與輸出目錄正確。

---

## 段 B — 打包流程健全化

`scripts/package.ps1` 修改:

1. 複製清單加入:`USER-MANUAL.md`、`LICENSE`、`NOTICE`。
2. 打包尾聲重新產生 `CHECKSUMS.txt`(SHA-256,涵蓋包內全部檔案;先確認現有
   CHECKSUMS 產生邏輯在哪——若 package.ps1 現版沒有,補上)。
3. 跑一次完整打包,重建 `dist/cairn-forensics/`,讓 binary 追上 main。

護欄:腳本維持純本地 build + copy + hash,無任何下載/網路行為(security.md §8)。

驗收:`dist/cairn-forensics/` 內含 7 項(cairn.exe、cairn-launcher.exe、rules\、
USER-MANUAL.md、LICENSE、NOTICE、CHECKSUMS.txt);雙擊 launcher 走一次快樂路徑;
`cairn.exe --version` 顯示的 build_sha 等於當下 main HEAD。

---

## 段 C — 使用手冊更新 + 概念章節

`USER-MANUAL.md` 單一文件維護(使用者選定,不拆兩份):

1. **新增「第 0 章:它怎麼運作、能幫你什麼」**,寫給非工程師:
   - 運作邏輯:收集(唯讀)→ 分析(Sigma 規則 + 可解釋啟發式)→ 報告(帶
     SHA-256 完整性簽章的時間軸 + HTML 報告)三階段管線;
   - 為什麼結果可信:每個檔案有 hash、manifest 記錄哪些模組跑了/為什麼跳過、
     所有 heuristic 附 reason 不給黑箱分數;
   - 什麼情境用它:疑似入侵端點的快速分類(triage),不是完整取證替代品;
   - 它不做什麼:不修改主機、不迴避 EDR、不連網(update-rules 除外且僅工程師用)。
2. **主要入口改寫**:一般使用者走 launcher 雙擊流程(含工程師模式兩項新功能);
   CLI 指令參考保留為工程師章節。
3. **補新功能**:BYOVD 偵測、IR 即時狀態面板、HTML 報告篩選/聚合、gate 重構後的
   persistence 判定行為。
4. **版本戳**:更新至當下 main HEAD 的 commit 與日期;授權敘述改 MIT(配合段 D)。

驗收:read-back 逐章核對;文內每個指令/路徑/選單項與實際程式碼逐一回源核對
(judgment.md §5 文件驗證標準);概念章節不出現未解釋的術語。

---

## 段 D — 授權 Apache-2.0 → MIT

1. `LICENSE`:換 MIT 全文,著作權行沿用 NOTICE 現有署名
   (`Copyright (c) 2026 Cairn project (ali-bobo)`)。
2. workspace `Cargo.toml`:`license = "MIT"`(各 crate 用 `license.workspace = true`
   自動繼承,免逐一改)。
3. `NOTICE`:開頭授權引用段改指 MIT;**Sigma DRL 1.1 歸屬段落逐字保留**——那是
   上游 SigmaHQ 規則的授權(rules/sigma/ 的 XOR 編碼規則 + PROVENANCE),
   不隨本專案授權變更,golden rule 5(rule_author)的法律基礎就在這。
4. `README.md`:授權章節同步。
5. 全 repo grep `Apache`,確認無殘留引用(docs/ 內歷史紀錄除外,不改史料)。

已知取捨(使用者知情):MIT 無 Apache-2.0 的專利授權條款;對個人開源專案
影響極小。

驗收:`grep -ri "apache" --include="*.toml" --include="LICENSE*" --include="NOTICE"`
無命中;`cargo package --list -p cairn-core` 等元資料檢查通過(或至少
`cargo check` 不因 license 欄位報警)。

---

## 段 E — 健全性混合審計

兩路並行,結果合流:

1. **fresh-context 獨立審計**(派 agent,對照 golden rules 8 條 + SRS):
   - 錯誤處理缺口(silent failure、被吞掉的 Err);
   - 擴充點健全度(新增 collector/heuristic 的接線成本、trait 縫是否仍乾淨);
   - 發佈流程缺口(對照 CLAUDE.md「Legitimacy work」清單:簽章、版本資源、
     hash 發佈、WDSI 送審——哪些已做哪些沒做);
   - 只審不改,產出 finding 清單(檔案:行號 + 嚴重度 + 一行修法)。
2. **backlog 差距校正**:REMAINING-WORK.md 段 1–7 逐段對照程式碼實況
   (例:段 1 HTML 已由 PR #30 完成,要標記;其餘段的前提是否仍成立)。

合流:兩邊結果合併進 REMAINING-WORK.md——新 finding 依嚴重度插入建議執行順序,
過期段落標記完成/修正前提;審計摘要(≤1 頁)直接附於 REMAINING-WORK.md 附錄,
不另開檔案(單一事實來源)。

驗收:REMAINING-WORK.md 的「目前位置」與各段狀態跟 `git log` / 程式碼實況
零矛盾;每個新 finding 有檔案:行號證據。

---

## 跨段紀律

- 每段獨立 branch + GitHub PR + CI 綠燈後 merge(絕不 local merge 直推 main)。
- 段 A 走 brainstorm(本 spec)→ writing-plans → subagent-driven-development;
  段 B/C/D 為小段,可由 writing-plans 產出的同一份 plan 內含或獨立小 PR;
  段 E 派工照 delegation.md §6(審計者 fresh context,驗收條件原文轉交)。
- 測試範圍紀律照 cairn/CLAUDE.md:subagent 跑 `cargo test -p cairn-launcher`,
  全 workspace 權威驗證留給 finishing-a-development-branch。
- 零新依賴(全段);schema 零變動;`#![forbid(unsafe_code)]` 在 cairn-launcher
  維持。
