# dev-history 索引

此索引記錄每個 spec/plan 的現況；深入讀個別 spec 前先看這裡判斷是否還相關。

| 日期 | Topic | 狀態 | 說明 | Commit |
|---|---|---|---|---|
| 2026-06-12 | S2-A：orchestrator + proc/net collector | 已合併 | live orchestrator + Proc/Net collector 基礎架構（PR #1） | c83a169 |
| 2026-06-13 | S2-B：heuristics（parentchild + netconn） | 已合併 | 首批純邏輯 heuristic analyzer 上線（PR #2） | 36a622f |
| 2026-06-13 | S2-C：persistence collector + heuristic | 已合併 | Run/RunOnce、Winlogon、IFEO、services、startup 持久化偵測 | bb2e92a |
| 2026-06-13 | S2-D：signature verification | 已合併 | WinVerifyTrust 簽章驗證接進 persist（PR #4） | c878cbf |
| 2026-06-13 | S2-E：process signed + full path | 已合併 | 行程完整路徑 + 簽章回填 + unsigned 放大器（PR #5） | 84cd5bf |
| 2026-06-13 | S2-F：binpath candidate normalization | 已合併 | binary_path 候選正規化（quote/env 展開）（PR #6） | 8b23b87 |
| 2026-06-14 | S2-G：catalog-signed verification | 已合併 | Catalog WinVerifyTrust fallback 完成（PR #7） | 7bae7d3 |
| 2026-06-14 | S2-H：heuristic calibration | 已合併 | 兩道抑制閘門降誤判（Userinit/AppData 白名單）（PR #9） | dd42d1e |
| 2026-06-14 | S2-I：scheduled tasks collector | 已合併 | XML 排程任務解析 + T1053.005 heuristic（PR #10） | c203139 |
| 2026-06-14 | S2-J：signer identity | 已合併 | 內嵌 Authenticode CN 簽署者欄位（PR #11） | a412993 |
| 2026-06-14 | S2-K：binary hashing | 已合併 | ProcessRecord 加 binary_sha256（capped streaming hash）（PR #12） | 3533fef |
| 2026-06-15 | S2-L：profile-only wiring（含 raw-NTFS decomposition） | 已合併 | `--profile`/`--only` 接線 + select_modules 純函式（PR #13） | 1f0fbfc |
| 2026-06-16 | S2-M：raw volume primitive | 已合併 | 唯讀 `\\.\C:` VolumeReader + MftCollector 骨架（PR #14） | ba4cf47 |
| 2026-06-17 | S2-N：$MFT MACB timestamps | 已合併 | $MFT SI/FN 雙軸 MACB 時間萃取（PR #15） | 7e1decf |
| 2026-06-18 | S2-N'：timestomp heuristic | 已合併 | SI/FN 落差偵測時間戳篡改（T1070.006）（PR #16） | 7878799 |
| 2026-06-18 | S2-O：path map | 已合併 | $MFT parent-ref 全路徑重建 | fc562e6 |
| 2026-06-20 | governance（NFR9/10 資源治理） | 已合併 | max-threads/priority 節流 + truncation 表面化 | 76b0c57 |
| 2026-06-20 | usn-journal（$J collector） | 已合併 | $UsnJrnl:$J ADS 解析（USN record scan） | cd6e9d4 |
| 2026-06-20 | hive-reader + shimcache | 已合併 | 離線鎖定 hive 讀取地基（notatin）+ AppCompatCache 解析 | 47881e5 |
| 2026-06-21 | amcache-collector（InventoryApplicationFile） | 已合併 | Amcache.hve 執行紀錄萃取 | 031d587 |
| 2026-06-21 | amcache-driver（InventoryDriverBinary） | 已合併 | 驅動 SHA1 萃取，供 BYOVD 比對用 | 96c4bc6 |
| 2026-06-21 | prefetch-collector | 已合併 | .pf 檔 MAM 解壓 + run_count/first-last run 三欄齊全 | 805f592 |
| 2026-06-22 | bam-collector | 已合併 | SYSTEM hive BAM 鍵，raw 讀繞過 ACL | 0ba542d |
| 2026-06-22 | userassist-collector | 已合併 | NTUSER.DAT UserAssist ROT13 解碼（S2 正式封頂） | df29f72 |
| 2026-06-24 | output-sink（S3） | 已合併 | Zip/Age sink（PR #26） | eddd2af |
| 2026-06-24 | srum-collector（僅有 plan，無 spec） | 已合併 | SRUM ESE 資料庫解析（srum_app/srum_net）（PR #27） | 9c0f2a4 |
| 2026-06-25 | details-client | 已合併 | 人類可讀 details_client 欄位填充 | 2fa6b03 |
| 2026-06-25 | bodyfile（FR20） | 已合併 | bodyfile/plaso 輸出格式 | 5b210b7 |
| 2026-06-25 | update-rules（FR19） | 已合併 | SigmaHQ 規則同步 + SSRF 白名單 + DRL 1.1 編碼 | f4bab7e |
| 2026-06-26 | noise-reduction-and-readability（S5-A） | 已合併 | details_client 豐富化、netconn/persist 抑制規則、bodyfile CSV 欄位 | a746f37 |
| 2026-06-26 | timeline-csv-enrichment（僅有 plan） | 已合併 | timeline.csv 加 Reason/Entity/DetailsClient 欄位 + UTF-8 BOM | c44cbac |
| 2026-06-26 | cross-artifact-correlation | 已合併 | CorrelationAnalyzer 跨文物佐證（後於 heuristic-gate-redesign 退場，見下） | ce80533 |
| 2026-06-27 | live-evtx-integration | 已合併 | EvtxLiveCollector + SigmaAnalyzer 接進 live run | f349fc6 |
| 2026-06-27 | cairn-launcher | 已合併 | 獨立 launcher 執行檔（選單+打包+執行） | 683e563 |
| 2026-06-28 | correlation-severity-tuning | 已合併 | 依路徑信任與簽章狀態調整關聯嚴重度 | 0a18758 |
| 2026-06-28 | account-heuristic | 已合併 | 帳號建立/刪除/群組事件 heuristic | 00b2efe |
| 2026-07-02 | heuristic-gate-redesign | 已合併 | dispositive-signal 模型修正 >90% 誤判率；CorrelationAnalyzer 退場、改由 persist gate 內建跨文物佐證 | 068983e |
| 2026-07-03 | ir-snapshot-panels | 已合併 | report.html 5 面板（conn/proc/exec/file/logon）+ LogonSessionCollector | 88831a1 |
| 2026-07-03 | fileless-attack-coverage（僅有 spec，無 plan） | 待辦（FUTURE） | WMI 訂閱 + EVTX 認證/PowerShell/橫向移動 + 登入暴力破解偵測；設計完成但尚未進入實作階段 | — |
| 2026-07-04 | byovd-driver-detection | 已合併 | amcache_driver SHA1 比對已知漏洞驅動清單 | 60691fd |
| 2026-07-04 | temporal-window-correlator（僅有 spec，無 plan） | spec 待審 | 誠實時間窗證據關聯（非因果鏈）；最新項目，剛完成 brainstorm，尚未進入 subagent-driven 執行 | — |
| 2026-07-08 | html-report-filtering | 已合併 | 報告篩選（嚴重度/文物/關鍵字）+ 同源 binary 聚合面板 + state_active 補接線 + netconn 改名 | 74aefba |
| 2026-07-09 | usability-governance（段 8） | 已合併 | launcher 工程師模式補實 + 打包健全化 + 手冊更新含概念章 + Apache→MIT + 混合健全性審計（含 build.rs PE 授權修正 F-11） | 30ecb8f |
| 2026-07-10 | resilience-audit（段 8 附錄） | 已合併（審計報告） | 12 findings；F-1（live proc 不採集 cmdline/integrity→parentchild 訊號靜默）列為段 9 主題；F-8 進度回饋缺失 | 30ecb8f |
| 2026-07-10 | proc-cmdline-integrity（段 9） | 規劃中 | F-1+F-8：live proc collector 補採集 cmdline（PEB/NtQueryInformationProcess）+ integrity（OpenProcessToken）+ 掃描進度回饋；動 unsafe WinAPI（cairn-collectors-win） | — |
