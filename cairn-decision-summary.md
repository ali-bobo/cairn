# Cairn 專案 — 決策摘要與長期評估

> 完整規格在 `cairn-SRS.md`(英文、高密度、為將來生成程式碼最佳化)。
> 這份是給你拍板方向用的。`cairn` 是暫定代號(中性、無攻擊意味),可改。

---

## 一、它是什麼(一句話)

一支**簽章過的單一 Rust 執行檔**,在客戶端點上**就地**做活體鑑識:解析活體狀態(行程樹 / 網路 / persistence)+ EVTX 事件 + 離線 artifact(MFT/登錄檔/Prefetch/Amcache…),套用 **Sigma 規則 + 啟發式研判**,輸出**精簡、帶嚴重度與 ATT&CK 標籤、附 SHA-256 manifest** 的時間軸。純 user-space、不碰 kernel、不做任何規避。

設計藍本 = Hayabusa(引擎)+ Chainsaw(artifact 獵捕)+ KAPE(採集/解析分離)+ Velociraptor offline collector(封裝),融進同一個 process。

---

## 二、我對「當成長期大專案」的誠實評估

**結論:值得做,但價值不在「再寫一個鑑識引擎」,而在「整合 + 你的 MDR 工作流貼合度」。** 請務必 MVP 先行。

**現實面 — 這是擁擠的賽道。** EVTX+Sigma 的 Rust 工具,Hayabusa 和 Chainsaw 已經做得很成熟;活體採集有 Velociraptor;離線 artifact 解析有 EZ Tools(C#)。如果你的工具只是「再做一次它們做過的事」,長期維護的投報率不高。

**真正的差異化(也就是這專案該賭的點):**
1. **單一執行檔、一次跑完「活體狀態 + 日誌 + 離線 artifact」** — 現在分析師要串 Hayabusa + Chainsaw + EZ Tools 多支工具,你把它收斂成一支。這個整合本身有價值。
2. **輸出 schema 直接餵你既有的 pipeline** — Finding 結構可直接接你的 `mdr-incident-report-builder` 與 `deidentify.py`。這是別人沒有、只有你會有的端到端優勢。
3. **雙語 Finding** — 技術版(en)+ 客戶白話版(zh-TW,不誇大、定義術語、保留不確定語氣),貼合你客戶溝通原則。

**成本面 — 要誠實看待規模。** 做到完整四階段是數個月等級的工程,而且部分 Rust 離線解析 crate(ESE/SRUM、某些 hive 邊界情況)成熟度不如 C# 的 EZ Tools,可能要自己包或回饋上游。所以:**Stage 1 必須自己就能用、就有價值**,不能等到全部做完才有產出。

**履歷/能力面 — 高價值。** 不論商業成敗,一個簽章、開源、走正規 DFIR 路線、用 Sigma/ATT&CK 的 Rust 鑑識工具,對你的專業定位是很強的作品。

---

## 三、必須先確認:你最初的方向被推翻了

你第一輪提到的「降熵、抹除特徵、對 EDR 隱形、看起來像系統原生元件」—— 研究證實這**正是惡意程式的特徵**,會讓行為型 EDR 更想抓你。合法工具走相反路線:**簽章、透明留痕、開源、可預測檔名、發布 hash、事前向客戶 SOC 申請 allowlist**。EDR 應該看得到你的工具、並認得它良性。這正好解決你第二輪講的「怕被誤認成駭客工具」—— 答案是**爭取被認可**,不是躲。

規格書 §13 已經把這條寫成**硬性需求**:injection / syscall 規避 / AMSI·ETW bypass / packing / 混淆 / artifact 抹除 一律 auto-reject。

---

## 四、技術上最硬的一塊(先知道)

Windows 的 $MFT、$J、登錄檔 hive 在系統運行時是鎖住的。解法是 **raw `\\.\C:` volume 讀取 + NTFS 解析**(Rust `ntfs`/`ntfs-reader`),需要 Administrator + `SeBackupPrivilege`;VSS 快照當備援。這是 KAPE/CyLR/Velociraptor 都在用的合法手段。

---

## 五、需要你拍板的方向選項

| # | 決策 | 選項 | 我的建議 |
|---|---|---|---|
| 1 | **第一階段做哪塊** | (A) EVTX+Sigma 引擎先(可獨立驗證、對標 Hayabusa) / (B) 活體採集先(行程/網路/persistence) | **A**:最容易驗證、風險最低、立刻能對標,且是其他模組的資料骨架 |
| 2 | **Sigma 引擎** | sigma_engine / sigmars / tau-engine / 自寫 | 先 benchmark `sigma_engine` 與 `sigmars`,用 trait 包起來可換 |
| 3 | **離線 artifact 範圍(S2)** | 全做 / 先做高價值(MFT、Amcache、Shimcache、persistence hive) | 先高價值;SRUM/ESE 因 crate 成熟度延到 S3 或砍 |
| 4 | **規則上架方式** | 純 .yml / XOR 編碼(避免 AV 對 .yml 誤判) | 編碼(Hayabusa 已有此先例) |
| 5 | **代號/檔名** | cairn / 你想的名字 | 隨意,但要中性、無攻擊意味、可預測 |
| 6 | **下一步交付** | (A) 我直接開 Cargo workspace + Stage1 骨架程式碼 / (B) 先把 S1 模組再細到函式級 spec / (C) 先做 Sigma 引擎選型 benchmark 計畫 | 看你想先動哪 |

---

## 六、建議路線(若你說「照建議走」)

1. 鎖定 **Stage 1 = EVTX + Sigma + 時間軸 + manifest**,當成可獨立交付的工具。
2. 我先開 workspace 骨架:`cairn-core`(Record/Finding 型別 + trait)、`cairn-cli`、`cairn-sigma`(SigmaMatcher trait)、`cairn-report`。
3. 接 `evtx` crate 把 EVTX → JSON record 跑通,先不接規則,先確認解析與輸出。
4. 選定 Sigma 引擎、做 logsource「去抽象化」對應表,跑 EVTX-ATTACK-SAMPLES 驗證命中。
5. S1 通過驗收門檻(命中正確、吞吐 ≤2× Hayabusa、manifest 可驗證)後,才往 S2 活體採集走。
6. 真正用在客戶前,先補完簽章 / README / WDSI / SOC runbook。

---

跟我說你在第五節的選擇(或「照建議走」),我就接著做你選的下一步交付。
