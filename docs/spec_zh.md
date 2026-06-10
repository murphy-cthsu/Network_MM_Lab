# 專案規格書 — TPM 硬體認證裝置 & AI 模型完整性（Raspberry Pi 5）

> 對象：開發團隊（人類閱讀）。English 版（`SPEC_EN.md`）給 Claude Code 當實作依據，內容一致、只是寫法更精簡可執行。

---

## 1. 一句話與動機

做一個以 **TPM 為硬體信任根**的遠端認證系統：裝置必須先「證明自己的軟體沒被竄改」，某個有用的功能才會放行。一旦被動手腳，功能直接失效，遠端驗證端也會把它標成 `COMPROMISED`。

為什麼這題在實驗課值得做：
- Demo 有強烈的「篡改即失能／翻紅燈」瞬間，不用解釋就看得懂。
- 用到真實硬體（TPM 晶片 + Hailo NPU），不是純軟體模擬。
- Phase 2 的「AI 模型完整性」主題夠新，教授幾乎不會看過學生做出實體版本（理由見第 11 節）。

分兩階段，且**兩階段共用約 90% 的程式碼**：
- **Phase 1（地基）**：認證「平台」（執行檔）。放行功能 = 解密並播放一段影片。
- **Phase 2（主打）**：把認證範圍延伸到 **Hailo NPU 上跑的 AI 模型檔**。換掉模型會被偵測，推論輸出被拒絕。

關鍵設計：**驗證端是通用的**——它只判斷「量測到的雜湊有沒有對上允許清單」，根本不在乎被量測的是執行檔（Phase 1）還是模型檔（Phase 2）。所以 Phase 2 主要只是改 IMA 量測政策 + 加一筆允許清單 + 換 payload。

---

## 2. 硬體（已確認的事實）

- **底板：Raspberry Pi 5**（已確認；因為 AI HAT+ 26 TOPS 只能透過 PCIe 在 Pi 5 上運作）。
- **TPM：LetsTrust TPM HAT（Infineon SLB9670，走 SPI）**——與參考專案同一顆晶片，照著做不會卡硬體。
- **AI 加速器：Raspberry Pi AI HAT+ 26 TOPS（Hailo-8）**——走 PCIe 排線，會佔住 GPIO，只有 Phase 2 才需要。
- OS：Raspberry Pi OS 64-bit（Bookworm）。
- 驗證端：開發筆電（能跑 Python 3 與 `swtpm` 即可）。

---

## 3. 開發工作流（重要，先讀這段）

核心觀念：**能在筆電上做的就在筆電上做，最後才上 Pi 驗證硬體。** 而且能在筆電上做的比你想的多。

- **軟體 TPM（`swtpm`）**：筆電裝一個 TPM 模擬器，整套認證邏輯（產生 AK、產生 quote、以及**整個驗證端**：驗簽、IMA log 重放、允許清單比對）都能在筆電上開發測試，完全不用碰 Pi。驗證端本來就跑在筆電上。
- **只有這三件事一定要在 Pi 上**：真實 TPM 硬體點亮、IMA 真的把量測寫進真實 PCR 10（kernel 功能、無法在筆電模擬）、Phase 2 的 Hailo 推論。
- **IMA 無法在筆電模擬**：所以筆電開發驗證端時，用 `dev/sample_ima_log/` 裡**事先錄好的 IMA log** 來測重放與比對邏輯。
- **GitHub**：當版本控制與真實來源（source of truth），很好。但要在 Pi 上快速迭代，比 commit-push-pull 更順的是 **VS Code Remote-SSH**——在筆電的編輯器寫、程式直接在 Pi 上跑。Git 用來打 checkpoint，Remote-SSH（或 `rsync`／`sshfs`）用來跑緊湊的開發迴圈。
- **先排雷**：動手寫一堆東西之前，先確認 Pi 5 在 IMA 底下真的看得到 TPM（這是 Pi 5 的已知雷，見第 7 節）。這就是 Phase 0 的關卡。

---

## 4. 架構

```
            (1) nonce 挑戰
 ┌────────────┐  ───────────────►   ┌──────────────────┐
 │  驗證端     │                      │   被驗證端        │
 │ （筆電）    │  ◄───────────────    │ （Raspberry Pi 5）│
 └────────────┘  (2) quote + IMA log └──────────────────┘
   - AK 公鑰                            - TPM（SLB9670）
   - allowlist.json（黃金雜湊）         - IMA → PCR 10 + 量測 log
   - 驗 quote 簽章（tpm2_checkquote）    - AK（受限簽章金鑰）
   - 重放 IMA log → 重算 PCR10          - 封印的秘密（綁 PCR policy）
   - 逐筆比對允許清單                    - payload（影片／Hailo 推論）
   - 判定 TRUSTED / COMPROMISED         - 竄改腳本（demo 用）
   - 儀表板（綠／紅）
```

**威脅模型（報告要誠實寫）**：Pi 5 沒有 x86 那種完整 UEFI measured-boot 鏈，所以我們用 **IMA 的執行期量測**，把執行／讀取的檔案雜湊 extend 進 PCR 10。我們防的是**軟體層的竄改**（換二進位檔／換模型），不是拔晶片那種實體攻擊。

**放行機制**：用 TPM 把一把秘密（AES 金鑰）**封印到 PCR 10 的 policy**。只有 PCR 10 與良好值相符，裝置才能 `tpm2_unseal` 解開它。這就是「被竄改後裝置自己失能」的戲劇效果。遠端驗證端負責**獨立驗證與視覺化**（它從不需要相信裝置的自我回報）。

---

## 5. 技術堆疊

- **被驗證端（Pi）**：Python 3、`tpm2-tss`、`tpm2-tools`、`tpm2-pytss`、Linux **IMA**。Phase 2 另加 **HailoRT** 與一個 `.hef` 模型（例如 Hailo model zoo 的 YOLOv8）。
- **驗證端（筆電）**：Python 3、**Flask**（HTTP + 儀表板）、`tpm2-tools`（`tpm2_checkquote`）或 `cryptography` 做驗簽、極簡 HTML/JS 儀表板。
- **開發**：`swtpm`（軟體 TPM）、VS Code Remote-SSH、GitHub。

---

## 6. Repo 結構

```
.
├── CLAUDE.md                 # （= SPEC_EN.md 副本，給 Claude Code）
├── README.md
├── attester/                 # 在 Pi 上跑
│   ├── provision.py          # 建立 EK + AK、保存 AK、匯出 AK 公鑰
│   ├── agent.py              # nonce → tpm2_quote(PCR10[,0-9]) + 讀 IMA log → POST
│   ├── seal.py               # 把 AES 金鑰封印／解封到 PCR-10 policy
│   └── payload/
│       ├── play_video.py     # Phase 1 放行功能（解密 + 播放）
│       └── infer_hailo.py    # Phase 2 放行功能（Hailo 推論）
├── verifier/                 # 在筆電上跑
│   ├── server.py             # Flask：/nonce、/evidence、/dashboard
│   ├── verify.py             # checkquote + IMA log 重放 + 允許清單比對
│   ├── allowlist.json        # 黃金量測（P1：執行檔；P2：+ 模型雜湊）
│   └── static/               # 儀表板 UI（綠／紅、量測清單）
├── tamper/
│   ├── tamper_binary.sh      # Phase 1 demo：改一個被量測的執行檔
│   └── swap_model.sh         # Phase 2 demo：替換 .hef 模型
├── dev/
│   ├── swtpm_setup.sh        # 筆電開發用的軟體 TPM
│   └── sample_ima_log/       # 離線開發驗證端用的錄製 IMA log
└── docs/
    ├── SPEC_EN.md
    └── SPEC_ZH.md
```

---

## 7. 認證協定（照這個流程實作）

1. 驗證端產生新的隨機 `nonce`（≥16 bytes），記下並設短 TTL，回傳。
2. 被驗證端用 **AK** 對 PCR 選擇（至少 **PCR 10**，可選加 0–9）跑 `tpm2_quote`，把 `nonce` 當 qualifying data（`-q`）。從 `/sys/kernel/security/ima/ascii_runtime_measurements` 讀 IMA log。
3. 被驗證端把 `{ quote, signature, pcr_values, ima_log }` POST 到 `/evidence`。
4. 驗證端：
   a. 用存好的 AK 公鑰 + `nonce` + 回報的 PCR 跑 `tpm2_checkquote` → 同時驗簽**並**確認 nonce 相符（防重放）。
   b. **重放 IMA log**：把每筆 template hash 依序折進一個 SHA-256 的 PCR-10 累積值，斷言它等於 quote 裡的 PCR 10（把 log 綁到 TPM 認證過的值）。
   c. 逐筆把 log 裡的檔案雜湊跟 `allowlist.json` 比對。任何一筆不在清單 → `COMPROMISED`，並記下是哪一筆失敗。
   d. 回傳判定 +（Phase 1/2）解封授權，或只回判定給儀表板。
5. 儀表板顯示 `TRUSTED`（綠）/ `COMPROMISED`（紅），並標出出問題的那一筆。

---

## 8. 分階段任務與完成定義（DoD）

### Phase 0 — 環境與硬體點亮（**最先做**）
- **0.1** 建 repo + 結構 + `.gitignore`（祕密、AK 私鑰 blob、金鑰一律不進 git）。
- **0.2** 筆電裝 `tpm2-tss`、`tpm2-tools`、`tpm2-pytss`、`swtpm`；`dev/swtpm_setup.sh` 起一個軟體 TPM。
  *DoD：* 筆電上對 swtpm 跑 `tpm2_pcrread sha256:10` 成功。
- **0.3** Pi 5 接上 LetsTrust TPM（Phase 0/1 先把 AI HAT 拆掉）。開 SPI；`config.txt` 加 `dtoverlay=tpm-slb9670`。
- **0.4 風險關卡**：build／boot 一個 **TPM 設成 built-in**（不是 module）且開 **IMA** 的 kernel；`cmdline.txt` 加 `ima_policy=tcb`（或自訂）。
  *DoD：* Pi 上 `tpm2_pcrread sha256:10` 顯示 **非零** PCR 10（即 `boot_aggregate` 有值）、`/dev/tpm0` 存在、IMA log 非空。**若出現 TPM-bypass，先在這裡解決，不要往下做。**

### Phase 1 — 平台認證 + 封印秘密的放行功能
- **1.1** `provision.py`：建 EK、建受限簽章 **AK**、保存 AK、匯出 AK 公鑰給驗證端。*DoD：* 產出 AK 公鑰檔，swtpm 與 Pi 都能跑。
- **1.2** `agent.py`：實作協定第 2–3 步。*DoD：* 對 swtpm + 樣本 IMA log 產出驗證端會接受的 quote 與封包。
- **1.3** `verify.py` + `server.py`：實作第 4 步（checkquote、IMA 重放、允許清單比對）+ `/nonce`、`/evidence`。*DoD：* 乾淨證據 → `TRUSTED`；含未知雜湊的證據 → `COMPROMISED` 並指出是哪一筆。
- **1.4** `seal.py`：把 AES 金鑰封印到 PCR-10 policy；`play_video.py` 解封 + 解密 + 播放短片。*DoD：* 乾淨狀態 → 解封成功 → 影片播放。
- **1.5** `verifier/static/`：儀表板（綠／紅 + 量測清單 + 標出失敗筆）。
- **1.6** `tamper/tamper_binary.sh`：改一個被量測的執行檔。*DoD：* 竄改後重新認證 → PCR-10 不符／清單比對失敗 → 解封**失敗** → 影片播不出來 → 儀表板**紅**。可重現 5/5 次。

### Phase 2 — AI 模型完整性（重用 Phase 1 全部）
- **2.1** 物理 + runtime：用**加長版 GPIO stacking header**（或把 TPM 的 SPI 用跳線接到露出的腳位）讓 TPM 與 Hailo 並存；裝 HailoRT；跑一個 baseline `.hef` 推論。*DoD：* `hailortcli fw-control identify` 正常 **且** 同時 `tpm2_pcrread` 仍看得到 TPM。
- **2.2** IMA 政策：加一條 `measure func=FILE_CHECK mask=MAY_READ`（或限定路徑／uid）的規則，讓**模型檔在被載入時被量測**進 PCR 10。*DoD：* 跑完推論後，`.hef` 雜湊出現在 IMA log。
- **2.3** `allowlist.json`：加入黃金模型雜湊；驗證端把模型完整性納入同一套認證。*DoD：* 乾淨模型 → `TRUSTED`。
- **2.4** 把模型使用綁在認證／封印上（例如解模型用的金鑰、或「採信輸出」的 token，封印到現在已包含模型量測的 PCR-10 policy）。
- **2.5** `tamper/swap_model.sh`：把 `.hef` 換成被改過的模型。*DoD：* 替換後重新認證 → IMA 量測改變 → `COMPROMISED` → 推論輸出被拒絕／標記 → 儀表板**紅**。可重現 5/5 次。

---

## 9. 已知風險與緩解
- **Pi 5 IMA/TPM bypass**：把 TPM 設 built-in、Phase 0 先驗證、必要時換較新 kernel。
- **AI HAT+ 擋住 GPIO**（passthrough header 太短）：用加長 stacking header 或跳線接 SPI；Phase 2 之前 AI HAT 先不要裝。
- **Pi 5 供電預算**（AI HAT + 周邊）：用官方 27W 電源，少接無關周邊。
- **IMA 對資料檔（模型）做讀取量測**：需要正確的政策規則（任務 2.2）。
- **重放／新鮮度**：nonce 設 TTL，並在 `tpm2_quote -q` 綁 nonce。
- **現場 demo 不穩**：事先備好「乾淨」與「被竄改」兩種狀態，竄改只要一個按鍵，務必彩排。

## 10. Demo 流程（目標 3–4 分鐘）
1. 乾淨開機 → 認證 → `TRUSTED`（綠）→ 影片播放（P1）／辨識正確（P2）。
2. 現場竄改：`tamper_binary.sh`（P1）或 `swap_model.sh`（P2）。
3. 重新認證 → `COMPROMISED`（紅）→ 放行功能失效／輸出被拒。
4. 一句話解釋：因為 IMA 量測到被改過的檔案，PCR 10 變了，封印金鑰不會釋出。

## 11. 專題定位與簡報框架（A/B/C/D；給報告與簡報用）

> 這一段同時是「回答助教相機問題」的標準說法，也是簡報開場的敘事骨架。
> **核心策略（避免爭議）**：把自己定位成 C2PA 的**互補層**，絕對不要說「C2PA 壞掉、我們取代它」——這樣才避得開「那不就已經有了」的質疑。

**🎯 記憶點（一句話，開場與結尾各講一次）：**
> 「簽章證明這張圖是誰簽的；我們證明簽的那一刻，產生它的那台裝置本身沒被動過手腳。」
>
> （DRM 版，更白話）「盒子憑什麼解得開影片？因為它得先向遠端證明自己的軟體沒被竄改。」

**A. 主題名稱**
平台完整性遠端認證——當「資料可信」還不夠，我們證明「裝置本身可信」。
（專案代號可取 VeriBox／TrustGate 之類，方便 repo 與投影片命名。）

**B. 主題背景**
在 AI 生成與深偽（deepfake）的時代，「這個影像／資料是真的嗎」成為關鍵問題。業界的回應是「內容來源憑證」：拍攝當下用相機裡的安全元件對影像做密碼學簽章（C2PA：Nikon、Google Pixel 10、Leica、Sony 都已導入）。但「數位證據可不可信」其實有三層，常被混為一談——把這三層講清楚，就顯得比一般人懂一截：
1. **EXIF／metadata 鑑識**：事後分析可竄改的中繼資料。Depp v. Heard 案用的就是這個（專家從 EXIF 看出照片是用編輯軟體輸出的），證明力弱、可被雙方互相反駁。
2. **C2PA 內容憑證**：拍攝當下的硬體簽章，證明「這張圖由某裝置產生、之後沒被編輯」，比 metadata 強很多。
3. **平台遠端認證（我們這一層）**：證明「產生資料的那台裝置，它執行的軟體本身沒被竄改」。

**C. 該背景現有問題**
C2PA 有一個它自己不保證、卻必須假設的前提：**簽章的那台裝置是可信的**。C2PA 只證明「這把金鑰簽了這張圖」，不證明「簽的當下裝置軟體沒被改」。若相機／裝置韌體被入侵，它照樣能對一張假造影像簽出合法簽章，驗證端仍會通過。真實佐證：**Nikon 的 C2PA 在 2025/9 因簽章漏洞被暫停、整批憑證撤銷**——弱點正是簽章系統本身。這個盲點不只相機：任何「你要相信它輸出」的邊緣裝置（感測器、AI 推論盒、DRM 用戶端）都一樣——「資料簽了沒？」有答案，但「產生它的平台在執行當下可不可信？」沒人驗。

**D. 方法／架構概述**
我們補上這缺的一層：在真實邊緣裝置（Raspberry Pi 5 + SLB9670 TPM）上，以 TPM 為信任根做遠端認證 + IMA 執行期量測。裝置把軟體狀態量測進 PCR 10，遠端驗證端發出挑戰、驗證 TPM 簽出的 quote 並比對允許清單。更關鍵的是把「有用的功能綁在完整性上」——秘密封印於 PCR 狀態，一旦被竄改，裝置就**無法執行其功能**（DRM 盒 demo：唯有通過驗證才解得開影片）。Phase 2 再把量測範圍延伸到 **AI 模型檔**，偵測模型被掉包 → 形成「可信 AI 推論」。
- **避免爭議的措辭**：明講我們與 C2PA **互補**而非取代——「C2PA 保護資料，我們保護產生資料的平台，也就是 C2PA 假設可信卻不去驗證的那台裝置」。
- **不宣稱首創**：邊緣裝置「裝置 + ML 模型」完整性認證在近期研究已有（如 TinyML 的 dual attestation 論文），我們的措辭是「呼應此新興方向，並在真實 Hailo NPU 上做出可運作的實體驗證」。
- **釐清用語**：我們做的是密碼學上的**模型完整性**，不是學界那個指公平性／可解釋性的「Trusted AI」；教授若說「看過 trusted AI」，要能當場區分。

## 12. 參考專案（研究後改寫，不要照抄）
- Infineon `remote-attestation-optiga-tpm`（Pi + Optiga TPM + IMA + 封印金鑰）。
- `tpm2-tools` 文件：`tpm2_createak`、`tpm2_quote`、`tpm2_checkquote`、`tpm2_createpolicy`、`tpm2_unseal`。
- HailoRT 範例／`rpicam-apps` 的 Hailo 後處理，當作 `.hef` 推論的 baseline。

## 13. 分工建議（3 人為例）
- **A — 韌體/核心**：Phase 0 的 kernel + TPM + IMA、provisioning、sealing。最難、最先卡，優先投人。
- **B — 驗證端**：Flask server、checkquote、IMA 重放、允許清單、儀表板。可在筆電獨立推進，不卡硬體。
- **C — Payload + Demo + Phase 2**：影片放行、Hailo 整合、竄改腳本、demo 腳本與彩排、報告論述。
> 三人都先用 swtpm 在筆電上把各自的部分跑通，硬體點亮（Phase 0）一好就整合上 Pi。