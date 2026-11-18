# 安裝與發佈維護

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.zh-TW.md)

本文件供準備 macOS、Windows 發佈的維護者，以及評估安裝方式的使用者閱讀。目前 CLI 可從原始碼建置；本機 snapshot 封裝已驗證；遠端 workflow 執行、可下載正式版本與套件管理器安裝尚未驗證。以下模板不代表套件已存在。

## 可用的安裝與升級方式

使用 [README](../README.zh-TW.md) 的原始碼建置指令。升級本機建置時，先保留舊執行檔，再建置已審核的來源版本、檢查 `--version`，驗證後替換執行檔。設定檔位於 repository 之外，應用程式不改寫設定。還原舊執行檔即可回滾執行檔，沒有資料庫 migration。

Release 壓縮檔安裝需要已確認版本、真實下載 URL、正確平台／架構，以及該發佈版本的 SHA-256 校驗值。macOS 使用 `shasum -a 256` 比對；Windows PowerShell 使用 `Get-FileHash -Algorithm SHA256`。校驗只能確認內容與已公布校驗值一致，不代表驗證發行者身分。首版規劃未簽章、未公證。壓縮檔名稱、內容、校驗值、Gatekeeper 處理方式與 Windows 安裝均需以真實產物驗證，才能將此方式標示為可用。

## 套件管理模板，尚不可直接執行

目的地已確認為 `vincent119/homebrew-tap`（`Formula/tlscheck.rb`）及 `vincent119/scoop-bucket`（`bucket/tlscheck.json`）。tlscheck 套件是否已發佈、下載 URL 與實際安裝尚未驗證。以下為預定介面，請等取得已驗證的發佈版本後再執行。

macOS Homebrew 預備安裝與升級：

```sh
brew tap vincent119/tap
brew install vincent119/tap/tlscheck
brew update
brew upgrade vincent119/tap/tlscheck
tlscheck --version
```

Windows PowerShell Scoop 預備安裝與升級：

```powershell
scoop bucket add tlscheck 'https://github.com/vincent119/scoop-bucket'
scoop install tlscheck/tlscheck
scoop update
scoop update tlscheck
tlscheck --version
```

安裝及升級前後，既有 `config.json` 內容必須保持不變。套件管理器回滾指令需要實際 formula／manifest 與版本保留證據，目前尚未驗證。

## 開發驗證

封裝前執行 README 的 Go 測試、race、vet 與空白檢查指令。測試資料維持合成，私有輸入不放入追蹤檔案。自動測試不使用公開服務，但 TLS 測試需要能綁定 loopback 連接埠。

目前證據區分 macOS arm64 原生執行與 Windows amd64 交叉建置。在 macOS 檢查 PowerShell 語法不等於 Windows 執行驗證。Windows 原生測試、規劃的四目標（darwin/windows × amd64/arm64）、壓縮檔安裝與套件升級均需各自取得證據。

## 發佈準備與失敗重試邊界

已實作 GitHub Actions workflow 與 GoReleaser v2.14.3 設定；本機 snapshot、壓縮檔與校驗通過；先前遠端 CI 的 packages 步驟失敗，本輪 PATH 修正尚未推送，完整跨平台結果待確認，未正式發佈。發佈前確認工具版本、workflow 權限、真實 tap／bucket 目的地與 owner、版本注入（`main.version`、`main.commit`）、架構矩陣、壓縮檔內容、SHA-256，以及兩種語言文件與 LICENSE。首版目標為 v0.1.0，不代表此版本已存在。

不發佈建置與建立 tag、push、GitHub Release、寫入套件庫必須分開；發佈需要明確授權。在設定與權限尚未驗證前，不提供正式發佈命令。

失敗時記錄來源 commit、預期版本、失敗階段與已發佈產物。檢查既有資產與套件版本後，只重試失敗階段。不得重新建立 tag、同版本覆寫不同內容、重複上傳已發佈資產，或未檢查就降版 tap／bucket。預發佈過濾與可重複執行的重試需以實際 workflow 測試。確認下載、校驗值、套件版本、安裝、`--version` 與設定未改變後，才能宣告成功。

## 仍需補齊的完成紀錄

| 證據 | 目前狀態 |
|---|---|
| macOS arm64 原始碼建置、CLI 說明與版本 | 已驗證 |
| Windows amd64 交叉建置 | 已驗證，不是原生執行測試 |
| Windows 原生執行與安裝 | 未驗證 |
| 四目標本機 snapshot 壓縮檔與校驗值 | 本機已驗證，未發佈 |
| Homebrew tap／Scoop bucket owner 與 repository | 已確認，未寫入遠端 |
| 套件安裝、升級及設定保留 | 未驗證 |
| 正式發佈、重試與預發佈行為 | 未驗證 |

取得真實封裝及安裝證據後，同步更新本文件與英文版本。不能因為已有命令模板，就將發佈說明標為完成。

## 指令參考

模板語法已對照官方 [Homebrew tap 文件](https://docs.brew.sh/Taps)、[Homebrew 指令參考](https://docs.brew.sh/Manpage)、[Scoop bucket 文件](https://github.com/ScoopInstaller/Scoop/wiki/Buckets) 與 [Scoop 指令](https://github.com/ScoopInstaller/Scoop/wiki/Commands)。這不代表 tlscheck 套件或安裝已完成驗證。

## 已實作的本機驗證

需要 Go 1.27.4、GoReleaser 2.14.3 與 Python 3，從 repository 根目錄執行：

```sh
goreleaser check
python3 -B -m unittest discover -s scripts -v
goreleaser release --snapshot --clean --skip=publish
python3 -B scripts/release.py verify
python3 -B scripts/install_check.py
```

前四個指令依 `tlscheck_<version>_<os>_<arch>` 模板產生並檢查 dist 產物。snapshot 的精確版本為 `0.0.0-snapshot-<short-commit>-dirty`；所有 snapshot 均保留此尾碼，即使 CI checkout 乾淨也一樣，以便與正式 tag 建置區分。GoReleaser 的 commit 中繼資料來自 HEAD；snapshot 可包含未提交變更，不得當成該 commit 的正式發佈。`--clean` 只會替換 `dist/`，需保留的產物請先備份。設定完全禁用 GoReleaser 自動發佈，明確發佈程式獨立執行。

`install_check.py` 將原生執行檔安裝至暫存目錄，重複替換作為本機重裝／升級檢查，執行 `--version`，並確認真實設定及隔離 sentinel 均未改變。這不會安裝 Homebrew／Scoop 套件，也不代表不同正式版本之間的升級已通過。檔名包含 `darwin`／`windows` 與 `amd64`／`arm64`；macOS 為 tar.gz，Windows 為 zip。每份包含執行檔、LICENSE、雙語 README 與雙語維護文件。`checksums.txt` 包含四份壓縮檔的 SHA-256。檔案時間固定為來源 commit 時間，以支援重複建置。

若需產生本機 Formula 與 manifest，請將下例替換為 snapshot 精確版本，包含前導 `v`；只寫入 `dist/tlscheck.rb` 與 `dist/tlscheck.json`。這些檔案中的 snapshot URL 並不存在於 GitHub，不得作為穩定套件發佈。

```text
python3 -B scripts/release.py packages --tag v0.0.0-snapshot-SHORTCOMMIT-dirty
```

選用 Make 指令：`make release-check`、`make snapshot`、`make verify-packages`。Python 僅用於維護流程，CLI 執行不需要它。

## 受保護的發佈流程

`.github/workflows/ci.yml` 在 `macos-15`（arm64）、`macos-15-intel`（amd64）與 `windows-2025`（amd64）測試。原生 job 下載 snapshot 壓縮檔並隔離安裝；Windows arm64 仍只有交叉建置。本機驗證不能證明這些遠端 job 已通過。Actions 固定 commit SHA、Go 固定 1.27.4、GoReleaser 固定 2.14.3。

`.github/workflows/release.yml` 接受 push 的 `v*` tag，或在該 tag 手動重跑。必要條件為可重用 CI 檢查通過、repository variable `ENABLE_RELEASE=true` 及 `release` environment。啟用變數前，請先在 environment 設定必要審核者與 tag 限制。本次沒有建立 environment 或 secret。`PACKAGE_REPOSITORY_TOKEN` 使用只限 `vincent119/homebrew-tap` 與 `vincent119/scoop-bucket` 的 contents 讀寫細粒度授權；主專案發佈使用 job 的 contents write `GITHUB_TOKEN`，腳本以 `GH_TOKEN` 讀取。不要將 secrets 提供給 pull request 檢查。

發佈程式還要求 `--execute`、`RELEASE_APPROVED` 等於精確 tag、乾淨來源、HEAD／tag 相同，以及 GoReleaser 中繼資料一致。先建立 draft，在內文固定來源 commit，只補缺少資產，下載核對每份內容，再改為已發佈。既有 Release 若來源不明或同名內容不同，就會停止。套件更新再次核對已發佈產物，略過預發佈與較新穩定版，接受相同版本相同內容，拒絕同版本不同內容，並以 GitHub Contents API 的 SHA 條件防止並行覆寫。發佈 job 共用不取消中的 concurrency group，將套件更新序列化。

檢查失敗階段後，重跑相同 tag 的 workflow。必須保留 Release 的來源標記，不得刪除以繞過不一致檢查。若 Release 成功但套件失敗，保留 Release；重跑時核對後續作。受控測試不連 GitHub 即模擬上述轉換。真實遠端重試、套件管理器安裝／升級及 Windows 原生結果仍待驗證。目前產物未簽章、未公證。

## 審查修正與重試細節

發佈程式分頁列舉授權可見的 Release，同時找到 draft 與已發佈版本；同一 tag 多個版本時拒絕處理。只有來源已核對、仍未發佈的 draft，才可移除空的 `state=starter` 資產並重傳；正常上傳資產、非空失敗資產與已發佈版本衝突仍受保護。最終發佈前比較最新穩定版本，明確設定 `make_latest`，舊版補發不會取代 Latest；預發佈永不成為穩定 Latest。

共用發佈 concurrency group 使用 `queue: max` 與 `cancel-in-progress: false`。GitHub 最多保留 100 個 pending，超額仍可能取消，佇列順序不保證等於 tag／版本順序，因此仍需版本比較。Actionlint 1.7.12 尚不認得此官方欄位；CI 透過 `scripts/lint_workflows.py` 驗證精確 concurrency 契約，只接受預期檔案／行號的該項未知欄位診斷，其餘錯誤仍會失敗。安裝固定版 Actionlint 後，可執行 `python3 -B scripts/lint_workflows.py`。工具未來支援此欄位後，wrapper 仍檢查佇列契約，不再需要接受該項診斷。本機未驗證遠端排程行為。

憑證 SAN URI 逐筆顯示，保留階層式 URI 的識別路徑（包含 SPIFFE 路徑），移除帳密、查詢與片段。不透明或無效 URI 以 `[URI]` 代替，避免回顯嵌入帳密。一般公開文字與本機路徑不猜測為網路 URL，只移除終端控制字元。

## CLI 相容性更新

參數與輸出以 [README](../README.zh-TW.md) 為準：預設 table，新增四格式／安全 output、強制 local/remote、語系覆寫、settings 與四 shell 補全。一般操作仍不寫設定；僅 settings 明確儲存例外。原生 Windows Console／ACL／提交、Fish 互動與四目標原生執行尚需平台驗證。本次不修改 CI 或建立發佈。

八項 CLI 審查修正已加入回歸：補全偵錯無寫入、空旗標值、shell help、終端斷線、ACL 保存／失敗清理、advice code、table 分隔符及逐輸入摘要。macOS ACL 透過固定 SDK 的有界原生屬性呼叫處理，CLI 不依賴外部 chmod／Python；測試才使用這些工具。Windows DACL 已有原生測試來源與交叉編譯，尚未以此宣稱 Windows 執行通過。

## CI 封裝工具 PATH 修正

固定版本 Action 只有 `install-only: true` 路徑會將安裝目錄加入後續 steps 的 PATH，因此 CI 先顯式安裝 v2.14.3，再於 shell 執行 `goreleaser --version`、`goreleaser check` 及既有 snapshot。Action SHA、唯讀 contents 權限、`--snapshot --skip=publish` 與 release.disable 保持不變。回歸檢查涵蓋安裝／執行順序與禁止發佈；本機成功不等於 GitHub runner 已通過。

行為依據：[固定版本 Action 原始碼](https://github.com/goreleaser/goreleaser-action/blob/e435ccd777264be153ace6237001ef4d979d3a7a/src/main.ts)。
