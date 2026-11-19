# 安裝與發佈維護

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.zh-TW.md)

本文件供準備 macOS、Windows 發佈的維護者，以及評估安裝方式的使用者閱讀。目前 CLI 可從原始碼建置。2026-11-18 的[跨平台 CI](https://github.com/vincent119/tlscheck/actions/runs/44285001106)（來源 `a1cff07676d94c4ac7e663bec5ea83c8584d42a9`、第 1 次執行）全部通過：四目標 snapshot 封裝與校驗，以及 macOS arm64／amd64、Windows amd64 的原生測試與隔離安裝／同版本重裝。Windows arm64 僅交叉建置；正式 Release、套件管理器安裝升級與實機互動仍待驗證。以下模板不代表套件已存在。

## 可用的安裝與升級方式

使用 [README](../README.zh-TW.md) 的原始碼建置指令。升級本機建置時，先保留舊執行檔，再建置已審核的來源版本、檢查 `--version`，驗證後替換執行檔。設定檔位於 repository 之外，一般檢查不改寫設定；只有 `--settings` 明確儲存才寫入。還原舊執行檔即可回滾執行檔，沒有資料庫 migration。

Release 壓縮檔安裝需要已確認版本、真實下載 URL、正確平台／架構，以及該發佈版本的 SHA-256 校驗值。macOS 使用 `shasum -a 256` 比對；Windows PowerShell 使用 `Get-FileHash -Algorithm SHA256`。校驗只能確認內容與已公布校驗值一致，不代表驗證發行者身分。首版規劃未簽章、未公證。CI 已驗證 snapshot 壓縮檔名稱、內容、校驗值與三個原生平台的隔離安裝；正式 Release 下載、Gatekeeper 處理與跨正式版本升級仍需另行驗證。

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

上述 CI 已在 macOS arm64／amd64 與 Windows amd64 執行 Go 測試、race、vet、27 項 Python 回歸、原生 CLI 版本檢查，以及 snapshot 隔離安裝／同版本重裝與設定保留檢查。darwin/windows × amd64/arm64 四目標均完成建置與 SHA-256 核對；Windows arm64 僅交叉建置。Windows 真實 Console 操作、Bash 載入相容補全套件後互動、Fish 語法與互動、Windows PowerShell 補全與 Homebrew／Scoop 安裝升級仍缺驗收紀錄。

2026-11-19 本機驗收補充：Zsh 5.9 的 10 項真正 Tab 補全通過，包含旗標／值、等號、`--`、停止條件及空白／Unicode 檔名；補全只呼叫隱藏協定，設定及 debug sentinel 不變。macOS CLI／PTY 的 5 項方向鍵／語系／主題預覽／Esc／Ctrl+C／取消驗收通過，stdout 空白，退出 0，終端設定欄位復原，實際 config 不變。儲存僅由隔離測試驗證，沒有對使用者設定做儲存。PowerShell 7.5.2 的無候選相容性已在本機修正：含描述／不含描述的原生引擎共 30 項驗收通過；Go 回歸另驗證等號、引號、游標中段與 AST 參數不變。無候選的占位保留已有字詞，空游標可多一個空白，不增加參數或回退檔名；正常 local／output 檔名補全保留。生成器對未知模板停止輸出，不使用私有反射或升級依賴。Windows 引擎／Console 仍需實機驗證，不能將先前 CI 通過當成此次修正的 Windows 證據。Bash 缺相容 bash-completion，Fish 未安裝，兩者完整互動均未通過。

## 發佈準備與失敗重試邊界

GitHub Actions CI 與 GoReleaser v2.14.3 的四目標試建置已通過上述遠端執行。先前的工具 PATH、Windows 檔案替換／IPv6 與 Python 編碼失敗已由此版本的成功回歸覆蓋；本次沒有正式發佈。發佈前確認工具版本、workflow 權限、真實 tap／bucket 目的地與 owner、版本注入（`main.version`、`main.commit`）、架構矩陣、壓縮檔內容、SHA-256，以及兩種語言文件與 LICENSE。首版目標為 v0.1.0，不代表此版本已存在。

不發佈建置與建立 tag、push、GitHub Release、寫入套件庫必須分開；發佈需要明確授權。在設定與權限尚未驗證前，不提供正式發佈命令。

失敗時記錄來源 commit、預期版本、失敗階段與已發佈產物。檢查既有資產與套件版本後，只重試失敗階段。不得重新建立 tag、同版本覆寫不同內容、重複上傳已發佈資產，或未檢查就降版 tap／bucket。預發佈過濾與可重複執行的重試需以實際 workflow 測試。確認下載、校驗值、套件版本、安裝、`--version` 與設定未改變後，才能宣告成功。

## 驗證紀錄與待驗項目

| 證據 | 目前狀態 |
|---|---|
| macOS arm64／amd64 原生測試、race、CLI 版本 | CI 已通過 |
| Windows amd64 原生測試、race、DACL／唯讀替換、CLI 版本 | CI 已通過 |
| 逾時設定與 DNS 前到期回歸 | 最新三平台普通／race 均具名 PASS、未 Skip；Windows 原生驗證已完成 |
| 三個原生目標的 snapshot 隔離安裝／同版本重裝、設定保留 | CI 已通過，未驗證跨正式版本升級 |
| 四目標 snapshot 壓縮檔與 SHA-256 | CI 已通過，未正式發佈；Windows arm64 僅交叉建置 |
| PowerShell 主測試及兩子案例具名 PASS、未 Skip | 三平台普通／race 六份 JSON 已核對，詳見下方證據 |
| 無 Go 的 Windows exe 自動驗收 | 使用者原生報告 53 項 PASS、0 FAIL；版本／雜湊與設定指紋已核對 |
| 真實 Console 與完整 shell 補全互動 | 仍待驗收，詳見開發驗證範圍 |
| Homebrew tap／Scoop bucket owner 與 repository | 已確認，未寫入遠端 |
| Homebrew／Scoop 安裝、跨版本升級及設定保留 | 未驗證 |
| 正式發佈、遠端重試與預發佈行為 | 受控回歸已通過；真實發佈流程未驗證 |

取得真實封裝及安裝證據後，同步更新本文件與英文版本。不能因為已有命令模板，就將發佈說明標為完成。

### PowerShell 具名測試證據

原生 CI 分別執行 `go test -json -count=1 ./...` 與 `go test -race -json -count=1 ./...`，使用 `pipefail` 與 `tee` 保存事件並保留 Go 的失敗結果。測試前確認 `pwsh` 可執行並輸出版本，不自動安裝。

`scripts/check_go_test_events.py` 分別驗證兩份 JSONL：固定套件 `github.com/vincent119/tlscheck/internal/app` 的 `TestPowerShellEmptyCandidatesDoNotFallbackToFiles`、`/包含描述` 與 `/不含描述` 必須各有 `run` 後接 `pass`，且套件完成 `pass`。主測試子樹不得 Skip；任何測試／建置失敗、缺事件、重複或順序錯誤、損壞 UTF-8／JSON、超過大小上限均使檢查失敗。套件 `ok` 或輸出文字中的 PASS 不能代替事件。

每個原生 job 無論成功或失敗，均嘗試上傳 `go-test-events-<matrix.os>`，僅包含 `go-test.jsonl` 與 `go-test-race.jsonl`，保留 7 天。早期步驟失敗時可能沒有事件檔，不能當成驗證通過。下載後從 repository 根目錄執行：

```bash
python3 -B scripts/check_go_test_events.py go-test.jsonl go-test-race.jsonl
```

已核對 [CI 44454812073 第二次執行](https://github.com/vincent119/tlscheck/actions/runs/44454812073/attempts/2)，來源 commit 為 `9e7bc08118ed1ef0d441872cf2ea26c690c972d2`，四個 jobs 均成功。下載三份 `go-test-events-<matrix.os>` 產物後，重新以檢查器逐份驗證六個 JSONL，結果如下：

| 原生平台 | 普通測試 | race 測試 |
|---|---|---|
| macOS arm64（macos-15） | 主測試及兩子案例均 PASS，未 Skip | 主測試及兩子案例均 PASS，未 Skip |
| macOS amd64（macos-15-intel） | 主測試及兩子案例均 PASS，未 Skip | 主測試及兩子案例均 PASS，未 Skip |
| Windows amd64（windows-2025） | 主測試及兩子案例均 PASS，未 Skip | 主測試及兩子案例均 PASS，未 Skip |

共 18 個必要具名 PASS，各自有先行 `run` 與套件完成 `pass`，主測試子樹無 Skip。第一次執行的 macOS amd64 因 Go proxy DNS 失敗，重跑後才取得成功事件；本次依原始 JSON 結案，不以舊 CI 44452386656 的套件成功記錄推定未 Skip。這些證據完成了 S09-T10 的跨平台引擎分項；真實 Windows Console／鍵盤 Tab、設定選單與其他尚缺實機的 shell 驗收仍未完成，S09-T10 與整份 S09 不因此整體結案。

### 逾時回歸的原生驗收

[CI 44463960289](https://github.com/vincent119/tlscheck/actions/runs/44463960289) 第一次執行已全數成功，來源 commit 為 `1bae9a18a85c60fd40bf38eedc24e1a948fd48a2`。三平台的六份普通／race JSON 已逐份核對：`internal/check` 的 `TestRemoteTimeoutOptionUsesSharedDeadline`、`/最小期限`、`/自訂期限`、`TestRemoteTimeoutBeforeDNSKeepsExecutionFailure` 均有具名 `run`→`pass`，沒有 Skip。既有 `TestRemoteSharesOneDeadlineAcrossNetworkStages` 也具名通過，所有套件完成成功。

這次關閉 S03-V03 的 Windows amd64 原生普通／race 驗證。測試使用標準 `testing/synctest` 虛擬時鐘，保留 1 ms 最小期限並驗證自訂期限，移除 DNS 必須在實際 1 ms 內開始的排程假設；DNS 前已到期時仍不得執行 DNS／連線，回報執行錯誤與結束碼 2。產品的共用 deadline、逾時值域與結束碼契約未變。前次 CI 44462742449 的 Windows race 失敗保留為修正前證據，不以交叉編譯代替這次原生結果。

本次 CI 不等同真實 Windows Console、鍵盤 Tab 或設定選單驗收，也不補足 Bash／Fish 等尚缺實機的 shell 項目；這些項目與正式套件安裝／升級仍維持未完成。

### 無 Go 的 Windows 執行檔自動驗收

已核對使用者提供的 `results.json`：Windows X64、系統版本 `10.0.26200.0`、PowerShell `7.6.10`，執行檔版本 `acceptance-75a1c67`，產品來源 commit 為 `75a1c673a1ddc2d10b22b96c985d991f985acef6`。此為使用者在 Windows 執行驗收包的證據，與前述 GitHub Actions 證據分開記錄。

報告包含 53 個不重複案例，全部 PASS、0 FAIL。其中兩種補全變體各 18 次程序成功，沒有非預期診斷；其他檢查涵蓋版本、三語說明、參數、四格式、報告覆寫保護及非 TTY 選單拒絕。程序紀錄共 42 次結束碼 0、11 次預期錯誤結束碼 2。日常設定、隔離設定及 debug sentinel 的前後指紋均相同。

| 核對項目 | SHA-256 |
|---|---|
| 驗收用 `tlscheck.exe` | `f6a807a47b6eb8b8fea2a4cb1a4fca029657e215002a567cc8063ee15b414ff2` |
| 驗收用 `test-windows.ps1` | `9eeefa4cd31579870fe6157be5711a7be3b2d2a499de769cabd923800293799e` |

兩個雜湊均符合當次交付檔案。產品 commit 不代表驗收腳本已包含在該 commit；本次腳本以其獨立雜湊追溯，也不宣稱該腳本已通過 Windows CI。原始報告只保存於私有驗收證據，不公開個人路徑或設定資訊。

這次完成 Windows 執行檔自動驗收，沒有執行真實鍵盤 Tab、互動選單儲存或 Console 模式復原驗收；這些項目仍未完成。Bash／Fish 與正式套件安裝／升級的缺口亦未關閉，整份 S09 不結案。

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

Python 維護工具與測試明確使用 UTF-8 讀寫文字檔，並以 UTF-8 解碼子程序文字輸出。CI 與發佈 workflow 全域設定 `PYTHONUTF8=1`、`PYTHONIOENCODING=utf-8`，避免 Windows 的預設 code page 無法讀取中文 YAML 或輸出中文日誌。手動執行上述 Python 指令前，請在目前終端工作階段設定：

```bash
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

Windows PowerShell：

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
```

這些設定僅套用目前工作階段與子程序，不修改使用者全域環境。編碼回歸會在子程序關閉 UTF-8 模式並將隱含編碼警告視為錯誤，再驗證安裝／lint 邊界與中文 stdout／stderr。上述 Windows amd64 CI 已另外通過這些回歸；本機模擬與原生執行證據分別記錄。


## 受保護的發佈流程

`.github/workflows/ci.yml` 在 `macos-15`（arm64）、`macos-15-intel`（amd64）與 `windows-2025`（amd64）測試。原生 job 下載 snapshot 壓縮檔並隔離安裝；Windows arm64 仍只有交叉建置。上述成功執行已核對這三個原生 job 及 packages job 的結果；這不包含真實 Console／完整補全互動或套件管理器驗收。Actions 固定 commit SHA、Go 固定 1.27.4、GoReleaser 固定 2.14.3。

`.github/workflows/release.yml` 接受 push 的 `v*` tag，或在該 tag 手動重跑。必要條件為可重用 CI 檢查通過、repository variable `ENABLE_RELEASE=true` 及 `release` environment。啟用變數前，請先在 environment 設定必要審核者與 tag 限制。本次沒有建立 environment 或 secret。`PACKAGE_REPOSITORY_TOKEN` 使用只限 `vincent119/homebrew-tap` 與 `vincent119/scoop-bucket` 的 contents 讀寫細粒度授權；主專案發佈使用 job 的 contents write `GITHUB_TOKEN`，腳本以 `GH_TOKEN` 讀取。不要將 secrets 提供給 pull request 檢查。

發佈程式還要求 `--execute`、`RELEASE_APPROVED` 等於精確 tag、乾淨來源、HEAD／tag 相同，以及 GoReleaser 中繼資料一致。先建立 draft，在內文固定來源 commit，只補缺少資產，下載核對每份內容，再改為已發佈。既有 Release 若來源不明或同名內容不同，就會停止。套件更新再次核對已發佈產物，略過預發佈與較新穩定版，接受相同版本相同內容，拒絕同版本不同內容，並以 GitHub Contents API 的 SHA 條件防止並行覆寫。發佈 job 共用不取消中的 concurrency group，將套件更新序列化。

檢查失敗階段後，重跑相同 tag 的 workflow。必須保留 Release 的來源標記，不得刪除以繞過不一致檢查。若 Release 成功但套件失敗，保留 Release；重跑時核對後續作。受控測試不連 GitHub 即模擬上述轉換。真實遠端重試與套件管理器安裝／升級仍待驗證。目前產物未簽章、未公證。

## 審查修正與重試細節

發佈程式分頁列舉授權可見的 Release，同時找到 draft 與已發佈版本；同一 tag 多個版本時拒絕處理。只有來源已核對、仍未發佈的 draft，才可移除空的 `state=starter` 資產並重傳；正常上傳資產、非空失敗資產與已發佈版本衝突仍受保護。最終發佈前比較最新穩定版本，明確設定 `make_latest`，舊版補發不會取代 Latest；預發佈永不成為穩定 Latest。

共用發佈 concurrency group 使用 `queue: max` 與 `cancel-in-progress: false`。GitHub 最多保留 100 個 pending，超額仍可能取消，佇列順序不保證等於 tag／版本順序，因此仍需版本比較。Actionlint 1.7.12 尚不認得此官方欄位；CI 透過 `scripts/lint_workflows.py` 驗證精確 concurrency 契約，只接受預期檔案／行號的該項未知欄位診斷，其餘錯誤仍會失敗。安裝固定版 Actionlint 後，可執行 `python3 -B scripts/lint_workflows.py`。工具未來支援此欄位後，wrapper 仍檢查佇列契約，不再需要接受該項診斷。本機未驗證遠端排程行為。

憑證 SAN URI 逐筆顯示，保留階層式 URI 的識別路徑（包含 SPIFFE 路徑），移除帳密、查詢與片段。不透明或無效 URI 以 `[URI]` 代替，避免回顯嵌入帳密。一般公開文字與本機路徑不猜測為網路 URL，只移除終端控制字元。

## CLI 相容性更新

參數與輸出以 [README](../README.zh-TW.md) 為準：預設 table，新增四格式／安全 output、強制 local/remote、語系覆寫、settings 與四 shell 補全。一般操作仍不寫設定；僅 settings 明確儲存例外。Windows amd64 的自動化 ACL／提交回歸已通過；真實 Windows Console 與完整 shell 補全互動仍待驗收。Windows arm64 僅交叉建置。正式發佈仍需獨立授權。

八項 CLI 審查修正已加入回歸：補全偵錯無寫入、空旗標值、shell help、終端斷線、ACL 保存／失敗清理、advice code、table 分隔符及逐輸入摘要。macOS ACL 透過固定 SDK 的有界原生屬性呼叫處理，CLI 不依賴外部 chmod／Python；測試才使用這些工具。Windows DACL、唯讀原子替換與失敗清理回歸已在上述 Windows amd64 CI 通過；這不代表所有 Windows／檔案系統組合均已驗證。

## CI 封裝工具 PATH 修正

固定版本 Action 只有 `install-only: true` 路徑會將安裝目錄加入後續 steps 的 PATH，因此 CI 先顯式安裝 v2.14.3，再於 shell 執行 `goreleaser --version`、`goreleaser check` 及既有 snapshot。Action SHA、唯讀 contents 權限、`--snapshot --skip=publish` 與 release.disable 保持不變。回歸檢查涵蓋安裝／執行順序與禁止發佈；上述 packages job 已通過工具版本、設定、Workflow 語法與四目標試建置檢查。

行為依據：[固定版本 Action 原始碼](https://github.com/goreleaser/goreleaser-action/blob/e435ccd777264be153ace6237001ef4d979d3a7a/src/main.ts)。
