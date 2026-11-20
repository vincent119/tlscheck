# 安裝與發佈前置作業

[English](releasing.md) | [繁體中文](releasing.zh-TW.md) | [README](../README.zh-TW.md)

先依平台完成下方安裝。維護者建立 tag 或啟用正式發佈前，須逐項核對發佈清單。本文件說明目前的保護機制與待補證據，不構成正式發佈授權。

## 套件安裝

**Homebrew／Scoop 套件目前尚未發布驗證。** macOS／Windows 壓縮檔與 SHA-256 校驗值請從 [GitHub Releases](https://github.com/vincent119/tlscheck/releases)取得。 以下為預定的使用者安裝指令，套件與對應 Release 資產確認後才可使用。原始碼建置放在[後段](#原始碼建置)，[README 安裝段落](../README.zh-TW.md#安裝)使用相同指令。

### Windows（Scoop）

```powershell
scoop bucket add tlscheck 'https://github.com/vincent119/scoop-bucket'
scoop install tlscheck/tlscheck
tlscheck --version
```

### macOS（Homebrew）

```sh
brew tap vincent119/tap
brew install vincent119/tap/tlscheck
tlscheck --version
```

### Linux

現有矩陣沒有 Linux 套件或發佈壓縮檔。Homebrew Formula 只有 `on_macos` 定義，未提供 Linuxbrew 安裝。可依[原始碼建置指令](../README.zh-TW.md#從原始碼建置)操作，並留意尚未原生驗收的限制。

## 平台狀態

| 平台 | 原始碼建置 | 原生 CI／安裝 | Release 封裝計畫 |
|---|---|---|---|
| Windows amd64 | 已驗證 | 普通／race 測試及隔離 snapshot 安裝／重裝通過 | ZIP |
| Windows arm64 | 交叉建置已驗證 | 原生驗收待完成 | ZIP，交叉建置 |
| macOS amd64／arm64 | 已驗證 | 普通／race 測試及隔離 snapshot 安裝／重裝通過 | tar.gz |
| Linux amd64／arm64 | 交叉建置已驗證 | 原生驗收待完成 | 未設定 |

請從 [GitHub Releases](https://github.com/vincent119/tlscheck/releases)選擇正式版本與資產。[2026-11-20 CI](https://github.com/vincent119/tlscheck/actions/runs/44693571937)，來源 `6394a47`，七項工作全數通過，涵蓋封裝、macOS／Windows 原生測試與 HTML 腳本回歸。該結果不涵蓋目前未提交的變更，也不證明正式版本安裝成功。Windows arm64 仍只有交叉建置證據，Console、瀏覽器清理與版面人工驗收須分開記錄。

CLI、報告格式、PFX 密碼規則與語系設定以 [README](../README.zh-TW.md) 為準。判斷驗收結果是否適用於候選版本時，須核對該紀錄的執行檔版本與來源 commit。

## 壓縮檔校驗與升級

取得正式版本後，選擇確切的作業系統、架構、版本與真實下載 URL。解壓縮前，比對該版本 `checksums.txt` 的 SHA-256。

macOS：

```sh
shasum -a 256 tlscheck_*.tar.gz
```

Windows PowerShell：

```powershell
Get-FileHash .\tlscheck_*.zip -Algorithm SHA256
```

校驗相同表示內容與已公布雜湊一致，不代表驗證發行者身分。目前產物規劃未簽章、未公證，真實 Release 下載、Gatekeeper 行為與跨正式版本升級尚未驗收。

替換前保留舊執行檔，新檔須通過 `--version` 與本機檢查後再使用。安裝前後保留並核對 `config.json`。一般 CLI 檢查不改寫設定，只有明確的設定儲存才會寫入。還原舊執行檔即可回滾 binary，沒有資料庫 migration。

Homebrew 與 Scoop 目的地為 `vincent119/homebrew-tap` 的 `Formula/tlscheck.rb`，以及 `vincent119/scoop-bucket` 的 `bucket/tlscheck.json`。已驗證套件正式上架後，升級指令為：

macOS Homebrew：

```sh
brew update
brew upgrade vincent119/tap/tlscheck
tlscheck --version
```

Windows PowerShell Scoop：

```powershell
scoop update
scoop update tlscheck
tlscheck --version
```

套件管理器回滾須有真實版本與保留行為的驗證。替換原始碼建置的執行檔，不能當作 Homebrew／Scoop 升級或回滾的證據。

## 原始碼建置

[建置指令](../README.zh-TW.md#從原始碼建置)涵蓋 Windows PowerShell、macOS 與 Linux，需要 Go 1.27.0 以上版本。一般建置未注入版本資訊時顯示 `development` 與 `unknown`。Linux amd64／arm64 已核對交叉建置，原生安裝仍未驗證。驗收時使用明確的執行檔路徑或既有 PATH 目錄，不改寫 shell 設定。

## 發佈前置清單

下表每項都是發佈準備條件，須記錄候選 commit、版本、建置設定、結果與證據連結。必要檢查未解決時，應停止準備，直到通過或由發佈負責人明確決定接受範圍。暫停中的驗收不會自動變成通過。

| 步驟 | 必須核對 | 證據與停止條件 |
|---|---|---|
| 1. 固定候選來源 | 已審查來源、乾淨工作目錄、選定版本、tag／來源一致 | 保存完整 commit 與預定 tag，不把未提交內容當作該 commit 的正式產物。 |
| 2. 執行程式檢查 | 原生普通／race、vet、Python／workflow 回歸 | 核對具名結果與所需平台。必要案例缺漏、失敗或 Skip 時停止。 |
| 3. 檢查 Go 已知漏洞 | 四個封裝目標、相同候選 commit 與設定的 Go 工具鏈 | 要求 govulncheck 成功結果，保留漏洞及執行錯誤，不用舊綠燈代替。 |
| 4. 建置並查驗封裝 | 固定 GoReleaser、四目標壓縮檔、metadata、檔案與 SHA-256 | 核對來源／版本及內容，包含雙語 README 與維護文件。 |
| 5. 驗證安裝與使用範圍 | 隔離安裝、設定保留、預定升級路徑、適用的人工檢查 | 列出 OS／架構，以及 Console／瀏覽器／版面等尚缺證據。 |
| 6. 核對發佈保護 | 發佈負責人核准、environment reviewers／tag 限制、套件目的地及憑證權限 | 設定查核後才啟用正式發佈，Token 值不寫入日誌或證據。 |
| 7. 發佈後查驗 | 明確核准的 tag、下載資產、套件版本與安裝結果 | Release 與套件更新分階段，部分失敗不算發佈完成。 |

### 本機檢查

目前 workflow 使用 Go 1.27.4、GoReleaser 2.14.3 與 Python 3。race 需要支援的原生 Go／C 工具鏈。從 repository 根目錄執行：

```sh
git status --short
git rev-parse HEAD
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
git diff --check
```

本機 `govulncheck` 指令只掃描目前的 Go 建置目標。獨立的 [Go 漏洞 workflow](../.github/workflows/go-vulnerability.yml) 使用固定 govulncheck v1.10.0、`CGO_ENABLED=0`，掃描 darwin/windows × amd64/arm64。工具先為 runner 主機安裝，再將目標設定套用至掃描。閘門採文字輸出的原生結束碼，JSON／SARIF 模式的退出語意不同。

本機以 Go 1.27.4 完成四目標 source 掃描，未回報可達的已知漏洞。正式發佈前須確認確切候選 commit 的遠端 workflow 結果。掃描結果對應當時工具鏈、目標與資料庫狀態，不代表完整安全保證。

**目前發佈串接：** [release.yml](../.github/workflows/release.yml) 會等待重用的 [ci.yml](../.github/workflows/ci.yml)，但不會自動等待獨立漏洞 workflow。維護者須在建立發佈 tag 前，核對相同來源 commit 的掃描全部成功。本次文件更新不加入自動相依，也不改變發佈權限。

### 不發佈的封裝驗證

執行維護工具前，先在目前終端設定 Python UTF-8 行為。

macOS／Linux shell：

```sh
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

Windows PowerShell：

```powershell
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
```

先保存 `dist/` 中需要保留的產物，`--clean` 會替換該輸出目錄。

```sh
goreleaser --version
goreleaser check
python3 -B -m unittest discover -s scripts -v
goreleaser release --snapshot --clean --skip=publish
python3 -B scripts/release.py verify
```

在支援的 macOS／Windows 原生主機核對相符的 snapshot 安裝：

```sh
python3 -B scripts/install_check.py
```

Linux 不能以原生安裝檢查期待取得 Linux 壓縮檔。現有矩陣只產生 macOS／Windows 四個封裝目標；Linux 主機可交叉建置這些產物，但不因此證明原生安裝。

snapshot 版本為 `0.0.0-snapshot-<short-commit>-dirty`，乾淨 CI 也保留此後綴。snapshot 可包含未提交檔案，不能只靠 HEAD metadata 判定全部內容。壓縮檔名稱為 `tlscheck_<version>_<os>_<arch>`，macOS 使用 tar.gz，Windows 使用 ZIP。每份包含執行檔、LICENSE、兩份 README 與兩份維護手冊，`checksums.txt` 涵蓋四份壓縮檔。

`install_check.py` 在暫存目錄安裝及重裝，核對 `--version`，確認真實設定與隔離 sentinel 不變。它不證明套件管理器安裝或跨版本升級。[.goreleaser.yaml](../.goreleaser.yaml) 已停用 GoReleaser 發佈，`scripts/release.py verify` 只執行本機封裝查核。

`packages --tag` 只產生本機 `dist/tlscheck.rb` 與 `dist/tlscheck.json`。tag 必須是壓縮檔確切版本再加前綴 `v`，snapshot URL 不是真實 GitHub 下載位置，不得提交成穩定套件更新。階段介面可用 `python3 -B scripts/release.py --help` 查詢。

workflow lint 使用固定 Actionlint v1.7.12，執行 `python3 -B scripts/lint_workflows.py`。wrapper 會先核對 `queue: max` 契約，只接受對應的精確不支援語法診斷，其餘診斷一律維持失敗。

## 發佈保護與失敗重試

[發佈 workflow](../.github/workflows/release.yml) 可由推送 `v*` tag 或手動 dispatch 啟動。正式發佈 job 另要求 tag ref、`ENABLE_RELEASE=true`、重用 CI 成功及 `release` environment。套件更新另須手動 dispatch 並指定 `update_packages=true`，預設為 false；tag 觸發的發佈不會自動更新 Homebrew／Scoop。啟用變數前，先設定必要 reviewers 與 tag 限制。本文件不建立這些設定，也不授權正式發佈。

主專案使用發佈 job 的 `GITHUB_TOKEN`，權限為 contents write，腳本透過 `GH_TOKEN` 讀取。`PACKAGE_REPOSITORY_TOKEN` 須為細粒度憑證，只允許兩個核准套件 repository 的必要存取。Pull request 檢查不提供發佈 secrets。

publisher 另要求 `--execute`、`RELEASE_APPROVED` 與確切 tag 相同、工作目錄乾淨、HEAD 等於 tag commit，以及 GoReleaser metadata 相符。流程先建立 draft、記錄來源 commit、補傳缺少資產、下載比對所有資產，再正式發佈。來源不明、非預期資產或同名不同內容都會停止。

套件更新會重新核對已發佈資產。預發佈不變更穩定套件，新版套件不降版，同版本同內容視為已完成，同版本不同內容則拒絕。GitHub Contents API 的 SHA 條件保護並行更新。所有發佈共用 `tlscheck-stable-release` 群組，採 `queue: max` 且不取消執行中工作；不假設佇列順序等於版本順序，因此仍須核對版本。

| 失敗階段 | 重試規則 |
|---|---|
| 程式檢查、漏洞掃描或封裝 | 修正原因後，對候選來源重跑失敗檢查，保留原始結果。 |
| draft 資產未齊 | 先核對來源與全部既有資產，再補缺檔。只允許來源已確認、尚未發佈的 draft 移除空的 starter 資產後重試。 |
| 已發佈資產衝突 | 停止並人工核對，不覆寫資產、不重建 tag，也不刪除來源標記。 |
| Release 成功、套件更新失敗 | 保留 Release，核對失敗階段後，重跑相同且已核准的 tag workflow。 |
| 重跑舊版本 | 再次比較穩定版本，舊版本不得替換 Latest 或使套件降版。 |

發佈成功須有約定範圍內的真實下載、校驗、版本、套件安裝升級與設定保留證據。FakeAPI 回歸只驗證重試決策，不等同 GitHub 真實發佈。跨版本升級、真實遠端重試、簽章／公證及其餘人工項目，仍須各自保存驗收紀錄。目前 CLI 契約見 [README](../README.zh-TW.md)。
