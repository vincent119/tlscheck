# tlscheck

tlscheck 用來檢查遠端 TLS 憑證、本機憑證鏈與憑證／私鑰配對。遇到 TLS 連線錯誤、部署前確認到期日，或想知道伺服器是否送出預期的憑證，都可以用它查核。

[![CI](https://github.com/vincent119/tlscheck/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vincent119/tlscheck/actions/workflows/ci.yml)
[![Go 漏洞掃描](https://img.shields.io/github/actions/workflow/status/vincent119/tlscheck/go-vulnerability.yml?branch=main&label=Go%20%E6%BC%8F%E6%B4%9E%E6%8E%83%E6%8F%8F&logo=githubactions)](https://github.com/vincent119/tlscheck/actions/workflows/go-vulnerability.yml)
[![Go](https://img.shields.io/badge/Go-1.27.0%2B-00ADD8?logo=go&logoColor=white)](go.mod)
[![授權](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-vincent119%2Ftlscheck-181717?logo=github)](https://github.com/vincent119/tlscheck)
[![Stars](https://img.shields.io/github/stars/vincent119/tlscheck?style=flat&logo=github)](https://github.com/vincent119/tlscheck/stargazers)

[English](README.md) | [繁體中文](README.zh-TW.md)

[版本變更紀錄](CHANGELOG.zh-TW.md)

預設以表格呈現，也能輸出 JSON、離線 HTML 與 Markdown。訊息支援英文、繁體中文和簡體中文。遠端握手的觀測結果與信任驗證分開顯示，本機私鑰只留在本機。

## 安裝

以下是預定的套件安裝方式。**Homebrew／Scoop 套件目前尚未發布驗證，請待套件上架後再使用。** macOS／Windows 執行檔及 `checksums.txt` 請從 [GitHub Releases](https://github.com/vincent119/tlscheck/releases)取得。 現階段可[從原始碼建置](#從原始碼建置)。壓縮檔校驗與發佈準備見[發佈手冊](docs/releasing.zh-TW.md)。

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

目前尚未提供 Linux 套件或發佈壓縮檔。現有 Homebrew Formula 只支援 macOS，不能當作 Linuxbrew 安裝方式；可用的建置指令見[從原始碼建置](#從原始碼建置)。

## 常用檢查

以下以安裝後的 `tlscheck` 指令示範。原始碼建置請改用 macOS／Linux 的 `./bin/tlscheck` 或 Windows 的 `.\bin\tlscheck.exe`。遠端目標需要網路，本機路徑請換成自己的檔案。

```sh
tlscheck example.com 'https://example.com:8443/'
tlscheck --local ./local/site.pem --local ./local/chain.pem --local ./local/site.key
tlscheck --local ./local/site.pem --detail full -L zh-TW
tlscheck --remote example.com --expiry-warning-days 14 --fail-on-expiry-warning
```

表格詳細程度預設為 `summary`，會減少重複的成功敘述，保留失敗、提醒與驗證限制。需要全部明細及診斷代碼時，使用 `--detail full`。這個參數只影響 table，其他格式維持完整內容。

到期提醒預設為 30 天，提醒本身不改變結束碼。加上 `--fail-on-expiry-warning` 後，提醒會使檢查回傳 1，也涵蓋已解析的 CA 與中繼憑證。`--expiry-warning-days 0` 會停用提醒及這項政策，過期檢查仍會執行。

自動辨識會優先讀取已存在的檔案。用 `--remote` 強制當作遠端目標，或用 `--local` 強制讀取本機檔案。檔名以 `-` 開頭時，請加上 `./`、`.\`，或放在 `--` 後面。

目標接受 DNS 名稱、經 IDNA 轉換的 Unicode 網域、IPv4、IPv6、`localhost` 與單段主機名稱。IPv6 帶連接埠時使用方括號，例如 `[2001:db8::1]:8443`；不接受 zone。這些 IP 是文件用位址，實際執行時須換成可連線的目標。

URL 必須使用標準 `https://`。預設連接埠為 443，指定值限 1–65535。連線與報告前會去除帳密、路徑、查詢參數及片段；shell 歷史仍可能保留原始指令，請勿將帳密寫進目標 URL。

## 批次目標與部署比對

目標清單使用 UTF-8，每行一個遠端目標。空白行及整行 `#` 註解會略過。每行只當作目標值，不會執行 shell 指令或解析成 CLI 旗標。

```text
# targets.txt
example.com
https://example.org:8443/
```

```sh
tlscheck --targets-file ./targets.txt
tlscheck --targets-file ./targets.txt --concurrency 4 -f json
tlscheck --targets-file ./targets.txt --connect-ip 0=192.0.2.10 --compare-cert 0=./local/expected.pem
tlscheck --remote example.com --compare-cert 0=./local/expected.pem
```

遠端預設循序檢查。`--concurrency` 接受 1–32；即使完成順序不同，報告仍依輸入順序排列。可重複指定 `--targets-file`，也能混合直接遠端與本機輸入。

映射格式為 `INDEX=VALUE`。所有清單展開後，統一從 0 編號，本機輸入及無效的非空目標行也占索引。相同網域重複出現時，各自保留獨立位置。映射只在第一個 `=` 分割，因此候選路徑可含空白、其他等號與 Windows 磁碟代號。

`--connect-ip INDEX=IP` 只改該目標的連線位置，SNI 與名稱驗證仍使用原網域，連接埠也沿用原目標。指定後不查 DNS、不回退其他位址。IP 須為純 IPv4 或 IPv6 literal，不帶方括號、zone 或連接埠。報告會分開顯示要求的 IP 與實際觀測到的 peer 位址。

`--compare-cert INDEX=PATH` 使用同一次 TLS 握手的葉憑證，與候選的完整憑證 DER 比較。同公鑰續期後仍是不同憑證。候選接受 PEM／DER 憑證或 PEM 鏈，完整 DER 去重後須恰有一張非 CA 憑證。混有私鑰、損壞區塊、其他容器、多張葉憑證或純 CA 的候選會被拒絕。候選不會加入本機配對集合或信任庫。

比對相同時仍可能信任失敗。憑證不同回傳 1，連線失敗回傳 2；未觀測到葉憑證時，比對顯示未執行。重複映射、綁到本機或無效目標、超出索引範圍，都會在網路檢查前拒絕。

## 本機格式與 PFX 密碼

| 物件 | 支援格式 | 編碼 |
|---|---|---|
| X.509 憑證，包含 CA | 憑證或 PEM 鏈 | PEM、DER |
| RSA 私鑰 | PKCS#1、PKCS#8 | PEM、DER |
| ECDSA 私鑰 | SEC1、PKCS#8，NIST P-224/P-256/P-384/P-521 | PEM、DER |
| Ed25519 私鑰 | PKCS#8 | PEM、DER |
| PKCS#7／P7B | 僅含憑證的 SignedData | PEM、DER |
| PKCS#12／PFX | 一把私鑰搭配憑證，或純憑證容器 | DER |

一般 PEM 解析遇到損壞或不支援區塊時，會保留其他有效物件，結束碼為 2。PFX 採原子解碼，失敗的容器不提供部分私鑰或憑證。不支援獨立加密私鑰檔案的解密；PFX 解密限於支援的容器格式。

```sh
tlscheck --local ./local/chain.p7b
tlscheck --local ./local/identity.pfx --ask-password 0
tlscheck --local ./local/identity.pfx --password-file '0=./local/pfx-password.txt'
```

PFX 未指定密碼來源時，會嘗試空密碼。`--ask-password INDEX` 以無回顯方式讀取，必須連接終端。不提供明文密碼旗標或密碼環境變數。密碼檔須為權限受限的一般檔案，且不可與輸入、候選憑證、目標清單或設定檔互為別名。Unix 須由目前使用者擁有，並使用只有擁有者能存取的權限，例如 `0600`。Windows 的擁有者及 ACL 允許項目限於目前使用者、SYSTEM 或 Administrators。

密碼檔使用 UTF-8、無 BOM，只移除最後一組 LF 或 CRLF，其餘空白保留。密碼上限為 4 KiB，僅接受不含 NUL 的 BMP 字元，不支援 emoji 等非 BMP 字元。PFX 支援 PBES2、PBKDF2-HMAC-SHA-256、AES-256-CBC 與 SHA-256 MAC，不支援舊式 RC2／3DES、SHA-1 組合。舊容器被拒絕時，請改用現代加密設定重新匯出。

## 完整參數

| 參數 | 短旗標 | 預設或用途 |
|---|---|---|
| `[target-or-file]...` | | 自動辨識，已存在檔案優先 |
| `--remote TARGET` | `-r` | 遠端輸入，可重複 |
| `--local PATH` | `-l` | 本機檔案，可重複 |
| `--targets-file PATH` | | 目標清單，可重複 |
| `--concurrency N` | | 1，範圍 1–32 |
| `--connect-ip INDEX=IP` | | 逐目標連線位址，可重複 |
| `--compare-cert INDEX=PATH` | | 逐目標預期憑證，可重複 |
| `--password-file INDEX=PATH` | | 受保護的 PFX 密碼檔，可重複 |
| `--ask-password INDEX` | | PFX 隱藏密碼提示，可重複 |
| `--language CODE` | `-L` | 單次覆寫為 `en`、`zh-TW` 或 `zh-CN` |
| `--format FORMAT` | `-f` | `table`、`json`、`html`、`markdown`，預設 `table` |
| `--detail LEVEL` | | `summary` 或 `full`，預設 `summary`，只影響 table |
| `--output PATH` | `-o` | `-` 代表 stdout |
| `--overwrite` | | 允許覆寫既有報告 |
| `--timeout DURATION` | `-t` | 每目標 10s，範圍 1ms–5m |
| `--expiry-warning-days N` | | 30，範圍 0–36500，0 停用提醒 |
| `--fail-on-expiry-warning` | | 到期提醒改為失敗 |
| `--settings` | `-s` | 互動語系與選單主題設定 |
| `--help` | `-h` | 顯示說明 |
| `--version` | `-V` | 顯示版本 |
| `--` | | 其後全部當作位置輸入 |

每個可重複旗標一次只接一個值，其餘旗標不得重複。布林旗標不接受值，例如 `--overwrite=true` 會被拒絕。說明與版本可搭配語系，但不可混用執行旗標或檢查目標。`--settings` 為獨立操作，`--settings --help` 可在不開啟選單的情況下查看說明。不帶參數時顯示說明並回傳 0。

## 儲存報告

```sh
tlscheck --local ./local/site.pem -f json -o ./report.json
tlscheck --local ./local/site.pem -f html -o ./report.html --overwrite
tlscheck --local ./local/site.pem -f markdown
```

格式由 `--format` 決定，不依副檔名推斷。`--output` 將報告寫入指定檔案，stdout 保持空白。父目錄必須已存在，覆寫既有檔案須加 `--overwrite`；不展開 `~`。

輸出會拒絕符號連結、特殊檔案，以及受保護輸入、候選、清單、密碼或設定檔的別名。完整報告序列化後才寫入暫存檔並提交。替換時會保留必要的原生安全屬性，無法保留則安全失敗。偵測到目的地變動會停止寫入；最後的快照檢查與重新命名，不保證能原子地防止任意外部程序競爭。

JSON 使用 `schema_version: 1`、穩定代碼與識別碼、UTC 時間，空集合為 `[]`，未觀測事實為 `null`。訊息依語系翻譯。新模式分別加入可選的 `inputs[].list_source`、`remote[].connection`、`remote[].comparison`，未使用時省略。嚴格拒絕未知欄位的消費者須配合更新。`summary.check_exit_code` 只涵蓋檢查結果，後續輸出失敗仍可使程序回傳 2。

HTML 為獨立離線文件，沒有 JavaScript 或外部資源，也不會自動開啟瀏覽器。所有格式都排除私鑰內容，目標 URL 的帳密與查詢參數會先移除。逐輸入計數可能因本機共用檢查而重疊，全域總數請看彙整結果。

## 語系與指令補全

使用 `-L zh-TW`、`-L zh-CN` 或 `-L en` 覆寫單次語系。有效 CLI 語系不讀取設定檔，也不儲存。未指定時，以 JSON 語系設定優先於預設英文；不支援自訂設定路徑或語系環境變數。

| 平台 | 設定檔 |
|---|---|
| macOS | `~/Library/Application Support/tlscheck/config.json` |
| Windows | `%AppData%\tlscheck\config.json` |

```json
{"language":"zh-TW","theme":"normal"}
```

`--settings` 的 stdin 與 stderr 都須連接終端。可用方向鍵、Enter、Esc、Ctrl+C，或按 `t` 選擇主題。只有「儲存並離開」才寫入 `config.json`，取消維持原設定。`normal`、`dark`、`light` 三種主題只影響選單。損壞的設定須先修復再儲存。缺少設定時使用英文與 normal；無效或不可讀的設定會在 stderr 提醒並採安全預設值，不單獨改變結束碼。設定上限為 64 KiB。

在目前 shell 載入補全：

```sh
# Bash，須先載入相容的 bash-completion 套件
source <(tlscheck completion bash)
# Zsh，須先執行 compinit
source <(tlscheck completion zsh)
# Fish
tlscheck completion fish | source
```

```powershell
tlscheck completion powershell | Out-String | Invoke-Expression
```

四種 shell 產生腳本時都接受 `--no-descriptions` 與語系覆寫。補全不執行憑證檢查、不讀取設定或憑證內容，檔名補全可列舉目錄。PowerShell 無候選占位會保留已有字詞並禁止回退檔名補全，空游標處可能多一個空白。Windows 真正鍵盤 Tab、選單儲存及 Console 復原仍待人工驗收，Bash／Fish 的完整互動證據也尚未齊全。

## 信任、結果與限制

本機檔案共用憑證／私鑰集合，以標準化公開金鑰 DER 配對並列出所有匹配。只有私鑰或只有憑證時不要求配對，遠端憑證不與本機私鑰配對。同時提供私鑰與站台憑證時，每把私鑰及每張站台憑證都須有匹配項目。CA 可與私鑰配對，但不要求提供私鑰。

信任來自作業系統信任庫，提供根憑證檔案不會安裝或信任該根。本機憑證檢查沒有主機名稱輸入。遠端依原目標身分驗證，握手完成本身不代表受信任。macOS 的單獨 CA 驗證使用 `/usr/bin/security`，禁止網路補鏈，再由 Go 檢查鏈。tlscheck 本身不主動透過 AIA 抓取簽發者，也不執行 CRL／OCSP 撤銷檢查。

| 結束碼 | 意義 |
|---|---|
| 0 | 適用檢查通過，或說明、補全、設定操作完成 |
| 1 | 憑證、私鑰、信任、配對、部署比對或已啟用的到期政策失敗 |
| 2 | 輸入、解析、不支援格式、網路、逾時、取消或輸出錯誤 |

取最高等級：2＞1＞0。只有提醒時回傳 0，除非已啟用到期失敗政策。未執行的檢查會明確標示。單項輸入錯誤仍可保留其他有效輸入；無效旗標、映射與全域資源超限，則在網路檢查前停止。設定提醒與執行診斷寫入 stderr，報告預設寫入 stdout，或由 `--output` 指定檔案。

| 資源 | 上限 |
|---|---|
| 本機檔案或比對候選 | 每檔實際讀取 10 MiB |
| 目標清單 | 每檔 1 MiB、每行 8 KiB，最多 200 份、合計 8 MiB |
| 批次模式展開後輸入 | 1,000 筆，含本機輸入與無效目標行 |
| 每個遠端目標 | DNS／TCP／TLS 共用期限，預設 10s |

PFX 解碼另有限制 ASN.1 深度、bag／憑證數、解密資料量及金鑰推導工作量。時間使用 UTC，剩餘天數向下取整。平台信任 API 有其取消限制。

tlscheck 不產生 CSR、私鑰或憑證，不更新部署、不檢查網頁內容或掃描加密套件，也不管理系統信任。密碼學檢查涵蓋解析後物件與公鑰一致性，不證明私鑰保密性或亂數品質。

## 從原始碼建置

需要 Go 1.27.0 以上版本，CI 使用 Go 1.27.4。取得 repository 後，從根目錄執行：

```sh
git clone https://github.com/vincent119/tlscheck.git
cd tlscheck
```

Windows PowerShell：

```powershell
go build -o bin/tlscheck.exe ./cmd/tlscheck
.\bin\tlscheck.exe --version
.\bin\tlscheck.exe --help
```

macOS／Linux：

```sh
go build -o bin/tlscheck ./cmd/tlscheck
./bin/tlscheck --version
./bin/tlscheck --help
```

Linux amd64／arm64 交叉建置已通過，尚未驗證 Linux 原生執行或安裝，也未納入 macOS／Windows 發佈壓縮檔矩陣。一般原始碼建置未注入版本資訊時，顯示 `development` 與 `unknown`。各平台狀態見[發佈文件](docs/releasing.zh-TW.md#平台狀態)。

## 開發與驗證

```sh
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...
git diff --check
```

`govulncheck` 依目前 Go 版本與建置目標，向 [Go 漏洞資料庫](https://go.dev/security/vuln/database)檢查可達的已知漏洞。獨立 workflow 掃描四種封裝目標，發現適用漏洞或掃描無法完成時會失敗。徽章反映實際執行結果，不代表已找到所有安全問題；請核對欲發佈來源 commit 對應的 workflow 結果。目前未發布測試覆蓋率百分比。

[2026-11-20 跨平台 CI](https://github.com/vincent119/tlscheck/actions/runs/44693571937)，來源 `6394a47`，七項工作全數通過，涵蓋封裝、原生普通／race 測試、隔離壓縮檔安裝、設定保留與 HTML 腳本回歸。macOS arm64／amd64 與 Windows amd64 有原生 CI 證據，Windows arm64 僅有交叉建置證據。這些結果不涵蓋真實 Console、HTML／表格人工可讀性或套件管理器安裝升級。race 偵測需要支援的原生 Go 與 C 工具鏈。

選用 GNU Make 時可執行 `make help`。執行檔放在 `bin/`，snapshot 壓縮檔放在 `dist/`，私有本機輸入可放已忽略的 `local/`。封裝與重試程序見[發佈維護文件](docs/releasing.zh-TW.md)。本 README 以目前 CLI 為準，Release 壓縮檔須核對版本與校驗值，目前未提供簽章或公證。

## 授權

[Apache License 2.0](LICENSE)。
