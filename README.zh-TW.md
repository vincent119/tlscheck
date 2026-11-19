# tlscheck

[English](README.md) | [繁體中文](README.zh-TW.md)

tlscheck 是 Go CLI，用於診斷遠端 TLS 憑證、檢查本機憑證與私鑰配對。握手事實與系統信任分開呈現，本機私鑰不參與遠端連線。

## 建置與開始使用

需要 Go 1.27.0 以上版本。Go 1.27.4 已在 macOS arm64／amd64 與 Windows amd64 的 CI 驗證。以下指令從 repository 根目錄執行；GNU Make 為選用工具。

macOS：

```sh
go build -o bin/tlscheck ./cmd/tlscheck
./bin/tlscheck
./bin/tlscheck --version
```

Windows 使用 PowerShell：

```powershell
go build -o bin/tlscheck.exe ./cmd/tlscheck
.\bin\tlscheck.exe
.\bin\tlscheck.exe --version
```

不帶參數會顯示說明並回傳 0。未修改的開發建置顯示版本 `development`、來源 commit `unknown`。`--help`／`-h` 顯示說明，`--version`／`-V` 顯示版本；可搭配 `--language`／`-L`，不得混用檢查目標或一般檢查旗標。未知旗標與無效組合回傳 2。本機檔名若以 `-` 開頭，可加上 `./`、`.\` 路徑前綴，或放在 `--` 後。

目前可從原始碼建置。2026-11-18 的[跨平台 CI](https://github.com/vincent119/tlscheck/actions/runs/44285001106)（來源 `a1cff07`）已通過四目標 snapshot 封裝與校驗，以及 macOS arm64／amd64、Windows amd64 的原生測試、隔離壓縮檔安裝／同版本重裝及設定保留檢查。Windows arm64 僅交叉建置。正式 Release、Homebrew／Scoop 安裝升級、簽章與公證尚未驗證；真實 Console 與完整 shell 補全互動仍待驗收。驗證紀錄與限制見[安裝與發佈維護](docs/releasing.zh-TW.md)。

## 檢查目標與檔案

以下範例需要自行準備本機檔案，或能連線到指定服務。公開網路範例僅示範用法，不代表安裝或連線驗證證據。

macOS：

```sh
./bin/tlscheck example.com 'https://example.com:8443/'
./bin/tlscheck 192.0.2.10 '[2001:db8::1]:443' '例子.測試'
./bin/tlscheck ./local/site.pem ./local/intermediate.pem ./local/site.key
./bin/tlscheck ./local/root.cer
./bin/tlscheck ./local/site.pem example.com ./local/site.key
./bin/tlscheck ./local/missing.pem
printf '%s\n' "$?"
```

Windows PowerShell：

```powershell
.\bin\tlscheck.exe example.com 'https://example.com:8443/'
.\bin\tlscheck.exe 192.0.2.10 '[2001:db8::1]:443' '例子.測試'
.\bin\tlscheck.exe .\local\site.pem .\local\intermediate.pem .\local\site.key
.\bin\tlscheck.exe .\local\root.cer
.\bin\tlscheck.exe .\local\site.pem example.com .\local\site.key
.\bin\tlscheck.exe .\local\missing.pem
$LASTEXITCODE
```

IP 範例使用文件保留位址，需替換成可連線目標。缺檔範例會回傳 2。站台憑證與私鑰即使配對成功，信任驗證仍可能失敗。

既有檔案優先於網路辨識。缺少的明確路徑，以及不存在的 `.pem`、`.cer`、`.crt`、`.key` 檔名均視為檔案錯誤，不轉作網路目標。只接受一般檔案。其他輸入視為 DNS 名稱、經 IDNA 正規化的 Unicode IDN、IPv4、IPv6、`localhost` 或單標籤主機名稱。不支援 IPv6 區域識別碼。

HTTPS URL 必須使用標準 `https://`；預設連接埠為 443，明確指定的連接埠必須是 1–65535 的整數。接受尾端 `/`。URL 帳密、路徑、查詢參數與片段在連線及報告前自動去除。不支援其他 URL scheme。請避免將帳密放進命令：即使報告會去除，shell 歷史仍可能保存原始輸入。

| 本機物件 | 支援格式 | 編碼 |
|---|---|---|
| X.509 憑證，包含 CA | 憑證 | PEM、DER |
| RSA 私鑰 | PKCS#1、PKCS#8 | PEM、DER |
| ECDSA 私鑰 | SEC1、PKCS#8；NIST P-224/P-256/P-384/P-521 | PEM、DER |
| Ed25519 私鑰 | PKCS#8 | PEM、DER |

接受多個 PEM 區塊。部分區塊損壞或不支援時，仍保留有效物件，最終結束碼為 2。不支援加密私鑰，不嘗試解密，也不提示輸入密碼。不支援 PKCS#12/PFX 與其他私鑰演算法。

## 完整參數與輸出

| 參數 | 短參數 | 預設／用途 |
|---|---|---|
| `[target-or-file]...` | | 自動辨識，既有檔案優先 |
| `--remote TARGET` | `-r` | 強制遠端，可重複，不讀同名本機檔案 |
| `--local PATH` | `-l` | 強制本機，可重複，缺檔不連線 |
| `--language CODE` | `-L` | 本次語系，en／zh-TW／zh-CN |
| `--format FORMAT` | `-f` | table（預設）／json／html／markdown |
| `--output PATH` | `-o` | 預設 `-`，代表 stdout |
| `--overwrite` | | 預設關閉，須搭配非 `-` 的 output |
| `--timeout DURATION` | `-t` | 10s，範圍 1ms–5m |
| `--expiry-warning-days DAYS` | | 30，範圍 0–36500，0 停用提醒 |
| `--settings` | `-s` | 獨立互動語系／theme 設定 |
| `--help` | `-h` | 說明，結束碼 0 |
| `--version` | `-V` | 版本，結束碼 0 |
| `--` | | 之後全視為位置輸入 |

位置、remote 與 local 依命令列出現順序檢查，不去重。remote/local 每次只接受一個值，逗號不拆分。其餘旗標不得重複；無值布林旗標不能寫成 `--overwrite=true`。必填值不可省略或設為空字串，包含 `--remote=`／`--local=`；此類錯誤不建立報告檔。`--settings` 不與檢查／語系旗標混用；`--settings --help` 可不進選單查看說明。只有語系旗標時顯示說明；只有一般執行旗標卻無目標時回傳 2。

```sh
./bin/tlscheck -r example.com --local ./local/site.pem -L zh-TW
./bin/tlscheck 'https://example.com:8443/' -t 5s --expiry-warning-days 14
./bin/tlscheck -l ./local/site.pem -f json -o ./report.json
./bin/tlscheck -l ./local/site.pem -f html -o ./report.html --overwrite
./bin/tlscheck -l ./local/site.pem -f markdown
./bin/tlscheck --settings
```

報告格式不依副檔名猜測。output 父目錄必須已存在；不展開 `~`。預設不覆蓋既有檔案；拒絕目錄、特殊檔案、symlink，以及與輸入／設定同檔或 hardlink 的目的地。完整序列化、暫存寫入、同步與關閉成功後才提交；若輸出失敗，程序回傳 2。JSON 的 `summary.check_exit_code` 只描述檢查結果，程序另可能因 I/O 失敗回傳 2。macOS 新報告檔使用 0600 並移除繼承 ACL；覆寫時保存原生 ACL、擁有者及群組。若安全屬性無法可靠保存，或 ACL 會妨礙提交／失敗清理，會拒絕覆寫並保留原檔。Windows 使用受保護 DACL 並檢查既有安全屬性；唯讀目的檔透過相對既有目錄 handle 的原子替換保存唯讀屬性與 DACL，不先移除原檔或清除其唯讀屬性。不支援此操作的 Windows／檔案系統會安全失敗；唯讀替換、DACL 保存與失敗清理已通過 Windows amd64 CI 回歸。檢查到目的地快照變更即停止；快照與重新命名之間不具有對任意外部程序的 compare-and-swap 保證。

JSON 為單一 UTF-8 物件、兩空格縮排及檔尾換行，固定 `schema_version: 1`。頂層包含 `tool`、`generated_at`（UTC）、`language`、依序 `inputs`、`local`、`remote` 與 `summary`。狀態固定為 `passed`／`failed`／`not_performed`；嚴重度為 `none`／`verification`／`execution`。代碼固定、說明依語系翻譯，空集合為 `[]`，未觀測 TLS 為 `null`。`advice` 為 `null` 或 `{ "code": "advice.…", "message": "…" }`，代碼不隨語系變更。table／HTML／Markdown 另有逐輸入結果與最高嚴重度摘要，以及 key ID／certificate ID 配對表；全域計數不因衍生視圖重複累計。table 將反斜線顯示為 `\\`、pipe 顯示為 `\u007c`，其他格式保留各自安全文字。憑證以完整 SHA-256 指紋識別，私鑰僅含逐來源識別碼與公開資訊；不輸出私鑰內容或原始完整 URL。HTML 不載入外部資源、不執行 JavaScript，也不自動開瀏覽器。

## 指令自動完成

`completion` 是保留的輔助子命令。檢查同名主機可用 `-r completion` 或 `-- completion`，同名檔案可用 `-l completion`。`completion SHELL --help`／`-h` 顯示該層說明。隱藏補全不回顯原始錯誤；生成腳本的偵錯函式不寫檔，`BASH_COMP_DEBUG_FILE` 不會啟用寫入。補全不連線、不讀設定或憑證內容；檔名補全可列舉目錄。Bash 須先載入與其版本相容的 bash-completion，提供 `_get_comp_words_by_ref`／`_init_completion`；僅 source 產生的腳本不足以補齊此 shell 依賴。目前本機缺少該套件，Bash 只完成腳本語法與協定驗證。

四種 shell 皆支援 `--no-descriptions` 及 `-L`／`--language`，不接受一般檢查旗標。

```sh
# Bash
source <(./bin/tlscheck completion bash)
# Zsh
source <(./bin/tlscheck completion zsh)
# Fish
./bin/tlscheck completion fish | source
# 只產生不含描述的腳本
./bin/tlscheck completion zsh --no-descriptions
```

PowerShell：

```powershell
.\bin\tlscheck.exe completion powershell | Out-String | Invoke-Expression
```

以上在目前 shell 載入；持久啟用時將對應指令加入自己的 shell 啟動檔。腳本生成及本機可用 shell 的語法驗證，不等於 Windows／Fish 原生互動已通過。

## 語系設定

本次語系可用 `--language en|zh-TW|zh-CN`／`-L` 指定，優先於 JSON 與預設英文。有效 CLI 語系不讀取設定檔，也不儲存。不支援語系環境變數或自訂設定路徑；平台目錄由 `os.UserConfigDir()` 決定。

| 平台 | 設定檔 |
|---|---|
| macOS | `~/Library/Application Support/tlscheck/config.json` |
| Windows | `%AppData%\tlscheck\config.json` |

執行 `tlscheck --settings`／`-s` 開啟互動選單。stdin 與 stderr 都必須連接終端；選單使用 stderr，stdout 保持空白。方向鍵移動、Enter 選擇、Esc 返回或取消、Ctrl+C 取消、`t` 開啟 theme。macOS 終端斷線會退出且不儲存。僅選擇「儲存並離開」才寫入設定，取消不寫。損壞或有未知欄位的既有設定須先手動修復。theme 為 `normal`／`dark`／`light`，只影響選單。也可手動建立 UTF-8、無 BOM 的 JSON：

```json
{"language":"en"}
```

```json
{"language":"zh-TW","theme":"normal"}
```

```json
{"language":"zh-CN"}
```

| 條件 | 行為 |
|---|---|
| 缺檔、缺少 `language` 或空字串 | 使用英文，不提醒 |
| 目錄取得、讀取、stat、close 錯誤或非一般檔案 | 英文提醒並回退 |
| 實際資料超過 64 KiB | 英文提醒並回退 |
| JSON／UTF-8 無效、根不是物件或有尾隨資料 | 英文提醒並回退 |
| 非字串值（包含 `null`）、未知或重複鍵 | 英文提醒並回退 |
| 除精確的 `en`、`zh-TW`、`zh-CN` 或空字串以外的值 | 英文提醒並回退 |

缺少或空字串 theme 使用 normal；不支援的 theme 會提醒並使用 normal。一般檢查、查詢與補全不寫設定。

table／HTML／Markdown 的輸入模式、嚴重度、檢查名稱、階段與 URI 遮蔽原因依語系顯示；JSON 識別碼、設定值、憑證原值及路徑保持不變。語系選項保留母語名稱，theme 選項使用翻譯標籤。若本地與英文模板都無法呈現，最終保底提示也依有效語系顯示；未知語系使用英文，不回顯內部訊息代碼。

設定提醒寫入 stderr，不單獨改變結束碼。缺少翻譯時回退英文。主機名稱、路徑、演算法與憑證公開原值保留原文；顯示時移除不安全的終端控制字元及 URL 附加內容。

## 信任與私鑰配對

所有本機檔案形成共同的憑證／私鑰集合；遠端目標獨立且依序檢查。本機私鑰不會傳送作為 client authentication，也不與遠端憑證配對。

信任使用作業系統信任庫。輸入根憑證只作為候選簽發者，不會自動變成受信任根。對端提供鏈表示伺服器實際送出的內容；已驗證鏈只在信任驗證成功後存在。握手完成或簽發者簽章鏈結有效，本身均不代表受信任。本機憑證沒有主機名稱輸入，因此名稱驗證顯示未執行。

單獨 CA 必須通過適用的有效期間／CA 約束，並建立通往系統受信任根的路徑。沒有可信路徑為檢查失敗（1）；信任機制無法讀取或執行為執行錯誤（2）。macOS 的單獨 CA 使用內建 `/usr/bin/security` 的 CA／基本 X.509 政策，禁止網路補鏈，再由 Go 檢查鏈。受保護暫存檔只包含憑證，不包含私鑰。平台政策可能加入額外檢查；tlscheck 本身不主動透過 AIA 抓取簽發者，也不執行 CRL／OCSP 撤銷檢查。

配對比較完整標準化公開金鑰 DER，不只比較演算法或位數，並列出所有匹配關係。重複憑證保留來源，私鑰逐來源保留。只有私鑰或只有憑證時不要求配對；私鑰與站台憑證同時存在時，每把私鑰與每張站台憑證均須有匹配項目。CA 可配對但不要求私鑰；只有 CA 加私鑰、沒有站台時，不要求完整覆蓋。無效私鑰不能產生成功配對。

RSA 執行標準有效性檢查。ECDSA 檢查私密純量範圍、公開點是否位於曲線，以及兩者一致性。Ed25519 檢查長度與 seed 導出一致性。檢查只涵蓋解析後物件，不涵蓋解析器已捨棄或正規化的原始欄位，不證明亂數品質、保密性、密碼學強度或所有安全屬性。報告只顯示公開中繼資訊，不輸出私鑰內容。

## 結果與限制

| 結束碼 | 意義 |
|---|---|
| 0 | 適用檢查通過、說明／版本／補全成功、設定儲存或取消，或只有到期／設定提醒 |
| 1 | 憑證、私鑰、信任或配對檢查失敗 |
| 2 | 輸入、解析、不支援格式、連線、逾時、取消或輸出錯誤 |

取最高等級：2＞1＞0。單項輸入失敗不停止其餘輸入；無效 CLI 旗標組合會在檢查前拒絕。狀態分為通過、失敗、未執行；未執行不等於通過，也不單獨造成失敗。彙整計數對應實際列出的檢查，不是輸入檔案數。

預設 table 報告與檢查失敗原因寫入 stdout。指定 `--output PATH` 時完整報告只寫入檔案，不在 stdout 顯示儲存提示。設定提醒與執行診斷寫入 stderr；執行錯誤可能同時出現在完整報告與診斷流。

每份本機憑證／私鑰檔案的實際讀取上限為 10 MiB。每個遠端目標的 DNS／TCP／TLS 握手預設共用 10 秒期限（可用 `--timeout`／`-t` 調整至 1ms–5m），不是每個階段各 10 秒。平台信任操作有其平台取消限制。時間使用 UTC；剩餘天數向下取整，剛過期的憑證可顯示 -1 天。尚未過期且預設 30 × 24 小時內到期的憑證會提醒；`--expiry-warning-days` 可設 0–36500，0 停用提醒但保留過期驗證，提醒本身不改變結束碼。

報告支援 table、JSON、獨立離線 HTML 與 GFM Markdown，不含終端色彩或動畫。tlscheck 不申請、續期或部署憑證，不檢查網頁內容、不掃描加密套件、不解密私鑰，也不管理系統信任。規劃首版產物未簽章、未公證；目前沒有已驗證的簽章／公證發佈版本。

## 開發與維護

兩種平台安裝 Go 後，均可從 repository 根目錄執行：

```text
go test ./...
go test -race ./...
go vet ./...
git diff --check
```

race 偵測需要支援的原生 Go 與 C 工具鏈。測試使用合成憑證與 loopback TLS 服務，不依賴公開服務，也不將根加入系統。macOS arm64／amd64 與 Windows amd64 已通過原生 Go 測試、race、vet、Python 回歸、隔離壓縮檔安裝／同版本重裝及 CLI 版本檢查。四目標 snapshot 均已建置與核對；Windows arm64 僅交叉建置，真實 Console、完整 shell 補全與套件管理器安裝升級仍待驗收。

選用 GNU Make 指令包含 `make help`、`make build`、`make test`、`make vet`、`make check`、`make fmt`。`make build` 產生 `bin/tlscheck`；Windows 請使用前述明確的 PowerShell 建置指令取得 `.exe` 副檔名。建置產物放 `bin/`、發佈產物放 `dist/`，私有本機檔案放已忽略的 `local/`。不全面忽略憑證／私鑰副檔名，以保留刻意建立的合成 fixture。

封裝、升級、驗證與重試狀態見雙語[發佈維護文件](docs/releasing.zh-TW.md)。行為變更時，請同步更新兩份 README 及對應維護說明。

## 授權

[Apache License 2.0](LICENSE)，保留官方英文原文。
