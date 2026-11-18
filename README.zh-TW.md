# tlscheck

[English](README.md) | [繁體中文](README.zh-TW.md)

規劃以 Go 開發的 CLI，用於檢查遠端 TLS 憑證，以及本機憑證與私鑰檔案。

## 專案狀態

目前處於規格規劃階段，尚無 CLI 實作、Go module、發佈版本或可安裝套件。安裝、建置與操作指令將在實作並驗證後補上。

規劃範圍包含輸入自動辨識、憑證鏈與金鑰配對檢查、英文與中文終端訊息，以及 macOS、Windows 發佈產物。

## Repository 慣例

- `.editorconfig` 定義文字格式，`.gitattributes` 控制換行。
- 建置與發佈產物放在 `bin/`、`dist/`。
- 私有本機憑證與私鑰放在已忽略的 `local/` 目錄，請勿提交敏感資料。不全面忽略憑證與私鑰副檔名，以保留刻意建立的測試 fixture。
- 私有規格存放於此 repository 之外。
- `make help` 列出目前可用的維護指令。GNU Make 為選用工具，未來使用 CLI 不需要安裝它。

## 授權

[Apache License 2.0](LICENSE)。
