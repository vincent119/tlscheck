// Package model 保存檢查流程共用的資料，不包含終端翻譯或信任決策。
package model

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
)

// Target 只保存連線所需主機，避免 URL 附加資料流入報告。
type Target struct {
	Host       string
	ASCIIHost  string
	Port       uint16
	InputIndex int
}

// String 使用實際連線用的 ASCII 主機，IPv6 以括號消歧。
func (t Target) String() string {
	return net.JoinHostPort(t.ASCIIHost, strconv.Itoa(int(t.Port)))
}

// SourceRef 的 Block 從 1 起算；DER 與檔案層錯誤使用 0。
type SourceRef struct {
	Path       string
	InputIndex int
	Block      int
	Encoding   string
}

// ParsedCertificate 只代表解析成功，不代表信任驗證通過。
type ParsedCertificate struct {
	Certificate *x509.Certificate
	Source      SourceRef
}

// ParsedKey 的私密物件不匯出，避免預設 JSON 序列化洩漏私鑰。
type ParsedKey struct {
	Source SourceRef
	Format string
	signer crypto.Signer
}

// NewParsedKey 只接受已解析的支援金鑰，不執行有效性或配對檢查。
func NewParsedKey(source SourceRef, format string, signer crypto.Signer) ParsedKey {
	return ParsedKey{Source: source, Format: format, signer: signer}
}

// Signer 僅供後續記憶體內檢查，不可傳入終端報告或日誌。
func (k ParsedKey) Signer() crypto.Signer { return k.signer }

// String 不展開私密欄位，避免格式化診斷洩漏金鑰。
func (k ParsedKey) String() string { return "私鑰物件（內容不顯示）" }

// GoString 同樣遮蔽 %#v，避免診斷時展開私密欄位。
func (k ParsedKey) GoString() string { return k.String() }

// IssueCode 供 i18n 使用；錯誤不保存原始 URL 或函式庫錯誤。
type IssueCode string

const (
	InvalidTarget         IssueCode = "input.invalid_target"
	UnsupportedScheme     IssueCode = "input.unsupported_scheme"
	InvalidPort           IssueCode = "input.invalid_port"
	UnsupportedZone       IssueCode = "input.unsupported_zone"
	FileNotFound          IssueCode = "input.file_not_found"
	FileUnreadable        IssueCode = "input.file_unreadable"
	NotRegularFile        IssueCode = "input.not_regular_file"
	FileTooLarge          IssueCode = "input.file_too_large"
	InvalidData           IssueCode = "input.invalid_data"
	UnsupportedBlock      IssueCode = "input.unsupported_block"
	EncryptedKey          IssueCode = "input.encrypted_key"
	UnsupportedKey        IssueCode = "input.unsupported_key"
	Canceled              IssueCode = "input.canceled"
	ContainerUnsupported  IssueCode = "input.container_unsupported"
	ContainerIntegrity    IssueCode = "input.container_integrity_failed"
	ContainerLimit        IssueCode = "input.container_resource_limit"
	PasswordUnavailable   IssueCode = "input.password_unavailable"
	PasswordNotApplicable IssueCode = "input.password_not_applicable"
	PasswordUnsupported   IssueCode = "input.password_unsupported"
)

// Issue 為輸入或執行錯誤，由 CLI 在 S06 統一對應結束碼 2。
type Issue struct {
	Code   IssueCode
	Source SourceRef
}

// Error 僅供內部診斷，使用者訊息由後續 i18n 依 Code 產生。
func (i Issue) Error() string {
	return fmt.Sprintf("輸入檢查錯誤：%s", i.Code)
}

// InputResult 可同時包含成功物件與錯誤，避免部分解析失敗吞掉其餘內容。
type InputResult struct {
	InputIndex   int
	Target       *Target
	Certificates []ParsedCertificate
	Keys         []ParsedKey
	Issues       []Issue
}

// InputKind 明確區分自動辨識與使用者指定模式。
type InputKind string

const (
	AutoInput       InputKind = "auto"
	RemoteInput     InputKind = "remote"
	LocalInput      InputKind = "local"
	TargetListInput InputKind = "targets_file"
)

// TargetListSource 只保留清單位置，Line為0表示整份清單的問題。
type TargetListSource struct {
	Path string
	Line int
}

// InputSpec 保留每次出現的順序，不以內容去重。
type InputSpec struct {
	Kind       InputKind
	Value      string
	Index      int
	ListSource *TargetListSource
	Problem    IssueCode
}
