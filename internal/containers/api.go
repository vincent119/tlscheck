// Package containers 解析有界憑證容器，不進行信任驗證或輸出秘密。
package containers

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"unicode/utf8"
)

// 安全錯誤不包含密碼、私鑰或函式庫原始診斷。
var (
	ErrLimit       = errLimit
	ErrUnsupported = errUnsupported
	ErrIntegrity   = errIntegrity
	ErrStructure   = errStructure
)

// MaxPasswordSize 限制密碼來源讀取及解碼前的bytes。
const MaxPasswordSize = 4096

// Result 的私密物件不匯出，避免反射序列化私鑰。
type Result struct{ data controlledResult }

// Certificates 只提供公開憑證供既有分析流程使用。
func (r Result) Certificates() []*x509.Certificate { return r.data.certs }

// Signer 只供記憶體內有效性與配對檢查，不可傳入報告或日誌。
func (r Result) Signer() crypto.Signer { return r.data.key }

// String 避免預設格式化展開私密物件。
func (r Result) String() string { return "容器物件（私鑰內容不顯示）" }

// GoString 避免 %#v 展開私密物件。
func (r Result) GoString() string { return r.String() }

// Decode 原子交付完整通過限制及完整性驗證的物件，不視為信任成功。
func Decode(ctx context.Context, data, password []byte) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if !PasswordSupported(password) {
		return Result{}, ErrUnsupported
	}
	result, _, err := controlledDecode(ctx, data, string(password), proposedLimits())
	if err != nil {
		return Result{}, err
	}
	return Result{data: result}, nil
}

// DecodeP7B 可保留結構完整容器的有效憑證及獨立問題分類。
func DecodeP7B(ctx context.Context, data []byte) ([]*x509.Certificate, []error, error) {
	r, err := parseP7B(ctx, data, proposedLimits())
	return r.certs, r.issues, err
}

// PasswordSupported 不正規化密碼，首版依上游限制拒絕非BMP、NUL及無效UTF-8。
func PasswordSupported(password []byte) bool {
	if len(password) > MaxPasswordSize || !utf8.Valid(password) {
		return false
	}
	for _, r := range string(password) {
		if r == 0 || r > 0xffff {
			return false
		}
	}
	return true
}

// Kind 只定位候選容器，不代表結構或完整性驗證成功，也不讀密碼。
func Kind(data []byte) string {
	var root asn1.RawValue
	_, err := asn1.Unmarshal(data, &root)
	if err != nil || root.Tag != asn1.TagSequence || root.Class != 0 {
		return ""
	}
	var first asn1.RawValue
	rest, err := asn1.Unmarshal(root.Bytes, &first)
	if err != nil {
		return ""
	}
	var oid asn1.ObjectIdentifier
	if first.Tag == asn1.TagOID && unmarshal(first.FullBytes, &oid) == nil && oid.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}) {
		return "PKCS#7"
	}
	if first.Tag == asn1.TagInteger {
		var ci contentInfo
		if _, err := asn1.Unmarshal(rest, &ci); err == nil && len(ci.ContentType) >= 7 {
			prefix := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7}
			if ci.ContentType[:6].Equal(prefix) {
				return "PKCS#12"
			}
		}
	}
	return ""
}
