// Package check 分開保存憑證事實、簽章鏈結與信任驗證結果。
package check

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
)

// Status 的零值為未執行，避免缺少結果時被誤認為通過。
type Status uint8

const (
	NotPerformed Status = iota
	Passed
	Failed
)

// FailureClass 供後續 CLI 彙整，不直接執行退出或翻譯。
type FailureClass uint8

const (
	NoFailure FailureClass = iota
	VerificationFailure
	ExecutionFailure
)

// Outcome 只包含穩定的訊息代碼，不保存函式庫錯誤原文。
type Outcome struct {
	Status Status
	Code   string
	Class  FailureClass
}

// Role 不以主體名稱或憑證排序猜測 CA 身分。
type Role string

const (
	Site Role = "site"
	CA   Role = "ca"
)

// CertificateInfo 僅包含公開欄位與固定時間下的分析結果。
type CertificateInfo struct {
	Subject            string
	Issuer             string
	SerialNumber       string
	FingerprintSHA256  string
	DNSNames           []string
	IPAddresses        []string
	EmailAddresses     []string
	URIs               []string
	PublicKeyAlgorithm string
	PublicKeyBits      int
	PublicKeyCurve     string
	NotBefore          time.Time
	NotAfter           time.Time
	RemainingDays      int64
	Expired            bool
	ExpiringSoon       bool
	SelfIssued         bool
	SelfSigned         bool
}

// IssuerLink 為候選關係事實，失配候選不會覆蓋其他成功候選。
type IssuerLink struct {
	IssuerFingerprint string
	SignatureValid    bool
}

// CertificateResult 將解析、時間、CA 約束、鏈結與信任分開。
type CertificateResult struct {
	Info          CertificateInfo
	Role          Role
	Sources       []model.SourceRef
	Parse         Outcome
	Validity      Outcome
	CAConstraints Outcome
	Linkage       Outcome
	Links         []IssuerLink
	Trust         TrustResult
}

// CertificateOptions 只調整提醒，不影響憑證時間與信任驗證。
type CertificateOptions struct{ ExpiryWarningDays int }

// AnalyzeCertificate 只分析公開資訊，不宣稱已建立信任。
func AnalyzeCertificate(cert *x509.Certificate, now time.Time) (CertificateInfo, error) {
	return AnalyzeCertificateWithOptions(cert, now, CertificateOptions{ExpiryWarningDays: 30})
}

// AnalyzeCertificateWithOptions 使用同一分析時間及明確提醒門檻。
func AnalyzeCertificateWithOptions(cert *x509.Certificate, now time.Time, options CertificateOptions) (CertificateInfo, error) {
	if options.ExpiryWarningDays < 0 || options.ExpiryWarningDays > 36500 {
		return CertificateInfo{}, errors.New("無效的到期提醒天數")
	}

	if cert == nil || len(cert.Raw) == 0 || cert.SerialNumber == nil || now.IsZero() {
		return CertificateInfo{}, errors.New("缺少已解析憑證或固定分析時間")
	}
	fingerprint := sha256.Sum256(cert.Raw)
	info := CertificateInfo{
		Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SerialNumber: cert.SerialNumber.Text(16),
		FingerprintSHA256: strings.ToUpper(hex.EncodeToString(fingerprint[:])),
		DNSNames:          append([]string(nil), cert.DNSNames...), EmailAddresses: append([]string(nil), cert.EmailAddresses...),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), NotBefore: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
		Expired: now.After(cert.NotAfter), SelfIssued: bytes.Equal(cert.RawSubject, cert.RawIssuer),
	}
	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
	}
	for _, uri := range cert.URIs {
		if uri != nil {
			info.URIs = append(info.URIs, uri.String())
		}
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key != nil && key.N != nil {
			info.PublicKeyBits = key.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if key != nil && key.Curve != nil {
			info.PublicKeyBits = key.Curve.Params().BitSize
			info.PublicKeyCurve = key.Curve.Params().Name
		}
	case ed25519.PublicKey:
		info.PublicKeyBits = len(key) * 8
	case *dsa.PublicKey:
		if key != nil && key.P != nil {
			info.PublicKeyBits = key.P.BitLen()
		}
	}
	// 不能用 Duration 算遠期憑證的日數，因為 Sub 會在約 290 年飽和。
	seconds := cert.NotAfter.Unix() - now.Unix()
	if cert.NotAfter.Nanosecond() < now.Nanosecond() {
		seconds--
	}
	info.RemainingDays = seconds / 86400
	if seconds < 0 && seconds%86400 != 0 {
		info.RemainingDays--
	}
	info.ExpiringSoon = options.ExpiryWarningDays > 0 && !info.Expired && cert.NotAfter.Sub(now) <= time.Duration(options.ExpiryWarningDays)*24*time.Hour
	info.SelfSigned = info.SelfIssued && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	return info, nil
}

func passed(code string) Outcome  { return Outcome{Status: Passed, Code: code} }
func skipped(code string) Outcome { return Outcome{Status: NotPerformed, Code: code} }
func failed(code string, class FailureClass) Outcome {
	return Outcome{Status: Failed, Code: code, Class: class}
}

func checkValidity(cert *x509.Certificate, now time.Time) Outcome {
	if now.Before(cert.NotBefore) {
		return failed("certificate.not_yet_valid", VerificationFailure)
	}
	if now.After(cert.NotAfter) {
		return failed("certificate.expired", VerificationFailure)
	}
	return passed("certificate.time_valid")
}

func checkCAConstraints(cert *x509.Certificate) Outcome {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return failed("certificate.ca_constraints_invalid", VerificationFailure)
	}
	hasKeyUsage := cert.KeyUsage != 0
	for _, extension := range cert.Extensions {
		if extension.Id.String() == "2.5.29.15" {
			hasKeyUsage = true
		}
	}
	if hasKeyUsage && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return failed("certificate.ca_signing_not_allowed", VerificationFailure)
	}
	return passed("certificate.ca_constraints_valid")
}
