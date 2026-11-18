// Package testutil 只產生測試用合成憑證，不讀寫系統信任設定。
package testutil

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// Identity 保持測試簽發所需憑證及金鑰，不可傳入報告或日誌。
type Identity struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// NewKey 使用標準亂數產生合成 Ed25519 key。
func NewKey(t testing.TB) crypto.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// Template 明確限定有效期，讓測試不依賴執行當天。
func Template(serial int64, name string, now time.Time, ca bool) *x509.Certificate {
	usage := x509.KeyUsageDigitalSignature
	if ca {
		usage |= x509.KeyUsageCertSign
	}
	return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: ca, KeyUsage: usage, SubjectKeyId: []byte{byte(serial), 1, 2, 3}}
}

// Issue 可使用相同 key 建立交叉簽章，但不把產物加入系統信任庫。
func Issue(t testing.TB, template *x509.Certificate, parent *Identity, key crypto.Signer) Identity {
	t.Helper()
	if key == nil {
		key = NewKey(t)
	}
	issuer, signer := template, key
	if parent != nil {
		issuer, signer = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Cert: cert, Key: key}
}
