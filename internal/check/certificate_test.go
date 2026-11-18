package check

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestCertificateFieldsAndPublicKeyAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := url.Parse("https://example.test/service")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name  string
		key   crypto.Signer
		bits  int
		curve string
	}{{"RSA", rsaKey, 2048, ""}, {"ECDSA", ecKey, 384, "P-384"}, {"Ed25519", testutil.NewKey(t), 256, ""}} {
		t.Run(tt.name, func(t *testing.T) {
			template := testutil.Template(0x1234, "欄位測試", fixedNow(), true)
			template.DNSNames = []string{"a.example.test", "b.example.test"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
			template.EmailAddresses = []string{"test@example.test"}
			template.URIs = []*url.URL{uri}
			identity := testutil.Issue(t, template, nil, tt.key)
			info, err := AnalyzeCertificate(identity.Cert, fixedNow().In(time.FixedZone("測試時區", 8*3600)))
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(identity.Cert.Raw)
			if info.Subject != identity.Cert.Subject.String() || info.Issuer != identity.Cert.Issuer.String() || info.SerialNumber != "1234" || info.FingerprintSHA256 != strings.ToUpper(hex.EncodeToString(hash[:])) {
				t.Fatal("主體／簽發者／序號／指紋錯誤")
			}
			if info.PublicKeyAlgorithm != tt.name || info.PublicKeyBits != tt.bits || info.PublicKeyCurve != tt.curve {
				t.Fatalf("公開金鑰資訊錯誤：%+v", info)
			}
			if len(info.DNSNames) != 2 || len(info.IPAddresses) != 2 || info.IPAddresses[1] != "::1" || len(info.EmailAddresses) != 1 || len(info.URIs) != 1 {
				t.Fatal("SAN 資訊遺失")
			}
			if info.NotBefore.Location() != time.UTC || info.NotAfter.Location() != time.UTC || !info.SelfIssued || !info.SelfSigned {
				t.Fatal("UTC 或自簽事實錯誤")
			}
			info.DNSNames[0] = "modified"
			if identity.Cert.DNSNames[0] == "modified" {
				t.Fatal("報告 slice 不應與來源共享可變資料")
			}
		})
	}
}

func TestValidityAndExpiryWarningBoundaries(t *testing.T) {
	now := fixedNow()
	template := testutil.Template(1, "CA", now, true)
	template.NotAfter = now
	root := testutil.Issue(t, template, nil, nil)
	for _, tt := range []struct {
		name             string
		clock            time.Time
		days             int64
		expired, warning bool
		valid            Status
	}{
		{"到期前一奈秒", now.Add(-time.Nanosecond), 0, false, true, Passed},
		{"到期當下", now, 0, false, true, Passed},
		{"到期後一奈秒", now.Add(time.Nanosecond), -1, true, false, Failed},
		{"生效前一奈秒", root.Cert.NotBefore.Add(-time.Nanosecond), 1, false, true, Failed},
		{"生效當下", root.Cert.NotBefore, 1, false, true, Passed},
		{"生效後一奈秒", root.Cert.NotBefore.Add(time.Nanosecond), 0, false, true, Passed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			info, err := AnalyzeCertificate(root.Cert, tt.clock)
			if err != nil {
				t.Fatal(err)
			}
			if info.RemainingDays != tt.days || info.Expired != tt.expired || info.ExpiringSoon != tt.warning {
				t.Fatalf("時間欄位錯誤：%+v", info)
			}
			pool := x509.NewCertPool()
			pool.AddCert(root.Cert)
			result := VerifyTrust(t.Context(), root.Cert, TrustOptions{Roots: pool, Now: tt.clock, Purpose: CAPurpose})
			if checkValidity(root.Cert, tt.clock).Status != tt.valid || result.Outcome.Status != tt.valid {
				t.Fatalf("有效期與信任結果不一致：%+v", result)
			}
		})
	}
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		template.NotAfter = now.Add(30 * 24 * time.Hour)
		cert := testutil.Issue(t, template, nil, nil).Cert
		clock := now.Add(-offset)
		info, err := AnalyzeCertificate(cert, clock)
		if err != nil {
			t.Fatal(err)
		}
		if info.ExpiringSoon != (offset <= 0) {
			t.Fatalf("30 天提醒不得依取整日數判斷：%s", offset)
		}
	}
}

func TestFarFutureCertificateDaysDoNotOverflow(t *testing.T) {
	template := testutil.Template(1, "遠期 CA", fixedNow(), true)
	template.NotAfter = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)
	cert := testutil.Issue(t, template, nil, nil).Cert
	info, err := AnalyzeCertificate(cert, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	want := (template.NotAfter.Unix() - fixedNow().Unix()) / 86400
	if info.RemainingDays != want || info.ExpiringSoon || info.Expired {
		t.Fatal("遠期憑證日數飽和或提醒錯誤")
	}
}

func TestSelfIssuedDoesNotImplySelfSigned(t *testing.T) {
	template := testutil.Template(1, "相同名稱 CA", fixedNow(), true)
	parent := testutil.Issue(t, template, nil, nil)
	child := testutil.Issue(t, testutil.Template(2, "相同名稱 CA", fixedNow(), true), &parent, nil)
	info, err := AnalyzeCertificate(child.Cert, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if !info.SelfIssued || info.SelfSigned {
		t.Fatal("同名簽發不代表自簽")
	}
	if bytes.Equal(child.Cert.Raw, parent.Cert.Raw) {
		t.Fatal("測試應包含不同憑證")
	}
}
