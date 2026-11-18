package check

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestExplicitNameVerificationIsOnlyUsedWhenRequested(t *testing.T) {
	root, intermediate, leaf := chain(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	issuers := x509.NewCertPool()
	issuers.AddCert(intermediate.Cert)
	for _, name := range []string{"", "example.test", "wrong.test"} {
		result := VerifyTrust(t.Context(), leaf.Cert, TrustOptions{Roots: pool, Intermediates: issuers, Now: fixedNow(), DNSName: name})
		want := Passed
		if name == "wrong.test" {
			want = Failed
		}
		if result.Outcome.Status != want {
			t.Fatalf("名稱驗證錯誤：%s %+v", name, result)
		}
		if name == "" && result.Hostname.Status != NotPerformed {
			t.Fatal("未提供名稱不可挑選 SAN")
		}
		if name != "" && result.Hostname.Status != want {
			t.Fatal("明確名稱驗證狀態未呈現")
		}
	}
}

func TestCAConstraintsCannotBeBypassedByDirectTrust(t *testing.T) {
	for _, scenario := range []string{"非 CA", "沒有基本約束", "明確禁止簽發", "缺少 KeyUsage", "零值 KeyUsage extension"} {
		t.Run(scenario, func(t *testing.T) {
			template := testutil.Template(1, "CA 約束", fixedNow(), true)
			switch scenario {
			case "非 CA":
				template.IsCA = false
			case "沒有基本約束":
				template.BasicConstraintsValid = false
			case "明確禁止簽發":
				template.KeyUsage = x509.KeyUsageDigitalSignature
			case "缺少 KeyUsage":
				template.KeyUsage = 0
			case "零值 KeyUsage extension":
				template.KeyUsage = 0
				encoded, err := asn1.Marshal(asn1.BitString{Bytes: []byte{0}, BitLength: 1})
				if err != nil {
					t.Fatal(err)
				}
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Critical: true, Value: encoded}}
			}
			cert := testutil.Issue(t, template, nil, nil).Cert
			pool := x509.NewCertPool()
			pool.AddCert(cert)
			result := VerifyTrust(t.Context(), cert, TrustOptions{Roots: pool, Now: fixedNow(), Purpose: CAPurpose})
			want := Failed
			if scenario == "缺少 KeyUsage" {
				want = Passed
			}
			if result.Outcome.Status != want || result.ServerUsage.Status != NotPerformed {
				t.Fatalf("CA 約束錯誤：%+v", result)
			}
		})
	}
}

func TestMalformedInputsAndCancellation(t *testing.T) {
	root, _, leaf := chain(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		ctx  context.Context
		cert *x509.Certificate
		opts TrustOptions
	}{
		{ctx, leaf.Cert, TrustOptions{Roots: pool, Now: fixedNow()}},
		{t.Context(), nil, TrustOptions{Roots: pool, Now: fixedNow()}},
		{t.Context(), leaf.Cert, TrustOptions{Now: fixedNow()}},
		{t.Context(), leaf.Cert, TrustOptions{Roots: pool}},
		{t.Context(), leaf.Cert, TrustOptions{Roots: pool, Now: fixedNow(), Purpose: Purpose(99)}},
	} {
		if result := VerifyTrust(tt.ctx, tt.cert, tt.opts); result.Outcome.Class != ExecutionFailure || len(result.Chains) != 0 {
			t.Fatalf("無效輸入應為執行錯誤：%+v", result)
		}
	}
	if _, err := AnalyzeCertificate(nil, fixedNow()); err == nil {
		t.Fatal("缺少憑證應回傳錯誤")
	}
	if r := NewAnalyzer(time.Time{}, rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{parsed(leaf.Cert, 0)}); r.Failure() != ExecutionFailure {
		t.Fatal("零時間不可偷偷使用現在時間")
	}
	if r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(ctx, []model.ParsedCertificate{parsed(leaf.Cert, 0)}); r.Failure() != ExecutionFailure {
		t.Fatal("已取消仍執行")
	}
	if r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{{}}); r.Failure() != ExecutionFailure {
		t.Fatal("無效已解析物件應回報錯誤")
	}
	if r := NewAnalyzer(fixedNow(), func(context.Context) (*x509.CertPool, error) { t.Fatal("空集合不應載入根"); return nil, nil }).AnalyzeLocal(t.Context(), nil); r.Failure() != NoFailure {
		t.Fatal("空集合不是失敗")
	}
}

func TestRootProviderCancellationPreservesFacts(t *testing.T) {
	_, _, leaf := chain(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := func(context.Context) (*x509.CertPool, error) { cancel(); return nil, context.Canceled }
	r := NewAnalyzer(fixedNow(), provider).AnalyzeLocal(ctx, []model.ParsedCertificate{parsed(leaf.Cert, 0)})
	if r.Failure() != ExecutionFailure || len(r.Certificates) != 1 || len(r.Issues) != 1 || r.Issues[0].Code != "trust.canceled" {
		t.Fatal("取消後應保留事實並回報已知原因")
	}
}

func TestUnhandledExtensionsAndAncestorConstraints(t *testing.T) {
	for _, scenario := range []string{"未知 critical extension", "祖先已過期", "超過 path length", "中繼禁止 ServerAuth", "名稱限制"} {
		t.Run(scenario, func(t *testing.T) {
			rootTemplate := testutil.Template(1, "根", fixedNow(), true)
			if scenario == "超過 path length" {
				rootTemplate.MaxPathLen = 0
				rootTemplate.MaxPathLenZero = true
			}
			if scenario == "祖先已過期" {
				rootTemplate.NotAfter = fixedNow().Add(-time.Second)
			}
			if scenario == "名稱限制" {
				rootTemplate.PermittedDNSDomainsCritical = true
				rootTemplate.PermittedDNSDomains = []string{"allowed.example.test"}
			}
			root := testutil.Issue(t, rootTemplate, nil, nil)
			caTemplate := testutil.Template(2, "中繼", fixedNow(), true)
			if scenario == "中繼禁止 ServerAuth" {
				caTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			ca := testutil.Issue(t, caTemplate, &root, nil)
			leafTemplate := testutil.Template(3, "站台", fixedNow(), false)
			if scenario == "未知 critical extension" {
				leafTemplate.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
			}
			if scenario == "名稱限制" {
				leafTemplate.DNSNames = []string{"other.example.test"}
			}
			leaf := testutil.Issue(t, leafTemplate, &ca, nil)
			r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{parsed(leaf.Cert, 0), parsed(ca.Cert, 1)})
			if result := findResult(t, r, leaf.Cert); result.Trust.Outcome.Status != Failed || r.Failure() != VerificationFailure {
				t.Fatalf("祖先／extension 約束未檢查：%+v", result)
			}
			result := findResult(t, r, leaf.Cert)
			if scenario == "名稱限制" && (result.Trust.Outcome.Code != "trust.name_constraints_violated" || result.Trust.Hostname.Status != NotPerformed) {
				t.Fatal("名稱限制與未提供預期主機名稱必須分開")
			}
			if scenario == "超過 path length" && result.Trust.Outcome.Code != "trust.path_length_exceeded" {
				t.Fatal("已知 path length 原因不應丟失")
			}
		})
	}
}

func TestSignatureCorruptionDoesNotLookTrusted(t *testing.T) {
	root, ca, leaf := chain(t)
	der := append([]byte(nil), leaf.Cert.Raw...)
	der[len(der)-1] ^= 1
	corrupt, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{parsed(corrupt, 0), parsed(ca.Cert, 1)})
	result := findResult(t, r, corrupt)
	if result.Parse.Status != Passed || result.Linkage.Status != Failed || result.Trust.Outcome.Status != Failed {
		t.Fatal("解析成功不能代表簽章或信任成功")
	}
}

func TestSafeTrustErrorClassification(t *testing.T) {
	for _, err := range []error{x509.SystemRootsError{Err: errors.New("敏感診斷")}, trustFailure{code: "trust.native_verifier_failed", class: ExecutionFailure}} {
		if result := classifyTrustError(err, fixedNow()); result.Class != ExecutionFailure {
			t.Fatal("執行錯誤不應改列憑證失敗")
		}
	}
	if result := classifyTrustError(errors.New("未知敏感診斷"), fixedNow()); result.Code != "trust.verification_failed" {
		t.Fatal("不得捏造未知原因或回顯錯誤")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := SystemRoots(ctx); err == nil {
		t.Fatal("根取得應尊重取消")
	}
}
