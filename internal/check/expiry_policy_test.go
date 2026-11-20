package check

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestExpiryPolicyUsesExistingWarningBoundary(t *testing.T) {
	now := fixedNow()
	template := testutil.Template(701, "expiry-boundary", now, true)
	template.NotAfter = now.Add(30 * 24 * time.Hour)
	identity := testutil.Issue(t, template, nil, nil)
	for _, tc := range []struct {
		name string
		now  time.Time
		days int
		hit  bool
	}{
		{"門檻前一奈秒", now.Add(-time.Nanosecond), 30, false},
		{"恰好門檻", now, 30, true},
		{"門檻後一奈秒", now.Add(time.Nanosecond), 30, true},
		{"零天停用", now, 0, false},
		{"恰到期時間", template.NotAfter, 30, true},
		{"已過期", template.NotAfter.Add(time.Nanosecond), 30, false},
		{"自訂七天未命中", now, 7, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := AnalyzeCertificateWithOptions(identity.Cert, tc.now, CertificateOptions{ExpiryWarningDays: tc.days})
			if err != nil {
				t.Fatal(err)
			}
			local := LocalResult{Certificates: []CertificateResult{{Info: info}}}
			actual := local.WithExpiryPolicy(tc.days)
			if (actual.Certificates[0].ExpiryPolicy != nil) != tc.hit || local.Certificates[0].ExpiryPolicy != nil {
				t.Fatal("政策邊界不符或修改呼叫者")
			}
			remote := RemoteResult{Certificates: []CertificateInfo{info}}
			checked := remote.WithExpiryPolicy(tc.days)
			if (len(checked.ExpiryPolicies) > 0) != tc.hit || len(remote.ExpiryPolicies) != 0 {
				t.Fatal("遠端政策邊界不符")
			}
			if tc.hit && (actual.Failure() != VerificationFailure || checked.Failure() != VerificationFailure) {
				t.Fatal("命中政策未回報驗證失敗")
			}
		})
	}
}

func TestExpiryPolicyDeduplicatesLocalSourcesAndKeepsRemoteOccurrences(t *testing.T) {
	now := fixedNow()
	template := testutil.Template(702, "expiry-ca", now, true)
	template.NotAfter = now.Add(20 * 24 * time.Hour)
	identity := testutil.Issue(t, template, nil, nil)
	analyzer := NewAnalyzer(now, rootsProvider(identity.Cert))
	local := analyzer.AnalyzeLocal(t.Context(), []model.ParsedCertificate{{Certificate: identity.Cert, Source: model.SourceRef{Path: "first.pem", InputIndex: 0, Block: 1}}, {Certificate: identity.Cert, Source: model.SourceRef{Path: "second.pem", InputIndex: 1, Block: 1}}})
	actual := local.WithExpiryPolicy(30)
	if len(actual.Certificates) != 1 || len(actual.Certificates[0].Sources) != 2 || actual.Certificates[0].ExpiryPolicy == nil || local.Failure() != NoFailure || actual.Failure() != VerificationFailure {
		t.Fatal("本機來源或去重政策不符")
	}
	remote := RemoteResult{Certificates: []CertificateInfo{actual.Certificates[0].Info, actual.Certificates[0].Info}}
	first := remote.WithExpiryPolicy(30)
	second := remote.WithExpiryPolicy(30)
	if len(first.ExpiryPolicies) != 2 || len(second.ExpiryPolicies) != 2 || first.ExpiryPolicies[0].CertificateIndex != 0 || first.ExpiryPolicies[1].CertificateIndex != 1 {
		t.Fatal("遠端位置被去重")
	}
}

func TestExpiryPolicyUsesRealObservedServerChain(t *testing.T) {
	now := fixedNow()
	template := testutil.Template(703, "expiry-root", now, true)
	template.NotAfter = now.Add(20 * 24 * time.Hour)
	root := testutil.Issue(t, template, nil, nil)
	leafTemplate := testutil.Template(704, "leaf", now, false)
	leafTemplate.DNSNames = []string{"example.test"}
	leafTemplate.NotAfter = now.Add(90 * 24 * time.Hour)
	leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	leaf := testutil.Issue(t, leafTemplate, &root, nil)
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Cert.Raw, root.Cert.Raw}, PrivateKey: leaf.Key}}}
	target, observed := remoteServer(t, cfg)
	result := checkerForLocalServer(root.Cert).Check(t.Context(), target)
	if result.Failure() != NoFailure || len(result.Certificates) != 2 {
		t.Fatal("合成TLS前置驗證失敗", result.Failure())
	}
	actual := result.WithExpiryPolicy(30)
	if len(actual.ExpiryPolicies) != 1 || actual.ExpiryPolicies[0].CertificateIndex != 1 || actual.ExpiryPolicies[0].FingerprintSHA256 != result.Certificates[1].FingerprintSHA256 || actual.Failure() != VerificationFailure {
		t.Fatal("伺服器送出根未執行政策")
	}
	// 觀測err來自握手後的Read；正常結束可回傳EOF，握手成功應由ConnectionState確認。
	if observation := <-observed; observation.applicationBytes != 0 || !observation.state.HandshakeComplete {
		t.Fatal("政策增加應用層請求", observation.err)
	}
}
