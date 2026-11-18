package check

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func fixedNow() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }

func chain(t *testing.T) (testutil.Identity, testutil.Identity, testutil.Identity) {
	t.Helper()
	now := fixedNow()
	root := testutil.Issue(t, testutil.Template(1, "根 CA", now, true), nil, nil)
	intermediate := testutil.Issue(t, testutil.Template(2, "中繼 CA", now, true), &root, nil)
	leafTemplate := testutil.Template(3, "站台", now, false)
	leafTemplate.DNSNames = []string{"example.test"}
	leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	leaf := testutil.Issue(t, leafTemplate, &intermediate, nil)
	return root, intermediate, leaf
}

func rootsProvider(roots ...*x509.Certificate) RootProvider {
	pool := x509.NewCertPool()
	for _, cert := range roots {
		pool.AddCert(cert)
	}
	return func(context.Context) (*x509.CertPool, error) { return pool, nil }
}

func parsed(cert *x509.Certificate, index int) model.ParsedCertificate {
	return model.ParsedCertificate{Certificate: cert, Source: model.SourceRef{Path: "合成憑證.pem", InputIndex: index, Block: index + 1, Encoding: "PEM"}}
}

func findResult(t *testing.T, r LocalResult, cert *x509.Certificate) CertificateResult {
	t.Helper()
	for _, result := range r.Certificates {
		for _, chain := range result.Trust.Chains {
			if len(chain) > 0 && bytes.Equal(chain[0].Raw, cert.Raw) {
				return result
			}
		}
		if result.Info.SerialNumber == cert.SerialNumber.Text(16) {
			return result
		}
	}
	t.Fatal("缺少指定憑證結果")
	return CertificateResult{}
}

func TestLocalDeduplicatesAndPreservesSources(t *testing.T) {
	root, intermediate, leaf := chain(t)
	otherTemplate := testutil.Template(4, "另一站台", fixedNow(), false)
	otherTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	other := testutil.Issue(t, otherTemplate, &intermediate, nil)
	provider := rootsProvider(root.Cert)
	pool, _ := provider(context.Background())
	before := pool.Clone()
	r := NewAnalyzer(fixedNow(), provider).AnalyzeLocal(context.Background(), []model.ParsedCertificate{parsed(leaf.Cert, 0), parsed(root.Cert, 1), parsed(other.Cert, 2), parsed(intermediate.Cert, 3), parsed(leaf.Cert, 4)})
	if len(r.Certificates) != 4 || r.Failure() != NoFailure {
		t.Fatalf("亂序集合失敗：%+v", r)
	}
	first := findResult(t, r, leaf.Cert)
	if len(first.Sources) != 2 || first.Sources[0].InputIndex != 0 || first.Sources[1].InputIndex != 4 {
		t.Fatal("去重遺失來源")
	}
	if first.Parse.Status != Passed || first.Linkage.Status != Passed || first.Trust.Outcome.Status != Passed {
		t.Fatal("解析／鏈結／信任未分開正確呈現")
	}
	if first.Trust.Hostname.Status != NotPerformed {
		t.Fatal("本機不應猜測名稱")
	}
	if !pool.Equal(before) {
		t.Fatal("驗證修改了信任 pool")
	}
}

func TestLocalTrustFailures(t *testing.T) {
	for _, scenario := range []string{"正常", "過期", "尚未生效", "未知根", "缺中繼", "錯誤用途", "根不可自動信任"} {
		t.Run(scenario, func(t *testing.T) {
			root, intermediate, leaf := chain(t)
			template := testutil.Template(3, "站台", fixedNow(), false)
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if scenario == "過期" {
				template.NotAfter = fixedNow().Add(-time.Second)
			}
			if scenario == "尚未生效" {
				template.NotBefore = fixedNow().Add(time.Second)
			}
			if scenario == "錯誤用途" {
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			leaf = testutil.Issue(t, template, &intermediate, leaf.Key)
			provider := rootsProvider(root.Cert)
			certs := []model.ParsedCertificate{parsed(leaf.Cert, 0), parsed(intermediate.Cert, 1)}
			if scenario == "未知根" || scenario == "根不可自動信任" {
				provider = rootsProvider()
			}
			if scenario == "根不可自動信任" {
				certs = append(certs, parsed(root.Cert, 2))
			}
			if scenario == "缺中繼" {
				certs = certs[:1]
			}
			r := NewAnalyzer(fixedNow(), provider).AnalyzeLocal(context.Background(), certs)
			result := findResult(t, r, leaf.Cert)
			want := VerificationFailure
			if scenario == "正常" {
				want = NoFailure
			}
			if r.Failure() != want {
				t.Fatalf("失敗類別預期 %d，實際 %d", want, r.Failure())
			}
			if scenario != "正常" && (result.Trust.Outcome.Status != Failed || len(result.Trust.Chains) != 0) {
				t.Fatal("失敗時不應捏造信任鏈")
			}
			if result.Trust.Hostname.Status != NotPerformed {
				t.Fatal("名稱應未執行")
			}
			if scenario == "過期" || scenario == "尚未生效" {
				if result.Validity.Status != Failed {
					t.Fatal("有效期間應獨立失敗")
				}
			}
			if scenario == "錯誤用途" && result.Trust.ServerUsage.Status != Failed {
				t.Fatal("伺服器用途錯誤未呈現")
			}
		})
	}
}

func TestStandaloneCAUsesAnyPurposeAndConstraints(t *testing.T) {
	now := fixedNow()
	root := testutil.Issue(t, testutil.Template(1, "根", now, true), nil, nil)
	for _, scenario := range []string{"根", "中繼", "私有根", "無簽發權限", "CA 過期"} {
		t.Run(scenario, func(t *testing.T) {
			template := testutil.Template(2, "CA", now, true)
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			if scenario == "無簽發權限" {
				template.KeyUsage = x509.KeyUsageDigitalSignature
			}
			if scenario == "CA 過期" {
				template.NotAfter = now.Add(-time.Second)
			}
			ca := testutil.Issue(t, template, &root, nil)
			provider := rootsProvider(root.Cert)
			if scenario == "根" || scenario == "私有根" {
				ca = root
			}
			if scenario == "私有根" {
				provider = rootsProvider()
			}
			r := NewAnalyzer(now, provider).AnalyzeLocal(context.Background(), []model.ParsedCertificate{parsed(ca.Cert, 0)})
			result := findResult(t, r, ca.Cert)
			if result.Role != CA || result.Trust.Hostname.Status != NotPerformed || result.Trust.ServerUsage.Status != NotPerformed {
				t.Fatal("CA 被當成站台或名稱已驗證")
			}
			want := NoFailure
			if scenario == "私有根" || scenario == "無簽發權限" || scenario == "CA 過期" {
				want = VerificationFailure
			}
			if r.Failure() != want {
				t.Fatalf("CA 失敗類別錯誤：%+v", result)
			}
			if scenario == "根" && !result.Info.SelfSigned {
				t.Fatal("自簽事實未呈現")
			}
			if scenario == "私有根" && result.Trust.Outcome.Code != "trust.unknown_authority" {
				t.Fatalf("不得捏造私有根損壞原因：%v", result.Trust.Outcome)
			}
		})
	}
}

func TestRootLoadingFailureIsExecutionError(t *testing.T) {
	_, _, leaf := chain(t)
	for _, provider := range []RootProvider{func(context.Context) (*x509.CertPool, error) { return nil, errors.New("不應顯示的系統診斷") }, func(context.Context) (*x509.CertPool, error) { return nil, nil }} {
		r := NewAnalyzer(fixedNow(), provider).AnalyzeLocal(context.Background(), []model.ParsedCertificate{parsed(leaf.Cert, 0)})
		if r.Failure() != ExecutionFailure || len(r.Certificates) != 1 {
			t.Fatal("系統根失敗應保留欄位並回報執行錯誤")
		}
		if r.Certificates[0].Trust.Outcome.Code != "trust.roots_unavailable" {
			t.Fatal("不應改用其他信任來源")
		}
	}
}

func TestAlternativeIssuersAndCrossSignedChains(t *testing.T) {
	now := fixedNow()
	rootA := testutil.Issue(t, testutil.Template(1, "根 A", now, true), nil, nil)
	rootB := testutil.Issue(t, testutil.Template(2, "根 B", now, true), nil, nil)
	key := testutil.NewKey(t)
	template := testutil.Template(3, "中繼", now, true)
	a := testutil.Issue(t, template, &rootA, key)
	templateB := testutil.Template(4, "中繼", now, true)
	templateB.SubjectKeyId = template.SubjectKeyId
	b := testutil.Issue(t, templateB, &rootB, key)
	wrong := testutil.Issue(t, testutil.Template(5, "中繼", now, true), &rootA, nil)
	leaf := testutil.Issue(t, testutil.Template(6, "站台", now, false), &a, nil)
	r := NewAnalyzer(now, rootsProvider(rootA.Cert, rootB.Cert)).AnalyzeLocal(context.Background(), []model.ParsedCertificate{parsed(leaf.Cert, 0), parsed(wrong.Cert, 1), parsed(a.Cert, 2), parsed(b.Cert, 3)})
	result := findResult(t, r, leaf.Cert)
	if r.Failure() != NoFailure || result.Linkage.Status != Passed || len(result.Trust.Chains) != 2 {
		t.Fatalf("有效替代鏈遺失或受錯誤候選影響：%+v", result)
	}
	valid := 0
	for _, link := range result.Links {
		if link.SignatureValid {
			valid++
		}
	}
	if valid != 2 || len(result.Links) != 3 {
		t.Fatal("候選簽章關係不完整")
	}
}

func TestLocalSignatureMismatchFailsLinkage(t *testing.T) {
	root, intermediate, leaf := chain(t)
	wrong := testutil.Issue(t, testutil.Template(2, "中繼 CA", fixedNow(), true), &root, nil)
	r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(context.Background(), []model.ParsedCertificate{parsed(leaf.Cert, 0), parsed(wrong.Cert, 1)})
	result := findResult(t, r, leaf.Cert)
	if result.Linkage.Status != Failed || result.Trust.Outcome.Status != Failed {
		t.Fatal("不能只比對 issuer 字串")
	}
	if bytes.Equal(intermediate.Cert.Raw, wrong.Cert.Raw) {
		t.Fatal("測試 key 不應相同")
	}
}

func TestSelfSignedSiteStillUsesServerPurpose(t *testing.T) {
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		template := testutil.Template(1, "自簽站台", fixedNow(), false)
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		leaf := testutil.Issue(t, template, nil, nil)
		r := NewAnalyzer(fixedNow(), rootsProvider(leaf.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{parsed(leaf.Cert, 0)})
		result := findResult(t, r, leaf.Cert)
		if result.Role != Site || !result.Info.SelfSigned {
			t.Fatal("自簽不代表 CA")
		}
		want := NoFailure
		if usage == x509.ExtKeyUsageClientAuth {
			want = VerificationFailure
		}
		if r.Failure() != want {
			t.Fatalf("直接受信任的自簽站台結果錯誤：%+v", result)
		}
	}
}

func TestLocalContinuesAfterInvalidCertificate(t *testing.T) {
	root, ca, leaf := chain(t)
	template := testutil.Template(4, "過期站台", fixedNow(), false)
	template.NotAfter = fixedNow().Add(-time.Second)
	expired := testutil.Issue(t, template, &ca, nil)
	r := NewAnalyzer(fixedNow(), rootsProvider(root.Cert)).AnalyzeLocal(t.Context(), []model.ParsedCertificate{{}, parsed(expired.Cert, 1), parsed(leaf.Cert, 2), parsed(ca.Cert, 3)})
	if r.Failure() != ExecutionFailure || len(r.Certificates) != 3 || len(r.Issues) != 1 {
		t.Fatal("輸入錯誤應保留其餘結果且優先於驗證失敗")
	}
	if findResult(t, r, leaf.Cert).Trust.Outcome.Status != Passed || findResult(t, r, expired.Cert).Trust.Outcome.Status != Failed {
		t.Fatal("未繼續處理或混合結果錯誤")
	}
}
