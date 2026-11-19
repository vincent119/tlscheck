package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestCLIHelpVersionFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"--version"}, {"--version", "example.com"}, {"--language=secret"}} {
		a := New()
		a.Load = func(context.Context) config.Result { return config.Result{Config: config.Config{Language: "zh-TW"}} }
		a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("資訊路徑不得解析"); return nil }
		var o, e bytes.Buffer
		code := a.Run(context.Background(), args, &o, &e)
		want := 0
		if len(args) > 1 || len(args) == 1 && strings.HasPrefix(args[0], "--language") {
			want = 2
		}
		if code != want || strings.Contains(o.String()+e.String(), "secret") {
			t.Fatal(code, o.String(), e.String())
		}
	}
}
func TestCLIMixedCollectionsAndSeverity(t *testing.T) {
	for _, severity := range []check.FailureClass{0, 1, 2} {
		a := New()
		a.Load = func(context.Context) config.Result {
			return config.Result{Config: config.Config{Language: "en"}, Warnings: []config.Warning{{Code: "config.invalid_json"}}}
		}
		a.Parse = input.NewParser().ParseAll
		a.Local = func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult {
			return check.LocalResult{Issues: []check.Outcome{{Code: "trust.unknown_authority", Status: check.Failed, Class: severity}}}
		}
		calls := 0
		a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
			calls++
			return check.RemoteResult{Target: target, Issues: []check.Outcome{{Code: "remote.connect_failed", Status: check.Failed, Class: severity}}}
		}
		var o, e bytes.Buffer
		code := a.Run(context.Background(), []string{"https://user:secret@example.com/path?token=hidden#fragment", "second.example"}, &o, &e)
		if code != int(severity) || calls != 2 {
			t.Fatal(code, calls)
		}
		for _, s := range []string{"secret", "hidden", "fragment", "user:"} {
			if strings.Contains(o.String()+e.String(), s) {
				t.Fatal("敏感資料洩漏")
			}
		}
		if !strings.Contains(e.String(), "English") {
			t.Fatal("設定提醒未分流")
		}
	}
}

func TestCLIRealLocalPairingAndContinue(t *testing.T) {
	now := time.Now().UTC()
	template := testutil.Template(1, "synthetic", now, false)
	template.NotAfter = now.Add(5 * 24 * time.Hour)
	identity := testutil.Issue(t, template, nil, nil)
	root := t.TempDir()
	cert := filepath.Join(root, "site.pem")
	key := filepath.Join(root, "key.pem")
	der, err := x509.MarshalPKCS8PrivateKey(identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		a := New()
		a.Now = func() time.Time { return now }
		a.Load = func(context.Context) config.Result { return config.Result{Config: config.Config{Language: lang}} }
		a.Local = func(ctx context.Context, c []model.ParsedCertificate, n time.Time) check.LocalResult {
			if len(c) != 1 {
				t.Fatal("本機集合錯誤")
			}
			return check.NewAnalyzer(n, func(context.Context) (*x509.CertPool, error) {
				pool := x509.NewCertPool()
				pool.AddCert(identity.Cert)
				return pool, nil
			}).AnalyzeLocal(ctx, c)
		}
		calls := 0
		a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
			calls++
			return check.RemoteResult{Target: target}
		}
		for _, bad := range []bool{false, true} {
			args := []string{"--detail=full", key, "example.com", cert, "second.example"}
			want := 0
			if bad {
				args = append(args, filepath.Join(root, "missing.pem"))
				want = 2
			}
			var out, diag bytes.Buffer
			if code := a.Run(context.Background(), args, &out, &diag); code != want {
				t.Fatalf("%s %d %s", lang, code, out.String())
			}
			if !strings.Contains(out.String(), "SHA-256") || strings.Contains(out.String(), "PRIVATE KEY") {
				t.Fatal("安全配對報告缺漏")
			}
		}
		if calls != 4 {
			t.Fatal("未繼續遠端項目")
		}
	}
}
func TestCLIWarningOnlyAndWriterFailure(t *testing.T) {
	a := New()
	a.Load = func(context.Context) config.Result {
		return config.Result{Config: config.Config{Language: "en"}, Warnings: []config.Warning{{Code: "config.invalid_json"}}}
	}
	var out, diag bytes.Buffer
	if a.Run(context.Background(), nil, &out, &diag) != 0 {
		t.Fatal("提醒改變結束碼")
	}
	if a.Run(context.Background(), nil, brokenWriter{}, &diag) != 2 {
		t.Fatal("輸出失敗應為 2")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("合成失敗") }

func TestCLIUntrustedCertificateURIsDoNotLeakCredentials(t *testing.T) {
	now := time.Now().UTC()
	template := testutil.Template(42, "合成 URI", now, false)
	for _, value := range []string{"urn:https://user:synthetic-secret@example.com/private?token=hidden#fragment", "spiffe://cluster.local/ns/default/sa/api"} {
		uri, err := url.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = append(template.URIs, uri)
	}
	identity := testutil.Issue(t, template, nil, nil)
	path := filepath.Join(t.TempDir(), "site.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.Now = func() time.Time { return now }
	a.Load = func(context.Context) config.Result { return config.Result{Config: config.Config{Language: "zh-TW"}} }
	var out, diag bytes.Buffer
	if code := a.Run(context.Background(), []string{"--detail=full", path}, &out, &diag); code != 1 {
		t.Fatalf("非信任憑證應回傳1：%d", code)
	}
	for _, bad := range []string{"synthetic-secret", "user:", "token=hidden", "#fragment"} {
		if strings.Contains(out.String()+diag.String(), bad) {
			t.Fatalf("憑證 URI 洩漏：%s", bad)
		}
	}
	if !strings.Contains(out.String(), "spiffe://cluster.local/ns/default/sa/api") {
		t.Fatal("有效 SAN 遺失")
	}
}
