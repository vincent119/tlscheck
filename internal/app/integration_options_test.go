package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func TestExplicitLanguageBypassesConfigAndLocalizesErrors(t *testing.T) {
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("明確語系不得讀設定"); return config.Result{} }
	for _, args := range [][]string{{"-Lzh-TW", "--help"}, {"--unknown=secret", "-Lzh-TW"}, {"-Lzh-TW", "--unknown=secret"}} {
		var out, diag bytes.Buffer
		code := a.Run(context.Background(), args, &out, &diag)
		if len(args) > 1 && strings.Contains(strings.Join(args, " "), "--unknown") {
			if code != 2 || !strings.Contains(diag.String(), "參數") || strings.Contains(diag.String(), "secret") {
				t.Fatal(code, diag.String())
			}
		} else if code != 0 {
			t.Fatal(code, diag.String())
		}
	}
}
func TestFourFormatsAndOutputProtectInputsBeforeChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	input := filepath.Join(dir, "source.pem")
	if err := os.WriteFile(input, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.Load = func(context.Context) config.Result { return config.Result{Config: config.Config{Language: "en"}} }
	calls := 0
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		calls++
		return check.RemoteResult{Target: target}
	}
	for _, format := range []string{"table", "json", "html", "markdown"} {
		var out, diag bytes.Buffer
		if code := a.Run(context.Background(), []string{"-r", "https://user:secret@example.com/private?q=hidden", "-f", format}, &out, &diag); code != 0 {
			t.Fatal(code, diag.String())
		}
		if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "hidden") {
			t.Fatal("秘密洩漏")
		}
		if format == "json" {
			var d report.Document
			if err := json.Unmarshal(out.Bytes(), &d); err != nil || len(d.Remote) != 1 || d.Remote[0].TLS != nil {
				t.Fatal(err, out.String())
			}
		}
	}
	var out, diag bytes.Buffer
	if code := a.Run(context.Background(), []string{"-r", "example.com", "-o", path, "-fjson"}, &out, &diag); code != 0 || out.Len() != 0 {
		t.Fatal(code, out.String(), diag.String())
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) {
		t.Fatal(err)
	}
	before := calls
	for _, args := range [][]string{{"-r", "example.com", "-o", path}, {"-r", "example.com", "-l", input, "-o", input, "--overwrite"}} {
		out.Reset()
		diag.Reset()
		if code := a.Run(context.Background(), args, &out, &diag); code != 2 || calls != before || out.Len() != 0 {
			t.Fatal(code, calls, before, out.String())
		}
	}
	out.Reset()
	diag.Reset()
	if a.Run(context.Background(), []string{"-r", "example.com", "-o", path, "--overwrite", "-fhtml"}, &out, &diag) != 0 || out.Len() != 0 {
		t.Fatal(diag.String())
	}
}
func TestSettingsNonTTYDoesNotCreateConfiguration(t *testing.T) {
	a := New()
	var out, diag bytes.Buffer
	if code := a.Run(context.Background(), []string{"--settings"}, &out, &diag); code != 2 || out.Len() != 0 {
		t.Fatal(code, out.String())
	}
}

func TestJSONPreservesDuplicateKeySourcesAndStableCertificateIDs(t *testing.T) {
	now := time.Now().UTC()
	identity := testutil.Issue(t, testutil.Template(1901, "合成配對", now, false), nil, nil)
	der, err := x509.MarshalPKCS8PrivateKey(identity.Key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "site.pem"), filepath.Join(dir, "site.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: identity.Cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	a := New()
	a.Now = func() time.Time { return now }
	a.Local = func(ctx context.Context, certs []model.ParsedCertificate, n time.Time) check.LocalResult {
		return check.NewAnalyzer(n, func(context.Context) (*x509.CertPool, error) {
			pool := x509.NewCertPool()
			pool.AddCert(identity.Cert)
			return pool, nil
		}).AnalyzeLocal(ctx, certs)
	}
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{"-Len", "-fjson", "-l", keyPath, "-l", certPath, "-l", keyPath, "-l", certPath}, &out, &diag); code != 0 {
		t.Fatal(code, diag.String())
	}
	var d report.Document
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Local.Certificates) != 1 || len(d.Local.Certificates[0].Sources) != 2 || len(d.Local.Keys) != 2 || d.Local.Keys[0].ID == d.Local.Keys[1].ID || len(d.Local.Pairs) != 2 {
		t.Fatal("來源／配對遺失")
	}
	hash := sha256.Sum256(identity.Cert.Raw)
	want := strings.ToUpper(hex.EncodeToString(hash[:]))
	for _, pair := range d.Local.Pairs {
		if pair.CertificateID != want || pair.KeyID == "" {
			t.Fatal(pair)
		}
	}
	if strings.Contains(out.String(), "PRIVATE KEY") || strings.Contains(out.String(), base64.StdEncoding.EncodeToString(der)) {
		t.Fatal("私鑰洩漏")
	}
}
func TestReportWriterFailureOverridesSuccessfulCheckExitCode(t *testing.T) {
	a := New()
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		return check.RemoteResult{Target: target}
	}
	var diag bytes.Buffer
	if code := a.Run(t.Context(), []string{"-Len", "-r", "example.com", "-fjson"}, brokenWriter{}, &diag); code != 2 {
		t.Fatal(code)
	}
}
