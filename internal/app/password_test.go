package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func containerApp(t *testing.T, trusted bool) App {
	t.Helper()
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("不應讀日常設定"); return config.Result{} }
	a.Now = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
	a.Local = func(ctx context.Context, certs []model.ParsedCertificate, now time.Time) check.LocalResult {
		return check.NewAnalyzer(now, func(context.Context) (*x509.CertPool, error) {
			pool := x509.NewCertPool()
			if trusted {
				root, err := x509.ParseCertificate(testutil.ContainerFixture(t, "root.der"))
				if err != nil {
					t.Fatal(err)
				}
				pool.AddCert(root)
			}
			return pool, nil
		}).AnalyzeLocal(ctx, certs)
	}
	return a
}
func writeContainer(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, testutil.ContainerFixture(t, name), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestPasswordBindingValidationAndCompletion(t *testing.T) {
	cases := [][]string{{"--password-file", "0=x"}, {"--ask-password", "-1", "x"}, {"--password-file", "0=", "x"}, {"--password-file", "+0=x", "x"}, {"--password-file", "999999999999999999999=x", "x"}, {"--password-file", "1=x", "x"}, {"--password-file", "0=x", "--ask-password", "0", "x"}, {"--password-file", "0=x", "--password-file", "0=y", "x"}, {"--remote", "example.invalid", "--ask-password", "0"}, {"--help", "--password-file", "0=x"}}
	for _, args := range cases {
		a := New()
		a.Load = func(context.Context) config.Result { t.Fatal("無效參數讀取設定"); return config.Result{} }
		a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("無效參數解析來源"); return nil }
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal("無效密碼參數未安全拒絕", args, code)
		}
	}
	o, err := parseOptions([]string{"a", "--password-file", "0=C:\\a=b.txt", "--ask-password", "1", "b"})
	if err != nil || o.Passwords[0].path != "C:\\a=b.txt" || !o.Passwords[1].ask {
		t.Fatal("密碼綁定順序或等號解析錯誤", err)
	}
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全讀取設定"); return config.Result{} }
	for _, flag := range []string{"--password-file", "--ask-password"} {
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"__complete", flag, ""}, &out, &diag); code != 0 || out.String() != ":4\n" {
			t.Fatal("密碼補全有副作用或檔名回退", flag, code, out.String())
		}
	}
}
func TestPFXIntegrationPairingAndFourFormatSecrecy(t *testing.T) {
	pfx := writeContainer(t, "modern.pfx")
	pass := testutil.PasswordFile(t, []byte("S12_SYNTHETIC_PASSWORD_CANARY\r\n"))
	extra := filepath.Join(t.TempDir(), "external.pem")
	if err := os.WriteFile(extra, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testutil.ContainerFixture(t, "leaf.der")}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"table", "json", "html", "markdown"} {
			t.Run(lang+"/"+format, func(t *testing.T) {
				a := containerApp(t, true)
				var out, diag bytes.Buffer
				code := a.Run(t.Context(), []string{"--local", pfx, "--local", extra, "--password-file", "0=" + pass, "-L", lang, "--format", format}, &out, &diag)
				if code != 0 {
					t.Fatal("有效容器未完成原有檢查", code, diag.String())
				}
				for _, secret := range []string{"S12_SYNTHETIC_PASSWORD_CANARY", "PRIVATE KEY", pass} {
					if strings.Contains(html.UnescapeString(out.String()+diag.String()), secret) {
						t.Fatal("報告洩漏密碼或私鑰", format)
					}
				}
				if format == "json" {
					var d report.Document
					if err := json.Unmarshal(out.Bytes(), &d); err != nil {
						t.Fatal(err)
					}
					if len(d.Local.Keys) != 1 || d.Local.Keys[0].Format != "PKCS#12" || len(d.Local.Pairs) != 1 {
						t.Fatal("容器私鑰配對資訊不符")
					}
					found := false
					for _, c := range d.Local.Certificates {
						if c.Info.Subject == "CN=S12 synthetic leaf" && len(c.Sources) == 2 {
							found = true
						}
					}
					if !found {
						t.Fatal("跨輸入憑證來源被吞掉")
					}
				}
			})
		}
	}
	a := containerApp(t, false)
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{pfx, "--password-file", "0=" + pass, "-L", "en", "-fjson"}, &out, &diag); code != 1 || !strings.Contains(out.String(), "trust.unknown_authority") {
		t.Fatal("容器root被提升信任", code, diag.String())
	}
}
func TestPasswordFailureContinuesAndProtectsFiles(t *testing.T) {
	pfx := writeContainer(t, "modern.pfx")
	certs := writeContainer(t, "cert-only.pfx")
	wrong := testutil.PasswordFile(t, []byte("wrong"))
	a := containerApp(t, true)
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{pfx, certs, "--password-file", "0=" + wrong, "-L", "en", "-fjson"}, &out, &diag); code != 2 || !strings.Contains(out.String(), "input.container_integrity_failed") || !strings.Contains(out.String(), "S12 synthetic leaf") {
		t.Fatal("錯誤密碼未繼續其他輸入", code, diag.String())
	}
	before, err := os.ReadFile(wrong)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{pfx, "--password-file", "0=" + wrong, "--output", wrong, "--overwrite", "-L", "en"}, &out, &diag); code != 2 || out.Len() != 0 {
		t.Fatal("密碼檔覆寫未阻擋", code)
	}
	after, err := os.ReadFile(wrong)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("密碼檔被改寫")
	}
	a.Remote = func(context.Context, model.Target, time.Time) check.RemoteResult {
		t.Fatal("錯綁密碼的自動遠端仍執行網路")
		return check.RemoteResult{}
	}
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{"example.invalid", "--password-file", "0=" + wrong, "-L", "en", "-fjson"}, &out, &diag); code != 2 || !strings.Contains(out.String(), "input.password_not_applicable") {
		t.Fatal("錯綁遠端未拒絕", code)
	}
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{pfx, "--password-file", "0=" + pfx, "-L", "en", "-fjson"}, &out, &diag); code != 2 || !strings.Contains(out.String(), "input.password_unavailable") {
		t.Fatal("密碼檔輸入別名未拒絕", code)
	}
}
func TestHiddenPasswordBytesAndPromptBinding(t *testing.T) {
	for _, tc := range []struct {
		data []byte
		want string
		fail bool
	}{{[]byte("  測試x\b \r"), "  測試 ", false}, {[]byte{3}, "", true}, {[]byte{4}, "", true}, {bytes.Repeat([]byte("a"), 4097), "", true}} {
		reader := bytes.NewReader(tc.data)
		got, err := readHiddenPassword(t.Context(), func(context.Context, bool) (byte, error) { return reader.ReadByte() })
		if tc.fail {
			if err == nil || len(got) != 0 {
				t.Fatal("隱藏輸入失敗仍回傳密碼")
			}
		} else if err != nil || string(got) != tc.want {
			t.Fatal("隱藏輸入改寫空白或字元", err, string(got))
		}
		clear(got)
	}
	pfx := writeContainer(t, "modern.pfx")
	a := containerApp(t, true)
	calls := 0
	a.passwordPrompt = func(context.Context, io.Writer, *i18n.Translator, int) ([]byte, error) {
		calls++
		return []byte("S12_SYNTHETIC_PASSWORD_CANARY"), nil
	}
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{pfx, "--ask-password", "0", "-L", "en"}, &out, &diag); code != 0 || calls != 1 {
		t.Fatal("顯式密碼提示次數不符", code, calls)
	}
	a.passwordPrompt = nil
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{pfx, "--ask-password", "0", "-L", "en", "-fjson"}, &out, &diag); code != 2 || !strings.Contains(out.String(), "input.password_unavailable") {
		t.Fatal("非TTY不得回退可見輸入", code)
	}
}
