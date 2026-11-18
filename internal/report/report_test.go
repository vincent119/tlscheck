package report

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/i18n"
)

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, errors.New("不得輸出底層錯誤") }
func TestReportLanguagesSafetyAndStreams(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		var out, err bytes.Buffer
		w := Writer{Out: &out, Diagnostics: &err, T: i18n.New(lang)}
		w.Field("field.target", "https://user:secret@example.com/a?token=private#hidden")
		w.Field("field.subject", "CN=測試\x1b\n")
		w.Outcome("field.trust", check.Outcome{Code: "trust.unknown_authority", Status: check.Failed, Class: check.VerificationFailure})
		if err.Len() != 0 {
			t.Fatal("檢查失敗不應寫診斷流")
		}
		w.Outcome("field.hostname", check.Outcome{Code: "certificate.hostname_not_provided"})
		w.Summary(1)
		s := out.String()
		for _, bad := range []string{"secret", "private", "hidden", "user:", "\x1b", "trust.unknown_authority", "<no value>", "unavailable"} {
			if strings.Contains(s, bad) {
				t.Fatalf("不安全輸出：%s", s)
			}
		}
		if w.Counts != [3]int{0, 1, 1} {
			t.Fatal(w.Counts)
		}
		w.Outcome("field.connection", check.Outcome{Code: "remote.connect_failed", Status: check.Failed, Class: check.ExecutionFailure})
		if err.Len() == 0 {
			t.Fatal("執行診斷缺漏")
		}
	}
	w := Writer{Out: badWriter{}, Diagnostics: badWriter{}, T: i18n.New("en")}
	w.Text("help.usage")
	if w.Err == nil {
		t.Fatal("寫入錯誤未保留")
	}
}

func TestCertificateURIsRemainSeparateAndOpaqueCredentialsAreHidden(t *testing.T) {
	for _, language := range []string{"en", "zh-TW", "zh-CN"} {
		var out, diag bytes.Buffer
		w := Writer{Out: &out, Diagnostics: &diag, T: i18n.New(language)}
		w.Certificate(check.CertificateInfo{URIs: []string{"urn:https://user:synthetic-secret@example.com/private?token=hidden#fragment", "spiffe://cluster.local/ns/default/sa/api", "https://user:synthetic-secret@example.com/identity?token=hidden#fragment"}})
		text := out.String()
		for _, bad := range []string{"synthetic-secret", "user:", "token=hidden", "#fragment"} {
			if strings.Contains(text, bad) {
				t.Fatalf("URI 敏感值洩漏：%s", text)
			}
		}
		for _, want := range []string{"spiffe://cluster.local/ns/default/sa/api", "https://example.com/identity"} {
			if !strings.Contains(text, want) {
				t.Fatalf("URI 遺失：%s", text)
			}
		}
	}
}
func TestPublicTextIsNotParsedAsTargetURL(t *testing.T) {
	for _, text := range []string{"CN=https://example.com/identity", "./local/https://example.com/private.pem", "spiffe://cluster.local/ns/default/sa/api"} {
		if got := Safe(text); got != text {
			t.Fatalf("公開文字遭改寫：%q", got)
		}
	}
}
