package report

import (
	"bytes"
	"encoding/json"
	"html"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/model"
)

func localizedFixture(language string) Document {
	source := model.SourceRef{Path: "parse-execution.pem", InputIndex: 0}
	target := model.Target{ASCIIHost: "example.com", Port: 443, InputIndex: 1}
	return Build(language, "test", "unknown", time.Now(), []model.InputSpec{{Kind: model.LocalInput, Value: source.Path, Index: 0}, {Kind: model.RemoteInput, Value: "example.com", Index: 1}}, []model.InputResult{{InputIndex: 0}, {InputIndex: 1, Target: &target}}, check.LocalResult{Certificates: []check.CertificateResult{{Sources: []model.SourceRef{source}, Info: check.CertificateInfo{Subject: "dns handshake execution", URIs: []string{"urn:synthetic-secret", "spiffe://cluster.local/ns/example?token=hidden"}}, Parse: check.Outcome{Code: "certificate.parsed", Status: check.Passed}}}}, check.PairingResult{}, []check.RemoteResult{{Target: target, Stage: "handshake", Handshake: check.Outcome{Code: "remote.handshake_failed", Status: check.Failed, Class: check.ExecutionFailure}}}, 2)
}
func TestHumanReportValuesAreLocalizedWithoutChangingJSON(t *testing.T) {
	for _, tc := range []struct {
		lang string
		want []string
	}{{"en", []string{"Local", "Remote", "Execution error", "TLS handshake", "Parsing"}}, {"zh-TW", []string{"本機", "遠端", "執行錯誤", "TLS 握手", "解析"}}, {"zh-CN", []string{"本地", "远程", "执行错误", "TLS 握手", "解析"}}} {
		d := localizedFixture(tc.lang)
		before, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"table", "html", "markdown"} {
			var out bytes.Buffer
			if err := Render(&out, format, d); err != nil {
				t.Fatal(err)
			}
			text := html.UnescapeString(out.String())
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Fatal(tc.lang, format, "缺少顯示翻譯", want)
				}
			}
			if !strings.Contains(text, "dns handshake execution") {
				t.Fatal("憑證原值被誤翻譯")
			}
		}
		after, err := json.Marshal(d)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("渲染改寫機器資料")
		}
		if d.Inputs[0].Kind != "local" || d.Remote[0].Stage != "handshake" || d.Remote[0].Checks[0].Name != "handshake" || d.Remote[0].Checks[0].Result.Severity != "execution" {
			t.Fatal("JSON識別碼被翻譯")
		}
	}
}
func TestHumanURIRedactionReasonsAreLocalized(t *testing.T) {
	for _, tc := range []struct {
		lang   string
		reason string
	}{{"en", "URI is invalid or opaque"}, {"zh-TW", "URI 無法安全解析或屬於不透明格式"}, {"zh-CN", "URI 无法安全解析或属于不透明格式"}} {
		d := localizedFixture(tc.lang)
		for _, format := range []string{"table", "html", "markdown"} {
			var out bytes.Buffer
			if err := Render(&out, format, d); err != nil {
				t.Fatal(err)
			}
			text := html.UnescapeString(out.String())
			if !strings.Contains(text, tc.reason) || strings.Contains(text, "synthetic-secret") || strings.Contains(text, "token=hidden") {
				t.Fatal(tc.lang, format, "遮蔽原因缺漏或洩密")
			}
		}
		if d.Local.Certificates[0].Info.URIs[0].Reason == nil || *d.Local.Certificates[0].Info.URIs[0].Reason != "uri.invalid_or_opaque" {
			t.Fatal("JSON遮蔽代碼變更")
		}
	}
}

func TestUnknownOrPublicValuesAreNotGuessedAsMessages(t *testing.T) {
	tr := i18n.New("zh-TW")
	for _, category := range []string{"kind", "severity", "stage", "check", "uri_reason"} {
		if got := displayValue(tr, category, "private.synthetic.unknown"); got != "private.synthetic.unknown" {
			t.Fatal("猜測未知識別碼")
		}
	}
	var rows []row
	flatten(tr, reflect.ValueOf(Tool{Name: "parse", Version: "execution", Commit: "handshake"}), "", &rows)
	for _, want := range []string{"parse", "execution", "handshake"} {
		found := false
		for _, r := range rows {
			if r.Value == want {
				found = true
			}
		}
		if !found {
			t.Fatal("工具原值被當成檢查名稱翻譯", want)
		}
	}
}
func TestEveryDisplayEnumHasAllThreeTranslations(t *testing.T) {
	groups := map[string][]string{"kind": {"auto", "local", "remote"}, "severity": {"none", "verification", "execution"}, "stage": {"input", "dns", "connect", "handshake", "verify", "complete"}, "check": {"parse", "validity", "ca_constraints", "linkage", "trust", "hostname", "server_usage", "key_validation", "pairing", "dns", "connection", "handshake", "revocation", "aia"}, "uri_reason": {"uri.invalid_or_opaque", "uri.sensitive_components_removed"}}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		tr := i18n.New(lang)
		fallback := tr.Text("private.synthetic.missing", nil)
		for group, values := range groups {
			for _, value := range values {
				got := displayValue(tr, group, value)
				if got == value || got == fallback {
					t.Fatal("顯示翻譯缺漏", lang, group, value)
				}
			}
		}
	}
}
