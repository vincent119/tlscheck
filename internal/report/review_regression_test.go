package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestAdviceHasStableCodeAndLocalizedMessage(t *testing.T) {
	messages := map[string]bool{}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		d := Build(lang, "test", "unknown", time.Now(), nil, nil, check.LocalResult{Issues: []check.Outcome{{Status: check.Failed, Class: check.VerificationFailure, Code: "certificate.expired"}}}, check.PairingResult{}, nil, 1)
		var out bytes.Buffer
		if err := Render(&out, "json", d); err != nil {
			t.Fatal(err)
		}
		var data struct {
			Local struct {
				Issues []struct {
					Result struct {
						Advice struct{ Code, Message string }
					}
				}
			}
		}
		if err := json.Unmarshal(out.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		advice := data.Local.Issues[0].Result.Advice
		if advice.Code != "advice.replace_certificate" || advice.Message == "" {
			t.Fatal(advice)
		}
		messages[advice.Message] = true
	}
	if len(messages) != 3 {
		t.Fatal("建議說明未依語系翻譯")
	}
}
func TestTableDataCannotForgeColumnSeparators(t *testing.T) {
	var out bytes.Buffer
	tableRow(&out, "欄位|來源", `CN=alpha|beta\gamma`)
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if strings.Count(line, "|") != 3 {
			t.Fatal("資料偽造欄位", line)
		}
	}
	if !strings.Contains(out.String(), `\u007c`) {
		t.Fatal("未明確跳脫 pipe")
	}
}
func TestPerInputSummaryAndPairTableDoNotRecountChecks(t *testing.T) {
	ok := check.Outcome{Status: check.Passed, Code: "certificate.parsed"}
	bad := check.Outcome{Status: check.Failed, Class: check.ExecutionFailure, Code: "remote.connect_failed"}
	source := model.SourceRef{Path: "site.pem", InputIndex: 0}
	d := Build("en", "test", "unknown", time.Now(), []model.InputSpec{{Kind: model.LocalInput, Value: "site.pem", Index: 0}, {Kind: model.RemoteInput, Value: "example.com", Index: 1}}, []model.InputResult{{InputIndex: 0}, {InputIndex: 1, Target: &model.Target{ASCIIHost: "example.com", Port: 443, InputIndex: 1}}}, check.LocalResult{Certificates: []check.CertificateResult{{Info: check.CertificateInfo{FingerprintSHA256: "CERT-ID"}, Sources: []model.SourceRef{source}, Parse: ok}}}, check.PairingResult{Keys: []check.KeyResult{{Info: check.KeyInfo{Source: source}}}, Certificates: []check.PairingCertificate{{FingerprintSHA256: "CERT-ID"}}, Pairs: []check.KeyCertificatePair{{KeyIndex: 0, CertificateIndex: 0}}}, []check.RemoteResult{{Target: model.Target{ASCIIHost: "example.com", Port: 443, InputIndex: 1}, Issues: []check.Outcome{bad}}}, 2)
	if len(d.Presentation.Inputs) != 2 || d.Presentation.Inputs[0].Status != "passed" || d.Presentation.Inputs[1].Status != "failed" || d.Presentation.Inputs[1].HighestSeverity != "execution" {
		t.Fatal("逐輸入結果關聯錯誤", d.Presentation)
	}
	before := d.Summary
	var out bytes.Buffer
	if err := Render(&out, "table", d); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Input summary", "Pair table", "CERT-ID", "key:0", "Execution error", "example.com:443"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal("缺少摘要／配對", want)
		}
	}
	if before != d.Summary {
		t.Fatal("摘要重複計數")
	}
}

func TestInputSummaryReusesSharedCertificateWithoutDoubleCountingSources(t *testing.T) {
	d := Document{Inputs: []Input{{Index: 0, Kind: "local"}, {Index: 1, Kind: "local"}, {Index: 2, Kind: "remote", Target: optional("example.com:443")}}, Local: Local{Certificates: []Certificate{{Sources: []Source{{InputIndex: 0}, {InputIndex: 0}, {InputIndex: 1}}, Checks: []Check{{Result: Result{Code: "certificate.parsed", Status: "passed", Severity: "none"}}}}}}, Remote: []Remote{{InputIndex: 2, Checks: []Check{{Result: Result{Code: "remote.connect_failed", Status: "failed", Severity: "execution"}}}}}}
	p := present(d)
	if p.Inputs[0].Passed != 1 || p.Inputs[1].Passed != 1 || p.Inputs[2].Passed != 0 || p.Inputs[2].Failed != 1 {
		t.Fatal(p)
	}
}
func TestAdviceIsExplicitNullForSuccessfulChecks(t *testing.T) {
	d := Build("en", "test", "unknown", time.Now(), nil, nil, check.LocalResult{Issues: []check.Outcome{{Status: check.Passed, Code: "certificate.parsed"}}}, check.PairingResult{}, nil, 0)
	var out bytes.Buffer
	if err := Render(&out, "json", d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"advice": null`) {
		t.Fatal("缺少 advice null 契約")
	}
}
