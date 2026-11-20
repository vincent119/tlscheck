package app

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
)

func expiryPolicyApp(t *testing.T, remote bool) App {
	t.Helper()
	a := New()
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	a.Now = func() time.Time { return now }
	info := check.CertificateInfo{Subject: "expiry-subject-canary", FingerprintSHA256: "EXPIRY-FINGERPRINT-CANARY", NotAfter: now.Add(20 * 24 * time.Hour), RemainingDays: 20, ExpiringSoon: true}
	a.Parse = func(context.Context, []string) []model.InputResult {
		if remote {
			return []model.InputResult{{InputIndex: 0, Target: &model.Target{Host: "example.invalid", ASCIIHost: "example.invalid", Port: 443, InputIndex: 0}}}
		}
		return []model.InputResult{{InputIndex: 0}}
	}
	a.Local = func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult {
		if remote {
			return check.LocalResult{}
		}
		return check.LocalResult{Certificates: []check.CertificateResult{{Info: info, Role: check.CA, Sources: []model.SourceRef{{Path: "synthetic.pem", InputIndex: 0, Block: 1, Encoding: "PEM"}, {Path: "synthetic.pem", InputIndex: 0, Block: 2, Encoding: "PEM"}}, Parse: check.Outcome{Status: check.Passed, Code: "certificate.parsed"}}}}
	}
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		leaf := info
		leaf.FingerprintSHA256 = "leaf"
		leaf.ExpiringSoon = false
		leaf.RemainingDays = 90
		leaf.NotAfter = now.Add(90 * 24 * time.Hour)
		root := info
		root.FingerprintSHA256 = "ROOT-FINGERPRINT-CANARY"
		return check.RemoteResult{Target: target, HandshakeComplete: true, Certificates: []check.CertificateInfo{leaf, info, root}}
	}
	return a
}

func expiryDocument(t *testing.T, a App, args ...string) (int, report.Document) {
	t.Helper()
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), append([]string{"synthetic.pem", "-L", "en", "-f", "json"}, args...), &out, &diag)
	var d report.Document
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatal("政策報告不是JSON", code, err, diag.String())
	}
	return code, d
}

func TestExpiryPolicyDisabledKeepsExistingExitCode(t *testing.T) {
	for _, remote := range []bool{false, true} {
		a := expiryPolicyApp(t, remote)
		code, d := expiryDocument(t, a)
		if code != 0 || d.Summary.Failed != 0 || d.Summary.Warnings == 0 {
			t.Fatal("未開啟旗標改變提醒退出碼", code, d.Summary)
		}
		data, _ := json.Marshal(d)
		if bytes.Contains(data, []byte("policy.expiry_warning_failed")) {
			t.Fatal("關閉政策仍增加檢查")
		}
	}
}
func TestExpiryPolicyAppliesToAllObservedCertificates(t *testing.T) {
	for _, remote := range []bool{false, true} {
		a := expiryPolicyApp(t, remote)
		_, before := expiryDocument(t, a)
		code, d := expiryDocument(t, a, "--fail-on-expiry-warning")
		want := 1
		if remote {
			want = 2
		}
		if code != 1 || d.Summary.CheckExitCode != 1 || d.Summary.Failed-before.Summary.Failed != want || d.Summary.Passed != before.Summary.Passed || d.Summary.NotPerformed != before.Summary.NotPerformed || d.Summary.Warnings != before.Summary.Warnings {
			t.Fatal("政策計數或退出碼不符", remote, code, d.Summary)
		}
		var checks []report.Check
		if remote {
			checks = d.Remote[0].Checks
		} else {
			checks = d.Local.Certificates[0].Checks
			if len(d.Local.Certificates[0].Sources) != 2 {
				t.Fatal("來源被政策去重")
			}
		}
		count := 0
		for _, c := range checks {
			if c.Result.Code == "policy.expiry_warning_failed" {
				count++
				if c.Name != "expiry_policy" || c.Result.Severity != "verification" || c.Result.Advice == nil || c.Result.Advice.Code != "advice.replace_certificate" || !strings.Contains(c.Result.Message, "30") {
					t.Fatal("政策缺少可追溯資訊", c)
				}
			}
		}
		if count != want {
			t.Fatal("未逐張保留政策", count, want)
		}
		if code, d := expiryDocument(t, a, "--fail-on-expiry-warning", "--expiry-warning-days", "0"); code != 0 || d.Summary.Failed != 0 {
			t.Fatal("0天未停用政策", code)
		}
	}
}
func TestExpiryPolicyPreservesExecutionFailurePriority(t *testing.T) {
	a := expiryPolicyApp(t, false)
	a.Parse = func(context.Context, []string) []model.InputResult {
		return []model.InputResult{{InputIndex: 0, Issues: []model.Issue{{Code: model.InvalidData}}}}
	}
	code, d := expiryDocument(t, a, "--fail-on-expiry-warning")
	if code != 2 || d.Summary.CheckExitCode != 2 || d.Summary.Failed != 2 {
		t.Fatal("執行失敗優先序或其他政策被吞掉", code, d.Summary)
	}
}
func TestExpiryPolicyArgumentsAndCompletionHaveNoSideEffects(t *testing.T) {
	for _, args := range [][]string{{"--fail-on-expiry-warning"}, {"x", "--fail-on-expiry-warning=false"}, {"x", "--fail-on-expiry-warning", "--fail-on-expiry-warning"}, {"--help", "--fail-on-expiry-warning"}, {"--version", "--fail-on-expiry-warning"}, {"--settings", "--fail-on-expiry-warning"}} {
		a := New()
		a.Load = func(context.Context) config.Result {
			t.Fatal("非法政策旗標不得讀設定")
			return config.Result{}
		}
		a.Parse = func(context.Context, []string) []model.InputResult {
			t.Fatal("非法政策旗標不得解析")
			return nil
		}
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal("非法政策參數未拒絕", args, code)
		}
	}
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全不得讀設定"); return config.Result{} }
	a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("補全不得解析"); return nil }
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{"__complete", "--fail-on-exp"}, &out, &diag); code != 0 || !strings.Contains(out.String(), "--fail-on-expiry-warning") {
		t.Fatal("缺少政策旗標補全", code, out.String())
	}
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{"__complete", "--fail-on-expiry-warning="}, &out, &diag); code != 0 || out.String() != ":4\n" || diag.Len() != 0 {
		t.Fatal("布林政策補全不應提供值或回退檔名", code, out.String())
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		out.Reset()
		diag.Reset()
		if code := a.Run(t.Context(), []string{"completion", shell}, &out, &diag); code != 0 || !strings.Contains(out.String(), "__complete") || diag.Len() != 0 {
			t.Fatal("四shell政策補全產生副作用", shell, code)
		}
	}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		out.Reset()
		diag.Reset()
		if code := a.Run(t.Context(), []string{"--help", "-L", lang}, &out, &diag); code != 0 || !strings.Contains(out.String(), "--fail-on-expiry-warning") {
			t.Fatal("help缺少政策旗標", lang, code)
		}
	}
}
func TestExpiryPolicyIsLocalizedInEveryFormat(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"table", "json", "html", "markdown"} {
			for _, detail := range []string{"summary", "full"} {
				var out, diag bytes.Buffer
				a := expiryPolicyApp(t, true)
				code := a.Run(t.Context(), []string{"synthetic.pem", "-L", lang, "-f", format, "--detail", detail, "--fail-on-expiry-warning"}, &out, &diag)
				text := html.UnescapeString(out.String())
				if format == "table" {
					// 僅串接同欄續行搜尋無空白識別碼，不用這項斷言宣稱空白無損。
					columns := make([]strings.Builder, 4)
					for _, line := range strings.Split(text, "\n") {
						parts := strings.Split(line, "|")
						for i := 1; i < len(parts)-1 && i <= len(columns); i++ {
							columns[i-1].WriteString(strings.ReplaceAll(parts[i], " ", ""))
						}
					}
					text = ""
					for i := range columns {
						text += columns[i].String() + "\n"
					}
				}
				if code != 1 || !strings.Contains(text, "policy.expiry_warning_failed") || !strings.Contains(text, "EXPIRY-FINGERPRINT-CANARY") {
					t.Fatal("四格式政策或憑證引用遺失", lang, format, detail, code)
				}
			}
		}
	}
}
