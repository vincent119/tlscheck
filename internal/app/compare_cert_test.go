package app

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"html"
	"io"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func comparisonFile(t *testing.T, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func comparisonIdentity(t *testing.T, serial int64) testutil.Identity {
	t.Helper()
	return testutil.Issue(t, testutil.Template(serial, "example.invalid", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC), false), nil, nil)
}

func TestCompareCertificateFlagAndInvalidBindingsHaveNoSideEffects(t *testing.T) {
	o, err := parseOptions([]string{"-r", "example.invalid", "--compare-cert", "0=expected.pem"})
	if err != nil || len(o.Inputs) != 1 {
		t.Fatal("逐目標憑證比對旗標未支援", err)
	}
	for _, binding := range []string{"", "0", "=file", "-1=file", "+0=file", "1=file", "999999999999999999999=file", "0=", "0=-", "0=bad\x00path"} {
		a := New()
		a.Load = func(context.Context) config.Result { t.Fatal("無效映射不得讀設定"); return config.Result{} }
		a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("無效映射不得解析"); return nil }
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"-r", "example.invalid", "--compare-cert", binding}, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal("無效候選綁定未拒絕", binding, code)
		}
	}
	for _, args := range [][]string{
		{"-r", "example.invalid", "--compare-cert", "0=a", "--compare-cert", "00=b"},
		{"--local", "a.pem", "--compare-cert", "0=b.pem"},
		{"-r", "bad input", "--compare-cert", "0=b.pem"},
		{"--version", "--compare-cert", "0=b.pem"},
		{"--settings", "--compare-cert", "0=b.pem"},
	} {
		var out, diag bytes.Buffer
		if code := New().Run(t.Context(), args, &out, &diag); code != 2 {
			t.Fatal("衝突映射未拒絕", args, code)
		}
	}
}

func TestCompareMappingsAndOutputAliasProtection(t *testing.T) {
	first := comparisonIdentity(t, 401)
	second := comparisonIdentity(t, 402)
	p1 := comparisonFile(t, "候選 a=1.pem", first.Cert.Raw)
	p2 := comparisonFile(t, "候選 b.pem", second.Cert.Raw)
	list := batchFile(t, "bad input\nexample.invalid\nexample.invalid\n")
	var calls atomic.Int32
	a := batchApp(&calls)
	a.RemoteWithIP = func(_ context.Context, target model.Target, ip netip.Addr, _ time.Time) check.RemoteResult {
		if ip != netip.MustParseAddr("127.0.0.1") {
			t.Error("IP映射混用")
		}
		calls.Add(1)
		leaf := first.Cert
		if target.InputIndex == 2 {
			leaf = second.Cert
		}
		return check.RemoteResult{Target: target, ServerChain: []*x509.Certificate{leaf}}
	}
	a.Local = func(_ context.Context, certs []model.ParsedCertificate, _ time.Time) check.LocalResult {
		if len(certs) != 0 {
			t.Fatal("候選滲入本機分析")
		}
		return check.LocalResult{}
	}
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"--targets-file", list, "--compare-cert", "1=" + p1, "--compare-cert", "2=" + p2, "--connect-ip", "1=127.0.0.1", "--connect-ip", "2=127.0.0.1", "--concurrency", "2", "-f", "json", "-L", "en"}, &out, &diag)
	var d report.Document
	if code != 2 || calls.Load() != 2 || json.Unmarshal(out.Bytes(), &d) != nil || len(d.Remote) != 2 || d.Remote[0].Comparison.Result.Status != "passed" || d.Remote[1].Comparison.Result.Status != "passed" || d.Remote[0].Comparison.CandidateSource != p1 || d.Remote[1].Comparison.CandidateSource != p2 {
		t.Fatal("批次候選映射不符", code, out.String())
	}
	for _, kind := range []string{"直接", "硬連結", "符號連結"} {
		t.Run(kind, func(t *testing.T) {
			destination := p1
			if kind != "直接" {
				destination = filepath.Join(t.TempDir(), "alias.pem")
				var err error
				if kind == "硬連結" {
					err = os.Link(p1, destination)
				} else {
					err = os.Symlink(p1, destination)
				}
				if err != nil {
					t.Fatal("無法建立測試別名：", err)
				}
			}
			calls.Store(0)
			out.Reset()
			diag.Reset()
			before, err := os.ReadFile(p1)
			if err != nil {
				t.Fatal(err)
			}
			code := a.Run(t.Context(), []string{"-r", "example.invalid", "--compare-cert", "0=" + p1, "--output", destination, "--overwrite", "-L", "en"}, &out, &diag)
			after, err := os.ReadFile(p1)
			if err != nil || code != 2 || calls.Load() != 0 || !bytes.Equal(before, after) {
				t.Fatal("候選來源或別名遭覆寫", code)
			}
		})
	}
}

func TestCompareCandidateFailureStopsBeforeRemoteOrPassword(t *testing.T) {
	path := comparisonFile(t, "ca-only.pem", testutil.Issue(t, testutil.Template(411, "ca", time.Now(), true), nil, nil).Cert.Raw)
	pfx := filepath.Join(t.TempDir(), "identity.pfx")
	if err := os.WriteFile(pfx, testutil.ContainerFixture(t, "modern.pfx"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	a := batchApp(&calls)
	a.passwordPrompt = func(context.Context, io.Writer, *i18n.Translator, int) ([]byte, error) {
		t.Fatal("候選無效不得提示密碼")
		return nil, nil
	}
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"-r", "example.invalid", "--local", pfx, "--ask-password", "1", "--compare-cert", "0=" + path, "-L", "zh-TW"}, &out, &diag)
	if code != 2 || calls.Load() != 0 || out.Len() != 0 || !strings.Contains(diag.String(), "候選") {
		t.Fatal("候選錯誤仍排程或缺翻譯", code, diag.String())
	}
}

func TestCompareReportsInThreeLanguagesAndFourFormats(t *testing.T) {
	candidate := comparisonIdentity(t, 421)
	path := comparisonFile(t, "候選=421.pem", candidate.Cert.Raw)
	observed := *candidate.Cert
	observed.SerialNumber = big.NewInt(422)
	observed.Raw = append(bytes.Clone(observed.Raw), 0)
	secretURI, _ := url.Parse("https://u:URI-SECRET@service.invalid/path?q=QUERY-SECRET")
	observed.URIs = []*url.URL{secretURI}
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"table", "json", "html", "markdown"} {
			for _, detail := range []string{"summary", "full"} {
				var calls atomic.Int32
				a := batchApp(&calls)
				a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
					calls.Add(1)
					return check.RemoteResult{Target: target, ServerChain: []*x509.Certificate{&observed}}
				}
				var out, diag bytes.Buffer
				code := a.Run(t.Context(), []string{"-r", "example.invalid", "--compare-cert", "0=" + path, "-L", lang, "-f", format, "--detail", detail}, &out, &diag)
				text := html.UnescapeString(out.String() + diag.String())
				if code != 1 || calls.Load() != 1 {
					t.Fatal("比對差異未回1", format, lang, code, diag.String())
				}
				for _, secret := range []string{"URI-SECRET", "QUERY-SECRET", "-----BEGIN"} {
					if strings.Contains(text, secret) {
						t.Fatal("候選或URI秘密洩漏", format)
					}
				}
				if !strings.Contains(text, "422") || !strings.Contains(text, "service.invalid/path") {
					t.Fatal("差異資料遺失", format, text)
				}
				if format == "json" {
					var d report.Document
					if json.Unmarshal(out.Bytes(), &d) != nil || d.SchemaVersion != 1 {
						t.Fatal("JSON契約不符")
					}
					if len(d.Remote) != 1 || d.Remote[0].Comparison == nil || d.Remote[0].Comparison.Result.Status != "failed" || d.Summary.Failed != 1 {
						t.Fatal("JSON比對或計數不符")
					}
				}
			}
		}
	}
}

func TestCompareSharedCandidateIsNotReadAgain(t *testing.T) {
	identity := comparisonIdentity(t, 431)
	path := comparisonFile(t, "shared.pem", identity.Cert.Raw)
	var calls atomic.Int32
	a := batchApp(&calls)
	a.Local = func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		return check.LocalResult{}
	}
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		calls.Add(1)
		return check.RemoteResult{Target: target, ServerChain: []*x509.Certificate{identity.Cert}}
	}
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"-r", "a.invalid", "-r", "b.invalid", "--compare-cert", "0=" + path, "--compare-cert", "1=" + path, "--concurrency", "2", "-f", "json", "-L", "en"}, &out, &diag)
	var d report.Document
	if code != 0 || calls.Load() != 2 || json.Unmarshal(out.Bytes(), &d) != nil || d.Summary.Passed != 2 {
		t.Fatal("worker重讀候選或結果混用", code, out.String())
	}
}

func TestCompareCompletionDoesNotReadCandidateOrFallback(t *testing.T) {
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全不得讀設定"); return config.Result{} }
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"completion", shell}, &out, &diag); code != 0 || out.Len() == 0 {
			t.Fatal("產生補全失敗", shell)
		}
	}
	var out, diag bytes.Buffer
	if code := a.Run(t.Context(), []string{"__complete", "--compare-cert", "0=missing"}, &out, &diag); code != 0 || out.String() != ":4\n" {
		t.Fatal("候選補全不可回退檔名", code, out.String())
	}
}

func TestCompareUnavailableLeafKeepsNullObservedFingerprint(t *testing.T) {
	identity := comparisonIdentity(t, 441)
	path := comparisonFile(t, "candidate.pem", identity.Cert.Raw)
	var calls atomic.Int32
	a := batchApp(&calls)
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		return check.RemoteResult{Target: target, Issues: []check.Outcome{{Status: check.Failed, Class: check.ExecutionFailure, Code: "remote.connect_failed"}}}
	}
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"-r", "example.invalid", "--compare-cert", "0=" + path, "-L", "en", "-f", "json"}, &out, &diag)
	var d report.Document
	if code != 2 || json.Unmarshal(out.Bytes(), &d) != nil || len(d.Remote) != 1 {
		t.Fatal("未觀測leaf的報告不符", code)
	}
	c := d.Remote[0].Comparison
	if c == nil || c.ObservedFingerprintSHA256 != nil || c.Result.Status != "not_performed" || c.Result.Code != "comparison.leaf_unavailable" || len(c.Differences) != 0 {
		t.Fatal("未觀測leaf仍填入假定指紋")
	}
}

func TestCompareCandidateCannotBeUsedAsPasswordSource(t *testing.T) {
	identity := comparisonIdentity(t, 451)
	path := comparisonFile(t, "candidate.pem", identity.Cert.Raw)
	pfx := filepath.Join(t.TempDir(), "identity.pfx")
	if err := os.WriteFile(pfx, testutil.ContainerFixture(t, "modern.pfx"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	a := batchApp(&calls)
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"-r", "example.invalid", "--local", pfx, "--compare-cert", "0=" + path, "--password-file", "1=" + path, "-L", "en", "-f", "json"}, &out, &diag)
	if code != 2 || !strings.Contains(out.String(), "input.password_unavailable") {
		t.Fatal("候選被當密碼讀取", code, out.String())
	}
}

func TestCompareHelpExplainsCandidateAndRepeatableFlags(t *testing.T) {
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		var out, diag bytes.Buffer
		if code := New().Run(t.Context(), []string{"--help", "-L", lang}, &out, &diag); code != 0 || diag.Len() != 0 {
			t.Fatal("比對說明失敗", lang)
		}
		if !strings.Contains(out.String(), i18n.New(lang).Text("flag.compare-cert", nil)) {
			t.Fatal("說明缺少比對語意", lang)
		}
		syntax := i18n.New(lang).Text("cli.syntax_help", nil)
		for _, flag := range []string{"--targets-file", "--connect-ip", "--compare-cert", "--password-file", "--ask-password"} {
			if !strings.Contains(syntax, flag) {
				t.Fatal("可重複旗標說明缺漏", lang, flag)
			}
		}
	}
}
