package app

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
	"github.com/vincent119/tlscheck/internal/testutil"
)

func batchFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "清單 檔案=1.txt")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func batchApp(calls *atomic.Int32) App {
	a := New()
	a.Now = func() time.Time { return time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC) }
	a.Remote = func(_ context.Context, target model.Target, _ time.Time) check.RemoteResult {
		calls.Add(1)
		return check.RemoteResult{Target: target, DNS: check.Outcome{Status: check.Passed, Code: "remote.dns_resolved"}}
	}
	return a
}
func TestTargetFilesPreserveOccurrenceAndLineSources(t *testing.T) {
	first := batchFile(t, " #header\r\n\r\nexample.invalid\r\nbad input\r\nexample.invalid\n")
	second := batchFile(t, "other.invalid\n")
	o, err := parseOptions([]string{"direct.invalid", "--targets-file", first, "--local", "cert.pem", "--targets-file", second})
	if err != nil {
		t.Fatal(err)
	}
	if issue := expandTargetLists(t.Context(), &o); issue != "" {
		t.Fatal(issue)
	}
	want := []string{"direct.invalid", "example.invalid", "bad input", "example.invalid", "cert.pem", "other.invalid"}
	for i, value := range want {
		if o.Inputs[i].Index != i || o.Inputs[i].Value != value {
			t.Fatal("跨清單及本機索引不符", i)
		}
	}
	if o.Inputs[2].ListSource.Line != 4 || o.Inputs[1].ListSource.Path != first || o.Inputs[5].ListSource.Line != 1 || o.Inputs[4].ListSource != nil {
		t.Fatal("來源行號或路徑不符")
	}
}
func TestBatchMappingsBindAfterExpansion(t *testing.T) {
	path := batchFile(t, "bad input\nexample.invalid\n")
	o, err := parseOptions([]string{"--targets-file", path, "--local", "identity.pfx", "--password-file", "2=password.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if expandTargetLists(t.Context(), &o) != "" || bindPasswords(&o) != nil || o.Passwords[2].path != "password.txt" {
		t.Fatal("密碼映射未依展開後索引")
	}
	o.PasswordFiles = []string{"1=password.txt"}
	if bindPasswords(&o) == nil {
		t.Fatal("密碼錯綁遠端未拒絕")
	}
}
func TestTargetFilesRejectLimitsBeforeScheduling(t *testing.T) {
	empty := batchFile(t, "")
	for _, count := range []int{200, 201} {
		o := RunOptions{TargetFiles: make([]string, count), Inputs: []model.InputSpec{{Kind: model.RemoteInput, Value: "example.invalid"}}}
		for i := 0; i < count; i++ {
			o.Inputs = append(o.Inputs, model.InputSpec{Kind: model.TargetListInput, Value: empty})
		}
		issue := expandTargetLists(t.Context(), &o)
		if (issue == "") != (count == 200) {
			t.Fatal("清單個數邊界不符", count, issue)
		}
	}
	thousand := batchFile(t, strings.Repeat("example.invalid\n", 1000))
	o := RunOptions{TargetFiles: []string{thousand}, Inputs: []model.InputSpec{{Kind: model.TargetListInput, Value: thousand}}}
	if issue := expandTargetLists(t.Context(), &o); issue != "" || len(o.Inputs) != 1000 {
		t.Fatal("1000筆誤拒絕", issue)
	}
	tooMany := batchFile(t, strings.Repeat("example.invalid\n", 1001))
	largeComments := batchFile(t, strings.Repeat("#\n", input.MaxTargetListSize/2))
	for _, args := range [][]string{{"--targets-file", tooMany}, {"example.invalid", "--targets-file", thousand}, append([]string{"example.invalid"}, repeatTargetFile(largeComments, 9)...)} {
		var calls atomic.Int32
		a := batchApp(&calls)
		var out, diag bytes.Buffer
		args = append(args, "-L", "en")
		if code := a.Run(t.Context(), args, &out, &diag); code != 2 || calls.Load() != 0 || out.Len() != 0 {
			t.Fatal("超出全域限制仍排程", code, calls.Load())
		}
	}
	o = RunOptions{TargetFiles: make([]string, 8), Inputs: []model.InputSpec{{Kind: model.RemoteInput, Value: "example.invalid"}}}
	for range 8 {
		o.Inputs = append(o.Inputs, model.InputSpec{Kind: model.TargetListInput, Value: largeComments})
	}
	if issue := expandTargetLists(t.Context(), &o); issue != "" {
		t.Fatal("8MiB恰上限誤拒絕", issue)
	}
}
func repeatTargetFile(path string, n int) []string {
	out := []string{}
	for range n {
		out = append(out, "--targets-file", path)
	}
	return out
}
func TestBatchSourcesInFourFormatsAndSafeErrors(t *testing.T) {
	path := batchFile(t, "#header\nhttps://user:SECRET-CANARY@example.invalid/private?q=QUERY-CANARY\nbad input\nother.invalid\n")
	for _, lang := range []string{"en", "zh-TW", "zh-CN"} {
		for _, format := range []string{"table", "json", "html", "markdown"} {
			var calls atomic.Int32
			a := batchApp(&calls)
			var out, diag bytes.Buffer
			code := a.Run(t.Context(), []string{"--targets-file", path, "--concurrency", "2", "-L", lang, "-f", format}, &out, &diag)
			if code != 2 || calls.Load() != 2 {
				t.Fatal("批次部分失敗未保留有效目標", lang, format, code, calls.Load())
			}
			for _, secret := range []string{"SECRET-CANARY", "QUERY-CANARY", "bad input"} {
				if strings.Contains(html.UnescapeString(out.String()+diag.String()), secret) {
					t.Fatal("清單原始內容洩漏", secret)
				}
			}
			text := html.UnescapeString(out.String())
			if strings.Index(text, "example.invalid") < 0 || strings.Index(text, "example.invalid") > strings.Index(text, "other.invalid") {
				t.Fatal("格式輸出順序改變", format)
			}
			if format == "json" {
				var d report.Document
				if json.Unmarshal(out.Bytes(), &d) != nil || d.SchemaVersion != 1 || len(d.Inputs) != 3 || len(d.Remote) != 2 || d.Inputs[1].ListSource.Line != 3 || d.Inputs[0].ListSource.Path != path || d.Inputs[2].Index != 2 {
					t.Fatal("JSON來源或索引不符")
				}
			}
		}
	}
}
func TestBatchFileFailureIsAtomicAndOtherInputsContinue(t *testing.T) {
	path := batchFile(t, "example.invalid\n\x00")
	var calls atomic.Int32
	a := batchApp(&calls)
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"--targets-file", path, "direct.invalid", "-L", "en", "-f", "json"}, &out, &diag)
	var d report.Document
	if json.Unmarshal(out.Bytes(), &d) != nil || code != 2 || calls.Load() != 1 || len(d.Inputs) != 2 || d.Inputs[0].ListSource.Line != 0 || d.Remote[0].Target != "direct.invalid:443" {
		t.Fatal("清單層失敗交付部分結果或吞其他輸入", code, calls.Load())
	}
}
func TestBatchQueryModesAndOutputProtectionHaveNoSideEffects(t *testing.T) {
	path := batchFile(t, "example.invalid\n")
	for _, args := range [][]string{{"--help", "--targets-file", path}, {"--version", "--concurrency", "2"}, {"--settings", "--targets-file", path}, {"example.invalid", "--concurrency", "0"}, {"example.invalid", "--concurrency", "33"}, {"example.invalid", "--concurrency", "2", "--concurrency", "2"}, {"--targets-file", "-"}, {"--targets-file", ""}} {
		a := New()
		a.Load = func(context.Context) config.Result {
			t.Fatal("非法批次參數不得讀設定")
			return config.Result{}
		}
		a.Parse = func(context.Context, []string) []model.InputResult {
			t.Fatal("非法批次參數不得解析")
			return nil
		}
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal("非法參數未拒絕", args, code)
		}
	}
	var calls atomic.Int32
	a := batchApp(&calls)
	var out, diag bytes.Buffer
	before, _ := os.ReadFile(path)
	if code := a.Run(t.Context(), []string{"--targets-file", path, "--output", path, "--overwrite", "-L", "en"}, &out, &diag); code != 2 || calls.Load() != 0 {
		t.Fatal("清單被輸出覆寫")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("清單內容改變")
	}
	a.Load = func(context.Context) config.Result { t.Fatal("補全不得讀設定"); return config.Result{} }
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{"__complete", "--concurrency", ""}, &out, &diag); code != 0 || !strings.HasSuffix(out.String(), ":4\n") || !strings.Contains(out.String(), "32") {
		t.Fatal("並行補全值不符")
	}
	out.Reset()
	diag.Reset()
	if code := a.Run(t.Context(), []string{"__complete", "--targets-file", ""}, &out, &diag); code != 0 || out.String() != ":0\n" {
		t.Fatal("清單檔補全不應讀內容或關閉檔名補全", code, out.String())
	}
}
func TestTargetListCannotBeReadAsPasswordFile(t *testing.T) {
	path := batchFile(t, "example.invalid\n")
	pfx := filepath.Join(t.TempDir(), "identity.pfx")
	if err := os.WriteFile(pfx, testutil.ContainerFixture(t, "modern.pfx"), 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	a := batchApp(&calls)
	var out, diag bytes.Buffer
	code := a.Run(t.Context(), []string{"--targets-file", path, "--local", pfx, "--password-file", "1=" + path, "-L", "en", "-f", "json"}, &out, &diag)
	if code != 2 || !strings.Contains(out.String(), "input.password_unavailable") {
		t.Fatal("清單被當密碼來源讀取", code)
	}
}

func TestBatchConcurrencyDoesNotChangeOrderedReport(t *testing.T) {
	for _, format := range []string{"table", "json", "html", "markdown"} {
		var calls atomic.Int32
		a := batchApp(&calls)
		run := func(extra ...string) []byte {
			t.Helper()
			var out, diag bytes.Buffer
			args := []string{"-r", "first.invalid", "-r", "second.invalid", "-L", "zh-TW", "-f", format, "--detail", "full"}
			args = append(args, extra...)
			if code := a.Run(t.Context(), args, &out, &diag); code != 0 || diag.Len() != 0 {
				t.Fatal("並行報告執行失敗", code)
			}
			return out.Bytes()
		}
		before := run()
		after := run("--concurrency", "2")
		if !bytes.Equal(before, after) {
			t.Fatal("並行改變報告順序或舊欄位", format)
		}
		if format == "json" && bytes.Contains(after, []byte("list_source")) {
			t.Fatal("直接目標不應新增清單欄位")
		}
	}
}
