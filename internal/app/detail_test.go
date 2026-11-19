package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestDetailArgumentsAndInvalidValuesHaveNoSideEffects(t *testing.T) {
	for _, args := range [][]string{{"--detail"}, {"--detail="}, {"--detail", "FULL", "x"}, {"--detail", "full", "--detail", "full", "x"}, {"--detail", "x", "--output", "never-created"}, {"--detail", "full", "--help"}, {"--detail", "full", "--settings"}} {
		a := New()
		a.Load = func(context.Context) config.Result { t.Fatal("非法 detail 不得讀設定"); return config.Result{} }
		a.Parse = func(context.Context, []string) []model.InputResult {
			t.Fatal("非法 detail 不得解析輸入")
			return nil
		}
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), args, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal("非法參數未安全拒絕", args, code, out.String())
		}
	}
	for _, args := range [][]string{{"x"}, {"--detail=summary", "x"}, {"--detail", "full", "x"}, {"--format=json", "--detail=full", "x"}} {
		o, err := parseOptions(args)
		if err != nil {
			t.Fatal("合法 detail 被拒絕", args, err)
		}
		want := "summary"
		for _, v := range args {
			if v == "full" || v == "--detail=full" {
				want = "full"
			}
		}
		if o.Detail != want {
			t.Fatal("詳細程度不符", o.Detail, want)
		}
	}
	o, err := parseOptions([]string{"--", "--detail", "full"})
	if err != nil || len(o.Inputs) != 2 {
		t.Fatal("分隔符後不得解析旗標", o, err)
	}
}

func TestDetailCompletionIsSideEffectFree(t *testing.T) {
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全不得讀設定"); return config.Result{} }
	a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("補全不得檢查輸入"); return nil }
	for _, prefix := range []string{"", "s", "unknown"} {
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"__complete", "--detail", prefix}, &out, &diag); code != 0 || !strings.Contains(out.String(), ":4") {
			t.Fatal("detail 補全不得回退檔名", out.String(), code)
		}
		if prefix == "" && (!strings.Contains(out.String(), "summary") || !strings.Contains(out.String(), "full")) {
			t.Fatal("缺少 detail 補全值")
		}
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"completion", shell}, &out, &diag); code != 0 || !strings.Contains(out.String(), "__complete") {
			t.Fatal("缺少 shell detail 補全", shell, code)
		}
	}
}

func TestCLIDefaultSummaryFullAndOtherFormats(t *testing.T) {
	a := New()
	a.Version = "full-version-canary"
	a.Now = func() time.Time { return time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC) }
	a.Parse = func(context.Context, []string) []model.InputResult { return nil }
	run := func(extra ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		args := append([]string{"synthetic.pem", "-L", "en"}, extra...)
		if code := a.Run(t.Context(), args, &out, &diag); code != 0 {
			t.Fatal("模式改變結束碼", code, diag.String())
		}
		return out.String()
	}
	summary := run()
	if !strings.Contains(summary, "--detail full") || strings.Contains(summary, a.Version) {
		t.Fatal("CLI 預設不是摘要")
	}
	if summary != run("--detail=summary") {
		t.Fatal("省略 detail 與明確摘要不同")
	}
	full := run("--detail=full")
	if strings.Contains(full, "--detail full") || !strings.Contains(full, a.Version) {
		t.Fatal("CLI 完整模式未保留 metadata")
	}
	for _, format := range []string{"json", "html", "markdown"} {
		if run("--format="+format, "--detail=summary") != run("--format="+format, "--detail=full") {
			t.Fatal("CLI detail 改變其他格式", format)
		}
	}
}
