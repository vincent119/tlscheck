package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestCompletionHasNoConfigurationOrCheckSideEffects(t *testing.T) {
	a := New()
	a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("補全不得解析檔案"); return nil }
	a.Load = func(context.Context) config.Result { t.Fatal("補全讀設定"); return config.Result{} }
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out, diag bytes.Buffer
		if code := a.Run(context.Background(), []string{"completion", shell}, &out, &diag); code != 0 || out.Len() == 0 || diag.Len() != 0 {
			t.Fatal(shell, code, diag.String())
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"__complete", "--language", ""}, "zh-TW"}, {[]string{"__complete", "--format="}, "markdown"}, {[]string{"__complete", "--timeout", ""}, "500ms"}, {[]string{"__complete", "--remote", ""}, ":4"}, {[]string{"__complete", "completion", ""}, "powershell"}} {
		var out, diag bytes.Buffer
		if code := a.Run(context.Background(), tc.args, &out, &diag); code != 0 || !strings.Contains(out.String(), tc.want) {
			t.Fatal(tc.args, code, out.String(), diag.String())
		}
	}
}

func TestCompletionStopsShellValuesAndSuppressesUsedFlags(t *testing.T) {
	a := New()
	for _, tc := range []struct {
		args            []string
		present, absent string
	}{{[]string{"__complete", "completion", "bash", ""}, ":4", "powershell"}, {[]string{"__complete", "--format", "json", "-"}, "--local", "--format\t"}, {[]string{"__complete", "example.com", "--f"}, "--format", ""}, {[]string{"__complete", "--", "--f"}, ":0", "--format"}} {
		var out, diag bytes.Buffer
		if code := a.Run(context.Background(), tc.args, &out, &diag); code != 0 || !strings.Contains(out.String(), tc.present) || tc.absent != "" && strings.Contains(out.String(), tc.absent) {
			t.Fatal(tc.args, code, out.String(), diag.String())
		}
	}
}

func TestCompletionQueriesDoNotSuggestPositionalInputs(t *testing.T) {
	for _, flag := range []string{"--help", "--version", "--settings"} {
		var out, diag bytes.Buffer
		if code := New().Run(t.Context(), []string{"__complete", flag, ""}, &out, &diag); code != 0 || out.String() != ":4\n" {
			t.Fatal(flag, code, out.String())
		}
	}
}
