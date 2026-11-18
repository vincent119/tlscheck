package app

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/model"
)

func TestCompletionProcessHelper(t *testing.T) {
	if os.Getenv("TLSCHECK_COMPLETION_TEST_HELPER") != "1" {
		return
	}
	a := New()
	a.Load = func(context.Context) config.Result { t.Fatal("補全讀設定"); return config.Result{} }
	a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("補全解析檔案"); return nil }
	for i, arg := range os.Args {
		if arg == "--" {
			os.Exit(a.Run(t.Context(), os.Args[i+1:], os.Stdout, os.Stderr))
		}
	}
	t.Fatal("缺少參數界線")
}
func TestCompletionNeverLeaksOrWritesDebugFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel")
	original := []byte("sentinel\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"__complete", "__completeNoDesc"} {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCompletionProcessHelper$", "--", mode, "https://user:synthetic-secret@example.com/private?q=hidden", "--unknown=private-value", "")
		cmd.Env = append(os.Environ(), "TLSCHECK_COMPLETION_TEST_HELPER=1", "BASH_COMP_DEBUG_FILE="+path)
		var out, diag bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &diag
		if err := cmd.Run(); err != nil {
			t.Fatal(err, diag.String())
		}
		if diag.Len() != 0 || strings.Contains(out.String(), "synthetic-secret") {
			t.Fatal("補全洩漏原始參數", diag.String())
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(data, original) {
			t.Fatal("補全修改偵錯檔")
		}
	}
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		var out, diag bytes.Buffer
		if code := New().Run(t.Context(), []string{"completion", shell}, &out, &diag); code != 0 {
			t.Fatal(code)
		}
		if strings.Contains(out.String(), "BASH_COMP_DEBUG_FILE") {
			t.Fatal("生成腳本仍包含偵錯寫檔", shell)
		}
	}
}
func TestEmptyInputFlagsFailBeforeChecksAndOutput(t *testing.T) {
	for _, flag := range []string{"--remote=", "--local=", "-r=", "-l="} {
		a := New()
		a.Local = func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult {
			t.Fatal("空值仍執行本機檢查")
			return check.LocalResult{}
		}
		a.Remote = func(context.Context, model.Target, time.Time) check.RemoteResult {
			t.Fatal("空值仍執行連線")
			return check.RemoteResult{}
		}
		a.Parse = func(context.Context, []string) []model.InputResult { t.Fatal("空值仍解析"); return nil }
		path := filepath.Join(t.TempDir(), "out")
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{flag, "-Len", "-fjson", "-o", path}, &out, &diag); code != 2 || out.Len() != 0 {
			t.Fatal(code, out.String())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("空值建立報告")
		}
	}
}
func TestEveryCompletionShellAllowsHelp(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		for _, help := range []string{"--help", "-h"} {
			var out, diag bytes.Buffer
			if code := New().Run(t.Context(), []string{"completion", shell, help}, &out, &diag); code != 0 || !strings.Contains(out.String(), "completion") {
				t.Fatal(shell, code, diag.String())
			}
		}
	}
	var out, diag bytes.Buffer
	if New().Run(t.Context(), []string{"completion", "invalid", "--help"}, &out, &diag) != 2 {
		t.Fatal("非法 shell 被說明吞掉")
	}
}
