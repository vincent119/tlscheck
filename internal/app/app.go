// Package app 編排唯讀檢查及明確報告／設定輸出，不在函式庫退出程序。
package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/filetxn"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
	"github.com/vincent119/tlscheck/internal/report"
)

// App 的邊界可替換以驗證不連線及本機集合隔離。
type App struct {
	Load            func(context.Context) config.Result
	Parse           func(context.Context, []string) []model.InputResult
	Local           func(context.Context, []model.ParsedCertificate, time.Time) check.LocalResult
	Pair            func(context.Context, []model.ParsedKey, []model.ParsedCertificate) check.PairingResult
	Remote          func(context.Context, model.Target, time.Time) check.RemoteResult
	Now             func() time.Time
	Version, Commit string
	passwordPrompt  func(context.Context, io.Writer, *i18n.Translator, int) ([]byte, error)
}

// Run 只回傳統一結束碼。
func (a App) Run(ctx context.Context, args []string, out, diagnostics io.Writer) int {
	if handled, code := a.completion(ctx, args, out, diagnostics); handled {
		return code
	}
	options, err := parseOptions(args)
	if err != nil {
		return argumentError(out, diagnostics, diagnosticLanguage(args))
	}
	cfg := config.Result{Config: config.Config{Language: options.Language, Theme: "normal"}}
	if options.Language == "" {
		cfg = a.Load(ctx)
	}
	t := i18n.New(cfg.Config.Language)
	for _, warning := range cfg.Warnings {
		if _, err := fmt.Fprintln(diagnostics, warning.Message()); err != nil {
			return 2
		}
	}
	if options.Help {
		return writeHelp(out, t, options.Settings)
	}
	if options.Version {
		if _, err := fmt.Fprintf(out, "tlscheck %s (%s)\n", report.Safe(a.Version), report.Safe(a.Commit)); err != nil {
			return 2
		}
		return 0
	}
	if options.Settings {
		return runSettings(ctx, diagnostics, cfg.Config)
	}
	var destination *filetxn.Transaction
	if options.Output != "-" {
		protected := input.NewParser().LocalPaths(ctx, options.Inputs)
		configPath, pathErr := config.Path()
		if pathErr != nil {
			return diagnosticError(diagnostics, t, "cli.output_failed")
		}
		protected = append(protected, configPath)
		for _, binding := range options.Passwords {
			if !binding.ask {
				protected = append(protected, binding.path)
			}
		}
		destination, err = filetxn.Prepare(ctx, options.Output, options.Overwrite, protected)
		if err != nil {
			return diagnosticError(diagnostics, t, "cli.output_failed")
		}
		defer destination.Close()
	}
	now := a.Now().UTC()
	inputs := a.parsePasswordInputs(ctx, options, diagnostics, t)
	var certs []model.ParsedCertificate
	var keys []model.ParsedKey
	for _, item := range inputs {
		certs = append(certs, item.Certificates...)
		keys = append(keys, item.Keys...)
	}
	var local check.LocalResult
	if a.Local != nil {
		local = a.Local(ctx, certs, now)
	} else {
		local = check.NewAnalyzerWithOptions(now, nil, check.CertificateOptions{ExpiryWarningDays: options.ExpiryWarningDays}).AnalyzeLocal(ctx, certs)
	}
	pairs := a.Pair(ctx, keys, certs)
	code := max(int(local.Failure()), int(pairs.Failure()))
	remotes := []check.RemoteResult{}
	for _, item := range inputs {
		if len(item.Issues) > 0 {
			code = 2
		}
		if item.Target != nil {
			var r check.RemoteResult
			if a.Remote != nil {
				r = a.Remote(ctx, *item.Target, now)
			} else {
				r = check.NewRemoteCheckerWithOptions(now, nil, check.RemoteOptions{Timeout: options.Timeout, ExpiryWarningDays: options.ExpiryWarningDays}).Check(ctx, *item.Target)
			}
			remotes = append(remotes, r)
			code = max(code, int(r.Failure()))
		}
	}
	if ctx.Err() != nil {
		code = 2
		local.Issues = append(local.Issues, check.Outcome{Status: check.Failed, Code: "input.canceled", Class: check.ExecutionFailure})
	}
	document := report.Build(cfg.Config.Language, a.Version, a.Commit, now, options.Inputs, inputs, local, pairs, remotes, code)
	if err := report.Diagnostics(diagnostics, document); err != nil {
		return 2
	}
	var buf bytes.Buffer
	if err := report.RenderWithOptions(&buf, options.Format, document, report.RenderOptions{Detail: report.Detail(options.Detail)}); err != nil {
		return diagnosticError(diagnostics, t, "cli.output_failed")
	}
	if destination != nil {
		err = destination.Commit(ctx, buf.Bytes())
	} else {
		_, err = io.Copy(out, &buf)
	}
	if err != nil {
		return diagnosticError(diagnostics, t, "cli.output_failed")
	}
	return code
}

func (a App) parseInputs(ctx context.Context, specs []model.InputSpec) []model.InputResult {
	allAuto := true
	values := make([]string, 0, len(specs))
	for _, s := range specs {
		values = append(values, s.Value)
		if s.Kind != model.AutoInput {
			allAuto = false
		}
	}
	if allAuto {
		return a.Parse(ctx, values)
	}
	results := make([]model.InputResult, 0, len(specs))
	p := input.NewParser()
	for _, s := range specs {
		results = append(results, p.ParseSpec(ctx, s))
	}
	return results
}

func argumentError(out, diagnostics io.Writer, language string) int {
	if language != "en" && language != "zh-TW" && language != "zh-CN" {
		language = "en"
	}
	t := i18n.New(language)
	fmt.Fprintln(diagnostics, t.Text("cli.invalid_arguments", nil))
	fmt.Fprintln(diagnostics, t.Text("cli.usage_hint", nil))
	return 2
}
func diagnosticError(out io.Writer, t *i18n.Translator, id string) int {
	fmt.Fprintln(out, t.Text(id, nil))
	return 2
}
func writeHelp(out io.Writer, t *i18n.Translator, settings bool) int {
	if settings {
		if _, err := fmt.Fprintln(out, t.Text("cli.settings_help", nil)); err != nil {
			return 2
		}
		return 0
	}
	for _, id := range []string{"help.usage", "help.description", "cli.flags_help", "cli.syntax_help", "cli.completion_help"} {
		if _, err := fmt.Fprintln(out, t.Text(id, nil)); err != nil {
			return 2
		}
	}
	return 0
}

// New 組裝既有能力，不新增信任來源或遠端金鑰輸入。
func New() App {
	return App{Load: config.NewLoader().Load, Parse: input.NewParser().ParseAll, Pair: check.PairLocal, Now: time.Now, Version: "development", Commit: "unknown"}
}
