// Package app 編排唯讀檢查，不在函式庫退出程序。
package app

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vincent119/tlscheck/internal/check"
	"github.com/vincent119/tlscheck/internal/config"
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
}

// Run 只回傳統一結束碼。
func (a App) Run(ctx context.Context, args []string, out, diagnostics io.Writer) int {
	cfg := a.Load(ctx)
	w := &report.Writer{Out: out, Diagnostics: diagnostics, T: i18n.New(cfg.Config.Language)}
	for _, warning := range cfg.Warnings {
		if _, err := fmt.Fprintln(diagnostics, warning.Message()); err != nil {
			w.Err = err
		}
	}
	finish := func(code int) int {
		if w.Err != nil {
			return 2
		}
		return code
	}
	if len(args) == 0 {
		for _, id := range []string{"help.usage", "help.description", "help.targets", "help.version", "help.language"} {
			w.Text(id)
		}
		return finish(0)
	}
	if len(args) == 1 && args[0] == "--version" {
		w.Field("field.version", a.Version)
		w.Field("field.commit", a.Commit)
		return finish(0)
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			w.Outcome("field.target", check.Outcome{Status: check.Failed, Code: "cli.invalid_arguments", Class: check.ExecutionFailure})
			return finish(2)
		}
	}
	now := a.Now().UTC()
	inputs := a.Parse(ctx, args)
	var certs []model.ParsedCertificate
	var keys []model.ParsedKey
	for _, item := range inputs {
		certs = append(certs, item.Certificates...)
		keys = append(keys, item.Keys...)
	}
	local := a.Local(ctx, certs, now)
	pairs := a.Pair(ctx, keys, certs)
	code := int(local.Failure())
	if int(pairs.Failure()) > code {
		code = int(pairs.Failure())
	}
	for _, item := range inputs {
		for _, issue := range item.Issues {
			w.Source(issue.Source)
			w.Outcome("field.parse", check.Outcome{Status: check.Failed, Code: string(issue.Code), Class: check.ExecutionFailure})
			code = 2
		}
		for _, c := range local.Certificates {
			if len(c.Sources) > 0 && c.Sources[0].InputIndex == item.InputIndex {
				w.LocalCertificate(c)
			}
		}
		for _, k := range pairs.Keys {
			if k.Info.Source.InputIndex == item.InputIndex {
				w.Key(k)
			}
		}
		if item.Target != nil {
			remote := a.Remote(ctx, *item.Target, now)
			w.Remote(remote)
			if int(remote.Failure()) > code {
				code = int(remote.Failure())
			}
		}
	}
	for _, c := range pairs.Certificates {
		w.Field("field.fingerprint_sha256", c.FingerprintSHA256)
		w.Outcome("field.pairing", c.Pairing)
	}
	for _, pair := range pairs.Pairs {
		w.Field("field.pairing", w.T.Text("report.pair", i18n.Params{"Key": fmt.Sprint(pair.KeyIndex), "Certificate": fmt.Sprint(pair.CertificateIndex)}))
	}
	w.Outcome("field.pairing", pairs.Pairing)
	for _, o := range append(local.Issues, pairs.Issues...) {
		w.Outcome("field.summary", o)
	}
	if ctx.Err() != nil {
		code = 2
		w.Outcome("field.summary", check.Outcome{Status: check.Failed, Code: "input.canceled", Class: check.ExecutionFailure})
	}
	if w.Err != nil {
		code = 2
	}
	w.Summary(code)
	return finish(code)
}

// New 組裝既有能力，不新增信任來源或遠端金鑰輸入。
func New() App {
	return App{Load: config.NewLoader().Load, Parse: input.NewParser().ParseAll, Local: func(ctx context.Context, c []model.ParsedCertificate, now time.Time) check.LocalResult {
		return check.NewAnalyzer(now, nil).AnalyzeLocal(ctx, c)
	}, Pair: check.PairLocal, Remote: func(ctx context.Context, t model.Target, now time.Time) check.RemoteResult {
		return check.NewRemoteChecker(now, nil).Check(ctx, t)
	}, Now: time.Now, Version: "development", Commit: "unknown"}
}
