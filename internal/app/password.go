package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"unicode/utf8"

	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/containers"
	"github.com/vincent119/tlscheck/internal/i18n"
	"github.com/vincent119/tlscheck/internal/input"
	"github.com/vincent119/tlscheck/internal/model"
)

func (a App) parsePasswordInputs(ctx context.Context, o RunOptions, diagnostics io.Writer, t *i18n.Translator) []model.InputResult {
	if len(o.Passwords) == 0 {
		return a.parseInputs(ctx, o.Inputs)
	}
	used := map[int]bool{}
	protected := input.NewParser().LocalPaths(ctx, o.Inputs)
	protected = append(protected, o.TargetFiles...)
	for _, path := range o.CompareCertPaths {
		protected = append(protected, path)
	}
	configPath, pathErr := config.Path()
	if pathErr == nil {
		protected = append(protected, configPath)
	}
	provider := func(ctx context.Context, source model.SourceRef) ([]byte, error) {
		binding, exists := o.Passwords[source.InputIndex]
		if !exists {
			return nil, nil
		}
		used[source.InputIndex] = true
		if binding.ask {
			prompt := a.passwordPrompt
			if prompt == nil {
				prompt = askPassword
			}
			return prompt(ctx, diagnostics, t, source.InputIndex)
		}
		if pathErr != nil {
			return nil, errors.New("無法確認設定檔保護範圍")
		}
		return input.ReadPasswordFile(ctx, binding.path, protected)
	}
	p := input.NewParserWithPasswordProvider(provider)
	results := make([]model.InputResult, 0, len(o.Inputs))
	for _, spec := range o.Inputs {
		r := p.ParseSpec(ctx, spec)
		if _, bound := o.Passwords[spec.Index]; bound && !used[spec.Index] && len(r.Issues) == 0 {
			source := model.SourceRef{InputIndex: spec.Index}
			if r.Target == nil {
				source.Path = spec.Value
			}
			r.Issues = append(r.Issues, model.Issue{Code: model.PasswordNotApplicable, Source: source})
			// 自動辨識後才知道是遠端時，不讓錯綁密碼的目標進入網路檢查。
			r.Target = nil
		}
		results = append(results, r)
	}
	return results
}
func terminal(in, out *os.File) (func(context.Context) (string, error), func() error, error) {
	read, restore, err := terminalBytes(in, out)
	if err != nil {
		return nil, nil, err
	}
	return keyReader(read), restore, nil
}
func askPassword(ctx context.Context, out io.Writer, t *i18n.Translator, index int) (password []byte, err error) {
	file, ok := out.(*os.File)
	if !ok {
		return nil, errors.New("密碼提示需要終端")
	}
	read, restore, err := terminalBytes(os.Stdin, file)
	if err != nil {
		return nil, err
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil {
			clear(password)
			password = nil
			err = restoreErr
		}
	}()
	if _, err = fmt.Fprint(out, t.Text("cli.password_prompt", i18n.Params{"Index": strconv.Itoa(index)})); err != nil {
		return nil, err
	}
	password, err = readHiddenPassword(ctx, read)
	if _, writeErr := fmt.Fprintln(out); writeErr != nil {
		clear(password)
		password = nil
		return nil, writeErr
	}
	return password, err
}
func readHiddenPassword(ctx context.Context, read func(context.Context, bool) (byte, error)) ([]byte, error) {
	password := make([]byte, 0, containers.MaxPasswordSize)
	fail := func(err error) ([]byte, error) { clear(password); return nil, err }
	for {
		b, err := read(ctx, true)
		if err != nil {
			return fail(err)
		}
		switch b {
		case 3, 27:
			return fail(context.Canceled)
		case 4:
			return fail(io.EOF)
		case 13, 10:
			return password, nil
		case 8, 127:
			if len(password) > 0 {
				_, n := utf8.DecodeLastRune(password)
				clear(password[len(password)-n:])
				password = password[:len(password)-n]
			}
		default:
			if len(password) >= containers.MaxPasswordSize {
				return fail(errors.New("密碼超過上限"))
			}
			password = append(password, b)
		}
	}
}
