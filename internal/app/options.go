package app

import (
	"errors"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vincent119/tlscheck/internal/model"
)

// RunOptions 是 CLI 與檢查編排之間的 typed 契約。
type RunOptions struct {
	Inputs                             []model.InputSpec
	Language, Format, Output           string
	Timeout                            time.Duration
	ExpiryWarningDays                  int
	Overwrite, Help, Version, Settings bool
}

var errArguments = errors.New("cli.invalid_arguments")

type countedValue struct {
	pflag.Value
	count   int
	boolean bool
}

func (v *countedValue) Set(s string) error {
	v.count++
	if v.count > 1 || v.boolean && s != "true" {
		return errArguments
	}
	return v.Value.Set(s)
}

func rootCommand(o *RunOptions) *cobra.Command {
	c := &cobra.Command{Use: "tlscheck [target-or-file]...", Args: cobra.ArbitraryArgs, SilenceErrors: true, SilenceUsage: true, DisableSuggestions: true, CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true}}
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	f := c.Flags()
	f.StringArrayP("remote", "r", nil, "遠端 TLS 目標")
	f.StringArrayP("local", "l", nil, "本機憑證或私鑰檔案")
	f.StringVarP(&o.Language, "language", "L", "", "en | zh-TW | zh-CN")
	f.StringVarP(&o.Format, "format", "f", "table", "table | json | html | markdown")
	f.StringVarP(&o.Output, "output", "o", "-", "報告目的地（- 為 stdout）")
	f.DurationVarP(&o.Timeout, "timeout", "t", 10*time.Second, "每個遠端目標總逾時（1ms–5m）")
	f.IntVar(&o.ExpiryWarningDays, "expiry-warning-days", 30, "到期提醒天數（0–36500）")
	f.BoolVar(&o.Overwrite, "overwrite", false, "允許覆寫既有報告")
	f.BoolVarP(&o.Settings, "settings", "s", false, "互動語系與 theme 設定")
	f.BoolVarP(&o.Help, "help", "h", false, "顯示說明")
	f.BoolVarP(&o.Version, "version", "V", false, "顯示版本")
	return c
}

func parseOptions(args []string) (RunOptions, error) {
	var o RunOptions
	c := rootCommand(&o)
	c.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "remote" && f.Name != "local" {
			f.Value = &countedValue{Value: f.Value, boolean: f.NoOptDefVal != ""}
		}
	})
	if err := c.ParseFlags(args); err != nil {
		return o, errArguments
	}
	f := c.Flags()
	if f.Changed("language") && o.Language != "en" && o.Language != "zh-TW" && o.Language != "zh-CN" {
		return o, errArguments
	}
	if o.Format != "table" && o.Format != "json" && o.Format != "html" && o.Format != "markdown" || o.Output == "" || o.Timeout < time.Millisecond || o.Timeout > 5*time.Minute || o.ExpiryWarningDays < 0 || o.ExpiryWarningDays > 36500 || o.Overwrite && o.Output == "-" {
		return o, errArguments
	}
	// pflag 已驗證語法；這層只依相同旗標描述定位 occurrence，不重做值的解析。
	positional := false
	add := func(kind model.InputKind, value string) {
		o.Inputs = append(o.Inputs, model.InputSpec{Kind: kind, Value: value, Index: len(o.Inputs)})
	}
	for i := 0; i < len(args); i++ {
		token := args[i]
		if positional {
			add(model.AutoInput, token)
			continue
		}
		if token == "--" {
			positional = true
			continue
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			add(model.AutoInput, token)
			continue
		}
		if strings.HasPrefix(token, "--") {
			name, value, has := strings.Cut(token[2:], "=")
			flag := f.Lookup(name)
			if flag == nil {
				return o, errArguments
			}
			if flag.NoOptDefVal != "" {
				if has {
					return o, errArguments
				}
				continue
			}
			if !has {
				i++
				if i >= len(args) {
					return o, errArguments
				}
				value = args[i]
			}
			if (name == "remote" || name == "local") && value == "" {
				return o, errArguments
			}
			if name == "remote" {
				add(model.RemoteInput, value)
			}
			if name == "local" {
				add(model.LocalInput, value)
			}
			continue
		}
		short := token[1:]
		for len(short) > 0 {
			flag := f.ShorthandLookup(short[:1])
			if flag == nil {
				return o, errArguments
			}
			short = short[1:]
			if flag.NoOptDefVal != "" {
				if strings.HasPrefix(short, "=") {
					return o, errArguments
				}
				continue
			}
			value := strings.TrimPrefix(short, "=")
			if short == "" {
				i++
				if i >= len(args) {
					return o, errArguments
				}
				value = args[i]
			}
			if (flag.Name == "remote" || flag.Name == "local") && value == "" {
				return o, errArguments
			}
			if flag.Name == "remote" {
				add(model.RemoteInput, value)
			}
			if flag.Name == "local" {
				add(model.LocalInput, value)
			}
			break
		}
	}
	query := o.Help || o.Version || o.Settings
	if query {
		if len(o.Inputs) > 0 {
			return o, errArguments
		}
		for _, name := range []string{"remote", "local", "format", "output", "overwrite", "timeout", "expiry-warning-days"} {
			if f.Changed(name) {
				return o, errArguments
			}
		}
		if o.Settings && (o.Version || f.Changed("language")) || o.Version && o.Help {
			return o, errArguments
		}
	} else if len(o.Inputs) == 0 {
		general := false
		f.Visit(func(flag *pflag.Flag) {
			if flag.Name != "language" {
				general = true
			}
		})
		if general {
			return o, errArguments
		}
		o.Help = true
	}
	return o, nil
}

// diagnosticLanguage 只定位明確語系；其他解析錯誤不能改變其前後順序的語意。
func diagnosticLanguage(args []string) string {
	var o RunOptions
	flags := rootCommand(&o).Flags()
	language, count := "", 0
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			break
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			continue
		}
		if strings.HasPrefix(token, "--") {
			name, value, equal := strings.Cut(token[2:], "=")
			f := flags.Lookup(name)
			if f == nil {
				continue
			}
			if f.NoOptDefVal == "" && !equal {
				if i+1 >= len(args) {
					continue
				}
				i++
				value = args[i]
			}
			if name == "language" {
				language = value
				count++
			}
			continue
		}
		short := token[1:]
		for len(short) > 0 {
			f := flags.ShorthandLookup(short[:1])
			if f == nil {
				break
			}
			short = short[1:]
			if f.NoOptDefVal != "" {
				continue
			}
			value := strings.TrimPrefix(short, "=")
			if short == "" {
				if i+1 >= len(args) {
					break
				}
				i++
				value = args[i]
			}
			if f.Name == "language" {
				language = value
				count++
			}
			break
		}
	}
	if count == 1 && (language == "en" || language == "zh-TW" || language == "zh-CN") {
		return language
	}
	return "en"
}
