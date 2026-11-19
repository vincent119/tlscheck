package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/vincent119/tlscheck/internal/i18n"
)

func completionCommand(o *RunOptions) *cobra.Command {
	root := rootCommand(o)
	root.RunE = func(*cobra.Command, []string) error { return errArguments }
	root.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	}
	values := map[string][]string{"language": {"en", "zh-TW", "zh-CN"}, "format": {"table", "json", "html", "markdown"}, "timeout": {"500ms", "1s", "5s", "10s", "30s", "1m"}, "expiry-warning-days": {"0", "7", "14", "30", "60", "90"}}
	for name, items := range values {
		_ = root.RegisterFlagCompletionFunc(name, func(_ *cobra.Command, _ []string, prefix string) ([]string, cobra.ShellCompDirective) {
			matches := []string{}
			for _, v := range items {
				if strings.HasPrefix(v, prefix) {
					matches = append(matches, v)
				}
			}
			return matches, cobra.ShellCompDirectiveNoFileComp
		})
	}
	_ = root.RegisterFlagCompletionFunc("remote", cobra.NoFileCompletions)
	_ = root.RegisterFlagCompletionFunc("local", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveDefault
	})
	_ = root.RegisterFlagCompletionFunc("output", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"-"}, cobra.ShellCompDirectiveDefault
	})
	for _, name := range []string{"help", "version", "settings", "overwrite"} {
		_ = root.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	for _, query := range []string{"help", "version", "settings"} {
		for _, general := range []string{"remote", "local", "format", "output", "timeout", "expiry-warning-days", "overwrite"} {
			root.MarkFlagsMutuallyExclusive(query, general)
		}
	}
	root.MarkFlagsMutuallyExclusive("settings", "version")
	root.MarkFlagsMutuallyExclusive("settings", "language")
	root.MarkFlagsMutuallyExclusive("help", "version")
	sub := &cobra.Command{Use: "completion [bash|zsh|fish|powershell]", Short: "Shell 補全", Args: cobra.MaximumNArgs(1), RunE: func(*cobra.Command, []string) error { return nil }}
	sub.Flags().Bool("no-descriptions", false, "省略補全描述")
	sub.Flags().StringP("language", "L", "", "en | zh-TW | zh-CN")
	sub.Flags().BoolP("help", "h", false, "顯示說明")
	sub.ValidArgsFunction = func(_ *cobra.Command, args []string, prefix string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return []string{"bash", "zsh", "fish", "powershell"}, cobra.ShellCompDirectiveNoFileComp
	}
	_ = sub.RegisterFlagCompletionFunc("language", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"en", "zh-TW", "zh-CN"}, cobra.ShellCompDirectiveNoFileComp
	})
	for _, name := range []string{"help", "no-descriptions"} {
		_ = sub.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	root.AddCommand(sub)
	return root
}
func completionPosition(args []string) int {
	var o RunOptions
	flags := rootCommand(&o).Flags()
	for i := 0; i < len(args); i++ {
		token := args[i]
		if token == "--" {
			return -1
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			if token == "completion" {
				return i
			}
			return -1
		}
		if strings.HasPrefix(token, "--") {
			name, _, equal := strings.Cut(token[2:], "=")
			f := flags.Lookup(name)
			if f == nil {
				return -1
			}
			if f.NoOptDefVal == "" && !equal {
				i++
			}
			continue
		}
		short := token[1:]
		for len(short) > 0 {
			f := flags.ShorthandLookup(short[:1])
			if f == nil {
				return -1
			}
			short = short[1:]
			if f.NoOptDefVal == "" {
				if short == "" {
					i++
				}
				break
			}
		}
	}
	return -1
}
func (a App) completion(ctx context.Context, args []string, out, diagnostics io.Writer) (bool, int) {
	var o RunOptions
	if len(args) > 0 && (args[0] == "__complete" || args[0] == "__completeNoDesc") {
		root := completionCommand(&o)
		localizeFlags(root, i18n.New(diagnosticLanguage(args[1:])))
		return true, completeRequest(root, args[1:], args[0] == "__completeNoDesc", out)
	}
	pos := completionPosition(args)
	if pos < 0 {
		return false, 0
	}
	root := completionCommand(&o)
	sub := root.Commands()[0]
	combined := append(append([]string{}, args[:pos]...), args[pos+1:]...)
	sub.Flags().VisitAll(func(f *pflag.Flag) { f.Value = &countedValue{Value: f.Value, boolean: f.NoOptDefVal != ""} })
	if err := sub.ParseFlags(combined); err != nil {
		return true, argumentError(out, diagnostics, diagnosticLanguage(combined))
	}
	language, _ := sub.Flags().GetString("language")
	if language != "" && language != "en" && language != "zh-TW" && language != "zh-CN" {
		return true, argumentError(out, diagnostics, diagnosticLanguage(combined))
	}
	if sub.Flags().Changed("language") && language == "" {
		return true, argumentError(out, diagnostics, diagnosticLanguage(combined))
	}
	t := i18n.New(language)
	shells := sub.Flags().Args()
	help, _ := sub.Flags().GetBool("help")
	for _, token := range combined {
		if strings.HasPrefix(token, "--help=") || strings.HasPrefix(token, "-h=") || strings.HasPrefix(token, "--no-descriptions=") {
			return true, argumentError(out, diagnostics, language)
		}
	}
	if len(shells) > 1 || len(shells) == 1 && !validShell(shells[0]) {
		return true, argumentError(out, diagnostics, language)
	}
	if help || len(shells) == 0 {
		_, err := fmt.Fprintln(out, t.Text("cli.completion_help", nil))
		if err != nil {
			return true, 2
		}
		return true, 0
	}
	noDescriptions, _ := sub.Flags().GetBool("no-descriptions")
	localizeFlags(root, t)
	var err error
	var script bytes.Buffer
	switch shells[0] {
	case "bash":
		err = root.GenBashCompletionV2(&script, !noDescriptions)
	case "zsh":
		if noDescriptions {
			err = root.GenZshCompletionNoDesc(&script)
		} else {
			err = root.GenZshCompletion(&script)
		}
	case "fish":
		err = root.GenFishCompletion(&script, !noDescriptions)
	case "powershell":
		if noDescriptions {
			err = root.GenPowerShellCompletion(&script)
		} else {
			err = root.GenPowerShellCompletionWithDesc(&script)
		}
	default:
		return true, argumentError(out, diagnostics, language)
	}
	if err != nil {
		return true, 2
	}
	cleaned, err := withoutDebugScript(script.String(), shells[0])
	if err != nil {
		return true, 2
	}
	if shells[0] == "powershell" {
		cleaned, err = withPowerShellEmptyCandidates(cleaned)
		if err != nil {
			return true, 2
		}
	}
	if _, err = io.WriteString(out, cleaned); err != nil {
		return true, 2
	}
	return true, 0
}
func localizeFlags(root *cobra.Command, t *i18n.Translator) {
	root.Flags().VisitAll(func(f *pflag.Flag) { f.Usage = t.Text("flag."+f.Name, nil) })
	for _, sub := range root.Commands() {
		sub.Short = t.Text("cli.completion_title", nil)
		sub.Flags().VisitAll(func(f *pflag.Flag) { f.Usage = t.Text("flag."+f.Name, nil) })
	}
}

func validShell(s string) bool { return s == "bash" || s == "zsh" || s == "fish" || s == "powershell" }

// withoutDebugScript 只改固定版本生成器的已知函式；形狀改變就停止，不能留下偵錯寫檔。
func withoutDebugScript(script, shell string) (string, error) {
	lines := strings.Split(script, "\n")
	start, end := -1, -1
	for i, line := range lines {
		if strings.HasPrefix(line, "__tlscheck_debug()") || strings.HasPrefix(line, "function __tlscheck_debug") {
			start = i
			break
		}
	}
	if start < 0 {
		return "", errors.New("未知補全腳本結構")
	}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" || shell == "fish" && lines[i] == "end" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", errors.New("未知補全腳本結構")
	}
	replacement := []string{"__tlscheck_debug() { :; }"}
	if shell == "fish" {
		replacement = []string{"function __tlscheck_debug", "end"}
	}
	if shell == "powershell" {
		replacement = []string{"function __tlscheck_debug { }"}
	}
	lines = append(append(append([]string{}, lines[:start]...), replacement...), lines[end+1:]...)
	cleaned := strings.Join(lines, "\n")
	if strings.Contains(cleaned, "BASH_COMP_DEBUG_FILE") {
		return "", errors.New("補全腳本仍包含偵錯寫入")
	}
	return cleaned, nil
}
