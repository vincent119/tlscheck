package app

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// completeRequest 只使用公開旗標描述及回呼，不進入會寫 os.Stderr／偵錯檔的 Cobra 執行器。
func completeRequest(root *cobra.Command, args []string, noDescriptions bool, out io.Writer) int {
	directive := cobra.ShellCompDirectiveError | cobra.ShellCompDirectiveNoFileComp
	emit := func(values []string, d cobra.ShellCompDirective) int {
		for _, value := range values {
			if noDescriptions {
				value, _, _ = strings.Cut(value, "\t")
			}
			if _, err := fmt.Fprintln(out, value); err != nil {
				return 2
			}
		}
		if _, err := fmt.Fprintf(out, ":%d\n", d); err != nil {
			return 2
		}
		return 0
	}
	if len(args) == 0 {
		return emit(nil, directive)
	}
	previous, prefix := args[:len(args)-1], args[len(args)-1]
	command := root
	used := map[string]bool{}
	positionals := []string{}
	afterDash := false
	var pending *pflag.Flag
	set := func(f *pflag.Flag, value string) bool {
		if used[f.Name] && f.Name != "remote" && f.Name != "local" {
			return false
		}
		if f.Value.Set(value) != nil {
			return false
		}
		if f.Name == "language" && value != "en" && value != "zh-TW" && value != "zh-CN" {
			return false
		}
		f.Changed = true
		used[f.Name] = true
		return true
	}
	for i := 0; i < len(previous); i++ {
		token := previous[i]
		if afterDash {
			positionals = append(positionals, token)
			continue
		}
		if token == "--" {
			afterDash = true
			continue
		}
		if !strings.HasPrefix(token, "-") || token == "-" {
			if command == root && len(positionals) == 0 && token == "completion" {
				for name := range used {
					if name != "language" {
						return emit(nil, directive)
					}
				}
				command = root.Commands()[0]
				continue
			}
			positionals = append(positionals, token)
			continue
		}
		consume := func(f *pflag.Flag, value string, attached bool) bool {
			if f == nil {
				return false
			}
			if f.NoOptDefVal != "" {
				if attached {
					return false
				}
				return set(f, f.NoOptDefVal)
			}
			if !attached {
				if i+1 == len(previous) {
					pending = f
					return true
				}
				i++
				value = previous[i]
			}
			return set(f, value)
		}
		if strings.HasPrefix(token, "--") {
			name, value, attached := strings.Cut(token[2:], "=")
			if !consume(command.Flags().Lookup(name), value, attached) {
				return emit(nil, directive)
			}
		} else {
			short := token[1:]
			for len(short) > 0 {
				f := command.Flags().ShorthandLookup(short[:1])
				if f == nil {
					return emit(nil, directive)
				}
				short = short[1:]
				if f.NoOptDefVal != "" {
					if strings.HasPrefix(short, "=") || !consume(f, "", false) {
						return emit(nil, directive)
					}
					continue
				}
				if !consume(f, strings.TrimPrefix(short, "="), short != "") {
					return emit(nil, directive)
				}
				break
			}
		}
	}
	if afterDash {
		return emit(nil, cobra.ShellCompDirectiveDefault)
	}
	valuePrefix := prefix
	if pending == nil && strings.HasPrefix(prefix, "--") {
		if name, value, ok := strings.Cut(prefix[2:], "="); ok {
			pending = command.Flags().Lookup(name)
			valuePrefix = value
			if pending == nil {
				return emit(nil, directive)
			}
		}
	}
	if pending == nil && strings.HasPrefix(prefix, "-") && !strings.HasPrefix(prefix, "--") && len(prefix) > 2 {
		f := command.Flags().ShorthandLookup(prefix[1:2])
		if f != nil && f.NoOptDefVal == "" {
			pending = f
			valuePrefix = strings.TrimPrefix(prefix[2:], "=")
		}
	}
	if pending != nil {
		if pending.NoOptDefVal != "" {
			return emit(nil, cobra.ShellCompDirectiveNoFileComp)
		}
		if callback, ok := command.GetFlagCompletionFunc(pending.Name); ok {
			values, d := callback(command, positionals, valuePrefix)
			return emit(filterCompletions(values, valuePrefix), d)
		}
		return emit(nil, cobra.ShellCompDirectiveNoFileComp)
	}
	if strings.HasPrefix(prefix, "-") {
		values := []string{}
		command.Flags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden || used[f.Name] && f.Name != "remote" && f.Name != "local" {
				return
			}
			for _, group := range f.Annotations["cobra_annotation_mutually_exclusive"] {
				for _, name := range strings.Fields(group) {
					if name != f.Name && used[name] {
						return
					}
				}
			}
			for _, name := range []string{"--" + f.Name, shortName(f.Shorthand)} {
				if name != "" && strings.HasPrefix(name, prefix) {
					values = append(values, name+"\t"+f.Usage)
				}
			}
		})
		return emit(values, cobra.ShellCompDirectiveNoFileComp)
	}
	if command == root && (used["help"] || used["version"] || used["settings"]) {
		return emit(nil, cobra.ShellCompDirectiveNoFileComp)
	}
	if command.ValidArgsFunction != nil {
		values, d := command.ValidArgsFunction(command, positionals, prefix)
		allowSubcommand := true
		for name := range used {
			if name != "language" {
				allowSubcommand = false
			}
		}
		if command == root && len(positionals) == 0 && allowSubcommand && strings.HasPrefix("completion", prefix) {
			values = append(values, "completion\t"+root.Commands()[0].Short)
		}
		return emit(filterCompletions(values, prefix), d)
	}
	return emit(nil, cobra.ShellCompDirectiveDefault)
}
func shortName(s string) string {
	if s == "" {
		return ""
	}
	return "-" + s
}
func filterCompletions(values []string, prefix string) []string {
	result := []string{}
	for _, v := range values {
		if strings.HasPrefix(v, prefix) {
			result = append(result, v)
		}
	}
	return result
}
