package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestOrderedCobraInputs(t *testing.T) {
	o, err := parseOptions([]string{"one", "-rtwo", "-l", "a,b.pem", "--remote=https://three/", "--", "-four", "completion"})
	if err != nil {
		t.Fatal(err)
	}
	want := []model.InputKind{model.AutoInput, model.RemoteInput, model.LocalInput, model.RemoteInput, model.AutoInput, model.AutoInput}
	values := []string{"one", "two", "a,b.pem", "https://three/", "-four", "completion"}
	if len(o.Inputs) != len(want) {
		t.Fatal(o.Inputs)
	}
	for i, v := range o.Inputs {
		if v.Kind != want[i] || v.Index != i || v.Value != values[i] {
			t.Fatal(o.Inputs)
		}
	}
}
func TestCLIFlagValidation(t *testing.T) {
	for _, args := range [][]string{{"--language"}, {"-L", ""}, {"--language=EN"}, {"-Lzh-TW", "-Len"}, {"--timeout=0s", "a"}, {"--timeout=6m", "a"}, {"--expiry-warning-days=-1", "a"}, {"--overwrite=false", "a"}, {"--overwrite", "a"}, {"--help", "a"}, {"--version", "--format=json"}, {"--settings", "-Len"}, {"--format=json"}, {"--help", "--help"}, {"--json", "a"}} {
		if _, err := parseOptions(args); err == nil {
			t.Fatalf("應拒絕 %q", args)
		}
	}
	for _, args := range [][]string{nil, {"-Len"}, {"--help"}, {"-V", "-Lzh-TW"}, {"--settings", "--help"}, {"-fjson", "--timeout=1ms", "--expiry-warning-days=0", "a"}} {
		if _, err := parseOptions(args); err != nil {
			t.Fatalf("應接受 %q: %v", args, err)
		}
	}
}

func TestHelpListsEveryPublicFlagInThreeLanguages(t *testing.T) {
	for _, language := range []string{"en", "zh-TW", "zh-CN"} {
		a := New()
		var out, diag bytes.Buffer
		if code := a.Run(t.Context(), []string{"-L", language, "--help"}, &out, &diag); code != 0 {
			t.Fatal(code, diag.String())
		}
		var o RunOptions
		rootCommand(&o).Flags().VisitAll(func(flag *pflag.Flag) {
			if !strings.Contains(out.String(), "--"+flag.Name) || flag.Shorthand != "" && !strings.Contains(out.String(), "-"+flag.Shorthand) {
				t.Fatal(language, flag.Name)
			}
		})
	}
}
