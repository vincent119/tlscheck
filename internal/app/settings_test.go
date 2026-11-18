package app

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/vincent119/tlscheck/internal/config"
)

func TestSettingsPreviewCancelAndExplicitSave(t *testing.T) {
	for _, tc := range []struct {
		keys            []string
		saves           int
		language, theme string
	}{{[]string{"enter", "down", "enter", "escape"}, 0, "en", "normal"}, {[]string{"enter", "down", "enter", "down", "enter", "down", "enter", "down", "down", "enter"}, 1, "zh-TW", "dark"}, {[]string{"ctrl-c"}, 0, "en", "normal"}} {
		var out bytes.Buffer
		calls := 0
		i := 0
		read := func(context.Context) (string, error) {
			if i >= len(tc.keys) {
				t.Fatal("選單未結束")
			}
			v := tc.keys[i]
			i++
			return v, nil
		}
		save := func(_ context.Context, c config.Config) error {
			calls++
			if c.Language != tc.language || c.Theme != tc.theme {
				t.Fatal(c)
			}
			return nil
		}
		if code := settingsMenu(context.Background(), &out, config.Config{Language: "en", Theme: "normal"}, read, save); code != 0 || calls != tc.saves {
			t.Fatal(code, calls)
		}
	}
}

func TestSettingsReadFailureNeverSaves(t *testing.T) {
	var out bytes.Buffer
	read := func(context.Context) (string, error) { return "", io.EOF }
	save := func(context.Context, config.Config) error { t.Fatal("斷線仍儲存"); return nil }
	if code := settingsMenu(t.Context(), &out, config.Config{Language: "en", Theme: "normal"}, read, save); code != 2 {
		t.Fatal(code)
	}
}
