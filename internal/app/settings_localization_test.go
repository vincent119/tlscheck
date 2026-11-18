package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/vincent119/tlscheck/internal/config"
)

func TestSettingsLabelsAreLocalizedWithoutChangingStoredValues(t *testing.T) {
	for _, tc := range []struct{ lang, themeName string }{{"en", "Dark"}, {"zh-TW", "深色"}, {"zh-CN", "深色"}} {
		var out bytes.Buffer
		i := 0
		keys := []string{"theme", "down", "enter", "down", "down", "enter"}
		saves := 0
		read := func(context.Context) (string, error) {
			if i >= len(keys) {
				t.Fatal("選單未結束")
			}
			key := keys[i]
			i++
			return key, nil
		}
		save := func(_ context.Context, c config.Config) error {
			saves++
			if c.Theme != "dark" || c.Language != tc.lang {
				t.Fatal("顯示名稱污染設定值", c)
			}
			return nil
		}
		if code := settingsMenu(t.Context(), &out, config.Config{Language: tc.lang, Theme: "normal"}, read, save); code != 0 || saves != 1 || !strings.Contains(out.String(), tc.themeName) {
			t.Fatal(tc.lang, code, "主題未翻譯")
		}
	}
}
