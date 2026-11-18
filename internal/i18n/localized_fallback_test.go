package i18n

import (
	"strings"
	"testing"
	"text/template"
)

func TestLocalizedUltimateFallback(t *testing.T) {
	for _, tc := range []struct{ language, want string }{{"en", "Unable to display this result."}, {"zh-TW", "無法顯示此結果。"}, {"zh-CN", "无法显示此结果。"}, {"unsupported", "Unable to display this result."}} {
		t.Run(tc.language, func(t *testing.T) {
			tr := New(tc.language)
			if got := tr.Text("private.synthetic.missing", nil); got != tc.want {
				t.Fatalf("保底語系錯誤：%q", got)
			}
			tr.english = map[string]*template.Template{"bad": parseTemplate("{{.Missing}}")}
			tr.translated = map[string]*template.Template{"bad": parseTemplate("{{.AlsoMissing}}")}
			if got := tr.Text("bad", nil); got != tc.want || strings.Contains(got, "Missing") {
				t.Fatalf("模板失敗保底不安全：%q", got)
			}
		})
	}
}

func TestLanguageAutonymsRemainRecognizable(t *testing.T) {
	for _, language := range []string{"en", "zh-TW", "zh-CN"} {
		tr := New(language)
		for key, want := range map[string]string{"language.name.en": "English", "language.name.zh-TW": "繁體中文", "language.name.zh-CN": "简体中文"} {
			if got := tr.Text(key, nil); got != want {
				t.Fatalf("語系母語名稱錯誤：%s %q", language, got)
			}
		}
	}
}
