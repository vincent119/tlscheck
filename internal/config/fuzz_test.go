package config

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
)

func FuzzConfigJSONNeverEscapesFallbackContract(f *testing.F) {
	for _, seed := range []string{`{}`, `{"language":"zh-TW"}`, `{"language":null}`, `{"language":"en","language":"zh-CN"}`, `[]`, "\xff"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFileSize+1 {
			return
		}
		loader := NewLoader()
		loader.userConfigDir = func() (string, error) { return "/synthetic-config", nil }
		loader.open = func(string) (fs.File, error) { return (fstest.MapFS{"config": {Data: data}}).Open("config") }
		r := loader.Load(context.Background())
		switch r.Config.Language {
		case "en", "zh-TW", "zh-CN":
		default:
			t.Fatalf("未知語系逃出：%q", r.Config.Language)
		}
		if len(r.Warnings) > 1 || len(r.Warnings) > 0 && r.Config.Language != "en" {
			t.Fatalf("回退契約遭破壞：%+v", r)
		}
	})
}
