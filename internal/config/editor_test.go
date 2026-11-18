package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestThemeAndExplicitSave(t *testing.T) {
	for _, data := range []string{`{"language":"zh-TW"}`, `{"language":"zh-TW","theme":"dark"}`, `{"theme":"light"}`} {
		r := loadData(t, data)
		if len(r.Warnings) != 0 || r.Config.Theme == "" {
			t.Fatal(r)
		}
	}
	root := t.TempDir()
	l := NewLoader()
	l.userConfigDir = func() (string, error) { return root, nil }
	e, err := l.Edit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tlscheck", "config.json")
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("編輯預覽建立檔案")
	}
	if err := e.Save(context.Background(), Config{Language: "zh-TW", Theme: "dark"}); err != nil {
		t.Fatal(err)
	}
	r := l.Load(context.Background())
	if r.Config.Language != "zh-TW" || r.Config.Theme != "dark" {
		t.Fatal(r)
	}
	e, err = l.Edit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"language":"en"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if e.Save(context.Background(), Config{Language: "zh-CN", Theme: "light"}) == nil {
		t.Fatal("覆寫並行設定")
	}
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	e, err = l.Edit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.Save(context.Background(), Config{Language: "en", Theme: "normal"}) == nil {
		t.Fatal("覆寫損壞設定")
	}
}
