package config

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func loadData(t *testing.T, data string) Result {
	t.Helper()
	l := NewLoader()
	l.userConfigDir = func() (string, error) { return t.TempDir(), nil }
	l.open = func(string) (fs.File, error) { return (fstest.MapFS{"config": {Data: []byte(data)}}).Open("config") }
	return l.Load(context.Background())
}

func TestConfigFallbackMatrix(t *testing.T) {
	cases := []struct{ name, data, language, warning string }{
		{"英文", `{"language":"en"}`, "en", ""},
		{"繁體", `{"language":"zh-TW"}`, "zh-TW", ""},
		{"簡體", `{"language":"zh-CN"}`, "zh-CN", ""},
		{"缺欄位", `{}`, "en", ""}, {"空值", `{"language":""}`, "en", ""},
		{"空檔", "", "en", "config.invalid_json"}, {"空白", "  \n", "en", "config.invalid_json"},
		{"未知語系", `{"language":"private-synthetic-value"}`, "en", "config.unsupported_language"},
		{"大小寫", `{"language":"ZH-tw"}`, "en", "config.unsupported_language"},
		{"空白語系", `{"language":" en "}`, "en", "config.unsupported_language"},
		{"數字", `{"language":12}`, "en", "config.invalid_type"},
		{"布林", `{"language":true}`, "en", "config.invalid_type"},
		{"null", `{"language":null}`, "en", "config.invalid_type"},
		{"陣列欄位", `{"language":[]}`, "en", "config.invalid_type"},
		{"物件欄位", `{"language":{}}`, "en", "config.invalid_type"},
		{"根陣列", `[]`, "en", "config.invalid_json"}, {"根null", `null`, "en", "config.invalid_json"},
		{"根字串", `"zh-TW"`, "en", "config.invalid_json"},
		{"尾隨", `{} {}`, "en", "config.invalid_json"},
		{"損壞", `{"language":`, "en", "config.invalid_json"},
		{"未知欄位", `{"language":"zh-TW","secret":"private-synthetic-value"}`, "en", "config.unknown_field"},
		{"大小寫鍵", `{"Language":"zh-TW"}`, "en", "config.unknown_field"},
		{"重複鍵", `{"language":"en","language":"zh-TW"}`, "en", "config.duplicate_field"},
		{"跳脫重複鍵", `{"language":"en","\u006canguage":"zh-TW"}`, "en", "config.duplicate_field"},
		{"無效UTF8", "{\"language\":\"\xff\"}", "en", "config.invalid_json"},
		{"恰好上限", `{"language":"zh-TW"}` + strings.Repeat(" ", MaxFileSize-len(`{"language":"zh-TW"}`)), "zh-TW", ""},
		{"超限", strings.Repeat(" ", MaxFileSize+1), "en", "config.too_large"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r := loadData(t, tt.data)
			if r.Config.Language != tt.language {
				t.Fatalf("語系不符：%+v", r)
			}
			requireWarning(t, r, tt.warning)
		})
	}
}

func requireWarning(t *testing.T, r Result, code string) {
	t.Helper()
	if code == "" {
		if len(r.Warnings) != 0 {
			t.Fatalf("不應提醒：%+v", r)
		}
		return
	}
	if len(r.Warnings) != 1 || r.Warnings[0].Code != code {
		t.Fatalf("提醒不符：%+v，預期 %s", r, code)
	}
	message := r.Warnings[0].Message()
	if message == "" || strings.Contains(message, code) || strings.Contains(message, "private-synthetic-value") {
		t.Fatalf("提醒洩漏或缺少翻譯：%q", message)
	}
	if !strings.Contains(message, "English") {
		t.Fatalf("提醒必須英文說明回退：%q", message)
	}
}

func TestConfigFixedPathAndReadOnly(t *testing.T) {
	for _, name := range []string{"Library/Application Support", "AppData/Roaming"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), filepath.FromSlash(name))
			path := filepath.Join(root, "tlscheck", "config.json")
			l := NewLoader()
			l.userConfigDir = func() (string, error) { return root, nil }
			original := l.open
			l.open = func(got string) (fs.File, error) {
				if got != path {
					t.Fatalf("路徑不符：%q", got)
				}
				return original(got)
			}
			r := l.Load(context.Background())
			if r.Config.Language != "en" {
				t.Fatal(r)
			}
			requireWarning(t, r, "")
			if _, err := os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("不應建立目錄：%v", err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			data := []byte(`{"language":"zh-TW"}`)
			if err := os.WriteFile(path, data, 0400); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			r = l.Load(context.Background())
			if r.Config.Language != "zh-TW" {
				t.Fatal(r)
			}
			requireWarning(t, r, "")
			after, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, data) || before.Mode() != after.Mode() || before.ModTime() != after.ModTime() {
				t.Fatal("設定遭修改")
			}
		})
	}
}

type faultFile struct {
	reader            io.Reader
	info              fs.FileInfo
	statErr, closeErr error
	closed            bool
	count             int
}

func (f *faultFile) Read(b []byte) (int, error) { n, e := f.reader.Read(b); f.count += n; return n, e }
func (f *faultFile) Stat() (fs.FileInfo, error) { return f.info, f.statErr }
func (f *faultFile) Close() error               { f.closed = true; return f.closeErr }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private-synthetic-value") }

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read(b []byte) (int, error) { r.cancel(); b[0] = ' '; return 1, nil }

func TestConfigIOFailuresAreNonfatalWarnings(t *testing.T) {
	regular, err := (fstest.MapFS{"f": {Data: []byte("{}")}}).Stat("f")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := (fstest.MapFS{}).Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name            string
		dirErr, openErr error
		file            *faultFile
		code            string
	}{
		{name: "目錄提供失敗", dirErr: errors.New("private-synthetic-value"), code: "config.directory_unavailable"},
		{name: "開啟權限", openErr: fs.ErrPermission, code: "config.unreadable"},
		{name: "缺檔", openErr: fs.ErrNotExist},
		{name: "stat失敗", file: &faultFile{statErr: fs.ErrPermission}, code: "config.unreadable"},
		{name: "特殊檔案", file: &faultFile{info: directory}, code: "config.unreadable"},
		{name: "讀取錯誤", file: &faultFile{info: regular, reader: errorReader{}}, code: "config.unreadable"},
		{name: "關閉錯誤", file: &faultFile{info: regular, reader: strings.NewReader(`{"language":"zh-TW"}`), closeErr: fs.ErrPermission}, code: "config.unreadable"},
		{name: "大小資訊過時", file: &faultFile{info: regular, reader: strings.NewReader(strings.Repeat(" ", MaxFileSize+100))}, code: "config.too_large"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			l := NewLoader()
			l.userConfigDir = func() (string, error) { return t.TempDir(), tt.dirErr }
			l.open = func(string) (fs.File, error) { return tt.file, tt.openErr }
			r := l.Load(context.Background())
			if r.Config.Language != "en" {
				t.Fatal(r)
			}
			requireWarning(t, r, tt.code)
			if tt.file != nil && (!tt.file.closed || tt.file.count > MaxFileSize+1) {
				t.Fatal("資源未關閉或讀取超限")
			}
		})
	}
	l := NewLoader()
	l.userConfigDir = func() (string, error) { return "", nil }
	requireWarning(t, l.Load(context.Background()), "config.directory_unavailable")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	requireWarning(t, NewLoader().Load(ctx), "config.canceled")
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	file := &faultFile{info: regular, reader: cancelReader{cancel}}
	l = NewLoader()
	l.userConfigDir = func() (string, error) { return t.TempDir(), nil }
	l.open = func(string) (fs.File, error) { return file, nil }
	requireWarning(t, l.Load(ctx), "config.canceled")
	if !file.closed {
		t.Fatal("取消未關閉")
	}
}

func TestConfigIgnoresLanguageOverridesAndWorkingDirectory(t *testing.T) {
	for _, key := range []string{"LANG", "LANGUAGE", "LC_ALL", "TLSCHECK_LANGUAGE", "VIPER_LANGUAGE"} {
		t.Setenv(key, "zh-CN")
	}
	before := append([]string(nil), os.Args...)
	t.Cleanup(func() { os.Args = before })
	os.Args = []string{"tlscheck", "--language", "zh-CN", "--config", "other.json"}
	if r := loadData(t, `{"language":"zh-TW"}`); r.Config.Language != "zh-TW" {
		t.Fatal(r)
	}
	if r := loadData(t, `{}`); r.Config.Language != "en" {
		t.Fatal(r)
	}
	root := t.TempDir()
	t.Chdir(root)
	if err := os.WriteFile("config.json", []byte(`{"language":"zh-CN"}`), 0600); err != nil {
		t.Fatal(err)
	}
	l := NewLoader()
	l.userConfigDir = func() (string, error) { return filepath.Join(root, "absent"), nil }
	r := l.Load(context.Background())
	if r.Config.Language != "en" {
		t.Fatal(r)
	}
	requireWarning(t, r, "")
}

func TestConfigUsesNativeUserConfigDirectory(t *testing.T) {
	directory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	loader := NewLoader()
	called := false
	loader.open = func(path string) (fs.File, error) {
		called = true
		if path != filepath.Join(directory, "tlscheck", "config.json") {
			t.Fatalf("原生路徑錯誤：%q", path)
		}
		return nil, fs.ErrNotExist
	}
	r := loader.Load(context.Background())
	if !called || r.Config.Language != "en" {
		t.Fatal(r)
	}
	requireWarning(t, r, "")
}

func TestConfigLoaderInstancesDoNotShareState(t *testing.T) {
	for _, language := range []string{"zh-TW", "zh-CN", "en"} {
		t.Run(language, func(t *testing.T) {
			t.Parallel()
			for range 5 {
				if got := loadData(t, `{"language":"`+language+`"}`).Config.Language; got != language {
					t.Fatalf("獨立實例互相污染：%s", got)
				}
			}
		})
	}
}
