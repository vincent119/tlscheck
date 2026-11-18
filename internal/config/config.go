// Package config 只讀取固定位置的語系設定，不提供覆寫或寫入介面。
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/spf13/viper"

	"github.com/vincent119/tlscheck/internal/i18n"
)

// MaxFileSize 限制實際讀取量，不信任預先取得的大小。
const MaxFileSize = 64 * 1024

// Config 的欄位只由 JSON 與預設值控制。
type Config struct {
	Language string `json:"language" mapstructure:"language"`
}

// Warning 不保存原始設定值、路徑或底層錯誤，不影響檢查結束碼。
type Warning struct{ Code string }

// Message 固定使用英文，確保錯誤語系設定仍有可理解的提醒。
func (w Warning) Message() string { return i18n.New("en").Text(w.Code, nil) }

// Result 將非致命設定提醒與檢查錯誤分開。
type Result struct {
	Config   Config
	Warnings []Warning
}

// Loader 的 I/O 邊界可注入，不保存單次載入狀態。
type Loader struct {
	userConfigDir func() (string, error)
	open          func(string) (fs.File, error)
}

// NewLoader 不建立設定目錄或設定檔。
func NewLoader() *Loader { return &Loader{userConfigDir: os.UserConfigDir, open: openFile} }

// Load 的提醒不宣告任何憑證檢查失敗。
func (l *Loader) Load(ctx context.Context) Result {
	if ctx.Err() != nil {
		return fallback("config.canceled")
	}
	directory, err := l.userConfigDir()
	if err != nil || directory == "" {
		return fallback("config.directory_unavailable")
	}
	file, err := l.open(filepath.Join(directory, "tlscheck", "config.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return fallback("")
	}
	if err != nil {
		return fallback("config.unreadable")
	}
	data, code := readConfig(ctx, file)
	if code != "" {
		return fallback(code)
	}
	if code = validateJSON(data); code != "" {
		return fallback(code)
	}
	settings := viper.New()
	settings.SetConfigType("json")
	settings.SetDefault("language", "en")
	if err := settings.ReadConfig(bytes.NewReader(data)); err != nil {
		return fallback("config.invalid_json")
	}
	var cfg Config
	if err := settings.UnmarshalExact(&cfg); err != nil {
		return fallback("config.invalid_type")
	}
	if cfg.Language == "" {
		cfg.Language = "en"
	}
	switch cfg.Language {
	case "en", "zh-TW", "zh-CN":
	default:
		return fallback("config.unsupported_language")
	}
	if ctx.Err() != nil {
		return fallback("config.canceled")
	}
	return Result{Config: cfg}
}

func fallback(code string) Result {
	r := Result{Config: Config{Language: "en"}}
	if code != "" {
		r.Warnings = []Warning{{Code: code}}
	}
	return r
}

func readConfig(ctx context.Context, file fs.File) (data []byte, code string) {
	defer func() {
		if err := file.Close(); err != nil {
			data = nil
			code = "config.unreadable"
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, "config.unreadable"
	}
	data, err = io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, MaxFileSize+1))
	if ctx.Err() != nil {
		return nil, "config.canceled"
	}
	if err != nil {
		return nil, "config.unreadable"
	}
	if len(data) > MaxFileSize {
		return nil, "config.too_large"
	}
	return data, ""
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

func validateJSON(data []byte) string {
	if !utf8.Valid(data) || !json.Valid(data) {
		return "config.invalid_json"
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return "config.invalid_json"
	}
	seen := false
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return "config.invalid_json"
		}
		if token != "language" {
			return "config.unknown_field"
		}
		if seen {
			return "config.duplicate_field"
		}
		seen = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return "config.invalid_json"
		}
		// JSON null 不得被解碼成 Go 字串的零值，掩蓋錯誤設定。
		if len(raw) == 0 || raw[0] != '"' {
			return "config.invalid_type"
		}
		var language string
		if err := json.Unmarshal(raw, &language); err != nil {
			return "config.invalid_type"
		}
	}
	if _, err := decoder.Token(); err != nil {
		return "config.invalid_json"
	}
	return ""
}
