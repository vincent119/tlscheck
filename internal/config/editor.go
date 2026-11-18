package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/vincent119/tlscheck/internal/filetxn"
)

// Editor 的快照只用於偵測選單期間的設定變動，不包含其他使用者資料。
type Editor struct {
	path     string
	original fs.FileInfo
	data     []byte
	blocked  bool
}

// Path 供報告目的地保護使用，不建立檔案或目錄。
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tlscheck", "config.json"), nil
}

// Edit 建立唯讀快照，損壞設定允許預覽但不能儲存。
func (l *Loader) Edit(ctx context.Context) (*Editor, error) {
	dir, err := l.userConfigDir()
	if err != nil || dir == "" {
		return nil, errors.New("無法取得設定目錄")
	}
	e := &Editor{path: filepath.Join(dir, "tlscheck", "config.json")}
	e.original, err = os.Lstat(e.path)
	if errors.Is(err, fs.ErrNotExist) {
		return e, nil
	}
	if err != nil {
		return nil, err
	}
	if !e.original.Mode().IsRegular() {
		e.blocked = true
		return e, nil
	}
	f, err := l.open(e.path)
	if err != nil {
		return nil, err
	}
	data, code := readConfig(ctx, f)
	if code != "" || validateJSON(data) != "" {
		e.blocked = true
		return e, nil
	}
	e.data = data
	return e, nil
}

// Save 只接受明確儲存動作，並拒絕覆寫預覽之後變動的設定。
func (e *Editor) Save(ctx context.Context, cfg Config) error {
	if e.blocked {
		return errors.New("請先修復既有設定檔")
	}
	if cfg.Language != "en" && cfg.Language != "zh-TW" && cfg.Language != "zh-CN" || cfg.Theme != "normal" && cfg.Theme != "dark" && cfg.Theme != "light" {
		return errors.New("無效設定")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	current, err := os.Lstat(e.path)
	if e.original == nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return errors.New("設定已變更")
		}
	} else {
		if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, e.original) {
			return errors.New("設定已變更")
		}
		f, err := openFile(e.path)
		if err != nil {
			return err
		}
		data, code := readConfig(ctx, f)
		if code != "" || !bytes.Equal(data, e.data) {
			return errors.New("設定已變更")
		}
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0700); err != nil {
		return err
	}
	tx, err := filetxn.Prepare(ctx, e.path, e.original != nil, nil)
	if err != nil {
		return err
	}
	defer tx.Close()
	if !tx.Matches(e.original, e.data) {
		return errors.New("設定已變更")
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return tx.Commit(ctx, data)
}

// Preview 僅從相同快照建立 typed Config，避免預覽與儲存讀取不同版本。
func (e *Editor) Preview() Config {
	cfg := Config{Language: "en", Theme: "normal"}
	if e.blocked || e.original == nil {
		return cfg
	}
	settings := viper.New()
	settings.SetConfigType("json")
	settings.SetDefault("language", "en")
	settings.SetDefault("theme", "normal")
	if settings.ReadConfig(bytes.NewReader(e.data)) != nil || settings.UnmarshalExact(&cfg) != nil {
		return Config{Language: "en", Theme: "normal"}
	}
	if cfg.Language != "en" && cfg.Language != "zh-TW" && cfg.Language != "zh-CN" {
		cfg.Language = "en"
	}
	if cfg.Theme != "normal" && cfg.Theme != "dark" && cfg.Theme != "light" {
		cfg.Theme = "normal"
	}
	return cfg
}
