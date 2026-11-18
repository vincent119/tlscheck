package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vincent119/tlscheck/internal/config"
	"github.com/vincent119/tlscheck/internal/i18n"
)

func runSettings(ctx context.Context, out io.Writer, cfg config.Config) int {
	file, ok := out.(*os.File)
	if !ok {
		return diagnosticError(out, i18n.New(cfg.Language), "cli.tty_required")
	}
	read, restore, err := terminal(os.Stdin, file)
	if err != nil {
		return diagnosticError(out, i18n.New(cfg.Language), "cli.tty_required")
	}
	code := 0
	defer func() { restore() }()
	editor, err := config.NewLoader().Edit(ctx)
	if err != nil {
		return diagnosticError(out, i18n.New(cfg.Language), "cli.settings_failed")
	}
	code = settingsMenu(ctx, out, editor.Preview(), read, editor.Save)
	if err := restore(); err != nil {
		return 2
	}
	return code
}

func settingsMenu(ctx context.Context, out io.Writer, cfg config.Config, read func(context.Context) (string, error), save func(context.Context, config.Config) error) int {
	if cfg.Theme == "" {
		cfg.Theme = "normal"
	}
	current, page := 0, "root"
	for {
		t := i18n.New(cfg.Language)
		options := []string{t.Text("settings.language", nil), t.Text("settings.theme", nil), t.Text("settings.save", nil), t.Text("settings.cancel", nil)}
		if page == "language" {
			options = []string{t.Text("language.name.en", nil), t.Text("language.name.zh-TW", nil), t.Text("language.name.zh-CN", nil)}
		}
		if page == "theme" {
			options = []string{t.Text("theme.normal", nil), t.Text("theme.dark", nil), t.Text("theme.light", nil)}
		}
		style := "\x1b[0m"
		if cfg.Theme == "dark" {
			style = "\x1b[97;40m"
		}
		if cfg.Theme == "light" {
			style = "\x1b[30;47m"
		}
		if _, err := fmt.Fprintf(out, "%s\x1b[2J\x1b[H%s\r\n%s: %s / %s\r\n", style, t.Text("settings.title", nil), t.Text("settings.current", nil), t.Text("language.name."+cfg.Language, nil), t.Text("theme."+cfg.Theme, nil)); err != nil {
			return 2
		}
		for i, option := range options {
			marker := "  "
			if i == current {
				marker = "> "
			}
			if _, err := fmt.Fprintf(out, "%s%s\r\n", marker, option); err != nil {
				return 2
			}
		}
		if _, err := fmt.Fprintf(out, "%s\r\n\x1b[0m", t.Text("settings.keys", nil)); err != nil {
			return 2
		}
		key, err := read(ctx)
		if errors.Is(err, context.Canceled) || key == "ctrl-c" {
			return 0
		}
		if err != nil {
			return diagnosticError(out, t, "cli.settings_failed")
		}
		switch key {
		case "up":
			current = (current + len(options) - 1) % len(options)
		case "down":
			current = (current + 1) % len(options)
		case "theme":
			page = "theme"
			current = settingIndex([]string{"normal", "dark", "light"}, cfg.Theme)
		case "escape":
			if page == "root" {
				return 0
			}
			page = "root"
			current = 0
		case "enter":
			if page == "language" {
				cfg.Language = []string{"en", "zh-TW", "zh-CN"}[current]
				page = "root"
				current = 0
				continue
			}
			if page == "theme" {
				cfg.Theme = []string{"normal", "dark", "light"}[current]
				page = "root"
				current = 0
				continue
			}
			switch current {
			case 0:
				page = "language"
				current = settingIndex([]string{"en", "zh-TW", "zh-CN"}, cfg.Language)
			case 1:
				page = "theme"
				current = settingIndex([]string{"normal", "dark", "light"}, cfg.Theme)
			case 2:
				if err := save(ctx, cfg); err != nil {
					return diagnosticError(out, t, "cli.settings_failed")
				}
				return 0
			case 3:
				return 0
			}
		}
	}
}
func keyReader(read func(context.Context, bool) (byte, error)) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		b, err := read(ctx, true)
		if err != nil {
			return "", err
		}
		switch b {
		case 3:
			return "ctrl-c", nil
		case 13, 10:
			return "enter", nil
		case 't':
			return "theme", nil
		case 27:
			next, err := read(ctx, false)
			if err != nil {
				return "escape", nil
			}
			if next != '[' && next != 'O' {
				return "escape", nil
			}
			next, err = read(ctx, false)
			if err != nil {
				return "escape", nil
			}
			if next == 'A' {
				return "up", nil
			}
			if next == 'B' {
				return "down", nil
			}
			return "", nil
		}
		return "", nil
	}
}

func settingIndex(values []string, current string) int {
	for i, value := range values {
		if value == current {
			return i
		}
	}
	return 0
}
