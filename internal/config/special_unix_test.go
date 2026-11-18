//go:build unix

package config

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestConfigFIFOIsRejectedWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "tlscheck", "config.json")
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	loader := NewLoader()
	loader.userConfigDir = func() (string, error) { return root, nil }
	requireWarning(t, loader.Load(context.Background()), "config.unreadable")
}
