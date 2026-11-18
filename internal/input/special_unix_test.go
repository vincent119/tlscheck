//go:build unix

package input

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestRejectsFIFOWithoutOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe.pem")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	p := NewParser()
	p.open = func(string) (fs.File, error) { t.Fatal("FIFO 不應開啟"); return nil, nil }
	r := p.Parse(context.Background(), path, 0)
	requireIssue(t, r, model.NotRegularFile)
}

func TestReplacementWithFIFOIsNonblocking(t *testing.T) {
	path := writeFile(t, "file.pem", []byte("x"))
	p := NewParser()
	originalStat := p.stat
	p.stat = func(value string) (os.FileInfo, error) {
		info, err := originalStat(value)
		if err != nil {
			return nil, err
		}
		if err := os.Remove(value); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(value, 0600); err != nil {
			t.Fatal(err)
		}
		return info, nil
	}
	r := p.Parse(context.Background(), path, 0)
	requireIssue(t, r, model.NotRegularFile)
}
