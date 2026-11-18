package input

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestExplicitModesDoNotCrossBoundaries(t *testing.T) {
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) { t.Fatal("遠端不得 stat"); return nil, os.ErrNotExist }
	r := p.ParseSpec(context.Background(), model.InputSpec{Kind: model.RemoteInput, Value: "example.com", Index: 3})
	if r.Target == nil || r.InputIndex != 3 {
		t.Fatal(r)
	}
	p = NewParser()
	missing := filepath.Join(t.TempDir(), "example.com")
	r = p.ParseSpec(context.Background(), model.InputSpec{Kind: model.LocalInput, Value: missing, Index: 4})
	if r.Target != nil || len(r.Issues) != 1 || r.Issues[0].Code != model.FileNotFound {
		t.Fatal(r)
	}
}

func TestOutputProtectionDoesNotTreatURLAsWindowsFilename(t *testing.T) {
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) { return nil, os.ErrInvalid }
	paths := p.LocalPaths(t.Context(), []model.InputSpec{{Kind: model.AutoInput, Value: "https://example.com/path?secret=hidden"}})
	if len(paths) != 0 {
		t.Fatal(paths)
	}
	p.stat = func(string) (fs.FileInfo, error) { t.Fatal("強制遠端不可 stat"); return nil, nil }
	if paths := p.LocalPaths(t.Context(), []model.InputSpec{{Kind: model.RemoteInput, Value: "example.com"}}); len(paths) != 0 {
		t.Fatal(paths)
	}
}
