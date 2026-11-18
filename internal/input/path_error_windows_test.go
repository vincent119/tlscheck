package input

import (
	"io/fs"
	"syscall"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestWindowsInvalidFilenameDoesNotRejectIPv6(t *testing.T) {
	value := "2001:db8::443"
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: value, Err: syscall.Errno(123)}
	}
	r := p.Parse(t.Context(), value, 0)
	if r.Target == nil || r.Target.String() != "[2001:db8::443]:443" || len(r.Issues) != 0 {
		t.Fatalf("Windows 無效檔名錯誤阻擋 IPv6：%v", r)
	}
	if paths := p.LocalPaths(t.Context(), []model.InputSpec{{Value: value}}); len(paths) != 0 {
		t.Fatalf("IPv6 誤列為保護路徑：%v", paths)
	}
}
