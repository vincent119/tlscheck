package input

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/vincent119/tlscheck/internal/model"
)

func TestIPTargetsSurviveWindowsPathErrors(t *testing.T) {
	for _, value := range []string{"2001:db8::443", "::1", "[::1]:8443", "127.0.0.1:8443"} {
		t.Run(value, func(t *testing.T) {
			p := NewParser()
			p.stat = func(string) (fs.FileInfo, error) {
				return nil, &fs.PathError{Op: "stat", Path: value, Err: fs.ErrInvalid}
			}
			r := p.Parse(t.Context(), value, 0)
			if r.Target == nil || len(r.Issues) != 0 {
				t.Fatalf("合法 IP 被檔名錯誤阻擋：%v", r)
			}
			if paths := p.LocalPaths(t.Context(), []model.InputSpec{{Kind: model.AutoInput, Value: value}}); len(paths) != 0 {
				t.Fatalf("遠端 IP 被當成本機保護路徑：%v", paths)
			}
			local := p.ParseSpec(t.Context(), model.InputSpec{Kind: model.LocalInput, Value: value})
			requireIssue(t, local, model.FileUnreadable)
			if local.Target != nil {
				t.Fatal("強制本機模式轉成遠端")
			}
		})
	}
}

func TestAutoIPStillPrefersExistingFiles(t *testing.T) {
	value := "2001:db8::443"
	filesystem := fstest.MapFS{value: &fstest.MapFile{Data: []byte("invalid certificate"), Mode: 0600}}
	p := NewParser()
	p.stat = filesystem.Stat
	p.open = filesystem.Open
	r := p.Parse(t.Context(), value, 0)
	if r.Target != nil || len(r.Issues) == 0 {
		t.Fatalf("既有同名檔案未優先解析：%v", r)
	}
	paths := p.LocalPaths(t.Context(), []model.InputSpec{{Kind: model.AutoInput, Value: value}})
	if len(paths) != 1 || paths[0] != value {
		t.Fatalf("既有 IP 名稱檔案未受保護：%v", paths)
	}
}

func TestIPClassificationDoesNotHideFileErrors(t *testing.T) {
	for _, value := range []string{"2001:db8::443", "./2001:db8::443", "bad::address", "report.pem"} {
		for _, statErr := range []error{fs.ErrPermission, fs.ErrInvalid} {
			if value == "2001:db8::443" && statErr == fs.ErrInvalid {
				continue
			}
			p := NewParser()
			p.stat = func(string) (fs.FileInfo, error) { return nil, statErr }
			r := p.Parse(t.Context(), value, 0)
			requireIssue(t, r, model.FileUnreadable)
			if paths := p.LocalPaths(t.Context(), []model.InputSpec{{Kind: model.AutoInput, Value: value}}); len(paths) != 1 || paths[0] != value {
				t.Fatalf("檔案錯誤的保護路徑遺失：%v", paths)
			}
		}
	}
}
