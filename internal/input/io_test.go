package input

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/vincent119/tlscheck/internal/model"
)

type faultFile struct {
	info     fs.FileInfo
	reader   io.Reader
	statErr  error
	closeErr error
	closed   bool
}

func (f *faultFile) Stat() (fs.FileInfo, error) { return f.info, f.statErr }
func (f *faultFile) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *faultFile) Close() error               { f.closed = true; return f.closeErr }

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("合成讀取錯誤") }

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read(p []byte) (int, error) { r.cancel(); p[0] = ' '; return 1, nil }

func TestFileFailuresAndStaleMetadata(t *testing.T) {
	regular, err := (fstest.MapFS{"file": &fstest.MapFile{Data: []byte("x"), Mode: 0600}}).Stat("file")
	if err != nil {
		t.Fatal(err)
	}
	directory, err := (fstest.MapFS{}).Stat(".")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name               string
		initial            fs.FileInfo
		statErr, errorOpen error
		file               *faultFile
		code               model.IssueCode
	}{
		{"無讀取權限", regular, nil, fs.ErrPermission, nil, model.FileUnreadable},
		{"stat 無權限", nil, fs.ErrPermission, nil, nil, model.FileUnreadable},
		{"開啟後 stat 失敗", regular, nil, nil, &faultFile{statErr: fs.ErrPermission}, model.FileUnreadable},
		{"開啟後變為目錄", regular, nil, nil, &faultFile{info: directory}, model.NotRegularFile},
		{"實際讀取失敗", regular, nil, nil, &faultFile{info: regular, reader: errorReader{}}, model.FileUnreadable},
		{"大小資訊過時", regular, nil, nil, &faultFile{info: regular, reader: bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxFileSize+2))}, model.FileTooLarge},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			p.stat = func(string) (fs.FileInfo, error) { return tt.initial, tt.statErr }
			p.open = func(string) (fs.File, error) { return tt.file, tt.errorOpen }
			r := p.Parse(context.Background(), "file", 0)
			requireIssue(t, r, tt.code)
			if tt.file != nil && !tt.file.closed {
				t.Fatal("檔案資源未關閉")
			}
		})
	}
}

func TestCancellationDuringRead(t *testing.T) {
	info, err := (fstest.MapFS{"file": &fstest.MapFile{Data: []byte("x"), Mode: 0600}}).Stat("file")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	file := &faultFile{info: info, reader: cancelReader{cancel: cancel}}
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) { return info, nil }
	p.open = func(string) (fs.File, error) { return file, nil }
	r := p.Parse(ctx, "file", 0)
	requireIssue(t, r, model.Canceled)
	if !file.closed {
		t.Fatal("取消後檔案未關閉")
	}
}

func TestRejectsEmptyAndUnrecognizedFiles(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("未知內容"), {0x30, 0x82, 0xff}} {
		r := NewParser().Parse(context.Background(), writeFile(t, "unknown", data), 0)
		requireIssue(t, r, model.InvalidData)
		if len(r.Certificates) != 0 || len(r.Keys) != 0 {
			t.Fatal("未知內容被當成有效物件")
		}
	}
}

func TestLongIDNIsNotLimitedByFileNameLength(t *testing.T) {
	value := strings.Repeat("例", 30) + "." + strings.Repeat("測", 30) + "." + strings.Repeat("試", 30)
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) {
		return nil, &fs.PathError{Op: "stat", Path: value, Err: syscall.ENAMETOOLONG}
	}
	r := p.Parse(context.Background(), value, 0)
	if r.Target == nil || len(r.Issues) != 0 {
		t.Fatalf("檔案系統名稱上限不應限制合法 IDN：%v", r.Issues)
	}
}

func TestCloseFailurePreservesParsedObjects(t *testing.T) {
	data := pemData("CERTIFICATE", certDER(t))
	info, err := (fstest.MapFS{"file": &fstest.MapFile{Data: data, Mode: 0600}}).Stat("file")
	if err != nil {
		t.Fatal(err)
	}
	file := &faultFile{info: info, reader: bytes.NewReader(data), closeErr: errors.New("合成關閉錯誤")}
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) { return info, nil }
	p.open = func(string) (fs.File, error) { return file, nil }
	r := p.Parse(context.Background(), "file", 0)
	requireIssue(t, r, model.FileUnreadable)
	if len(r.Certificates) != 1 || !file.closed {
		t.Fatal("關閉失敗不應丟棄已取得物件")
	}
}
