package input

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincent119/tlscheck/internal/model"
)

func targetListFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "目標 清單=1.txt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func commentBytes(n int) []byte {
	data := bytes.Repeat([]byte("#\n"), n/2)
	if n%2 != 0 {
		data = append(data, '#')
	}
	return data
}
func TestTargetListReaderPreservesLinesAndRejectsAtomicFailures(t *testing.T) {
	p := NewParser()
	got := p.ReadTargetList(t.Context(), targetListFixture(t, []byte(" # note\r\n\r\nexample.invalid\r\nbad input\r\nexample.invalid\n")), MaxTargetListBytes)
	if got.Issue != "" || len(got.Entries) != 3 || got.Entries[0].Line != 3 || got.Entries[1].Line != 4 || got.Entries[2].Value != "example.invalid" {
		t.Fatal("清單順序或行號不符", got.Issue, got.Entries)
	}
	cases := map[string][]byte{"無效UTF8": append([]byte("example.invalid\n"), 255), "BOM": append([]byte{239, 187, 191}, []byte("example.invalid")...), "NUL": []byte("example.invalid\n\x00"), "超長行": append([]byte("example.invalid\n"), bytes.Repeat([]byte{'a'}, MaxTargetLineSize+1)...), "內嵌CR": []byte("example.invalid\rbad"), "孤立CR": []byte("example.invalid\r"), "單檔超限": commentBytes(MaxTargetListSize + 1)}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			result := p.ReadTargetList(t.Context(), targetListFixture(t, data), MaxTargetListBytes)
			if result.Issue == "" || len(result.Entries) != 0 {
				t.Fatal("失敗清單交付部分目標", result.Issue)
			}
		})
	}
	for _, data := range [][]byte{commentBytes(MaxTargetListSize), append([]byte{'#'}, bytes.Repeat([]byte{' '}, MaxTargetLineSize-1)...)} {
		result := p.ReadTargetList(t.Context(), targetListFixture(t, data), MaxTargetListBytes)
		if result.Issue != "" {
			t.Fatal("恰上限誤拒絕", result.Issue)
		}
	}
	limited := p.ReadTargetList(t.Context(), targetListFixture(t, []byte("example.invalid")), 2)
	if limited.Issue != BatchLimitExceeded || limited.Bytes != 3 || len(limited.Entries) != 0 {
		t.Fatal("全域預算未有界拒絕", limited)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p.open = func(string) (fs.File, error) { t.Fatal("取消後不得開檔"); return nil, errors.New("unused") }
	if got := p.ReadTargetList(ctx, "unused", MaxTargetListBytes); got.Issue != model.Canceled {
		t.Fatal("取消代碼不符")
	}
}

type closingTargetFile struct{ fs.File }

func (f closingTargetFile) Close() error { _ = f.File.Close(); return errors.New("合成關閉失敗") }
func TestTargetListCloseFailureDoesNotHideBudgetFailure(t *testing.T) {
	path := targetListFixture(t, []byte("example.invalid"))
	p := NewParser()
	p.open = func(path string) (fs.File, error) { f, err := os.Open(path); return closingTargetFile{f}, err }
	for _, remaining := range []int{MaxTargetListBytes, 0} {
		r := p.ReadTargetList(t.Context(), path, remaining)
		want := TargetListUnreadable
		if remaining == 0 {
			want = BatchLimitExceeded
		}
		if r.Issue != want || len(r.Entries) != 0 {
			t.Fatal("關閉錯誤掩蓋限制或交付部分內容", r.Issue)
		}
	}
}
func TestListEntriesCannotReadLocalFilesOrBecomeFlags(t *testing.T) {
	p := NewParser()
	p.stat = func(string) (fs.FileInfo, error) { t.Fatal("清單條目不得stat本機來源"); return nil, nil }
	p.open = func(string) (fs.File, error) { t.Fatal("清單條目不得讀本機檔"); return nil, nil }
	for _, raw := range []string{"./secret.pem", "--help", "C:\\private.key"} {
		r := p.ParseSpec(t.Context(), model.InputSpec{Kind: model.RemoteInput, Value: raw})
		if r.Target != nil || len(r.Issues) == 0 {
			t.Fatal("清單條目未強制remote", raw)
		}
	}
}
