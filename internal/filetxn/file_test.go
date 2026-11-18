package filetxn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCommitProtectsAliasesAndConcurrentChanges(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	output := filepath.Join(dir, "out")
	if err := os.WriteFile(input, []byte("original"), 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), input, true, []string{input}); err == nil {
		t.Fatal("允許覆寫來源")
	}
	if err := os.Link(input, output); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(context.Background(), output, true, []string{input}); err == nil {
		t.Fatal("允許 hardlink")
	}
	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input, output); err == nil {
		if _, err := Prepare(context.Background(), output, true, nil); err == nil {
			t.Fatal("允許 symlink")
		}
		if err := os.Remove(output); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := Prepare(context.Background(), output, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := os.WriteFile(output, []byte("racer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background(), []byte("report")); err == nil {
		t.Fatal("覆寫並行建立檔")
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "racer" {
		t.Fatal(string(data), err)
	}
	tx2, err := Prepare(context.Background(), output, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx2.Close()
	if err := os.WriteFile(output, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if tx2.Commit(context.Background(), []byte("report")) == nil {
		t.Fatal("覆寫並行修改檔")
	}
}
func TestCommitIsAtomicAndPreservesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	tx, err := Prepare(context.Background(), path, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background(), []byte("first")); err != nil {
		t.Fatal(err)
	}
	tx.Close()
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil || before.Mode().Perm()&0222 != 0 {
		t.Fatalf("未建立唯讀目的檔：%v，%v", before, err)
	}
	tx, err = Prepare(context.Background(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(context.Background(), []byte("next")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "next" {
		t.Fatal(string(data), err)
	}
	info, err := os.Stat(path)
	// Windows 以唯讀屬性呈現 0444；比較實際快照才能驗證各平台權限保存。
	if err != nil || info.Mode().Perm() != before.Mode().Perm() {
		t.Fatal(info, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}

func TestConcurrentNoReplaceHasExactlyOneWinner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	first, err := Prepare(context.Background(), path, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Prepare(context.Background(), path, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	results := make(chan error, 2)
	go func() { results <- first.Commit(context.Background(), []byte("one")) }()
	go func() { results <- second.Commit(context.Background(), []byte("two")) }()
	wins := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatal(wins)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}
func TestCanceledCommitPreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(context.Background(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tx.Commit(ctx, []byte("replacement")) == nil {
		t.Fatal("取消仍提交")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatal(string(data), err)
	}
}
func TestMissingProtectedFileThroughParentAliasIsRejected(t *testing.T) {
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Skip("此平台無 symlink 權限")
	}
	if _, err := Prepare(context.Background(), filepath.Join(dir, "missing.pem"), false, []string{filepath.Join(alias, "missing.pem")}); err == nil {
		t.Fatal("允許覆寫尚未建立的別名來源")
	}
}

type failingTemporaryFile struct {
	*os.File
	stage string
}

func (f failingTemporaryFile) Write(p []byte) (int, error) {
	if f.stage == "write" {
		return 0, errors.New("合成寫入失敗")
	}
	if f.stage == "short" {
		return 0, nil
	}
	return f.File.Write(p)
}
func (f failingTemporaryFile) Sync() error {
	if f.stage == "sync" {
		return errors.New("合成同步失敗")
	}
	return f.File.Sync()
}
func (f failingTemporaryFile) Close() error {
	err := f.File.Close()
	if f.stage == "close" {
		return errors.New("合成關閉失敗")
	}
	return err
}
func TestIOFailuresPreserveOriginalAndRemoveTemporaryFiles(t *testing.T) {
	for _, stage := range []string{"write", "short", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			tx, err := Prepare(t.Context(), path, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Close()
			tx.create = func(name string) (temporaryFile, error) {
				f, err := tx.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				return failingTemporaryFile{f, stage}, err
			}
			if tx.Commit(t.Context(), []byte("replacement")) == nil {
				t.Fatal("錯誤未傳遞")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "original" {
				t.Fatal(string(data), err)
			}
			entries, err := os.ReadDir(filepath.Dir(path))
			if err != nil || len(entries) != 1 {
				t.Fatal(entries, err)
			}
		})
	}
}

func TestMissingConfigurationCaseAliasIsRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Prepare(t.Context(), filepath.Join(dir, "CONFIG.JSON"), false, []string{filepath.Join(dir, "config.json")}); err == nil {
		t.Fatal("缺檔別名繞過設定保護")
	}
}

func TestSecurityFailurePreservesOriginalAndCleansTemporaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	calls := 0
	originalSecure := tx.secure
	tx.secure = func(file temporaryFile, state *securityState) error {
		calls++
		if calls == 2 {
			return errors.New("合成權限保存失敗")
		}
		return originalSecure(file, state)
	}
	if tx.Commit(t.Context(), []byte("replacement")) == nil {
		t.Fatal("忽略權限保存失敗")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
}
