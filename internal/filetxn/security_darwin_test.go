package filetxn

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOverwritePreservesNativeACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone deny write", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	writable := func() bool {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false
		}
		f.Close()
		return true
	}
	if writable() {
		t.Fatal("未建立 ACL 限制")
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err == nil {
		defer tx.Close()
		err = tx.Commit(t.Context(), []byte("replacement"))
	}
	if err != nil {
		t.Fatal("原生ACL保存失敗", err)
	}
	if writable() {
		t.Fatal("覆寫移除了原生 ACL")
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "replacement" {
		t.Fatal("ACL保存成功但報告內容未更新")
	}
}

func TestConcurrentACLChangeIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone deny write", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	if tx.Commit(t.Context(), []byte("replacement")) == nil {
		t.Fatal("未拒絕ACL快照變更")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatal(err)
	}
}

func TestRestrictiveACLCannotLeaveTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	t.Cleanup(func() {
		entries, _ := os.ReadDir(dir)
		for _, entry := range entries {
			_ = exec.Command("/bin/chmod", "-N", filepath.Join(dir, entry.Name())).Run()
		}
	})
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), "/bin/chmod", "+a", "everyone deny delete", path).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err == nil {
		defer tx.Close()
		err = tx.Commit(t.Context(), []byte("replacement"))
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) != 1 {
		t.Fatal("ACL導致暫存檔殘留", entries, err)
	}
	if err != nil {
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != "original" {
			t.Fatal("失敗破壞原檔")
		}
	}
}
