//go:build unix

package input

import (
	"github.com/vincent119/tlscheck/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

func TestPasswordFileRejectsPublicModeAndSymlink(t *testing.T) {
	path := testutil.PasswordFile(t, []byte("secret"))
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPasswordFile(t.Context(), path, nil); err == nil {
		t.Fatal("公開可讀密碼檔未拒絕")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPasswordFile(t.Context(), link, nil); err == nil {
		t.Fatal("密碼symlink未拒絕")
	}
}
