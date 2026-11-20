//go:build unix

package testutil

import (
	"os"
	"testing"
)

func securePasswordFixture(t testing.TB, path string) {
	t.Helper()
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal("設定合成密碼檔權限失敗", err)
	}
}
