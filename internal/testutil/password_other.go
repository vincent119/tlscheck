//go:build !unix && !windows

package testutil

import "testing"

func securePasswordFixture(t testing.TB, path string) {
	t.Helper()
	t.Fatal("本平台無密碼檔安全測試邊界")
}
