package testutil

import (
	"embed"
	"os"
	"path/filepath"
	"testing"
)

// 本組fixture只含合成公開憑證及加密PFX，不嵌入明文私鑰。
//
//go:embed testdata/containers/*
var containerFixtures embed.FS

// ContainerFixture 回傳可修改副本，避免測試共用同一個底層buffer。
func ContainerFixture(t testing.TB, name string) []byte {
	t.Helper()
	data, err := containerFixtures.ReadFile("testdata/containers/" + name)
	if err != nil {
		t.Fatal("讀取合成容器fixture失敗", err)
	}
	return data
}

// PasswordFile 只在測試隔離目錄建立私有權限密碼檔。
func PasswordFile(t testing.TB, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "密碼 file.txt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("建立合成密碼檔失敗", err)
	}
	securePasswordFixture(t, path)
	return path
}
