package filetxn

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsReadonlyOverwritePreservesSecurity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "唯讀報告.txt")
	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(D;;0x2;;;WD)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// 成功案例必須分享刪除權限，否則保留的舊 handle 會自行阻擋替換。
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := os.NewFile(uintptr(handle), path)
	if old == nil {
		windows.CloseHandle(handle)
		t.Fatal("無法接管舊檔案 handle")
	}
	defer old.Close()
	before, err := readSecurity(old)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(t.Context(), []byte("replacement")); err != nil {
		t.Fatalf("唯讀目的檔原子替換失敗：%v", err)
	}
	current, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	after, err := readSecurity(current)
	if err != nil || !sameSecurity(before, after) {
		t.Fatalf("替換未保留安全屬性：%v", err)
	}
	info, err := current.Stat()
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatalf("替換未保留唯讀屬性：%v，%v", info, err)
	}
	data, err := io.ReadAll(current)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("新 handle 未取得完整新內容：%q，%v", data, err)
	}
	data, err = io.ReadAll(old)
	if err != nil || string(data) != "original" {
		t.Fatalf("舊 handle 內容被原地修改：%q，%v", data, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("提交留下暫存檔：%v，%v", entries, err)
	}
}

func TestWindowsFailedReadonlyOverwritePreservesOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
	if err := os.WriteFile(path, []byte("original"), 0400); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	// 不分享刪除權限，以真實檔案鎖驗證提交失敗時沒有先移除目的地。
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	before, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInformation)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(t.Context(), []byte("replacement")); err == nil {
		t.Fatal("忽略禁止刪除分享的目的檔鎖")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("失敗破壞原內容：%q，%v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0444 {
		t.Fatalf("失敗破壞原唯讀屬性：%v，%v", info, err)
	}
	after, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, securityInformation)
	if err != nil || before.String() != after.String() {
		t.Fatalf("失敗改變原安全屬性：%v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("失敗留下暫存檔：%v，%v", entries, err)
	}
}
