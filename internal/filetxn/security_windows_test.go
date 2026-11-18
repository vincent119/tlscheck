package filetxn

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDACLIsPreservedAcrossOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report")
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
	writable := func() bool {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false
		}
		f.Close()
		return true
	}
	if writable() {
		t.Fatal("未建立DACL限制")
	}
	tx, err := Prepare(t.Context(), path, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Commit(t.Context(), []byte("replacement")); err != nil {
		t.Fatal(err)
	}
	if writable() {
		t.Fatal("覆寫遺失DACL")
	}
}
