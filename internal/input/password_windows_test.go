package input

import (
	"github.com/vincent119/tlscheck/internal/testutil"
	"golang.org/x/sys/windows"
	"testing"
)

func TestPasswordFileRejectsBroadWindowsDACL(t *testing.T) {
	path := testutil.PasswordFile(t, []byte("synthetic"))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;GR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPasswordFile(t.Context(), path, nil); err == nil {
		t.Fatal("Everyone可讀密碼檔未拒絕")
	}
}
