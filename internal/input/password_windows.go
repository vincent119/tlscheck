package input

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openPasswordFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errPassword
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errPassword
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errPassword
	}
	return os.NewFile(uintptr(h), path), nil
}
func passwordPermissions(f *os.File, info os.FileInfo) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return errPassword
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return errPassword
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return errPassword
	}
	allowed := func(sid *windows.SID) bool {
		return sid != nil && (windows.EqualSid(sid, user.User.Sid) || windows.EqualSid(sid, system) || windows.EqualSid(sid, admins))
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errPassword
	}
	owner, _, err := sd.Owner()
	if err != nil || !allowed(owner) {
		return errPassword
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errPassword
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil {
			return errPassword
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !allowed((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
				return errPassword
			}
		case windows.ACCESS_DENIED_ACE_TYPE:
		default:
			return errPassword
		}
	}
	return nil
}
