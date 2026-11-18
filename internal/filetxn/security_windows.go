package filetxn

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const securityInformation = windows.OWNER_SECURITY_INFORMATION | windows.GROUP_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION

func readSecurity(file *os.File) (securityState, error) {
	descriptor, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, securityInformation)
	if err != nil {
		return securityState{}, err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return securityState{}, err
	}
	if dacl != nil {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return securityState{}, err
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE {
				return securityState{}, errors.New("不支援安全保存此 DACL 類型")
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && ace.Mask&(windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_ALL|windows.GENERIC_WRITE) != 0 {
				return securityState{}, errors.New("此 DACL 無法保證安全提交與清理")
			}
		}
	}
	sddl := descriptor.String()
	if sddl == "" {
		return securityState{}, errors.New("無法可靠讀取安全描述")
	}
	return securityState{Data: []byte(sddl)}, nil
}
func applySecurity(file temporaryFile, state *securityState) error {
	var descriptor *windows.SECURITY_DESCRIPTOR
	var err error
	if state == nil {
		user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
		if userErr != nil {
			return userErr
		}
		descriptor, err = windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	} else {
		descriptor, err = windows.SecurityDescriptorFromString(string(state.Data))
	}
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if state != nil {
		current, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, securityInformation)
		if err != nil {
			return err
		}
		owner, _, err := descriptor.Owner()
		if err != nil {
			return err
		}
		currentOwner, _, err := current.Owner()
		if err != nil {
			return err
		}
		group, _, err := descriptor.Group()
		if err != nil {
			return err
		}
		currentGroup, _, err := current.Group()
		if err != nil {
			return err
		}
		// 無法在目前權限下保持擁有者／群組時直接失敗，不默默改變檔案歸屬。
		if owner == nil || currentOwner == nil || group == nil || currentGroup == nil || !windows.EqualSid(owner, currentOwner) || !windows.EqualSid(group, currentGroup) {
			return errors.New("無法保留檔案擁有者或群組")
		}
	}
	// os.File 的一般寫入 handle 未必具 WRITE_DAC；以原 handle 重開，避免跟隨路徑別名。
	reopen := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")
	if err := reopen.Find(); err != nil {
		return err
	}
	handle, _, callErr := reopen.Call(file.Fd(), uintptr(windows.READ_CONTROL|windows.WRITE_DAC), uintptr(windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE), 0)
	if windows.Handle(handle) == windows.InvalidHandle {
		return callErr
	}
	defer windows.CloseHandle(windows.Handle(handle))
	return windows.SetSecurityInfo(windows.Handle(handle), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
