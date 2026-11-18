package filetxn

import (
	"encoding/binary"
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func readSecurity(file *os.File) (securityState, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return securityState{}, err
	}
	attributes := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buffer := make([]byte, 4096)
	// x/sys 未匯出 fgetattrlist；以固定大小 native attrlist 呼叫，只解析有界的 ACL 記錄。
	_, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, file.Fd(), uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
	if errno != 0 {
		return securityState{}, errno
	}
	length := int(binary.LittleEndian.Uint32(buffer[:4]))
	offset := 4 + int(int32(binary.LittleEndian.Uint32(buffer[4:8])))
	size := int(binary.LittleEndian.Uint32(buffer[8:12]))
	if length == 12 && size == 0 && offset == 12 {
		return securityState{Data: noACL(), UID: stat.Uid, GID: stat.Gid}, nil
	}
	if length < 12 || length > len(buffer) || offset < 12 || size < 44 || offset+size > length {
		return securityState{}, errors.New("無法可靠讀取原生 ACL")
	}
	acl := append([]byte{}, buffer[offset:offset+size]...)
	count := binary.LittleEndian.Uint32(acl[36:40])
	if binary.LittleEndian.Uint32(acl[:4]) != 0x012cc16d || count != 0xffffffff && (count > 128 || 44+int(count)*24 != len(acl)) {
		return securityState{}, errors.New("未知原生 ACL 結構")
	}
	if count != 0xffffffff {
		for i := 0; i < int(count); i++ {
			entry := acl[44+i*24 : 44+(i+1)*24]
			flags := binary.LittleEndian.Uint32(entry[16:20])
			rights := binary.LittleEndian.Uint32(entry[20:24])
			// 這些 deny 規則可能連失敗清理都禁止；在建立暫存檔前保守拒絕。
			if flags&0xf == 2 && rights&((1<<4)|(1<<12)|(1<<21)|(1<<23)) != 0 {
				return securityState{}, errors.New("此 ACL 無法保證安全提交與清理")
			}
		}
	}
	return securityState{Data: acl, UID: stat.Uid, GID: stat.Gid}, nil
}
func applySecurity(file temporaryFile, state *securityState) error {
	fd := file.Fd()
	if state == nil {
		// 新檔不得藉父目錄繼承的 ACL 放寬 0600；清除 ACL 後再寫入內容。
		return setACL(fd, noACL())
	}
	if err := unix.Fchown(int(fd), int(state.UID), int(state.GID)); err != nil {
		return err
	}
	return setACL(fd, state.Data)
}
func setACL(fd uintptr, acl []byte) error {
	attributes := unix.Attrlist{Bitmapcount: 5, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	buffer := make([]byte, 8+len(acl))
	binary.LittleEndian.PutUint32(buffer, 8)
	binary.LittleEndian.PutUint32(buffer[4:], uint32(len(acl)))
	copy(buffer[8:], acl)
	_, _, errno := unix.Syscall6(unix.SYS_FSETATTRLIST, fd, uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func noACL() []byte {
	empty := make([]byte, 44)
	binary.LittleEndian.PutUint32(empty, 0x012cc16d)
	binary.LittleEndian.PutUint32(empty[36:], 0xffffffff)
	return empty
}
