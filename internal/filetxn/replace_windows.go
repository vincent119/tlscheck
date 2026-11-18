package filetxn

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type renameInformation struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

func (t *Transaction) replace(name string) error {
	err := t.replaceWindows(name)
	if err != nil {
		return &os.LinkError{Op: "renameat", Old: name, New: t.base, Err: err}
	}
	return nil
}

func (t *Transaction) replaceWindows(name string) error {
	// 來源與目的地都相對於既有 Root，不能退回絕對路徑而重新跟隨父目錄。
	directory, err := t.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	root := windows.Handle(directory.Fd())
	source, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root,
		ObjectName:    source,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.DELETE|windows.SYNCHRONIZE|windows.FILE_READ_ATTRIBUTES,
		&attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return errChanged
	}
	target, err := windows.UTF16FromString(t.base)
	if err != nil {
		return err
	}
	target = target[:len(target)-1]
	var header renameInformation
	buffer := make([]byte, max(int(unsafe.Sizeof(header)), int(unsafe.Offsetof(header.FileName))+len(target)*2))
	request := (*renameInformation)(unsafe.Pointer(&buffer[0]))
	request.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS | windows.FILE_RENAME_IGNORE_READONLY_ATTRIBUTE
	request.RootDirectory = root
	request.FileNameLength = uint32(len(target) * 2)
	copy(unsafe.Slice(&request.FileName[0], len(target)), target)
	// 不清除原檔唯讀屬性，也不先刪除目的地；不支援此原子操作時安全失敗。
	const fileRenameInformationEx = 65
	return windows.NtSetInformationFile(handle, &status, &buffer[0], uint32(len(buffer)), fileRenameInformationEx)
}
