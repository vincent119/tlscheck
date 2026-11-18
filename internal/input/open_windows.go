package input

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openFile(path string) (fs.File, error) { return os.Open(path) }

func isInvalidName(err error) bool {
	const errorInvalidName syscall.Errno = 123
	return errors.Is(err, fs.ErrInvalid) || errors.Is(err, errorInvalidName)
}

func isNameTooLong(err error) bool {
	// Windows 的實際路徑錯誤使用 Win32 code，不能只比對 POSIX 相容碼。
	const errorFilenameExcedRange syscall.Errno = 206
	return errors.Is(err, syscall.ENAMETOOLONG) || errors.Is(err, errorFilenameExcedRange)
}
