//go:build unix

package input

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openFile(path string) (fs.File, error) {
	// O_NONBLOCK 避免 stat 與 open 之間被替換成 FIFO 時卡住；一般檔案不受影響。
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func isNameTooLong(err error) bool { return errors.Is(err, syscall.ENAMETOOLONG) }
