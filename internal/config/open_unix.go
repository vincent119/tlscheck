//go:build unix

package config

import (
	"io/fs"
	"os"
	"syscall"
)

func openFile(path string) (fs.File, error) {
	// 避免設定路徑被替換為 FIFO 時阻塞，一般檔案不受影響。
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
