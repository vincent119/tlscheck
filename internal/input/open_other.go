//go:build !unix && !windows

package input

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

func openFile(path string) (fs.File, error) { return os.Open(path) }

func isNameTooLong(err error) bool { return errors.Is(err, syscall.ENAMETOOLONG) }
