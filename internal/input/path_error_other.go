//go:build !windows

package input

import (
	"errors"
	"io/fs"
)

func isInvalidName(err error) bool { return errors.Is(err, fs.ErrInvalid) }
