//go:build !darwin && !windows

package app

import (
	"context"
	"errors"
	"os"
)

func terminalBytes(in, out *os.File) (func(context.Context, bool) (byte, error), func() error, error) {
	return nil, nil, errors.New("本平台未提供互動終端")
}
