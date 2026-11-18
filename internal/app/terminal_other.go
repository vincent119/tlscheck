//go:build !darwin && !windows

package app

import (
	"context"
	"errors"
	"os"
)

func terminal(in, out *os.File) (func(context.Context) (string, error), func() error, error) {
	return nil, nil, errors.New("本平台未提供互動終端")
}
