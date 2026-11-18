package app

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func terminal(in, out *os.File) (func(context.Context) (string, error), func() error, error) {
	ih, oh := windows.Handle(in.Fd()), windows.Handle(out.Fd())
	var im, om uint32
	if err := windows.GetConsoleMode(ih, &im); err != nil {
		return nil, nil, err
	}
	if err := windows.GetConsoleMode(oh, &om); err != nil {
		return nil, nil, err
	}
	raw := im &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	raw |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(ih, raw); err != nil {
		return nil, nil, err
	}
	if err := windows.SetConsoleMode(oh, om|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		windows.SetConsoleMode(ih, im)
		return nil, nil, err
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		e := windows.SetConsoleMode(ih, im)
		e2 := windows.SetConsoleMode(oh, om)
		if e != nil {
			return e
		}
		if e2 != nil {
			return e2
		}
		restored = true
		return nil
	}
	read := func(ctx context.Context, wait bool) (byte, error) {
		for {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			event, err := windows.WaitForSingleObject(ih, 100)
			if err != nil {
				return 0, err
			}
			if event == uint32(windows.WAIT_TIMEOUT) {
				if !wait {
					return 0, io.EOF
				}
				continue
			}
			var b [1]byte
			n, err := in.Read(b[:])
			if err != nil {
				return 0, err
			}
			if n > 0 {
				return b[0], nil
			}
		}
	}
	return keyReader(read), restore, nil
}
