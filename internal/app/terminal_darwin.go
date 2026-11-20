package app

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func terminalBytes(in, out *os.File) (func(context.Context, bool) (byte, error), func() error, error) {
	before, err := unix.IoctlGetTermios(int(in.Fd()), unix.TIOCGETA)
	if err != nil {
		return nil, nil, err
	}
	if _, err := unix.IoctlGetTermios(int(out.Fd()), unix.TIOCGETA); err != nil {
		return nil, nil, err
	}
	raw := *before
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Iflag &^= unix.IXON | unix.ICRNL | unix.BRKINT | unix.INPCK | unix.ISTRIP
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 1
	if err := unix.IoctlSetTermios(int(in.Fd()), unix.TIOCSETA, &raw); err != nil {
		return nil, nil, err
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		if err := unix.IoctlSetTermios(int(in.Fd()), unix.TIOCSETA, before); err != nil {
			return err
		}
		restored = true
		return nil
	}
	read := func(ctx context.Context, wait bool) (byte, error) {
		for {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
			events := []unix.PollFd{{Fd: int32(in.Fd()), Events: unix.POLLIN}}
			count, err := unix.Poll(events, 100)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return 0, err
			}
			if events[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
				return 0, io.EOF
			}
			if count == 0 {
				if !wait {
					return 0, io.EOF
				}
				continue
			}
			var b [1]byte
			n, err := unix.Read(int(in.Fd()), b[:])
			if err != nil {
				return 0, err
			}
			if n > 0 {
				return b[0], nil
			}
			return 0, io.EOF
		}
	}
	return read, restore, nil
}
