//go:build unix

package filetxn

import "golang.org/x/sys/unix"

const openReadFlags = unix.O_NONBLOCK | unix.O_NOFOLLOW
