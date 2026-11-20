package input

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/vincent119/tlscheck/internal/containers"
)

var errPassword = errors.New("無法安全取得密碼")

// ReadPasswordFile 只讀受保護regular file，錯誤不含路徑或內容。
func ReadPasswordFile(ctx context.Context, path string, protected []string) (password []byte, err error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() {
		return nil, errPassword
	}
	f, e := openPasswordFile(path)
	if e != nil {
		return nil, errPassword
	}
	defer func() {
		if e := f.Close(); e != nil {
			clear(password)
			password = nil
			err = errPassword
		}
	}()
	current, e := f.Stat()
	if e != nil || !current.Mode().IsRegular() || !os.SameFile(before, current) || passwordPermissions(f, current) != nil {
		return nil, errPassword
	}
	for _, p := range protected {
		if other, e := os.Stat(p); e == nil && os.SameFile(current, other) {
			return nil, errPassword
		}
	}
	data, e := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: f}, containers.MaxPasswordSize+1))
	if e != nil || len(data) > containers.MaxPasswordSize {
		clear(data)
		return nil, errPassword
	}
	// 讀取後再確認權限，不能以最初的mode或ACL快照當成永久保證。
	after, e := f.Stat()
	if e != nil || passwordPermissions(f, after) != nil {
		clear(data)
		return nil, errPassword
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
		if len(data) > 0 && data[len(data)-1] == '\r' {
			data = data[:len(data)-1]
		}
	}
	if !utf8.Valid(data) || bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) || bytes.ContainsAny(data, "\x00\r\n") {
		clear(data)
		return nil, errPassword
	}
	return data, nil
}
