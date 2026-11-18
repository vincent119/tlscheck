// Package filetxn 提供同目錄暫存與不覆寫提交，所有錯誤由呼叫者轉成安全訊息。
package filetxn

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/text/unicode/norm"
)

var errChanged = errors.New("目的地身分或內容已變更")

type temporaryFile interface {
	io.Writer
	Sync() error
	Close() error
	Chmod(fs.FileMode) error
	Fd() uintptr
}

// Transaction 保留目錄 handle，避免提交時重新跟隨父目錄路徑。
type Transaction struct {
	create          func(string) (temporaryFile, error)
	secure          func(temporaryFile, *securityState) error
	root            *os.Root
	directory, base string
	parent          fs.FileInfo
	original        fs.FileInfo
	digest          [32]byte
	security        *securityState
	overwrite       bool
	protected       []string
}

// Prepare 不建立目的地，也不建立父目錄。
func Prepare(ctx context.Context, path string, overwrite bool, protected []string) (*Transaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, base := filepath.Dir(absolute), filepath.Base(absolute)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	t := &Transaction{root: root, directory: dir, base: base, overwrite: overwrite, protected: append([]string{}, protected...)}
	success := false
	defer func() {
		if !success {
			root.Close()
		}
	}()
	t.parent, err = os.Stat(dir)
	if err != nil {
		return nil, err
	}
	t.original, err = root.Lstat(base)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err = t.checkProtected(); err != nil {
		return nil, err
	}
	if t.original != nil {
		if !t.original.Mode().IsRegular() || !overwrite {
			return nil, errChanged
		}
		t.digest, err = t.hash(ctx)
		if err == nil {
			var state securityState
			state, err = t.securitySnapshot()
			if err == nil {
				t.security = &state
			}
		}
		if err != nil {
			return nil, err
		}
	}
	t.secure = applySecurity
	t.create = func(name string) (temporaryFile, error) {
		return root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	}
	success = true
	return t, nil
}
func (t *Transaction) hash(ctx context.Context) ([32]byte, error) {
	var sum [32]byte
	file, err := t.root.OpenFile(t.base, os.O_RDONLY|openReadFlags, 0)
	if err != nil {
		return sum, err
	}
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, t.original) {
		file.Close()
		return sum, errChanged
	}
	h := sha256.New()
	buffer := make([]byte, 32*1024)
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		var n int
		n, err = file.Read(buffer)
		if n > 0 {
			h.Write(buffer[:n])
		}
		if err == io.EOF {
			err = nil
			break
		}
		if err != nil {
			break
		}
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	copy(sum[:], h.Sum(nil))
	return sum, err
}
func (t *Transaction) checkProtected() error {
	candidate := filepath.Join(t.directory, t.base)
	current, err := t.root.Lstat(t.base)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if current != nil && !current.Mode().IsRegular() {
		return errChanged
	}
	for _, path := range t.protected {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		// 缺檔時沒有 inode 可比較；對大小寫與 Unicode 正規化語意不明的別名採保守拒絕。
		if absolute == candidate || strings.EqualFold(norm.NFC.String(canonical(absolute, 0)), norm.NFC.String(canonical(candidate, 0))) {
			return errChanged
		}
		info, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if current != nil && os.SameFile(info, current) {
			return errChanged
		}
	}
	return nil
}
func (t *Transaction) unchanged(ctx context.Context) error {
	parent, err := os.Stat(t.directory)
	if err != nil || !os.SameFile(parent, t.parent) {
		return errChanged
	}
	current, err := t.root.Lstat(t.base)
	if t.original == nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return errChanged
		}
		return t.checkProtected()
	}
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(current, t.original) || current.Mode() != t.original.Mode() || current.Size() != t.original.Size() || !current.ModTime().Equal(t.original.ModTime()) {
		return errChanged
	}
	digest, err := t.hash(ctx)
	if err != nil || digest != t.digest {
		return errChanged
	}
	state, err := t.securitySnapshot()
	if err != nil || t.security == nil || !sameSecurity(state, *t.security) {
		return errChanged
	}
	return t.checkProtected()
}

// Commit 在完整寫入、同步及關閉後提交；不存在保護使用原子 Link。
func (t *Transaction) Commit(ctx context.Context, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.unchanged(ctx); err != nil {
		return err
	}
	name := ".tlscheck-" + rand.Text() + ".tmp"
	f, err := t.create(name)
	if err != nil {
		return err
	}
	defer t.root.Remove(name)
	if err := t.secure(f, nil); err != nil {
		f.Close()
		return err
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil && t.original != nil {
		writeErr = f.Chmod(t.original.Mode().Perm())
	}
	if writeErr == nil && t.security != nil {
		writeErr = t.secure(f, t.security)
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.unchanged(ctx); err != nil {
		return err
	}
	if !t.overwrite || t.original == nil {
		return t.root.Link(name, t.base)
	}
	return t.replace(name)
}

// Close 釋放目錄 handle，不刪除原始目的地。
func (t *Transaction) Close() error { return t.root.Close() }

// Matches 將較早的編輯快照連接到交易快照，拒絕兩次檢查間的替換。
func (t *Transaction) Matches(info fs.FileInfo, data []byte) bool {
	if info == nil {
		return t.original == nil
	}
	return t.original != nil && os.SameFile(info, t.original) && info.Mode() == t.original.Mode() && info.Size() == t.original.Size() && info.ModTime().Equal(t.original.ModTime()) && sha256.Sum256(data) == t.digest
}

func canonical(path string, depth int) string {
	if depth > 40 {
		return path
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(path), target)
			}
			return canonical(target, depth+1)
		}
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path
	}
	return filepath.Join(canonical(parent, depth+1), filepath.Base(path))
}

func (t *Transaction) securitySnapshot() (securityState, error) {
	f, err := t.root.OpenFile(t.base, os.O_RDONLY|openReadFlags, 0)
	if err != nil {
		return securityState{}, err
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, t.original) {
		f.Close()
		return securityState{}, errChanged
	}
	state, err := readSecurity(f)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return state, err
}
func sameSecurity(a, b securityState) bool {
	return a.UID == b.UID && a.GID == b.GID && bytes.Equal(a.Data, b.Data)
}
