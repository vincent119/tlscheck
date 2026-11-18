//go:build !windows

package filetxn

func (t *Transaction) replace(name string) error { return t.root.Rename(name, t.base) }
