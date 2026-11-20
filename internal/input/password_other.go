//go:build !unix && !windows

package input

import "os"

func openPasswordFile(string) (*os.File, error)       { return nil, errPassword }
func passwordPermissions(*os.File, os.FileInfo) error { return errPassword }
