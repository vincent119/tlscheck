//go:build !darwin && !windows

package filetxn

import (
	"errors"
	"os"
)

func readSecurity(*os.File) (securityState, error) {
	return securityState{}, errors.New("此平台無法可靠保存原生 ACL")
}
func applySecurity(temporaryFile, *securityState) error {
	return errors.New("此平台無法可靠設定原生 ACL")
}
