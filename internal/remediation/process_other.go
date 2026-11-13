//go:build !linux && !darwin

package remediation

import (
	"errors"
	"os/exec"
)

func superviseProcess(_ *exec.Cmd) error {
	return errors.New("supervised package-manager execution is not supported on this operating system")
}

func sandboxCredential(_ *exec.Cmd, uid, _ uint32) error {
	if uid == 0 {
		return nil
	}
	return errors.New("sandbox credential separation is unsupported on this operating system")
}
