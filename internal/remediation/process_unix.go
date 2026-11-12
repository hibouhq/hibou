//go:build linux || darwin

package remediation

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func superviseProcess(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 2 * time.Second
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}

		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func sandboxCredential(cmd *exec.Cmd, uid, gid uint32) error {
	if uid == 0 {
		return nil
	}
	if os.Geteuid() != 0 || gid == 0 {
		return errors.New("sandbox identity requires a privileged container supervisor and non-root tool identity")
	}
	cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}
	return nil
}
