// Package initproc lets the binary act as a minimal init when it runs as PID 1.
//
// In a container the entrypoint is PID 1, and PID 1 inherits every orphaned
// process. Git orphans processes routinely — a lazy blob fetch in a partial
// clone, a background auto-maintenance — and an init that never reaps them
// accumulates zombies until the cgroup's pids limit refuses every fork(). The
// CVE feed sweep and secret-scan clones then fail with "cannot fork():
// Resource temporarily unavailable" until the pod restarts, and a backlog
// needing more forks than the limit allows never recovers at all.
//
// The fix is the one tini implements: PID 1 runs the real program as a child,
// reaps everything, forwards signals, and exits with the child's status. Doing
// it in-binary keeps the base image unchanged and covers `docker run` as well
// as Kubernetes.
package initproc

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// childEnv marks the supervised child so it does not supervise in turn.
const childEnv = "HIBOU_INIT_CHILD"

// forwarded are the signals passed through to the child. SIGCHLD drives
// reaping; SIGURG is the Go runtime's own preemption signal and must not be
// forwarded; SIGKILL and SIGSTOP cannot be caught.
var forwarded = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2,
}

// SuperviseIfPID1 supervises the program when it is PID 1 and never returns in that
// case. Anywhere else — a developer shell, a CI step, the supervised child
// itself — it returns immediately and the program runs normally. If the
// supervisor cannot start the child it also returns, so the program runs
// unsupervised rather than not at all.
func SuperviseIfPID1() {
	if os.Getpid() != 1 || os.Getenv(childEnv) != "" {
		return
	}
	code, err := supervise(os.Args, os.Environ())
	if err != nil {
		fmt.Fprintf(os.Stderr, "initproc: %v; running without a reaping init\n", err)
		return
	}
	os.Exit(code)
}

// supervise starts the program as a child, reaps every process that exits
// under this one (the child and any orphans re-parented here), forwards
// signals, and returns the child's exit code once it exits.
//
// It reaps with wait4(-1) and never through os.Process.Wait, so it must run
// in a process that starts no other children of its own — which is why
// SuperviseIfPID1 is called first thing in main.
func supervise(args, env []string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}

	sigs := make(chan os.Signal, 64)
	// Registered before the child starts: a SIGCHLD from a child that exits
	// immediately must not be missed.
	signal.Notify(sigs, append([]os.Signal{syscall.SIGCHLD}, forwarded...)...)
	defer signal.Stop(sigs)

	// #nosec G702 -- exe is this binary (os.Executable) and args are its own os.Args, re-executed verbatim.
	child, err := os.StartProcess(exe, args, &os.ProcAttr{
		Env:   append(env, childEnv+"=1"),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return 0, fmt.Errorf("start child: %w", err)
	}

	// SIGCHLD can coalesce; the ticker drains anything a coalesced signal hid.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case sig := <-sigs:
			if sig != syscall.SIGCHLD {
				_ = child.Signal(sig)
				continue
			}
		case <-ticker.C:
		}
		if code, exited := reap(child.Pid); exited {
			return code, nil
		}
	}
}

// reap collects every exited child without blocking and reports the
// supervised child's exit code once it is among them.
func reap(childPid int) (code int, childExited bool) {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return code, childExited
		}
		if pid == childPid {
			childExited = true
			code = exitCode(status)
		}
	}
}

// exitCode maps a wait status to a shell-style exit code.
func exitCode(status syscall.WaitStatus) int {
	switch {
	case status.Exited():
		return status.ExitStatus()
	case status.Signaled():
		return 128 + int(status.Signal())
	default:
		return 1
	}
}
