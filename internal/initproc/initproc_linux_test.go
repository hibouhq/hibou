package initproc

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperEnv selects what the re-executed test binary does as the supervised
// child.
const helperEnv = "HIBOU_INITPROC_HELPER"

// TestHelperProcess is not a test: it is the body of the supervised child.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv(helperEnv) {
	case "":
		return
	case "exit3":
		os.Exit(3)
	case "orphan":
		// sh backgrounds a sleep and exits at once, so the sleep is orphaned and
		// re-parented to the nearest subreaper — the supervisor. It dies while
		// this child is still running, so only the supervisor can reap it.
		if err := exec.Command("sh", "-c", "sleep 0.2 & exit 0").Run(); err != nil {
			os.Exit(2)
		}
		time.Sleep(1 * time.Second)
		os.Exit(0)
	}
}

// asSubreaper makes this test process adopt orphans the way PID 1 does in a
// container, which is the condition supervise exists for.
func asSubreaper(t *testing.T) {
	t.Helper()
	const prSetChildSubreaper = 36
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		t.Skipf("PR_SET_CHILD_SUBREAPER unavailable: %v", errno)
	}
}

func helperArgs() []string {
	return []string{os.Args[0], "-test.run=^TestHelperProcess$"}
}

func TestSuperviseReturnsChildExitCode(t *testing.T) {
	asSubreaper(t)
	code, err := supervise(helperArgs(), append(os.Environ(), helperEnv+"=exit3"))
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Fatalf("exit code = %d, want the child's 3", code)
	}
}

func TestSuperviseReapsOrphans(t *testing.T) {
	asSubreaper(t)
	code, err := supervise(helperArgs(), append(os.Environ(), helperEnv+"=orphan"))
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if zombies := zombieChildren(t, os.Getpid()); len(zombies) > 0 {
		t.Fatalf("zombie children left unreaped: %v — orphans would accumulate until fork() fails", zombies)
	}
}

// zombieChildren lists processes in state Z whose parent is ppid.
func zombieChildren(t *testing.T, ppid int) []int {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	var zombies []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		status, err := os.ReadFile("/proc/" + entry.Name() + "/status")
		if err != nil {
			continue
		}
		var state string
		parent := -1
		for _, line := range strings.Split(string(status), "\n") {
			switch {
			case strings.HasPrefix(line, "State:"):
				state = strings.TrimSpace(strings.TrimPrefix(line, "State:"))
			case strings.HasPrefix(line, "PPid:"):
				parent, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
			}
		}
		if parent == ppid && strings.HasPrefix(state, "Z") {
			zombies = append(zombies, pid)
		}
	}
	return zombies
}
