package cmd

import (
	"context"
	"errors"
	"os/exec"
)

// execCommandOutput runs a program with its arguments, never a shell.
func execCommandOutput(dir, name string, args ...string) ([]byte, int, error) {
	// #nosec G204 -- fixed program names, arguments built by hibou.
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
		err = nil
	} else if err != nil {
		code = -1
	}
	return output, code, err
}
