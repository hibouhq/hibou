package remediation

import (
	"context"

	"github.com/hibouhq/hibou/internal/gitexec"
)

func gitOutput(ctx context.Context, root, home string, args ...string) ([]byte, error) {
	return runGit(ctx, root, home, nil, args...)
}

func runGit(ctx context.Context, root, home string, input []byte, args ...string) ([]byte, error) {
	return gitexec.Run(ctx, gitexec.Config{Dir: root, Home: home, LocalOnly: true, StdoutLimit: MaxPatchBytes + 1}, input, args...)
}
