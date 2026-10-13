// Package planpath validates the repository-relative paths a scan plan hands
// to scanners (module roots, targets, exclusions, owner scope overrides). The
// server that plans, the API that stores owner overrides and the CLI that runs
// the plan all use this one check, so a path one side accepts is never one
// the other refuses or, worse, one a scanner reads as an option or as a path
// outside the checkout (Q14).
package planpath

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsafe reports a path that could be read as an option or that points
// outside the repository.
var ErrUnsafe = errors.New("unsafe plan path")

// Validate accepts a slash-separated path below the repository root; "."
// (the repository itself) is allowed. It refuses an empty path, NUL, a
// leading '-', absolute paths (leading '/' or '\', a drive letter such as
// "C:"), any backslash (a Windows separator that would bypass the segment
// check), and ".." segments.
func Validate(p string) error {
	switch {
	case p == "":
		return fmt.Errorf("%w: empty", ErrUnsafe)
	case strings.ContainsRune(p, 0):
		return fmt.Errorf("%w: NUL byte", ErrUnsafe)
	case strings.HasPrefix(p, "-"):
		return fmt.Errorf("%w: starts with '-'", ErrUnsafe)
	case strings.HasPrefix(p, "/"), hasDriveLetter(p):
		return fmt.Errorf("%w: absolute", ErrUnsafe)
	case strings.Contains(p, `\`):
		return fmt.Errorf("%w: backslash", ErrUnsafe)
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == ".." {
			return fmt.Errorf("%w: '..' segment", ErrUnsafe)
		}
	}
	return nil
}

// Valid is Validate as a predicate.
func Valid(p string) bool { return Validate(p) == nil }

func hasDriveLetter(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0] | 0x20 // lower-case ASCII letters
	return c >= 'a' && c <= 'z'
}
