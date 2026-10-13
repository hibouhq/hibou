package planpath

import (
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	for path, want := range map[string]bool{
		".":              true,
		"java":           true,
		"web/app":        true,
		"src/-literal":   true,
		"a..b/c":         true,
		"":               false,
		"-x":             false,
		"--exclude=*":    false,
		"/etc":           false,
		`\etc`:           false,
		`\\server\share`: false,
		"C:":             false,
		"c:/windows":     false,
		`a\..\b`:         false,
		`a\b`:            false,
		"..":             false,
		"../etc":         false,
		"a/../b":         false,
		"a/..":           false,
		"a\x00b":         false,
	} {
		err := Validate(path)
		if (err == nil) != want {
			t.Errorf("Validate(%q) = %v, want valid=%v", path, err, want)
		}
		if err != nil && !errors.Is(err, ErrUnsafe) {
			t.Errorf("Validate(%q) error %v does not wrap ErrUnsafe", path, err)
		}
		if Valid(path) != want {
			t.Errorf("Valid(%q) != %v", path, want)
		}
	}
}
