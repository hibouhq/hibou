package license

import (
	"reflect"
	"testing"
)

func TestAlternatives(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  [][]string
	}{
		{"MIT", [][]string{{"MIT"}}},
		{"MIT OR Apache-2.0", [][]string{{"MIT"}, {"Apache-2.0"}}},
		{"(MIT OR Apache-2.0) AND BSD-3-Clause", [][]string{{"MIT", "BSD-3-Clause"}, {"Apache-2.0", "BSD-3-Clause"}}},
		{"GPL-2.0-only WITH Classpath-exception-2.0", [][]string{{"GPL-2.0-only WITH Classpath-exception-2.0"}}},
	} {
		got, err := Alternatives(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Alternatives(%q)=%v err=%v want %v", tc.input, got, err, tc.want)
		}
	}
	for _, invalid := range []string{"", "MIT AND", "OR MIT", "(MIT", "MIT OR )", "MIT License AND GPL-2.0-only", "MIT WITH"} {
		if _, err := Alternatives(invalid); err == nil {
			t.Errorf("accepted malformed licence expression %q", invalid)
		}
	}
}
