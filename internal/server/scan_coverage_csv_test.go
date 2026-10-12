package server

import "testing"

func TestCSVSafeDefusesFormulaPrefixes(t *testing.T) {
	cases := map[string]string{
		"=HYPERLINK(\"http://x\")": "'=HYPERLINK(\"http://x\")",
		"+1":                       "'+1",
		"-2":                       "'-2",
		"@SUM(A1)":                 "'@SUM(A1)",
		"\tcmd":                    "'\tcmd",
		"\rcmd":                    "'\rcmd",
		"0123abcd":                 "0123abcd",
		"":                         "",
	}
	for in, want := range cases {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}
