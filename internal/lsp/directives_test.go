package lsp

import "testing"

func TestDirectiveEdits(t *testing.T) {
	t.Parallel()

	finding := func(tool, rule string) apiFinding {
		return apiFinding{ScannerName: tool, PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: rule, Type: "sast"}
	}
	cases := []struct {
		name     string
		f        apiFinding
		file     string
		line     string
		wantText string
		wantLine int
		wantChar int
	}{
		{"gosec trailing", finding("gosec", "G304"), "a.go", "\tf, _ := os.Open(p)", " // #nosec G304 -- reviewed", 0, 19},
		{"opengrep above, reason on its own line", finding("opengrep oss", "go.lang.security.audit.sqli"), "a.go", "\tdb.Query(q)", "\t// reviewed\n\t// nosemgrep: go.lang.security.audit.sqli\n", 0, 0},
		{"semgrep in python", finding("semgrep oss", "python.flask.xss"), "app.py", "    return render(x)", "    # reviewed\n    # nosemgrep: python.flask.xss\n", 0, 0},
		{"eslint", finding("eslint", "no-eval"), "a.ts", "eval(x)", "// eslint-disable-next-line no-eval -- reviewed\n", 0, 0},
		{"bandit", finding("bandit", "B602"), "a.py", "subprocess.call(x, shell=True)", " # nosec B602 # reviewed", 0, 30},
		{"gitleaks", apiFinding{ScannerName: "gitleaks", Type: "secret", PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "generic-api-key"}, "config.yaml", "key: abc", " # gitleaks:allow -- reviewed", 0, 8},
	}
	for _, tc := range cases {
		d, ok := directiveFor(tc.f, "reviewed")
		if !ok {
			t.Errorf("%s: no directive", tc.name)
			continue
		}
		edit, ok := directiveEdit(d, tc.file, []string{tc.line}, 0)
		if !ok {
			t.Errorf("%s: no edit", tc.name)
			continue
		}
		if edit.NewText != tc.wantText || edit.Range.Start.Line != tc.wantLine || edit.Range.Start.Character != tc.wantChar {
			t.Errorf("%s: edit = %q at %d:%d, want %q at %d:%d", tc.name, edit.NewText, edit.Range.Start.Line, edit.Range.Start.Character, tc.wantText, tc.wantLine, tc.wantChar)
		}
	}
}

func TestDirectiveRefusals(t *testing.T) {
	t.Parallel()

	gosec := apiFinding{ScannerName: "gosec", PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "G101"}
	if _, ok := directiveFor(gosec, "   "); ok {
		t.Error("a directive without justification must be refused")
	}
	if _, ok := directiveFor(apiFinding{ScannerName: "gosec"}, "x"); ok {
		t.Error("gosec without a rule ID would be a blanket #nosec")
	}
	if _, ok := directiveFor(apiFinding{ScannerName: "checkov", PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "CKV_AWS_1"}, "x"); ok {
		t.Error("checkov placement depends on the resource block; no quick fix")
	}
	evil := apiFinding{ScannerName: "gosec", PrimaryIdentifierKind: "rule", PrimaryIdentifierValue: "G101\n// injected"}
	if _, ok := directiveFor(evil, "x"); ok {
		t.Error("rule IDs with line breaks must be refused")
	}
	d, _ := directiveFor(gosec, "x")
	if _, ok := directiveEdit(d, "a.py", []string{"x = 1"}, 0); ok {
		t.Error("gosec directive in a Python file must be refused")
	}
	if _, ok := directiveEdit(d, "README", []string{"x"}, 0); ok {
		t.Error("unknown comment syntax must be refused")
	}
	if got := sanitizeReason("multi\nline */ reason"); got != "multi line * / reason" {
		t.Errorf("sanitizeReason = %q", got)
	}
}
