package orgprovision

import (
	"strings"
	"testing"

	"github.com/hibouhq/hibou/internal/api"
)

func TestSlugifyAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "already valid lowercase", input: "acme", want: "acme"},
		{name: "already valid hyphenated", input: "my-org", want: "my-org"},
		{name: "mixed case", input: "Acme", want: "acme"},
		{name: "underscore", input: "Foo_Bar", want: "foo-bar"},
		{name: "dot", input: "acme.io", want: "acme-io"},
		{name: "whitespace", input: "  hello  world  ", want: "hello-world"},
		{name: "leading trailing symbols", input: "__weird__", want: "weird"},
		{name: "multiple symbols", input: "a@@@b", want: "a-b"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := slugifyAccount(tt.input); got != tt.want {
				t.Fatalf("slugifyAccount(%q) = %q, want %q", tt.input, got, tt.want)
			}
			if tt.want != "" && !api.IsValidSlug(tt.want) {
				t.Fatalf("expected %q to satisfy api.IsValidSlug", tt.want)
			}
		})
	}
}

func TestSlugifyAccountTruncatesLongValues(t *testing.T) {
	t.Parallel()

	input := strings.Repeat("a", 62) + "!!!" + strings.Repeat("b", 10)
	got := slugifyAccount(input)
	if len(got) > 63 {
		t.Fatalf("expected slug length <= 63, got %d (%q)", len(got), got)
	}
	if strings.HasSuffix(got, "-") {
		t.Fatalf("expected no trailing hyphen, got %q", got)
	}
	if !api.IsValidSlug(got) {
		t.Fatalf("expected truncated slug %q to satisfy api.IsValidSlug", got)
	}
}
