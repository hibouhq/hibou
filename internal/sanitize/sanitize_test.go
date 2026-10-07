package sanitize

import "testing"

func TestText(t *testing.T) {
	cases := []struct{ in, want string }{
		// The observed corruption: entity-encoded arrow, truncated mid-entity
		// (upstream lost only the ';'). html.UnescapeString decodes HTML5
		// legacy unterminated refs, so the arrow is RECOVERED, not amputated.
		{"glibc: Non-progress DoS in SHIFT_JISX0213 -&gt", "glibc: Non-progress DoS in SHIFT_JISX0213 ->"},
		{"overflow via &gt", "overflow via >"},
		// Complete entities decode.
		{"EUC_JISX0213 -&gt; UCS-4 conversion", "EUC_JISX0213 -> UCS-4 conversion"},
		{"a &lt;b&gt; c &amp; d", "a <b> c & d"},
		// Stumps cut too deep to decode are amputated…
		{"overflow via &g", "overflow via"},
		{"count &#3", "count"},
		// …while legitimate trailing ampersand text survives the allowlist.
		{"research &", "research &"},
		{"vulnerability in AT&T", "vulnerability in AT&T"},
		// Clean text is untouched; idempotent.
		{"plain title", "plain title"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Text(c.in); got != c.want {
			t.Errorf("Text(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if Text(Text("x -&gt")) != Text("x -&gt") {
		t.Error("Text is not idempotent")
	}
}
