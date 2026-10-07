// Package sanitize cleans third-party advisory text before it is stored.
//
// Upstream databases ship titles with HTML entities ("-&gt;" for "->") and
// sometimes truncate them MID-entity ("…SHIFT_JISX0213 -&gt", observed from a
// vendor feed via Trivy), which then renders literally in every UI. Decoding
// belongs at ingest, not display: the stored text is exported (VEX, CSAF,
// compliance reports) and must be honest everywhere, not only in our SPA.
package sanitize

import (
	"html"
	"regexp"
	"strings"
)

// brokenTrailingEntity matches an entity the upstream cut before its ';' —
// after decoding, every complete entity is gone, so a trailing '&'-run can
// only be the stump of a truncated one ("-&gt", "&am"). Deliberately an
// allowlist of the entities that occur in advisory prose, not a generic
// `&\w+$`: a title legitimately ending in "AT&T" or "R&D" must survive.
var brokenTrailingEntity = regexp.MustCompile(`&(?:#[0-9xX]{0,6}|a(?:m(?:p)?)?|l(?:t)?|g(?:t)?|q(?:u(?:o(?:t)?)?)?|ap(?:o(?:s)?)?|nb(?:s(?:p)?)?)$`)

// Text decodes HTML entities and amputates a trailing entity stump, returning
// trimmed text. Idempotent; safe on already-clean input.
func Text(value string) string {
	decoded := html.UnescapeString(value)
	decoded = brokenTrailingEntity.ReplaceAllString(decoded, "")
	return strings.TrimSpace(decoded)
}
