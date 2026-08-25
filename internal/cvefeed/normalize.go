package cvefeed

import "strings"

// ProductKey folds a CNA's free-text vendor or product string into the key
// subscriptions match on.
//
// These fields are free text and are not consistent, even from one CNA within
// one hour: a sample of 1,910 affected entries carried `lodash` under vendors
// "Lodash" and "lodash", and `lodash-amd` under both "lodash" and
// "Lodash-amd". Casefolding and dropping every non-alphanumeric rune collapses
// that class of difference without inventing matches — "Apache Tomcat" and
// "apache tomcat" agree, while "Apache Tomcat" and "Apache Struts" still do
// not.
//
// The raw string is always kept alongside the key: the key is for matching and
// indexing, never for display.
func ProductKey(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		}
	}
	return b.String()
}

// IsPlaceholder reports whether a vendor or product string carries no identity.
//
// About 1% of affected entries use "n/a" or "unknown" rather than omitting the
// field. Matching on those would join unrelated products under one key, so they
// are treated as absent.
func IsPlaceholder(value string) bool {
	switch ProductKey(value) {
	case "", "na", "notapplicable", "unknown", "none", "unspecified":
		return true
	}
	return false
}
