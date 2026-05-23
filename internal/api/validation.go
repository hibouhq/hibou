package api

import "regexp"

var slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func IsValidSlug(s string) bool {
	return len(s) >= 2 && len(s) <= 63 && slugRegex.MatchString(s)
}
