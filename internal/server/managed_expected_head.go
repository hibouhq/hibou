package server

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
)

var managedFullCommitSHA = regexp.MustCompile(`^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$`)

func checkManagedExpectedHead(w http.ResponseWriter, expected, current string) bool {
	if expected == "" {
		return true
	}
	if !managedFullCommitSHA.MatchString(expected) {
		api.JSONError(w, http.StatusBadRequest, "expected_head_sha must be a full 40- or 64-character hexadecimal commit SHA")
		return false
	}
	if !strings.EqualFold(expected, current) {
		api.JSONError(w, http.StatusConflict, "target head differs from expected_head_sha; refresh and review the current commit before preparing")
		return false
	}
	return true
}
