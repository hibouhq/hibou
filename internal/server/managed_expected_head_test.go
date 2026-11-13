package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedExpectedHeadRejectsStaleAndInvalidSHA(t *testing.T) {
	for _, tt := range []struct {
		name, expected, current string
		want                    int
	}{
		{"omitted remains backward compatible", "", strings.Repeat("a", 40), http.StatusOK},
		{"exact branch head", strings.Repeat("a", 40), strings.Repeat("a", 40), http.StatusOK},
		{"case normalized", strings.Repeat("A", 40), strings.Repeat("a", 40), http.StatusOK},
		{"sha256 commit", strings.Repeat("a", 64), strings.Repeat("a", 64), http.StatusOK},
		{"stale branch head", strings.Repeat("a", 40), strings.Repeat("b", 40), http.StatusConflict},
		{"abbreviated SHA", "abcdef", strings.Repeat("a", 40), http.StatusBadRequest},
		{"non hexadecimal", strings.Repeat("z", 40), strings.Repeat("a", 40), http.StatusBadRequest},
		{"unexpected SHA length", strings.Repeat("a", 41), strings.Repeat("a", 40), http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			proceed := checkManagedExpectedHead(w, tt.expected, tt.current)
			if proceed != (tt.want == http.StatusOK) || w.Code != tt.want {
				t.Fatalf("head guard proceed=%v status=%d body=%s", proceed, w.Code, w.Body.String())
			}
		})
	}
}
