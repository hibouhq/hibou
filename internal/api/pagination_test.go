package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePaginationCapsPage(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x?page=1000000000&per_page=100", nil)
	got := ParsePagination(r)
	if got.Page != MaxPage {
		t.Fatalf("page = %d, want %d", got.Page, MaxPage)
	}
	if got.Offset != (MaxPage-1)*MaxPerPage {
		t.Fatalf("offset = %d, want %d", got.Offset, (MaxPage-1)*MaxPerPage)
	}
	// strconv.Atoi saturates on overflow; the cap still applies.
	r = httptest.NewRequest(http.MethodGet, "/x?page=99999999999999999999999", nil)
	if got := ParsePagination(r); got.Page != MaxPage || got.Offset < 0 {
		t.Fatalf("overflowing page = %#v, want capped", got)
	}
}
