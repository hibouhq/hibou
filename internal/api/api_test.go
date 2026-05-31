package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantPage int
		wantSize int
		wantOff  int
	}{
		{name: "defaults", query: "", wantPage: 1, wantSize: 20, wantOff: 0},
		{name: "valid params", query: "?page=3&per_page=50", wantPage: 3, wantSize: 50, wantOff: 100},
		{name: "zero page defaults", query: "?page=0", wantPage: 1, wantSize: 20, wantOff: 0},
		{name: "negative page defaults", query: "?page=-5", wantPage: 1, wantSize: 20, wantOff: 0},
		{name: "zero per page defaults", query: "?per_page=0", wantPage: 1, wantSize: 20, wantOff: 0},
		{name: "per page clamps", query: "?per_page=200", wantPage: 1, wantSize: 100, wantOff: 0},
		{name: "non numeric defaults", query: "?page=abc&per_page=xyz", wantPage: 1, wantSize: 20, wantOff: 0},
		{name: "offset calculation", query: "?page=2&per_page=10", wantPage: 2, wantSize: 10, wantOff: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)

			got := ParsePagination(r)
			want := PaginationParams{Page: tt.wantPage, PerPage: tt.wantSize, Offset: tt.wantOff}
			if got != want {
				t.Fatalf("ParsePagination() = %#v, want %#v", got, want)
			}
		})
	}
}

func TestIsValidSlug(t *testing.T) {
	maxLengthSlug := strings.Repeat("a", 63)
	tooLongSlug := strings.Repeat("a", 64)

	tests := []struct {
		name string
		slug string
		want bool
	}{
		{name: "hyphenated", slug: "my-repo", want: true},
		{name: "too short", slug: "a", want: false},
		{name: "minimum length", slug: "ab", want: true},
		{name: "maximum length", slug: maxLengthSlug, want: true},
		{name: "too long", slug: tooLongSlug, want: false},
		{name: "uppercase", slug: "My-Repo", want: false},
		{name: "underscore", slug: "my_repo", want: false},
		{name: "space", slug: "my repo", want: false},
		{name: "leading hyphen", slug: "-my-repo", want: false},
		{name: "trailing hyphen", slug: "my-repo-", want: false},
		{name: "consecutive hyphen", slug: "my--repo", want: false},
		{name: "empty", slug: "", want: false},
		{name: "numeric", slug: "123", want: true},
		{name: "mixed", slug: "a1-b2", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidSlug(tt.slug); got != tt.want {
				t.Fatalf("IsValidSlug(%q) = %v, want %v", tt.slug, got, tt.want)
			}
		})
	}
}

func TestJSON(t *testing.T) {
	recorder := httptest.NewRecorder()
	payload := map[string]any{"name": "hibou", "count": float64(2)}

	JSON(recorder, http.StatusOK, payload)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}

	var resp Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if resp.Error != nil {
		t.Fatalf("unexpected error payload: %#v", resp.Error)
	}
	if !reflect.DeepEqual(resp.Data, payload) {
		t.Fatalf("data = %#v, want %#v", resp.Data, payload)
	}
}

func TestJSONList(t *testing.T) {
	recorder := httptest.NewRecorder()
	payload := []string{"repo-a", "repo-b"}

	JSONList(recorder, payload, 2, 10, 55)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}

	var resp ListResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if !reflect.DeepEqual(resp.Data, []any{"repo-a", "repo-b"}) {
		t.Fatalf("data = %#v, want %#v", resp.Data, []any{"repo-a", "repo-b"})
	}
	if resp.Pagination != (Pagination{Page: 2, PerPage: 10, Total: 55}) {
		t.Fatalf("pagination = %#v, want %#v", resp.Pagination, Pagination{Page: 2, PerPage: 10, Total: 55})
	}
}

func TestJSONError(t *testing.T) {
	recorder := httptest.NewRecorder()

	JSONError(recorder, http.StatusNotFound, "not found")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want %q", got, "application/json")
	}

	var resp Response
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if resp.Error == nil {
		t.Fatal("expected error payload")
	}
	if resp.Error.Code != http.StatusNotFound {
		t.Fatalf("error.code = %d, want %d", resp.Error.Code, http.StatusNotFound)
	}
	if resp.Error.Message != "not found" {
		t.Fatalf("error.message = %q, want %q", resp.Error.Message, "not found")
	}
}
