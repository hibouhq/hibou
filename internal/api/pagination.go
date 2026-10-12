package api

import (
	"net/http"
	"strconv"
)

const (
	DefaultPage    = 1
	DefaultPerPage = 20
	MaxPerPage     = 100
	// MaxPage bounds deep paging: several handlers fetch page*per_page rows
	// before slicing, so an unbounded page is an unbounded LIMIT. Clients
	// that need more than MaxPage*MaxPerPage rows should filter instead.
	MaxPage = 1000
)

type PaginationParams struct {
	Page    int
	PerPage int
	Offset  int
}

func ParsePagination(r *http.Request) PaginationParams {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = DefaultPage
	}
	if page > MaxPage {
		page = MaxPage
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 {
		perPage = DefaultPerPage
	}
	if perPage > MaxPerPage {
		perPage = MaxPerPage
	}

	return PaginationParams{
		Page:    page,
		PerPage: perPage,
		Offset:  (page - 1) * perPage,
	}
}
