package lsp

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

// The CWE catalog behind the web UI's cwe:, cwe-tree:, cwe-set: and
// cwe-category: completions (ADR-037). Both endpoints are reference data any
// authenticated caller may read.

// cweSets returns the named CWE lists and the View 1400 categories as the
// server sends them ({version, sets, categories}).
func (s *Server) cweSets(ctx context.Context) (json.RawMessage, error) {
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	return out, client.get(ctx, "/cwe/sets", nil, &out)
}

type cweSearchParams struct {
	Query string `json:"query"`
	// Roots, when Query is empty, lists the pillar and class entries a
	// cwe-tree: query usually starts from.
	Roots bool `json:"roots"`
}

// cweSearch searches the catalog by id or title ({version, entries}).
func (s *Server) cweSearch(ctx context.Context, p cweSearchParams) (json.RawMessage, error) {
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	query := strings.TrimSpace(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(p.Query)), "CWE-"))
	switch {
	case query != "":
		q.Set("q", query)
		q.Set("limit", strconv.Itoa(20))
	case p.Roots:
		q.Set("abstraction", "pillar")
	default:
		return json.RawMessage(`{"entries":[]}`), nil
	}
	var out json.RawMessage
	return out, client.get(ctx, "/cwe", q, &out)
}
