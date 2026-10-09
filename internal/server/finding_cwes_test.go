package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
)

func callFindingHandler(t *testing.T, srv *Server, handler http.HandlerFunc, method string, org *store.Organization, user *store.User, repo *store.Repository, fingerprint string, body any) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "/findings", bytes.NewReader(payload))
	req = req.WithContext(internalauth.WithUser(req.Context(), user))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("provider", "github")
	routeCtx.URLParams.Add("slug", org.Slug)
	routeCtx.URLParams.Add("repoSlug", repo.Slug)
	if fingerprint != "" {
		routeCtx.URLParams.Add("fingerprint", fingerprint)
	}
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	return recorder
}

type findingEnvelope struct {
	Data store.Vulnerability `json:"data"`
}

// ADR-037: a human or an agent filing a finding classifies it; the CWEs are
// validated against the catalog, shown on the finding, and editable — but only
// on manual findings.
func TestManualFindingDeclaredCWEs(t *testing.T) {
	srv, org, admin, repo, snapshotID := newBatchTriageFixture(t)

	rejected := callFindingHandler(t, srv, srv.handleCreateFinding, http.MethodPost, org, admin, repo, "", map[string]any{
		"title": "bad id", "severity": "high", "cwes": []string{"CWE-99999"},
	})
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("unknown CWE: status %d, want 400 (%s)", rejected.Code, rejected.Body.String())
	}

	created := callFindingHandler(t, srv, srv.handleCreateFinding, http.MethodPost, org, admin, repo, "", map[string]any{
		"title": "SQL built from request input", "severity": "high", "rule_id": "manual/sqli",
		"file_path": "db/query.go", "start_line": 42, "cwes": []string{"CWE-89", "89", "cwe-564"},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: status %d (%s)", created.Code, created.Body.String())
	}
	var finding findingEnvelope
	if err := json.Unmarshal(created.Body.Bytes(), &finding); err != nil {
		t.Fatal(err)
	}
	if got := cweIDsOf(finding.Data.CWEs); len(got) != 2 || got[0] != 89 || got[1] != 564 {
		t.Fatalf("created CWEs = %v, want [89 564]", got)
	}
	if finding.Data.CWEs[0].Source != store.FindingCWESourceDeclared || finding.Data.CWEs[0].Name == "" {
		t.Fatalf("declared CWE = %+v", finding.Data.CWEs[0])
	}

	updated := callFindingHandler(t, srv, srv.handleSetFindingCWEs, http.MethodPut, org, admin, repo, finding.Data.Fingerprint, map[string]any{
		"cwes": []string{"CWE-78"},
	})
	if updated.Code != http.StatusOK {
		t.Fatalf("update: status %d (%s)", updated.Code, updated.Body.String())
	}
	if err := json.Unmarshal(updated.Body.Bytes(), &finding); err != nil {
		t.Fatal(err)
	}
	if got := cweIDsOf(finding.Data.CWEs); len(got) != 1 || got[0] != 78 {
		t.Fatalf("updated CWEs = %v, want [78]", got)
	}

	// The list carries the same CWEs.
	listed, _, err := srv.queries.ListVulnerabilitiesBySnapshot(context.Background(), snapshotID, store.VulnerabilityListOptions{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	srv.attachCWEs(context.Background(), listed)
	if len(listed) != 1 || len(cweIDsOf(listed[0].CWEs)) != 1 {
		t.Fatalf("listed CWEs = %+v", listed)
	}

	// A scanner finding's CWEs belong to the scanner.
	scannerFingerprint := seedTriageFinding(t, srv, snapshotID, "G201")
	conflict := callFindingHandler(t, srv, srv.handleSetFindingCWEs, http.MethodPut, org, admin, repo, scannerFingerprint, map[string]any{
		"cwes": []string{"CWE-89"},
	})
	if conflict.Code != http.StatusConflict {
		t.Fatalf("reclassifying a scanner finding: status %d, want 409", conflict.Code)
	}
}

func cweIDsOf(cwes []store.FindingCWE) []int {
	out := make([]int, 0, len(cwes))
	for _, item := range cwes {
		out = append(out, item.ID)
	}
	return out
}
