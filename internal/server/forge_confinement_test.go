package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/metrics"
	"github.com/hibouhq/hibou/internal/store"
)

// confinementForge is a provider whose confinement check returns canned
// findings; the embedded nil Provider panics on anything else.
type confinementForge struct {
	forge.Provider
	id       string
	findings []forge.ConfinementFinding
	err      error
	calls    atomic.Int32
}

func (f *confinementForge) ID() string { return f.id }

func (f *confinementForge) CheckConfinement(context.Context) ([]forge.ConfinementFinding, error) {
	f.calls.Add(1)
	return f.findings, f.err
}

func TestForgeConfinementReport(t *testing.T) {
	gh := &confinementForge{id: "github", findings: []forge.ConfinementFinding{
		{Repository: "acme/open", Severity: forge.ConfinementError, Code: forge.ConfinementCodeUnrestricted},
		{Repository: "acme/open", Severity: forge.ConfinementError, Code: forge.ConfinementCodeDefaultBranch},
		{Repository: "acme/bypass", Severity: forge.ConfinementError, Code: forge.ConfinementCodeBypass, Ruleset: "hibou-confine"},
		{Repository: "acme/ok", Severity: forge.ConfinementOK, Code: forge.ConfinementCodeNoWrite},
	}}
	fj := &confinementForge{id: "forgejo", err: errors.New("forge down")}
	srv := &Server{
		cfg:    config.Config{InstanceAdmins: []string{"admin@example.com"}},
		log:    zerolog.Nop(),
		forges: map[string]forge.Provider{"gh-test-confinement": gh, "fj-test-confinement": fj},
	}
	request := func(email, query string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/instance/forges/confinement"+query, nil)
		if email != "" {
			req = req.WithContext(auth.WithUser(req.Context(), &store.User{Email: email, Provider: "github", ProviderID: "1"}))
		}
		rec := httptest.NewRecorder()
		srv.handleInstanceForgeConfinement(rec, req)
		return rec
	}

	if code := request("", "").Code; code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", code)
	}
	if code := request("dev@example.com", "").Code; code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d, want 403", code)
	}
	if gh.calls.Load() != 0 {
		t.Fatal("a refused request ran the check")
	}

	rec := request("admin@example.com", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin status = %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Data forgeConfinementReport `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data.Forges) != 2 || body.Data.CheckedAt.IsZero() {
		t.Fatalf("report = %+v", body.Data)
	}
	byForge := map[string]forgeConfinementResult{}
	for _, result := range body.Data.Forges {
		byForge[result.Forge] = result
	}
	if got := byForge["gh-test-confinement"]; got.UnconfinedRepositories != 2 || len(got.Findings) != 4 || got.Provider != "github" {
		t.Errorf("github result = %+v, want 2 unconfined repositories", got)
	}
	if got := byForge["fj-test-confinement"]; got.Error != "forge down" || got.Findings == nil {
		t.Errorf("forgejo result = %+v, want the error and an empty findings list", got)
	}
	var gauge dto.Metric
	if err := metrics.ForgeUnconfinedRepositories.WithLabelValues("gh-test-confinement").Write(&gauge); err != nil {
		t.Fatal(err)
	}
	if got := gauge.GetGauge().GetValue(); got != 2 {
		t.Errorf("gauge = %v, want 2", got)
	}

	// The cached report is served; refresh runs a new check.
	request("admin@example.com", "")
	if gh.calls.Load() != 1 {
		t.Fatalf("checks = %d, want 1 (cached)", gh.calls.Load())
	}
	request("admin@example.com", "?refresh=true")
	if gh.calls.Load() != 2 {
		t.Fatalf("checks = %d, want 2 after refresh", gh.calls.Load())
	}
	srv.logForgeConfinement(srv.latestForgeConfinement())
}
