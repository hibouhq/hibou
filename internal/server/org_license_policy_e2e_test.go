package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// End-to-end through the HTTP handlers: write a policy, read it back, retire it,
// and confirm each step reports what actually happened. The pieces are unit
// tested individually; this checks they are wired to each other.
func TestOrgLicensePolicyEndToEnd(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv, org, admin, _ := newDiscoveryTestServer(t)

	put := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		req := newOrgRequest(t, admin, http.MethodPut, "/api/v1/orgs/github/"+org.Slug+"/licenses/policy", "github", org.Slug)
		req.Body = io.NopCloser(bytes.NewBufferString(body))
		recorder := httptest.NewRecorder()
		srv.handleUpdateOrgLicensePolicy(recorder, req)
		return recorder
	}
	get := func() orgLicensePolicyResponse {
		t.Helper()
		req := newOrgRequest(t, admin, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/licenses/policy", "github", org.Slug)
		recorder := httptest.NewRecorder()
		srv.handleGetOrgLicensePolicy(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET status = %d: %s", recorder.Code, recorder.Body.String())
		}
		var envelope struct {
			Data orgLicensePolicyResponse `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return envelope.Data
	}

	// Nothing set yet.
	if response := get(); response.Configured {
		t.Fatalf("expected no policy, got %+v", response)
	}

	// An unknown category is rejected rather than stored to match nothing.
	if recorder := put(`{"deny_categories":["copyleftt"]}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown category = %d: %s", recorder.Code, recorder.Body.String())
	}
	// So is an unknown scope.
	if recorder := put(`{"deny_categories":["copyleft"],"evaluate":"sometimes"}`); recorder.Code != http.StatusBadRequest {
		t.Fatalf("bad evaluate = %d: %s", recorder.Code, recorder.Body.String())
	}

	if recorder := put(`{"deny_categories":["copyleft","network-copyleft"],"deny_unknown":true,"evaluate":"new"}`); recorder.Code != http.StatusOK {
		t.Fatalf("save = %d: %s", recorder.Code, recorder.Body.String())
	}

	stored := get()
	if !stored.Configured || stored.Policy == nil {
		t.Fatalf("policy not configured after save: %+v", stored)
	}
	if len(stored.Policy.DenyCategories) != 2 || !stored.Policy.DenyUnknown {
		t.Errorf("policy = %+v", stored.Policy)
	}
	// The plain GET must not have run the forge fan-out.
	if stored.ReposScanned {
		t.Error("the plain read must not scan repositories")
	}

	// The gate must now see it — this is the wiring that matters, since the whole
	// point of an org policy is that it reaches repositories declaring none.
	spec, err := srv.queries.GetOrgLicensePolicy(ctx, org.ID)
	if err != nil || spec == nil {
		t.Fatalf("gate-side read: %v (%+v)", err, spec)
	}
	if v := spec.Policy().Evaluate([]string{"GPL-3.0-only"}); v == nil {
		t.Error("the stored policy should deny copyleft when the gate applies it")
	}
	if v := spec.Policy().Evaluate([]string{"MIT"}); v != nil {
		t.Errorf("MIT should pass, got %+v", v)
	}

	// A deny-nothing policy saves but is reported as not enforcing.
	if recorder := put(`{"deny_unknown":false}`); recorder.Code != http.StatusOK {
		t.Fatalf("empty save = %d: %s", recorder.Code, recorder.Body.String())
	}
	if response := get(); response.Configured {
		t.Error("a policy that denies nothing must not report as configured")
	}

	// Restore something real, then retire it.
	if recorder := put(`{"deny_categories":["copyleft"],"deny_unknown":true}`); recorder.Code != http.StatusOK {
		t.Fatalf("restore = %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := put(`{"enabled":false}`); recorder.Code != http.StatusOK {
		t.Fatalf("retire = %d: %s", recorder.Code, recorder.Body.String())
	}
	if response := get(); response.Configured {
		t.Error("a retired policy must not report as configured")
	}
	// And the gate must stop seeing it.
	if spec, err := srv.queries.GetOrgLicensePolicy(ctx, org.ID); err != nil || spec != nil {
		t.Errorf("gate must not see a retired policy: %v (%+v)", err, spec)
	}

	// Re-adopting after a retirement must work — the constraint collision that
	// broke this once was invisible until exercised end to end.
	if recorder := put(`{"deny_categories":["network-copyleft"],"deny_unknown":true}`); recorder.Code != http.StatusOK {
		t.Fatalf("re-adopt = %d: %s", recorder.Code, recorder.Body.String())
	}
	final := get()
	if !final.Configured || len(final.Policy.DenyCategories) != 1 || final.Policy.DenyCategories[0] != "network-copyleft" {
		t.Errorf("re-adopted policy = %+v", final.Policy)
	}
}
