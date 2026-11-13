package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/remediation"
	"github.com/hibouhq/hibou/internal/store"
)

func TestManagedSelectionUsesServerBoundUnits(t *testing.T) {
	unit := remediation.Unit{ID: "module", Manifest: "module/package.json", RequiredFiles: []string{"module/package-lock.json"}, InputSHA256: map[string]string{"module/package-lock.json": "trusted"}}
	result := remediation.ManagedResult{Modules: []remediation.ManagedModule{{Manifest: unit.Manifest, Unit: &unit}, {Manifest: "unavailable/package.json", Unavailable: "unsupported manager"}}}
	selected, err := selectManagedUnits(result, []managedSelection{{ID: "module", UpgradeLevel: "minor", VersionTargets: []remediation.VersionTarget{{Name: "pkg", Mode: "exact", Version: "2.0.0"}}}})
	if err != nil || len(selected) != 1 || selected[0].InputSHA256["module/package-lock.json"] != "trusted" || selected[0].Manifest != unit.Manifest {
		t.Fatalf("server binding lost: %v %v", selected, err)
	}
	for _, input := range [][]managedSelection{nil, {{ID: "unavailable", UpgradeLevel: "patch"}}, {{ID: "module", UpgradeLevel: "anything"}}, {{ID: "module", UpgradeLevel: "patch"}, {ID: "module", UpgradeLevel: "minor"}}} {
		if _, err := selectManagedUnits(result, input); err == nil {
			t.Fatalf("invalid selection accepted: %v", input)
		}
	}
}

func TestManagedArtifactReadRefusesNonReady(t *testing.T) {
	srv := &Server{}
	for _, state := range []string{"failed", "generating", "cancelled", "awaiting_selection", "expired"} {
		_, err := srv.managedArtifact(context.Background(), &store.RemediationJob{State: state, ArtifactKey: "not-read", ExpiresAt: time.Now().Add(time.Hour)})
		if err == nil {
			t.Fatalf("non-ready %s could be downloaded or published", state)
		}
	}
}

func TestManagedDecodeRejectsInjectedExecutionFields(t *testing.T) {
	var req struct {
		Revision int                `json:"revision"`
		Units    []managedSelection `json:"units"`
	}
	for _, body := range []string{`{"revision":1,"repository":"/host","units":[]}`, `{"revision":1,"units":[]} {}`, `{"units":[{"id":"x","upgrade_level":"patch","required_files":["secret"]}]}`} {
		w := httptest.NewRecorder()
		if decodeManaged(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), &req) {
			t.Fatalf("execution fields accepted: %s", body)
		}
	}
}

func TestManagedConsentIsExplicitAndOrgBound(t *testing.T) {
	org := &store.Organization{ID: uuid.New(), Settings: json.RawMessage(`{"other":true}`)}
	if managedOrgConsent(org) {
		t.Fatal("missing consent allowed publication")
	}

	org.Settings = json.RawMessage(`{"managed_remediation_pr_consent":true}`)
	if !managedOrgConsent(org) {
		t.Fatal("explicit consent missing")
	}
}
