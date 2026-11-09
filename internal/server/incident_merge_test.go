package server

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// mergeFixture opens exploited-vulnerability incidents on chosen advisories
// of one repository.
type mergeFixture struct {
	incidentFixture
	t *testing.T
}

func (m mergeFixture) advisory(canonical string, aliases ...string) uuid.UUID {
	m.t.Helper()
	ctx := context.Background()
	advisory, err := m.srv.queries.UpsertAdvisory(ctx, dbgen.UpsertAdvisoryParams{CanonicalID: canonical, Title: canonical})
	if err != nil {
		m.t.Fatal(err)
	}
	for _, alias := range append([]string{canonical}, aliases...) {
		if err := m.srv.queries.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisory.ID, Alias: alias}); err != nil {
			m.t.Fatal(err)
		}
	}
	return advisory.ID
}

func (m mergeFixture) open(advisoryID uuid.UUID) dbgen.Incident {
	m.t.Helper()
	inc, created, err := m.srv.openIncident(context.Background(), incidentOpenInput{
		OrgID: m.org.ID, RepoID: uuid.NullUUID{UUID: m.repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability,
		SubjectType: incident.SubjectAdvisory, SubjectID: advisoryID.String(), Title: "exploited " + advisoryID.String()[:8],
		Priority: "P1", SignalSource: "kev", Regimes: []string{incident.RegimeCRA}, Actor: m.actor,
	})
	if err != nil || !created {
		m.t.Fatalf("open: created=%v err=%v", created, err)
	}
	return inc
}

func newMergeFixture(t *testing.T) mergeFixture {
	return mergeFixture{incidentFixture: newIncidentFixture(t), t: t}
}

func randomCVE() string { return fmt.Sprintf("CVE-2098-%05d", rand.IntN(90000)+10000) }

// One vulnerability under two names merges; a grouped advisory and one of
// the CVEs it groups do not, automatically or by hand.
func TestIncidentMergeOnlyJoinsTheSameVulnerability(t *testing.T) {
	t.Parallel()
	m := newMergeFixture(t)
	ctx := context.Background()

	// Aliases are unique: the GHSA record that arrives second keeps no CVE.
	cve := randomCVE()
	ghsa := "GHSA-" + uuid.NewString()[:4] + "-test-same"
	byCVE := m.open(m.advisory(cve, ghsa))
	byGHSA := m.open(m.advisory(ghsa, cve))
	if why, err := m.srv.mergeCompatibility(ctx, byCVE, byGHSA); err != nil || why != "" {
		t.Fatalf("CVE and its GHSA: why=%q err=%v", why, err)
	}

	// A grouped advisory (two HTTP/2 floods under one id) and the record of
	// one of the CVEs it groups: they share that CVE and are still two
	// vulnerabilities.
	ping, reset := randomCVE(), randomCVE()
	grouped := m.open(m.advisory(ping, reset))
	single := m.open(m.advisory(reset))
	why, err := m.srv.mergeCompatibility(ctx, grouped, single)
	if err != nil || !strings.Contains(why, "different vulnerabilities") {
		t.Fatalf("grouped advisory vs one of its CVEs: why=%q err=%v", why, err)
	}
	if _, err := m.srv.proposeOrMergeIncidents(ctx, grouped, single, m.actor, "same flood"); err == nil {
		t.Fatal("a manual merge of two CVEs was accepted")
	}

	// The automatic pass folds the alias pair and leaves the grouped one.
	m.srv.mergeAliasSiblings(ctx, single)
	m.srv.mergeAliasSiblings(ctx, byGHSA)
	for _, inc := range []dbgen.Incident{byGHSA, single} {
		reloaded, err := m.srv.queries.Incidents().GetIncident(ctx, inc.ID)
		if err != nil {
			t.Fatal(err)
		}
		wantMerged := inc.ID == byGHSA.ID
		if reloaded.MergedInto.Valid != wantMerged {
			t.Fatalf("#%d merged=%v, want %v", inc.Number, reloaded.MergedInto.Valid, wantMerged)
		}
	}
}

// Under four-eyes one person proposes the merge and another applies it; the
// author can neither approve it nor see it left in place after cancelling.
func TestIncidentMergeFourEyes(t *testing.T) {
	t.Parallel()
	m := newMergeFixture(t)
	ctx := context.Background()
	if _, err := m.srv.queries.Incidents().UpsertIncidentSettings(ctx, dbgen.UpsertIncidentSettingsParams{
		OrgID: m.org.ID, DefaultRules: json.RawMessage(`null`), LockedRules: json.RawMessage(`[]`), InternalTargets: json.RawMessage(`{}`),
		NationalRegimes: json.RawMessage(`[]`), FourEyes: true, DueSoonLeadMinutes: 360,
	}); err != nil {
		t.Fatal(err)
	}
	other, err := m.srv.queries.CreateUser(ctx, uniqueName(t, "second")+"@example.com", "Second", "github", uniqueName(t, "second"))
	if err != nil {
		t.Fatal(err)
	}
	second := incidentActor{ID: uuid.NullUUID{UUID: other.ID, Valid: true}, Type: audit.ActorUser, Display: "Second"}

	cve, ghsa := randomCVE(), "GHSA-"+uuid.NewString()[:4]+"-test-dupe"
	survivor := m.open(m.advisory(cve, ghsa))
	duplicate := m.open(m.advisory(ghsa, cve))

	proposed, err := m.srv.proposeOrMergeIncidents(ctx, survivor, duplicate, m.actor, "same CVE under its GHSA")
	if err != nil || !proposed {
		t.Fatalf("propose: proposed=%v err=%v", proposed, err)
	}
	duplicate, _ = m.srv.queries.Incidents().GetIncident(ctx, duplicate.ID)
	if _, ok := pendingMerge(duplicate); !ok || duplicate.MergedInto.Valid {
		t.Fatalf("proposal not recorded or merged early: %s", duplicate.ProposedMerge)
	}
	if _, err := m.srv.approveIncidentMerge(ctx, duplicate, m.actor); err == nil {
		t.Fatal("the author approved their own merge")
	}

	// Cancelled, then proposed again and approved by the second person.
	if err := m.srv.cancelIncidentMerge(ctx, duplicate, m.actor, "wrong target"); err != nil {
		t.Fatal(err)
	}
	duplicate, _ = m.srv.queries.Incidents().GetIncident(ctx, duplicate.ID)
	if _, ok := pendingMerge(duplicate); ok {
		t.Fatal("cancelled proposal still pending")
	}
	if _, err := m.srv.proposeOrMergeIncidents(ctx, survivor, duplicate, m.actor, "same CVE under its GHSA"); err != nil {
		t.Fatal(err)
	}
	duplicate, _ = m.srv.queries.Incidents().GetIncident(ctx, duplicate.ID)
	into, err := m.srv.approveIncidentMerge(ctx, duplicate, second)
	if err != nil || into != survivor.Number {
		t.Fatalf("approve: into=%d err=%v", into, err)
	}
	duplicate, _ = m.srv.queries.Incidents().GetIncident(ctx, duplicate.ID)
	if !duplicate.MergedInto.Valid || duplicate.MergedInto.UUID != survivor.ID {
		t.Fatalf("not merged into the survivor: %+v", duplicate.MergedInto)
	}
	if _, ok := pendingMerge(duplicate); ok {
		t.Fatal("proposal left on the merged incident")
	}
}

// An internal-regime incident (a policy breach) sends its regime's steps as
// an empty list: null broke the incident page.
func TestIncidentDetailInternalRegimeStepsAreAList(t *testing.T) {
	t.Parallel()
	m := newMergeFixture(t)
	inc, _, err := m.srv.openIncident(context.Background(), incidentOpenInput{
		OrgID: m.org.ID, RepoID: uuid.NullUUID{UUID: m.repo.ID, Valid: true}, Kind: incident.KindPolicyBreach,
		Title: "policy breach", SignalSource: "trigger", Actor: m.actor,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(internalauth.WithUser(context.Background(), m.admin))
	detail, err := m.srv.incidentDetail(req, m.org, inc)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(detail.Regimes)
	if len(detail.Regimes) == 0 || strings.Contains(string(payload), `"steps":null`) {
		t.Fatalf("regimes = %s", payload)
	}
}
