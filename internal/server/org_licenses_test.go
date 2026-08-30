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

	"github.com/hibouhq/hibou/internal/apitoken"
	internalauth "github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestHandleGetOrgLicensesOrgWideTokenScope(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	call := func(tokenAuth *internalauth.TokenAuth) *httptest.ResponseRecorder {
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/licenses", "github", org.Slug)
		if tokenAuth != nil {
			req = req.WithContext(internalauth.WithTokenAuth(req.Context(), tokenAuth))
		}
		recorder := httptest.NewRecorder()
		srv.handleGetOrgLicenses(recorder, req)
		return recorder
	}

	// A repo-list scoped token must not read an org-wide aggregate: the response
	// would silently span repos outside its selector.
	repoScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"allowed-repo"}},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapComponents: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(repoScoped); recorder.Code != http.StatusForbidden {
		t.Fatalf("repo-list scoped licenses = %d: %s", recorder.Code, recorder.Body.String())
	}

	orgWide := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapComponents: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(orgWide); recorder.Code != http.StatusOK {
		t.Fatalf("org-wide scoped licenses = %d: %s", recorder.Code, recorder.Body.String())
	}

	// A token holding some other capability must not reach component licenses.
	wrongCap := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:   org.Slug,
			Repos: apitoken.RepoSelector{Mode: apitoken.RepoAll},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{
				apitoken.CapCoverage: apitoken.AccessRead,
			},
		},
	}
	if recorder := call(wrongCap); recorder.Code != http.StatusForbidden {
		t.Fatalf("coverage-scoped licenses = %d: %s", recorder.Code, recorder.Body.String())
	}

	if recorder := call(&internalauth.TokenAuth{}); recorder.Code != http.StatusOK {
		t.Fatalf("unscoped licenses = %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder := call(nil); recorder.Code != http.StatusOK {
		t.Fatalf("session licenses = %d: %s", recorder.Code, recorder.Body.String())
	}
}

// An org with no usable snapshot must still return the full envelope, with the
// coverage block saying so. A bare 200 with null lists would render as "no
// license exposure" instead of "nothing was measured".
func TestHandleGetOrgLicensesEmptyOrgStillReportsCoverage(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/licenses", "github", org.Slug)
	recorder := httptest.NewRecorder()
	srv.handleGetOrgLicenses(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}

	// Responses are wrapped by api.JSON as {"data": ...}.
	var envelope struct {
		Data orgLicenseOverviewResponse `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	response := envelope.Data
	if response.Categories == nil || response.Licenses == nil || response.Repos == nil {
		t.Fatalf("nil lists in response: %+v", response)
	}
	if response.Coverage.ComponentsTotal != 0 {
		t.Fatalf("components_total = %d, want 0", response.Coverage.ComponentsTotal)
	}
}

func TestSummarizeComponentLicenses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		raw        []string
		category   license.Category
		declared   bool
		recognized bool
		entries    []string
	}{
		{
			name:       "no metadata is undeclared, not merely unrecognized",
			raw:        nil,
			category:   license.CategoryUnknown,
			declared:   false,
			recognized: false,
			entries:    []string{},
		},
		{
			// Blank strings are what an SBOM with empty license nodes yields;
			// they must not read as declared metadata.
			name:       "blank entries are undeclared",
			raw:        []string{"", "   "},
			category:   license.CategoryUnknown,
			declared:   false,
			recognized: false,
			entries:    []string{},
		},
		{
			name:       "unrecognized identifier is declared but not recognized",
			raw:        []string{"Acme-Corp-Internal-1.0"},
			category:   license.CategoryUnknown,
			declared:   true,
			recognized: false,
			entries:    []string{"Acme-Corp-Internal-1.0"},
		},
		{
			name:       "parenthesised expression is normalized for grouping",
			raw:        []string{"(MPL-2.0 AND MIT)"},
			category:   license.CategoryWeakCopyleft,
			declared:   true,
			recognized: true,
			entries:    []string{"MPL-2.0 AND MIT"},
		},
		{
			name:       "separate entries take the most restrictive",
			raw:        []string{"MIT", "GPL-3.0-only"},
			category:   license.CategoryCopyleft,
			declared:   true,
			recognized: true,
			entries:    []string{"MIT", "GPL-3.0-only"},
		},
		{
			name:       "an elective expression resolves to the alternative you would pick",
			raw:        []string{"MIT OR GPL-3.0-only"},
			category:   license.CategoryPermissive,
			declared:   true,
			recognized: true,
			entries:    []string{"MIT OR GPL-3.0-only"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := summarizeComponentLicenses(tc.raw)
			if facts.category != tc.category {
				t.Errorf("category = %s, want %s", facts.category, tc.category)
			}
			if facts.declared != tc.declared {
				t.Errorf("declared = %t, want %t", facts.declared, tc.declared)
			}
			if facts.recognized != tc.recognized {
				t.Errorf("recognized = %t, want %t", facts.recognized, tc.recognized)
			}
			if len(facts.entries) != len(tc.entries) {
				t.Fatalf("entries = %q, want %q", facts.entries, tc.entries)
			}
			for i := range tc.entries {
				if facts.entries[i] != tc.entries[i] {
					t.Errorf("entries[%d] = %q, want %q", i, facts.entries[i], tc.entries[i])
				}
			}
		})
	}
}

// The per-repo ordering must surface the repo that needs a decision, not the
// one with the biggest dependency tree.
func TestRiskWeightRanksRestrictiveExposureFirst(t *testing.T) {
	t.Parallel()

	permissiveHeavy := orgLicenseRepoStat{ByCategory: map[string]int{string(license.CategoryPermissive): 900}}
	oneNetworkCopyleft := orgLicenseRepoStat{ByCategory: map[string]int{string(license.CategoryNetworkCopyleft): 1}}
	if riskWeight(oneNetworkCopyleft) <= riskWeight(permissiveHeavy) {
		t.Fatalf("one AGPL component (%d) must outrank 900 permissive ones (%d)",
			riskWeight(oneNetworkCopyleft), riskWeight(permissiveHeavy))
	}

	sourceAvailable := orgLicenseRepoStat{ByCategory: map[string]int{string(license.CategorySourceAvailable): 1}}
	if riskWeight(sourceAvailable) <= riskWeight(oneNetworkCopyleft) {
		t.Fatal("source-available must outrank network-copyleft")
	}
}

// buildOrgLicenseOverview is where the counting rules live, and miscounting is
// the failure mode that makes a compliance dashboard worse than none. These
// exercise it directly with synthetic rows.
func TestBuildOrgLicenseOverviewCounting(t *testing.T) {
	t.Parallel()

	repoA, repoB := uuid.New(), uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoA: {
			repo:     &store.Repository{ID: repoA, Slug: "alpha", Name: "Alpha"},
			snapshot: &store.Snapshot{Status: "complete", CreatedAt: time.Now()},
		},
		repoB: {
			repo:     &store.Repository{ID: repoB, Slug: "beta", Name: "Beta"},
			snapshot: &store.Snapshot{Status: "complete", CreatedAt: time.Now()},
		},
	}

	row := func(repoID uuid.UUID, purl, version string, licenses ...string) dbgen.ListComponentLicensesBySnapshotsRow {
		return dbgen.ListComponentLicensesBySnapshotsRow{
			RepoID: repoID, ID: uuid.New(), Purl: purl,
			Name: purl, Version: version, Ecosystem: "npm", Licenses: licenses,
		}
	}

	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		// Shared by both repos: one org component, two repos.
		row(repoA, "pkg:npm/shared", "1.0.0", "MIT"),
		row(repoB, "pkg:npm/shared", "1.0.0", "MIT"),
		// Same package, different version: a distinct component.
		row(repoA, "pkg:npm/shared", "2.0.0", "MIT"),
		// Copyleft, one repo only.
		row(repoA, "pkg:npm/gpl-thing", "1.0.0", "GPL-3.0-only"),
		// Undeclared: no license metadata at all.
		row(repoB, "pkg:npm/mystery", "1.0.0"),
		// Unrecognized: declared, but not in the catalog.
		row(repoB, "pkg:npm/corp", "1.0.0", "Acme-Internal-1.0"),
		// Normalization: these two must collapse onto one license row.
		row(repoA, "pkg:npm/parens", "1.0.0", "(MIT)"),
		row(repoB, "pkg:npm/spaces", "1.0.0", "  MIT  "),
	}

	overview := buildOrgLicenseOverview(rows, repos, 3)

	if overview.Coverage.ReposEnrolled != 3 {
		t.Errorf("repos_enrolled = %d, want 3 (passed through, not derived)", overview.Coverage.ReposEnrolled)
	}
	if overview.Coverage.ReposWithSnapshot != 2 {
		t.Errorf("repos_with_snapshot = %d, want 2", overview.Coverage.ReposWithSnapshot)
	}
	if overview.Coverage.ReposWithComponents != 2 {
		t.Errorf("repos_with_components = %d, want 2", overview.Coverage.ReposWithComponents)
	}
	// 7 distinct purl@version: shared@1, shared@2, gpl-thing, mystery, corp, parens, spaces.
	if overview.Coverage.ComponentsTotal != 7 {
		t.Errorf("components_total = %d, want 7 (deduped by purl@version)", overview.Coverage.ComponentsTotal)
	}
	if overview.Coverage.Undeclared != 1 {
		t.Errorf("undeclared = %d, want 1", overview.Coverage.Undeclared)
	}
	if overview.Coverage.Unrecognized != 1 {
		t.Errorf("unrecognized = %d, want 1", overview.Coverage.Unrecognized)
	}

	// Categories must partition the component total exactly — no double count,
	// no component missing from every bucket.
	categorySum := 0
	byCategory := make(map[string]orgLicenseCategoryStat)
	for _, stat := range overview.Categories {
		categorySum += stat.Components
		byCategory[stat.Category] = stat
	}
	if categorySum != overview.Coverage.ComponentsTotal {
		t.Errorf("category components sum = %d, want %d (must partition)", categorySum, overview.Coverage.ComponentsTotal)
	}
	if len(overview.Categories) != len(license.Categories()) {
		t.Errorf("categories = %d entries, want all %d including empties", len(overview.Categories), len(license.Categories()))
	}
	if got := byCategory[string(license.CategoryUnknown)].Components; got != 2 {
		t.Errorf("unknown components = %d, want 2 (undeclared + unrecognized)", got)
	}
	if got := byCategory[string(license.CategoryPermissive)].Components; got != 4 {
		t.Errorf("permissive components = %d, want 4 (shared@1, shared@2, parens, spaces)", got)
	}
	if got := byCategory[string(license.CategoryCopyleft)].Repos; got != 1 {
		t.Errorf("copyleft repos = %d, want 1", got)
	}

	// "MIT", "(MIT)" and "  MIT  " must be one row, on 4 components / 2 repos.
	var mit *orgLicenseStat
	for i := range overview.Licenses {
		if overview.Licenses[i].License == "MIT" {
			mit = &overview.Licenses[i]
		}
		if overview.Licenses[i].License == "(MIT)" {
			t.Error("un-normalized \"(MIT)\" leaked into the license table")
		}
	}
	if mit == nil {
		t.Fatal("no MIT row")
	}
	if mit.Components != 4 || mit.Repos != 2 {
		t.Errorf("MIT = %d components / %d repos, want 4 / 2", mit.Components, mit.Repos)
	}
	// Sorted by component count, so the most-used license leads.
	if overview.Licenses[0].License != "MIT" {
		t.Errorf("licenses[0] = %q, want MIT (highest component count first)", overview.Licenses[0].License)
	}

	// Per-repo rows count every component in that repo, not deduped org-wide.
	repoRows := make(map[string]orgLicenseRepoStat)
	for _, stat := range overview.Repos {
		repoRows[stat.Slug] = stat
	}
	if got := repoRows["alpha"].Components; got != 4 {
		t.Errorf("alpha components = %d, want 4", got)
	}
	if got := repoRows["beta"].Components; got != 4 {
		t.Errorf("beta components = %d, want 4", got)
	}
	if got := repoRows["beta"].Undeclared; got != 1 {
		t.Errorf("beta undeclared = %d, want 1", got)
	}
	// alpha carries the GPL component, so it must sort above beta.
	if overview.Repos[0].Slug != "alpha" {
		t.Errorf("repos[0] = %q, want alpha (copyleft outranks beta's unknowns)", overview.Repos[0].Slug)
	}
}

// Rows for a repo the caller did not resolve must be dropped, not attributed to
// a zero-value repo. Otherwise a stale snapshot id would invent a nameless row.
func TestBuildOrgLicenseOverviewIgnoresUnknownRepos(t *testing.T) {
	t.Parallel()

	known := uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		known: {repo: &store.Repository{ID: known, Slug: "known"}, snapshot: &store.Snapshot{Status: "complete"}},
	}
	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		{RepoID: known, ID: uuid.New(), Purl: "pkg:npm/a", Version: "1", Licenses: []string{"MIT"}},
		{RepoID: uuid.New(), ID: uuid.New(), Purl: "pkg:npm/b", Version: "1", Licenses: []string{"AGPL-3.0-only"}},
	}

	overview := buildOrgLicenseOverview(rows, repos, 1)
	if overview.Coverage.ComponentsTotal != 1 {
		t.Errorf("components_total = %d, want 1 (unknown repo dropped)", overview.Coverage.ComponentsTotal)
	}
	if len(overview.Repos) != 1 || overview.Repos[0].Slug != "known" {
		t.Errorf("repos = %+v, want only the known repo", overview.Repos)
	}
	for _, stat := range overview.Licenses {
		if stat.License == "AGPL-3.0-only" {
			t.Error("component from an unresolved repo leaked into the license table")
		}
	}
}

// A conjunctive expression must be flagged so the table does not look like it
// disagrees with the gate, which resolves AND and OR differently.
func TestBuildOrgLicenseOverviewFlagsExpressionKind(t *testing.T) {
	t.Parallel()

	repoID := uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoID: {repo: &store.Repository{ID: repoID, Slug: "r"}, snapshot: &store.Snapshot{Status: "complete"}},
	}
	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		{RepoID: repoID, ID: uuid.New(), Purl: "pkg:npm/and", Version: "1", Licenses: []string{"MPL-2.0 AND MIT"}},
		{RepoID: repoID, ID: uuid.New(), Purl: "pkg:npm/or", Version: "1", Licenses: []string{"MIT OR GPL-3.0-only"}},
	}

	overview := buildOrgLicenseOverview(rows, repos, 1)
	flags := make(map[string]orgLicenseStat)
	for _, stat := range overview.Licenses {
		flags[stat.License] = stat
	}

	conjunctive := flags["MPL-2.0 AND MIT"]
	if !conjunctive.HasAnd || conjunctive.HasOr {
		t.Errorf("AND expression flags = and:%t or:%t, want and:true or:false", conjunctive.HasAnd, conjunctive.HasOr)
	}
	if conjunctive.Category != string(license.CategoryWeakCopyleft) {
		t.Errorf("AND category = %s, want weak-copyleft (most restrictive operand)", conjunctive.Category)
	}

	elective := flags["MIT OR GPL-3.0-only"]
	if elective.HasAnd || !elective.HasOr {
		t.Errorf("OR expression flags = and:%t or:%t, want and:false or:true", elective.HasAnd, elective.HasOr)
	}
	if elective.Category != string(license.CategoryPermissive) {
		t.Errorf("OR category = %s, want permissive (the alternative a consumer picks)", elective.Category)
	}
}

// The aggregation tests above are pure. This one executes the new SQL against a
// real database, because a query that only ever runs in production is untested.
// It also pins the join semantics: one row per (snapshot, component), carrying
// the repo that owns the snapshot.
func TestListComponentLicensesBySnapshotsQuery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv, org, _, _ := newDiscoveryTestServer(t)
	repoOne := createUploadTestRepository(t, srv, org)
	repoTwo := createUploadTestRepository(t, srv, org)

	seed := func(repo *store.Repository, sha string, licensesByPurl map[string][]string) uuid.UUID {
		t.Helper()
		ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
		if err != nil {
			t.Fatalf("GetRefByRepoAndName: %v", err)
		}
		if ref == nil {
			ref, err = srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
			if err != nil {
				t.Fatalf("CreateRef: %v", err)
			}
		}
		snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, sha, store.SnapshotStatusComplete)
		if err != nil {
			t.Fatalf("CreateSnapshot: %v", err)
		}
		for purl, licenses := range licensesByPurl {
			component, err := srv.queries.UpsertComponent(ctx, purl, purl, "1.0.0", "npm", licenses)
			if err != nil {
				t.Fatalf("UpsertComponent: %v", err)
			}
			if err := srv.queries.AttachComponentToSnapshot(ctx, snapshot.ID, component.ID, nil); err != nil {
				t.Fatalf("AttachComponentToSnapshot: %v", err)
			}
		}
		return snapshot.ID
	}

	// A purl unique to this test run, so a shared test database cannot make the
	// assertions below depend on other tests' rows.
	prefix := "pkg:npm/lic-" + uuid.NewString()[:8] + "-"
	shared := prefix + "shared"
	gpl := prefix + "gpl"
	bare := prefix + "bare"

	snapshotOne := seed(repoOne, "sha-lic-one", map[string][]string{
		shared: {"MIT"},
		gpl:    {"GPL-3.0-only"},
	})
	snapshotTwo := seed(repoTwo, "sha-lic-two", map[string][]string{
		shared: {"MIT"},
		bare:   {}, // no license metadata at all
	})

	rows, err := srv.queries.ListComponentLicensesBySnapshots(ctx, []uuid.UUID{snapshotOne, snapshotTwo})
	if err != nil {
		t.Fatalf("ListComponentLicensesBySnapshots: %v", err)
	}

	type key struct {
		repoID uuid.UUID
		purl   string
	}
	got := make(map[key][]string)
	for _, row := range rows {
		if !strings.HasPrefix(row.Purl, prefix) {
			continue // rows seeded by other tests in the shared database
		}
		got[key{row.RepoID, row.Purl}] = row.Licenses
	}

	if len(got) != 4 {
		t.Fatalf("rows = %d, want 4 (2 per snapshot): %+v", len(got), got)
	}
	if licenses := got[key{repoOne.ID, shared}]; len(licenses) != 1 || licenses[0] != "MIT" {
		t.Errorf("repoOne shared licenses = %+v, want [MIT]", licenses)
	}
	if licenses := got[key{repoTwo.ID, shared}]; len(licenses) != 1 || licenses[0] != "MIT" {
		t.Errorf("repoTwo shared licenses = %+v, want [MIT] (same component, both repos)", licenses)
	}
	if licenses := got[key{repoOne.ID, gpl}]; len(licenses) != 1 || licenses[0] != "GPL-3.0-only" {
		t.Errorf("repoOne gpl licenses = %+v, want [GPL-3.0-only]", licenses)
	}
	if licenses := got[key{repoTwo.ID, bare}]; len(licenses) != 0 {
		t.Errorf("repoTwo bare licenses = %+v, want empty", licenses)
	}
	// The GPL component belongs to repoOne only; the query must not bleed it
	// across the repo boundary.
	if _, leaked := got[key{repoTwo.ID, gpl}]; leaked {
		t.Error("repoOne's component appeared under repoTwo")
	}

	// And the rows feed the aggregation correctly end to end.
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoOne.ID: {repo: repoOne, snapshot: &store.Snapshot{ID: snapshotOne, Status: store.SnapshotStatusComplete}},
		repoTwo.ID: {repo: repoTwo, snapshot: &store.Snapshot{ID: snapshotTwo, Status: store.SnapshotStatusComplete}},
	}
	scoped := make([]dbgen.ListComponentLicensesBySnapshotsRow, 0, len(rows))
	for _, row := range rows {
		if strings.HasPrefix(row.Purl, prefix) {
			scoped = append(scoped, row)
		}
	}
	overview := buildOrgLicenseOverview(scoped, repos, 2)
	if overview.Coverage.ComponentsTotal != 3 {
		t.Errorf("components_total = %d, want 3 (shared counted once)", overview.Coverage.ComponentsTotal)
	}
	if overview.Coverage.Undeclared != 1 {
		t.Errorf("undeclared = %d, want 1", overview.Coverage.Undeclared)
	}
	if overview.Repos[0].Slug != repoOne.Slug {
		t.Errorf("repos[0] = %q, want %q (holds the copyleft component)", overview.Repos[0].Slug, repoOne.Slug)
	}
}

func TestBuildOrgLicenseComponentsFilteringAndOrdering(t *testing.T) {
	t.Parallel()

	repoA, repoB := uuid.New(), uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoA: {repo: &store.Repository{ID: repoA, Slug: "alpha"}, snapshot: &store.Snapshot{Status: "complete"}},
		repoB: {repo: &store.Repository{ID: repoB, Slug: "beta"}, snapshot: &store.Snapshot{Status: "complete"}},
	}
	row := func(repoID uuid.UUID, purl string, licenses ...string) dbgen.ListComponentLicensesBySnapshotsRow {
		return dbgen.ListComponentLicensesBySnapshotsRow{
			RepoID: repoID, ID: uuid.New(), Purl: purl, Name: purl, Version: "1.0.0", Ecosystem: "npm", Licenses: licenses,
		}
	}
	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		row(repoA, "pkg:npm/permissive", "MIT"),
		row(repoA, "pkg:npm/copyleft", "GPL-3.0-only"),
		row(repoB, "pkg:npm/network", "AGPL-3.0-only"),
		row(repoA, "pkg:npm/undeclared"),
		row(repoB, "pkg:npm/undeclared"),
		row(repoA, "pkg:npm/parens", "(MIT)"),
	}

	all := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{})
	if len(all) != 5 {
		t.Fatalf("rows = %d, want 5 distinct components: %+v", len(all), all)
	}
	// Most restrictive first: AGPL outranks GPL outranks unknown outranks MIT.
	if all[0].Category != string(license.CategoryNetworkCopyleft) {
		t.Errorf("first row category = %s, want network-copyleft", all[0].Category)
	}
	if last := all[len(all)-1].Category; last != string(license.CategoryPermissive) {
		t.Errorf("last row category = %s, want permissive", last)
	}

	// The shared undeclared component collapses to one row carrying both repos.
	var undeclared *orgLicenseComponentResponse
	for i := range all {
		if all[i].Purl == "pkg:npm/undeclared" {
			undeclared = &all[i]
		}
	}
	if undeclared == nil {
		t.Fatal("undeclared component missing")
	}
	if len(undeclared.Repos) != 2 {
		t.Errorf("undeclared repos = %v, want both", undeclared.Repos)
	}
	if undeclared.Declared {
		t.Error("component with no licenses must report declared=false")
	}

	// undeclared=true isolates the generator problem from catalog misses.
	onlyUndeclared := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{undeclared: true})
	if len(onlyUndeclared) != 1 || onlyUndeclared[0].Purl != "pkg:npm/undeclared" {
		t.Errorf("undeclared filter = %+v, want just the undeclared component", onlyUndeclared)
	}

	// The license filter is normalized on both sides, so a link built from the
	// "MIT" row also finds the component whose SBOM said "(MIT)".
	mit := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{license: license.NormalizeID("(mit)")})
	if len(mit) != 2 {
		t.Errorf("MIT filter matched %d, want 2 (MIT and (MIT)): %+v", len(mit), mit)
	}

	byCategory := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{category: "COPYLEFT"})
	if len(byCategory) != 1 || byCategory[0].Purl != "pkg:npm/copyleft" {
		t.Errorf("category filter = %+v, want the copyleft component (case-insensitive)", byCategory)
	}

	byRepo := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{repo: "beta"})
	if len(byRepo) != 2 {
		t.Errorf("repo filter matched %d, want 2 (network + undeclared): %+v", len(byRepo), byRepo)
	}
}

func TestHandleListOrgLicenseComponentsScopeAndEmptyOrg(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	call := func(tokenAuth *internalauth.TokenAuth) *httptest.ResponseRecorder {
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/licenses/components", "github", org.Slug)
		if tokenAuth != nil {
			req = req.WithContext(internalauth.WithTokenAuth(req.Context(), tokenAuth))
		}
		recorder := httptest.NewRecorder()
		srv.handleListOrgLicenseComponents(recorder, req)
		return recorder
	}

	repoScoped := &internalauth.TokenAuth{
		Scoped: true,
		Scope: apitoken.Scope{
			Org:         org.Slug,
			Repos:       apitoken.RepoSelector{Mode: apitoken.RepoList, Slugs: []string{"allowed-repo"}},
			Permissions: map[apitoken.Capability]apitoken.AccessLevel{apitoken.CapComponents: apitoken.AccessRead},
		},
	}
	if recorder := call(repoScoped); recorder.Code != http.StatusForbidden {
		t.Fatalf("repo-list scoped drilldown = %d: %s", recorder.Code, recorder.Body.String())
	}

	// Empty org: a well-formed empty page, not an error and not a null list.
	recorder := call(nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var envelope struct {
		Data       []orgLicenseComponentResponse `json:"data"`
		Pagination struct {
			Total   int `json:"total"`
			PerPage int `json:"per_page"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if envelope.Data == nil {
		t.Error("data must be an empty array, not null")
	}
	if envelope.Pagination.Total != 0 {
		t.Errorf("total = %d, want 0", envelope.Pagination.Total)
	}
}

// Paging past the end must return an empty page rather than the last page again
// or an out-of-range panic.
func TestPaginateLicenseComponents(t *testing.T) {
	t.Parallel()

	rows := make([]orgLicenseComponentResponse, 0, 3)
	for _, name := range []string{"a", "b", "c"} {
		rows = append(rows, orgLicenseComponentResponse{Purl: "pkg:npm/" + name, Name: name})
	}

	cases := []struct {
		name    string
		offset  int
		perPage int
		want    []string
	}{
		{"first page", 0, 2, []string{"a", "b"}},
		{"last partial page", 2, 2, []string{"c"}},
		{"exactly at the end", 3, 2, nil},
		{"past the end", 10, 2, nil},
		{"negative offset", -1, 2, nil},
		{"zero per page", 0, 0, nil},
		{"per page larger than the set", 0, 100, []string{"a", "b", "c"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := paginateLicenseComponents(rows, tc.offset, tc.perPage)
			if got == nil {
				t.Fatal("must never return nil — a null list renders as an error client-side")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d rows, want %d", len(got), len(tc.want))
			}
			for i, name := range tc.want {
				if got[i].Name != name {
					t.Errorf("row %d = %q, want %q", i, got[i].Name, name)
				}
			}
		})
	}

	if got := paginateLicenseComponents(nil, 0, 20); got == nil || len(got) != 0 {
		t.Errorf("empty input = %+v, want empty non-nil", got)
	}
}

// The provenance merge is the risky part: `||` is shallow, and the previous
// query used ON CONFLICT DO NOTHING. A component present in two uploaded SBOMs
// must end up carrying both, not just the first or just the last.
func TestComponentProvenanceLabelsAccumulateAcrossArtifacts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	srv, org, _, _ := newDiscoveryTestServer(t)
	repo := createUploadTestRepository(t, srv, org)

	ref, err := srv.queries.GetRefByRepoAndName(ctx, repo.ID, "main", store.RefTypeBranch)
	if err != nil {
		t.Fatalf("GetRefByRepoAndName: %v", err)
	}
	if ref == nil {
		ref, err = srv.queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreateRef: %v", err)
		}
	}
	snapshot, err := srv.queries.CreateSnapshot(ctx, ref.ID, "sha-provenance", store.SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}

	purl := "pkg:npm/shared-" + uuid.NewString()[:8]
	component, err := srv.queries.UpsertComponent(ctx, purl, "shared", "1.0.0", "npm", []string{"MIT"})
	if err != nil {
		t.Fatalf("UpsertComponent: %v", err)
	}

	// Same component, ingested from two different uploads.
	for _, artifact := range []store.SnapshotArtifact{
		{Filename: "go-sbom.cdx.json", Kind: "sbom"},
		{Filename: "frontend-sbom.cdx.json", Kind: "sbom"},
	} {
		if err := srv.queries.AttachComponentToSnapshot(ctx, snapshot.ID, component.ID, componentProvenanceLabels(artifact)); err != nil {
			t.Fatalf("AttachComponentToSnapshot(%s): %v", artifact.Filename, err)
		}
	}

	var raw []byte
	if err := srv.db.QueryRowContext(ctx,
		`SELECT labels FROM snapshot_components WHERE snapshot_id = $1 AND component_id = $2`,
		snapshot.ID, component.ID,
	).Scan(&raw); err != nil {
		t.Fatalf("select labels: %v", err)
	}
	labels := map[string]any{}
	if err := json.Unmarshal(raw, &labels); err != nil {
		t.Fatalf("unmarshal labels %q: %v", raw, err)
	}

	for _, key := range []string{"sbom:go-sbom.cdx.json", "sbom:frontend-sbom.cdx.json", "sbom_kind:sbom"} {
		if _, ok := labels[key]; !ok {
			t.Errorf("labels missing %q — the merge dropped an artifact: %v", key, labels)
		}
	}
}

func TestComponentProvenanceLabels(t *testing.T) {
	t.Parallel()

	// An unnamed artifact carries no information the snapshot does not already
	// have, so it must not write an empty-ish label object.
	if got := componentProvenanceLabels(store.SnapshotArtifact{}); got != nil {
		t.Errorf("unnamed artifact = %s, want nil", got)
	}
	if got := componentProvenanceLabels(store.SnapshotArtifact{Filename: "   "}); got != nil {
		t.Errorf("blank filename = %s, want nil", got)
	}

	labels := map[string]any{}
	if err := json.Unmarshal(componentProvenanceLabels(store.SnapshotArtifact{Filename: "a.json", Kind: "sbom"}), &labels); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(labels) != 2 {
		t.Errorf("labels = %v, want filename + kind", labels)
	}
	// Flat keys, because the column is merged shallowly.
	for key, value := range labels {
		if _, nested := value.(map[string]any); nested {
			t.Errorf("label %q is nested; a shallow merge would replace it", key)
		}
	}
}

// The compliance headline counts only what needs chasing. A repository that
// tightens its own policy is not an exception, and conflating the two would send
// someone after work that does not exist.
func TestPolicyAttentionRankOrdersDeparturesFirst(t *testing.T) {
	t.Parallel()

	mixed := orgLicensePolicyRepo{Slug: "mixed", Source: delta.LicenseSourceRepository, Relation: string(license.RelationMixed)}
	looser := orgLicensePolicyRepo{Slug: "looser", Source: delta.LicenseSourceRepository, Relation: string(license.RelationLooser)}
	unreadable := orgLicensePolicyRepo{Slug: "unreadable", Unreadable: true}
	stricter := orgLicensePolicyRepo{Slug: "stricter", Source: delta.LicenseSourceRepository, Relation: string(license.RelationStricter)}
	inheriting := orgLicensePolicyRepo{Slug: "inheriting", Source: delta.LicenseSourceOrganization}

	ranks := []struct {
		name string
		repo orgLicensePolicyRepo
	}{
		{"mixed", mixed},
		{"looser", looser},
		{"unreadable", unreadable},
		{"stricter", stricter},
		{"inheriting", inheriting},
	}
	// Strictly descending: each rung must outrank the next.
	for i := 0; i+1 < len(ranks); i++ {
		if policyAttentionRank(ranks[i].repo) <= policyAttentionRank(ranks[i+1].repo) {
			t.Errorf("%s (%d) must outrank %s (%d)",
				ranks[i].name, policyAttentionRank(ranks[i].repo),
				ranks[i+1].name, policyAttentionRank(ranks[i+1].repo))
		}
	}

	// An unreadable config outranks a compliant override on purpose: an unknown
	// is not a pass.
	if policyAttentionRank(unreadable) <= policyAttentionRank(stricter) {
		t.Error("an unreadable config must outrank a stricter override")
	}
}

func TestPolicySpecResponseNeverEmitsNullLists(t *testing.T) {
	t.Parallel()

	// A null list renders as an error client-side, and an org policy with no
	// deny list is a legitimate state.
	response := policySpecResponse(license.Spec{DenyUnknown: true})
	if response.DenyCategories == nil || response.Deny == nil || response.Allow == nil || response.ExemptPurls == nil {
		t.Fatalf("null list in %+v", response)
	}
	if response.Evaluate != license.EvaluateNew {
		t.Errorf("evaluate = %q, want the delta-scoped default", response.Evaluate)
	}
}

func TestValidLicenseCategory(t *testing.T) {
	t.Parallel()

	for _, category := range license.Categories() {
		if !validLicenseCategory(string(category)) {
			t.Errorf("%q must be accepted", category)
		}
	}
	// Case and padding are tolerated; nonsense is not, so a typo cannot sit in
	// the database silently matching nothing.
	if !validLicenseCategory("  COPYLEFT ") {
		t.Error("category validation must tolerate case and padding")
	}
	for _, invalid := range []string{"", "copyleftt", "gpl", "permissive-ish"} {
		if validLicenseCategory(invalid) {
			t.Errorf("%q must be rejected", invalid)
		}
	}
}

// An empty repo list must not be readable as "no overrides" when the scan was
// never run. That distinction is the difference between an all-clear and no data.
func TestOrgLicensePolicyRepoScanIsOptIn(t *testing.T) {
	t.Parallel()

	srv, org, _, member := newDiscoveryTestServer(t)
	call := func(query string) orgLicensePolicyResponse {
		t.Helper()
		req := newOrgRequest(t, member, http.MethodGet, "/api/v1/orgs/github/"+org.Slug+"/licenses/policy"+query, "github", org.Slug)
		recorder := httptest.NewRecorder()
		srv.handleGetOrgLicensePolicy(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", recorder.Code, recorder.Body.String())
		}
		var envelope struct {
			Data orgLicensePolicyResponse `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return envelope.Data
	}

	if response := call(""); response.ReposScanned {
		t.Error("the forge fan-out must not run without being asked for")
	}
	if response := call("?include_repos=true"); !response.ReposScanned {
		t.Error("include_repos=true must run the scan")
	}
	// A malformed value must not trigger the expensive path.
	for _, query := range []string{"?include_repos", "?include_repos=maybe", "?include_repos=0", "?include_repos=false"} {
		if response := call(query); response.ReposScanned {
			t.Errorf("%q must not trigger the scan", query)
		}
	}
}

// The simulator must produce the number the gate would produce, which means
// evaluating the policy rather than summing category tiles — those disagree on
// OR expressions on purpose.
func TestSimulateLicensePolicy(t *testing.T) {
	t.Parallel()

	repoA, repoB := uuid.New(), uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoA: {repo: &store.Repository{ID: repoA, Slug: "alpha", Name: "Alpha"}, snapshot: &store.Snapshot{Status: "complete"}},
		repoB: {repo: &store.Repository{ID: repoB, Slug: "beta", Name: "Beta"}, snapshot: &store.Snapshot{Status: "complete"}},
	}
	row := func(repoID uuid.UUID, purl string, licenses ...string) dbgen.ListComponentLicensesBySnapshotsRow {
		return dbgen.ListComponentLicensesBySnapshotsRow{
			RepoID: repoID, ID: uuid.New(), Purl: purl, Name: purl, Version: "1.0.0", Ecosystem: "npm", Licenses: licenses,
		}
	}
	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		row(repoA, "pkg:npm/mit", "MIT"),
		row(repoA, "pkg:npm/gpl", "GPL-3.0-only"),
		row(repoB, "pkg:npm/gpl", "GPL-3.0-only"), // shared: one component, two repos
		row(repoB, "pkg:npm/agpl", "AGPL-3.0-only"),
		row(repoA, "pkg:npm/mystery"),                      // no metadata
		row(repoA, "pkg:npm/dual", "MIT OR GPL-3.0-only"),  // elective
		row(repoA, "pkg:npm/eslint-thing", "GPL-3.0-only"), // exemption candidate
	}

	// An empty policy flags nothing, whatever the inventory looks like.
	empty := simulateLicensePolicy(rows, repos, license.Spec{DenyUnknown: false})
	if empty.ComponentsFlagged != 0 {
		t.Errorf("an empty policy must flag nothing, got %d", empty.ComponentsFlagged)
	}
	// Six distinct components from seven rows: pkg:npm/gpl is in both repos at
	// the same version and counts once org-wide.
	if empty.ComponentsTotal != 6 {
		t.Errorf("components_total = %d, want 6 (deduped by purl@version)", empty.ComponentsTotal)
	}

	spec := license.Spec{DenyCategories: []string{"copyleft", "network-copyleft"}, DenyUnknown: true}
	result := simulateLicensePolicy(rows, repos, spec)

	// gpl, agpl, mystery, eslint-thing = 4. mit passes; dual passes because OR
	// lets the consumer pick MIT — the distinction a tile-summing simulator
	// would get wrong.
	if result.ComponentsFlagged != 4 {
		t.Errorf("flagged = %d, want 4: %+v", result.ComponentsFlagged, result.Licenses)
	}
	if result.ReposTotal != 2 {
		t.Errorf("repos_total = %d, want 2", result.ReposTotal)
	}

	byRepo := make(map[string]int)
	for _, repo := range result.Repos {
		byRepo[repo.Slug] = repo.Count
	}
	// alpha: gpl, mystery, eslint-thing. beta: gpl, agpl.
	if byRepo["alpha"] != 3 || byRepo["beta"] != 2 {
		t.Errorf("per-repo counts = %+v, want alpha 3 / beta 2", byRepo)
	}
	// Worst first.
	if result.Repos[0].Slug != "alpha" {
		t.Errorf("repos[0] = %q, want alpha", result.Repos[0].Slug)
	}

	// A missing license is named as such, not as a license called "".
	var undeclared bool
	for _, stat := range result.Licenses {
		if stat.License == "no license metadata" {
			undeclared = true
		}
		if stat.License == "" {
			t.Error("an empty license name leaked into the simulation")
		}
	}
	if !undeclared {
		t.Errorf("the undeclared component must be attributed: %+v", result.Licenses)
	}

	// Exemptions reduce the flagged count and are reported, so the effect of the
	// list is visible rather than inferred.
	spec.ExemptPurls = []string{"pkg:npm/eslint-*"}
	exempted := simulateLicensePolicy(rows, repos, spec)
	if exempted.ComponentsFlagged != 3 {
		t.Errorf("flagged with exemption = %d, want 3", exempted.ComponentsFlagged)
	}
	if exempted.Exempted != 1 {
		t.Errorf("exempted = %d, want 1", exempted.Exempted)
	}
	if count := repoCount(exempted.Repos, "alpha"); count != 2 {
		t.Errorf("alpha count with exemption = %d, want 2", count)
	}

	// An allow entry clears the id everywhere.
	allowed := simulateLicensePolicy(rows, repos, license.Spec{
		DenyCategories: []string{"copyleft", "network-copyleft"},
		Allow:          []string{"GPL-3.0-only"},
		DenyUnknown:    true,
	})
	// agpl + mystery remain.
	if allowed.ComponentsFlagged != 2 {
		t.Errorf("flagged with allow = %d, want 2: %+v", allowed.ComponentsFlagged, allowed.Licenses)
	}

	// Repos with nothing flagged are omitted rather than listed as zeroes.
	onlyBeta := simulateLicensePolicy(rows, repos, license.Spec{DenyCategories: []string{"network-copyleft"}})
	if len(onlyBeta.Repos) != 1 || onlyBeta.Repos[0].Slug != "beta" {
		t.Errorf("repos = %+v, want only beta", onlyBeta.Repos)
	}
}

func repoCount(repos []orgLicenseSimulationRepo, slug string) int {
	for _, repo := range repos {
		if repo.Slug == slug {
			return repo.Count
		}
	}
	return 0
}

// The drilldown is paginated, and its rows are built from a Go map, whose
// iteration order is randomized. If the comparator leaves any two rows tied, a
// stable sort preserves that random order and the page boundaries move between
// identical requests — a component then shows up on two pages, or on none.
//
// Two components sharing a name and a version is not contrived: it is the same
// package present in two ecosystems.
func TestBuildOrgLicenseComponentsOrderingIsDeterministic(t *testing.T) {
	t.Parallel()

	repoID := uuid.New()
	repos := map[uuid.UUID]orgRepoSnapshot{
		repoID: {repo: &store.Repository{ID: repoID, Slug: "r"}, snapshot: &store.Snapshot{Status: "complete"}},
	}
	// Same Name, same Version, same category, same repo count — tied on every
	// field the comparator looked at before Purl.
	rows := []dbgen.ListComponentLicensesBySnapshotsRow{
		{RepoID: repoID, ID: uuid.New(), Purl: "pkg:npm/bar", Name: "bar", Version: "1.0.0", Licenses: []string{"MIT"}},
		{RepoID: repoID, ID: uuid.New(), Purl: "pkg:maven/org.example/bar", Name: "bar", Version: "1.0.0", Licenses: []string{"MIT"}},
		{RepoID: repoID, ID: uuid.New(), Purl: "pkg:golang/bar", Name: "bar", Version: "1.0.0", Licenses: []string{"MIT"}},
	}

	first := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{})
	if len(first) != 3 {
		t.Fatalf("rows = %d, want 3", len(first))
	}

	// Repeat enough times that map-order randomness would show up.
	for attempt := 0; attempt < 200; attempt++ {
		got := buildOrgLicenseComponents(rows, repos, orgLicenseComponentFilter{})
		for i := range got {
			if got[i].Purl != first[i].Purl {
				t.Fatalf("attempt %d position %d = %q, want %q — ordering is not deterministic",
					attempt, i, got[i].Purl, first[i].Purl)
			}
		}
	}

	// And the order is the documented one: ascending purl among equals.
	if first[0].Purl != "pkg:golang/bar" || first[2].Purl != "pkg:npm/bar" {
		t.Errorf("order = %q, want ascending purl", []string{first[0].Purl, first[1].Purl, first[2].Purl})
	}
}
