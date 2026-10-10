package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type cweFixture struct {
	db         *sql.DB
	queries    *Queries
	repoID     uuid.UUID
	snapshotID uuid.UUID
	ruleID     uuid.UUID
	userID     uuid.UUID
	// Findings by role.
	sast, sastNoRule, sastResultTaxa, sastDeclared, dependency, secret, manual uuid.UUID
}

// One finding per CWE source of the finding_cwes view, plus the negative
// cases: a declaration on a scanner finding (ignored) and a finding with no
// CWE at all.
func newCWEFixture(t *testing.T) cweFixture {
	t.Helper()
	db := openStoreTestDB(t, "cwe model")
	queries := NewQueries(db)
	ctx := context.Background()
	f := cweFixture{db: db, queries: queries}

	org, err := queries.CreateOrganization(ctx, uniqueStoreTestName(t, "org"), uniqueStoreTestName(t, "org"), "CWE Org", "github")
	if err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	repo, err := queries.CreateRepository(ctx, org.ID, nil, uniqueStoreTestName(t, "repo"), uniqueStoreTestName(t, "repo"), "github", uniqueStoreTestName(t, "pid"), "main", "enrolled")
	if err != nil {
		t.Fatalf("CreateRepository: %v", err)
	}
	f.repoID = repo.ID
	ref, err := queries.CreateRef(ctx, repo.ID, "main", RefTypeBranch, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreateRef: %v", err)
	}
	snapshot, err := queries.CreateSnapshot(ctx, ref.ID, "abc123", SnapshotStatusComplete)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	f.snapshotID = snapshot.ID
	user, err := queries.CreateUser(ctx, uniqueStoreTestName(t, "u")+"@example.test", "Author", "github", uniqueStoreTestName(t, "uid"))
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	f.userID = user.ID

	tool := uniqueStoreTestName(t, "gosec")
	f.ruleID, err = queries.UpsertScanRule(ctx, dbgen.UpsertScanRuleParams{Tool: tool, RuleID: "G201", Tags: []string{}, Properties: []byte(`{}`)})
	if err != nil {
		t.Fatalf("UpsertScanRule: %v", err)
	}
	if err := queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{f.ruleID: {89}}); err != nil {
		t.Fatalf("SyncScanRuleCWEs: %v", err)
	}
	advisory, err := upsertRatedAdvisory(ctx, queries, dbgen.UpsertAdvisoryParams{CanonicalID: "CVE-2099-" + uuid.NewString()[:8], Title: "xss"}, dbgen.SetAdvisoryRatingParams{Severity: dbgen.SeverityLevelHigh})
	if err != nil {
		t.Fatalf("UpsertAdvisory: %v", err)
	}
	if err := queries.AddAdvisoryCWEs(ctx, advisory.ID, []int{79}); err != nil {
		t.Fatalf("AddAdvisoryCWEs: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM advisories WHERE id = $1`, advisory.ID) })

	create := func(kind, fingerprint string, mutate func(*dbgen.CreateVulnerabilityParams)) uuid.UUID {
		params := dbgen.CreateVulnerabilityParams{
			Type: kind, SnapshotID: snapshot.ID, Title: fingerprint, Fingerprint: fingerprint,
			OriginalSeverity: dbgen.SeverityLevelHigh, Severity: dbgen.SeverityLevelHigh, Status: "detected",
			Metadata: []byte(`{}`),
		}
		if mutate != nil {
			mutate(&params)
		}
		vulnerability, err := queries.CreateVulnerability(ctx, params)
		if err != nil {
			t.Fatalf("CreateVulnerability(%s): %v", fingerprint, err)
		}
		return vulnerability.ID
	}
	withRule := func(p *dbgen.CreateVulnerabilityParams) { p.RuleRefID = uuid.NullUUID{UUID: f.ruleID, Valid: true} }
	f.sast = create("sast", "fp-sast", withRule)
	f.sastNoRule = create("sast", "fp-sast-norule", nil)
	f.sastResultTaxa = create("sast", "fp-sast-taxa", withRule)
	f.sastDeclared = create("sast", "fp-sast-declared", nil)
	f.dependency = create("dependency", "fp-dep", func(p *dbgen.CreateVulnerabilityParams) {
		p.AdvisoryID = uuid.NullUUID{UUID: advisory.ID, Valid: true}
	})
	f.secret = create("secret", "fp-secret", nil)
	f.manual = create("manual", "fp-manual", func(p *dbgen.CreateVulnerabilityParams) {
		p.CreatedBy = uuid.NullUUID{UUID: user.ID, Valid: true}
		p.Origin = dbgen.FindingOriginHuman
	})

	if err := queries.ReplaceSnapshotSARIFResultCWEs(ctx, snapshot.ID, []string{"fp-sast", "fp-sast-taxa"}, map[string][]int{"fp-sast-taxa": {1321}}); err != nil {
		t.Fatalf("ReplaceSnapshotSARIFResultCWEs: %v", err)
	}
	by := FindingCWEDeclarer{UserID: uuid.NullUUID{UUID: user.ID, Valid: true}}
	if err := queries.ReplaceDeclaredFindingCWEs(ctx, repo.ID, "fp-manual", []int{22}, by); err != nil {
		t.Fatalf("ReplaceDeclaredFindingCWEs(manual): %v", err)
	}
	// Declared on a scanner finding: stored, but the view must ignore it.
	if err := queries.ReplaceDeclaredFindingCWEs(ctx, repo.ID, "fp-sast-declared", []int{352}, by); err != nil {
		t.Fatalf("ReplaceDeclaredFindingCWEs(sast): %v", err)
	}
	return f
}

func TestFindingCWEsResolveEverySource(t *testing.T) {
	f := newCWEFixture(t)
	got, err := f.queries.ListFindingCWEs(context.Background(), []uuid.UUID{f.sast, f.sastNoRule, f.sastResultTaxa, f.sastDeclared, f.dependency, f.secret, f.manual})
	if err != nil {
		t.Fatalf("ListFindingCWEs: %v", err)
	}
	want := map[uuid.UUID][]int{
		f.sast:           {89},
		f.sastResultTaxa: {89, 1321},
		f.dependency:     {79},
		f.secret:         {798},
		f.manual:         {22},
	}
	for id, ids := range want {
		if actual := cweIDs(got[id]); !slices.Equal(actual, ids) {
			t.Errorf("finding %s: CWEs = %v, want %v", id, actual, ids)
		}
	}
	for _, id := range []uuid.UUID{f.sastNoRule, f.sastDeclared} {
		if len(got[id]) != 0 {
			t.Errorf("finding %s must carry no CWE, got %v", id, cweIDs(got[id]))
		}
	}
	if sql := got[f.sast][0]; sql.Source != FindingCWESourceRule || sql.Name == "" {
		t.Errorf("rule CWE = %+v, want source rule with a catalog title", sql)
	}
	if manual := got[f.manual][0]; manual.Source != FindingCWESourceDeclared {
		t.Errorf("manual CWE source = %q", manual.Source)
	}
}

// The view (point reads), filterquery.CWESQL (filters) and findingCWERowsSQL
// (aggregation) encode the same four sources in three shapes for
// performance; this pins them to identical answers.
func TestFindingCWEFormsAgree(t *testing.T) {
	f := newCWEFixture(t)
	ctx := context.Background()

	// Ground truth: the view.
	viewRows := map[uuid.UUID][]int{}
	rows, err := f.db.QueryContext(ctx, `SELECT fc.vulnerability_id, fc.cwe_id FROM finding_cwes fc
		JOIN vulnerabilities v ON v.id = fc.vulnerability_id WHERE v.snapshot_id = $1`, f.snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id uuid.UUID
		var cweID int
		if err := rows.Scan(&id, &cweID); err != nil {
			t.Fatal(err)
		}
		viewRows[id] = append(viewRows[id], cweID)
	}
	rows.Close()

	allIDs := []uuid.UUID{f.sast, f.sastNoRule, f.sastResultTaxa, f.sastDeclared, f.dependency, f.secret, f.manual}
	for _, query := range []string{"cwe:89", "cwe:79", "cwe:798", "cwe:22", "cwe:1321", "cwe:352", "cwe-tree:74", "cwe-set:owasp-a03", "cwe:none", "cwe:any", "cwe:79,none"} {
		node, err := filterquery.Parse(query)
		if err != nil {
			t.Fatalf("Parse(%q): %v", query, err)
		}
		compiled, err := filterquery.ToSQL(node, 2)
		if err != nil {
			t.Fatalf("ToSQL(%q): %v", query, err)
		}
		listed, _, err := f.queries.ListVulnerabilitiesBySnapshotDynamicWithFilters(ctx, f.snapshotID, compiled.Where, compiled.Params, "", false, "", 100, 0)
		if err != nil {
			t.Fatalf("list %q: %v", query, err)
		}
		got := map[uuid.UUID]bool{}
		for _, vulnerability := range listed {
			got[vulnerability.ID] = true
		}
		qualifier := node.(filterquery.QualifierNode)
		selector, err := cwe.ParseSelector(qualifier.Key, splitForTest(qualifier.Value))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range allIDs {
			if want := selector.Matches(viewRows[id]); got[id] != want {
				t.Errorf("%s: finding with CWEs %v matched=%v, view says %v", query, viewRows[id], got[id], want)
			}
		}
	}

	// Aggregation form vs the view, through the facet.
	facets, err := f.queries.FacetVulnerabilitiesBySnapshot(ctx, f.snapshotID, VulnerabilityListOptions{})
	if err != nil {
		t.Fatalf("FacetVulnerabilitiesBySnapshot: %v", err)
	}
	wantFacet := map[string]int{}
	for _, ids := range viewRows {
		for _, id := range ids {
			wantFacet[strconv.Itoa(id)]++
		}
	}
	if fmt.Sprint(facets.CWE) != fmt.Sprint(wantFacet) {
		t.Fatalf("cwe facet = %v, view counts = %v", facets.CWE, wantFacet)
	}

	// A filterquery expression scopes the facet like the list.
	node, _ := filterquery.Parse("type:dependency")
	scoped, err := f.queries.FacetVulnerabilitiesBySnapshot(ctx, f.snapshotID, VulnerabilityListOptions{Filter: node})
	if err != nil {
		t.Fatalf("scoped facet: %v", err)
	}
	if fmt.Sprint(scoped.CWE) != "map[79:1]" {
		t.Fatalf("scoped cwe facet = %v, want only the dependency's CWE-79", scoped.CWE)
	}
}

// Re-ingesting an unchanged scan must write nothing (xmin unchanged); a
// changed set removes and adds only the difference.
func TestCWESyncWritesOnlyChanges(t *testing.T) {
	f := newCWEFixture(t)
	ctx := context.Background()
	xmin := func() map[int]string {
		out := map[int]string{}
		rows, err := f.db.QueryContext(ctx, `SELECT cwe_id, xmin::text FROM scan_rule_cwes WHERE scan_rule_id = $1`, f.ruleID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id int
			var version string
			if err := rows.Scan(&id, &version); err != nil {
				t.Fatal(err)
			}
			out[id] = version
		}
		return out
	}

	if err := f.queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{f.ruleID: {89, 564}}); err != nil {
		t.Fatal(err)
	}
	before := xmin()
	if err := f.queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{f.ruleID: {89, 564}}); err != nil {
		t.Fatal(err)
	}
	if after := xmin(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("unchanged resync rewrote rows: %v → %v", before, after)
	}
	if err := f.queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{f.ruleID: {564, 943}}); err != nil {
		t.Fatal(err)
	}
	after := xmin()
	if len(after) != 2 || after[564] != before[564] || after[943] == "" {
		t.Fatalf("changed sync = %v (before %v); want 564 untouched, 89 gone, 943 added", after, before)
	}
	if err := f.queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{f.ruleID: nil}); err != nil {
		t.Fatal(err)
	}
	if after := xmin(); len(after) != 0 {
		t.Fatalf("empty set must clear the rule, got %v", after)
	}

	// SARIF result taxa: a fingerprint that stops listing a taxon loses it.
	if err := f.queries.ReplaceSnapshotSARIFResultCWEs(ctx, f.snapshotID, []string{"fp-sast-taxa"}, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM finding_cwe_assertions WHERE repo_id = $1 AND source = 'sarif_result'`, f.repoID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale sarif_result rows: %d", count)
	}

	// A declaration needs a principal; the schema also rejects one on SARIF rows.
	if err := f.queries.ReplaceDeclaredFindingCWEs(ctx, f.repoID, "fp-manual", []int{22}, FindingCWEDeclarer{}); err == nil {
		t.Fatal("declaration without a principal accepted")
	}
	if _, err := f.db.ExecContext(ctx, `INSERT INTO finding_cwe_assertions (repo_id, fingerprint, cwe_id, source, declared_by) VALUES ($1, 'x', 1, 'sarif_result', $2)`, f.repoID, f.userID); err == nil {
		t.Fatal("sarif_result row with a principal accepted")
	}
}

func cweIDs(cwes []FindingCWE) []int {
	out := make([]int, 0, len(cwes))
	for _, item := range cwes {
		out = append(out, item.ID)
	}
	sort.Ints(out)
	return out
}

func splitForTest(value string) []string {
	out := []string{}
	start := 0
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == ',' {
			out = append(out, value[start:index])
			start = index + 1
		}
	}
	return out
}

func TestListCWEUsage(t *testing.T) {
	f := newCWEFixture(t)
	report, err := f.queries.ListCWEUsage(context.Background(), []uuid.UUID{f.snapshotID}, nil)
	if err != nil {
		t.Fatalf("ListCWEUsage: %v", err)
	}
	got := map[int]CWEUsage{}
	for _, usage := range report.CWEs {
		got[usage.ID] = usage
	}
	for id, want := range map[int]int{89: 2, 1321: 1, 79: 1, 798: 1, 22: 1} {
		if got[id].Total != want {
			t.Errorf("CWE-%d total = %d, want %d", id, got[id].Total, want)
		}
	}
	if got[89].ByType["sast"] != 2 || got[89].Category == nil || got[89].Category.Slug != "injection" || got[89].MaxSeverity != "high" {
		t.Errorf("CWE-89 usage = %+v", got[89])
	}
	if got[79].ByType["dependency"] != 1 {
		t.Errorf("CWE-79 must count the dependency finding: %+v", got[79])
	}
	if report.CWEs[0].ID != 89 {
		t.Errorf("list must sort by total: first is CWE-%d", report.CWEs[0].ID)
	}
	if report.NoCWE != 2 || report.TotalFindings != 7 {
		t.Errorf("coverage = %d without CWE of %d, want 2 of 7", report.NoCWE, report.TotalFindings)
	}

	node, _ := filterquery.Parse("type:dependency")
	scoped, err := f.queries.ListCWEUsage(context.Background(), []uuid.UUID{f.snapshotID}, node)
	if err != nil {
		t.Fatalf("scoped ListCWEUsage: %v", err)
	}
	if len(scoped.CWEs) != 1 || scoped.CWEs[0].ID != 79 || scoped.TotalFindings != 1 || scoped.NoCWE != 0 {
		t.Errorf("scoped usage = %+v", scoped)
	}
}

// The CWE tab's "Code" link: a CWE minus dependency-shaped findings.
func TestCWEFilterWithExclusion(t *testing.T) {
	f := newCWEFixture(t)
	ctx := context.Background()
	count := func(query string) int {
		node, err := filterquery.Parse(query)
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := filterquery.ToSQL(node, 2)
		if err != nil {
			t.Fatal(err)
		}
		_, total, err := f.queries.ListVulnerabilitiesBySnapshotDynamicWithFilters(ctx, f.snapshotID, compiled.Where, compiled.Params, "", false, "", 100, 0)
		if err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return total
	}
	for query, want := range map[string]int{
		"cwe:89 -type:dependency,container,malware": 2, // both SAST rows
		"cwe:79 -type:dependency,container,malware": 0, // only the dependency carries 79
		"cwe:79 type:dependency,container,malware":  1,
		"-cwe:none": 5, // same as cwe:any
	} {
		if got := count(query); got != want {
			t.Errorf("%s: %d findings, want %d", query, got, want)
		}
	}
}
