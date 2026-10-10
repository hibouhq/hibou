package store

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// findingCWEKeyColumns are the vulnerabilities columns findingCWERowsSQL
// needs from its input relation.
const findingCWEKeyColumns = "v.id, v.rule_ref_id, v.advisory_id, v.repo_id, v.fingerprint, v.type, v.severity"

// findingCWERowsSQL yields (id, cwe_id) rows for every finding in relation
// (which exposes findingCWEKeyColumns), with the finding_cwes view's four
// branches. It is the set-oriented form of the view for aggregation over a
// whole filtered snapshot: each branch is one hash join against a claim
// table, where joining the view would re-read vulnerabilities per branch.
// TestFindingCWEFormsAgree keeps it, the view and filterquery.CWESQL in step.
//
// Rows also carry the finding's type and severity, for per-CWE breakdowns.
// Measured on 100k findings in one snapshot: ~0.4 s, against ~7 s for the
// same aggregate joined through the view.
func findingCWERowsSQL(relation string) string {
	return fmt.Sprintf(`SELECT %[1]s.id, rc.cwe_id, %[1]s.type, %[1]s.severity FROM %[1]s JOIN scan_rule_cwes rc ON rc.scan_rule_id = %[1]s.rule_ref_id
UNION ALL SELECT %[1]s.id, ac.cwe_id, %[1]s.type, %[1]s.severity FROM %[1]s JOIN advisory_cwes ac ON ac.advisory_id = %[1]s.advisory_id
UNION ALL SELECT %[1]s.id, fa.cwe_id, %[1]s.type, %[1]s.severity FROM %[1]s JOIN finding_cwe_assertions fa ON fa.repo_id = %[1]s.repo_id AND fa.fingerprint = %[1]s.fingerprint
  WHERE fa.source = 'sarif_result' OR %[1]s.type = 'manual'
UNION ALL SELECT %[1]s.id, 798, %[1]s.type, %[1]s.severity FROM %[1]s WHERE %[1]s.type = 'secret'`, relation)
}

// CWEUsage is one CWE present in a scope of findings (the CWE list).
type CWEUsage struct {
	ID          int          `json:"id"`
	Name        string       `json:"name"`
	Abstraction string       `json:"abstraction,omitempty"`
	Deprecated  bool         `json:"deprecated,omitempty"`
	Category    *cwe.SetRef  `json:"category,omitempty"`
	Sets        []cwe.SetRef `json:"sets,omitempty"`
	// Descendants counts the View 1000 sub-types a cwe-tree: query adds.
	Descendants int            `json:"descendants"`
	Total       int            `json:"total"`
	ByType      map[string]int `json:"by_type"`
	MaxSeverity string         `json:"max_severity"`
}

// CWEUsageReport is the CWE list for a scope: every CWE present, plus how
// many findings in scope carry none (coverage gaps the list must not hide).
type CWEUsageReport struct {
	CWEs          []CWEUsage `json:"cwes"`
	NoCWE         int        `json:"no_cwe"`
	TotalFindings int        `json:"total_findings"`
}

var severityOrder = map[string]int{"critical": 6, "high": 5, "medium": 4, "unknown": 3, "low": 2, "info": 1}

// ListCWEUsage aggregates the CWEs carried by findings in snapshotIDs. A
// filter (the bar's q) scopes it exactly like the list; without one, open
// findings (status detected) are counted, the list's own default.
func (q *Queries) ListCWEUsage(ctx context.Context, snapshotIDs []uuid.UUID, filter filterquery.Node) (*CWEUsageReport, error) {
	report := &CWEUsageReport{CWEs: []CWEUsage{}}
	if len(snapshotIDs) == 0 {
		return report, nil
	}
	args := []interface{}{pq.Array(snapshotIDs)}
	from := "vulnerabilities v"
	where := "v.snapshot_id = ANY($1)"
	if filter != nil {
		compiled, err := filterquery.ToSQL(filter, 2)
		if err != nil {
			return nil, err
		}
		// filterquery may reference the acceptance/dispute aliases.
		from += "\n" + acceptanceJoinClause
		where += " AND " + compiled.Where
		args = append(args, compiled.Params...)
	} else {
		where += " AND v.status = 'detected'"
	}

	// #nosec G201 -- from/where are constant fragments or filterquery output; values are positional.
	rows, err := q.sqlDB.QueryContext(ctx, fmt.Sprintf(`WITH f AS (SELECT %s FROM %s WHERE %s)
SELECT x.cwe_id, x.type::text, x.severity::text, COUNT(DISTINCT x.id)::bigint FROM (%s) x
GROUP BY x.cwe_id, x.type, x.severity`, findingCWEKeyColumns, from, where, findingCWERowsSQL("f")), args...)
	if err != nil {
		return nil, fmt.Errorf("aggregate cwe usage: %w", err)
	}
	defer rows.Close()
	catalog := cwe.Default()
	byID := map[int]*CWEUsage{}
	for rows.Next() {
		var id int
		var kind, severity string
		var count int64
		if err := rows.Scan(&id, &kind, &severity, &count); err != nil {
			return nil, err
		}
		usage, ok := byID[id]
		if !ok {
			entry, _ := catalog.Lookup(id)
			usage = &CWEUsage{
				ID: id, Name: entry.Name, Abstraction: entry.Abstraction, Deprecated: entry.Deprecated(),
				Category: catalog.CategoryRef(id), Sets: catalog.SetRefs(id), ByType: map[string]int{},
				Descendants: len(catalog.Descendants(id)) - 1,
			}
			byID[id] = usage
		}
		// A finding is counted once per (cwe, type, severity) group, and a
		// finding has one type and one severity, so sums stay distinct.
		usage.Total += int(count)
		usage.ByType[kind] += int(count)
		if severityOrder[severity] > severityOrder[usage.MaxSeverity] {
			usage.MaxSeverity = severity
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, usage := range byID {
		report.CWEs = append(report.CWEs, *usage)
	}
	sort.Slice(report.CWEs, func(i, j int) bool {
		if report.CWEs[i].Total != report.CWEs[j].Total {
			return report.CWEs[i].Total > report.CWEs[j].Total
		}
		return report.CWEs[i].ID < report.CWEs[j].ID
	})

	none, _, _ := filterquery.CWESQL("v", cwe.Selector{None: true}, len(args)+1)
	// #nosec G201 -- constant fragments; values are positional.
	countSQL := fmt.Sprintf(`SELECT COUNT(*)::bigint, COUNT(*) FILTER (WHERE %s)::bigint FROM %s WHERE %s`, none, from, where)
	var total, noCWE int64
	if err := q.sqlDB.QueryRowContext(ctx, countSQL, args...).Scan(&total, &noCWE); err != nil {
		return nil, fmt.Errorf("count cwe coverage: %w", err)
	}
	report.TotalFindings = int(total)
	report.NoCWE = int(noCWE)
	return report, nil
}

// FindingCWESource says where a finding's CWE came from (ADR-037 §4).
type FindingCWESource string

const (
	FindingCWESourceRule        FindingCWESource = "rule"
	FindingCWESourceAdvisory    FindingCWESource = "advisory"
	FindingCWESourceSARIFResult FindingCWESource = "sarif_result"
	FindingCWESourceDeclared    FindingCWESource = "declared"
	FindingCWESourceType        FindingCWESource = "type"
)

// FindingCWE is one CWE a finding carries, resolved against the catalog.
type FindingCWE struct {
	ID          int              `json:"id"`
	Name        string           `json:"name"`
	Abstraction string           `json:"abstraction,omitempty"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Source      FindingCWESource `json:"source"`
	// Category is the MITRE View 1400 category (Injection, Encryption, …).
	Category *cwe.SetRef `json:"category,omitempty"`
	// Sets are the named sets (Top 25, OWASP) the CWE belongs to; filled on
	// the finding detail only, from the in-memory catalog.
	Sets []cwe.SetRef `json:"sets,omitempty"`
}

// AttachFindingCWEs sets each finding's CWEs from one batched lookup, the
// way KEV and FixedInPRs are attached per page.
func (q *Queries) AttachFindingCWEs(ctx context.Context, vulnerabilities []Vulnerability) error {
	if len(vulnerabilities) == 0 {
		return nil
	}
	ids := make([]uuid.UUID, 0, len(vulnerabilities))
	for _, vulnerability := range vulnerabilities {
		ids = append(ids, vulnerability.ID)
	}
	byFinding, err := q.ListFindingCWEs(ctx, ids)
	if err != nil {
		return err
	}
	for index := range vulnerabilities {
		cwes := byFinding[vulnerabilities[index].ID]
		if cwes == nil {
			// An empty list, not null: "no CWE" is an answer the UI renders.
			cwes = []FindingCWE{}
		}
		vulnerabilities[index].CWEs = cwes
	}
	return nil
}

// ListFindingCWEs returns the CWEs of each finding, deduplicated by id (the
// first source wins: rule, advisory, SARIF result, declaration, type), with
// titles from the embedded catalog.
func (q *Queries) ListFindingCWEs(ctx context.Context, vulnerabilityIDs []uuid.UUID) (map[uuid.UUID][]FindingCWE, error) {
	out := make(map[uuid.UUID][]FindingCWE, len(vulnerabilityIDs))
	if len(vulnerabilityIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.ListFindingCWEs(ctx, vulnerabilityIDs)
	if err != nil {
		return nil, fmt.Errorf("list finding cwes: %w", err)
	}
	catalog := cwe.Default()
	seen := make(map[uuid.UUID]map[int]struct{}, len(vulnerabilityIDs))
	for _, row := range rows {
		id := int(row.CweID)
		if seen[row.VulnerabilityID] == nil {
			seen[row.VulnerabilityID] = map[int]struct{}{}
		}
		if _, dup := seen[row.VulnerabilityID][id]; dup {
			continue
		}
		seen[row.VulnerabilityID][id] = struct{}{}
		entry, _ := catalog.Lookup(id)
		out[row.VulnerabilityID] = append(out[row.VulnerabilityID], FindingCWE{
			ID:          id,
			Name:        entry.Name,
			Abstraction: entry.Abstraction,
			Deprecated:  entry.Deprecated(),
			Source:      FindingCWESource(row.Source),
			Category:    catalog.CategoryRef(id),
		})
	}
	return out, nil
}

// SyncScanRuleCWEs makes each rule in byRule carry exactly its CWEs (an
// empty list clears it): the scanner's current definition is authoritative.
// One statement for a whole artifact, writing nothing when unchanged.
func (q *Queries) SyncScanRuleCWEs(ctx context.Context, byRule map[uuid.UUID][]int) error {
	if len(byRule) == 0 {
		return nil
	}
	ruleIDs := make([]uuid.UUID, 0, len(byRule))
	pairRules := make([]uuid.UUID, 0, len(byRule))
	pairCWEs := make([]int32, 0, len(byRule))
	for ruleID, ids := range byRule {
		ruleIDs = append(ruleIDs, ruleID)
		for _, id := range toInt32s(ids) {
			pairRules = append(pairRules, ruleID)
			pairCWEs = append(pairCWEs, id)
		}
	}
	return q.db.SyncScanRuleCWEs(ctx, dbgen.SyncScanRuleCWEsParams{RuleIds: ruleIDs, PairRuleIds: pairRules, PairCweIds: pairCWEs})
}

// AddAdvisoryCWEs unions ids into the advisory's CWE set.
func (q *Queries) AddAdvisoryCWEs(ctx context.Context, advisoryID uuid.UUID, ids []int) error {
	if len(ids) == 0 {
		return nil
	}
	return q.db.AddAdvisoryCWEs(ctx, dbgen.AddAdvisoryCWEsParams{AdvisoryID: advisoryID, CweIds: toInt32s(ids)})
}

// ListAdvisoryCWEs returns each advisory's CWE ids.
func (q *Queries) ListAdvisoryCWEs(ctx context.Context, advisoryIDs []uuid.UUID) (map[uuid.UUID][]int, error) {
	out := make(map[uuid.UUID][]int, len(advisoryIDs))
	if len(advisoryIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.ListAdvisoryCWEs(ctx, advisoryIDs)
	if err != nil {
		return nil, fmt.Errorf("list advisory cwes: %w", err)
	}
	for _, row := range rows {
		out[row.AdvisoryID] = append(out[row.AdvisoryID], int(row.CweID))
	}
	return out, nil
}

// ListScanRuleCWEs returns each scan rule's CWE ids.
func (q *Queries) ListScanRuleCWEs(ctx context.Context, scanRuleIDs []uuid.UUID) (map[uuid.UUID][]int, error) {
	out := make(map[uuid.UUID][]int, len(scanRuleIDs))
	if len(scanRuleIDs) == 0 {
		return out, nil
	}
	rows, err := q.db.ListScanRuleCWEs(ctx, scanRuleIDs)
	if err != nil {
		return nil, fmt.Errorf("list scan rule cwes: %w", err)
	}
	for _, row := range rows {
		out[row.ScanRuleID] = append(out[row.ScanRuleID], int(row.CweID))
	}
	return out, nil
}

// ListCVERecordCWEs returns a CVE feed record's CWE ids.
func (q *Queries) ListCVERecordCWEs(ctx context.Context, cveID string) ([]int, error) {
	rows, err := q.db.ListCVERecordCWEs(ctx, cveID)
	if err != nil {
		return nil, fmt.Errorf("list cve record cwes: %w", err)
	}
	return fromInt32s(rows), nil
}

// FindingCWEDeclarer is the accountable principal of a declared CWE set
// (00009 origin rule): a user, an API token, or both.
type FindingCWEDeclarer struct {
	UserID   uuid.NullUUID
	APIKeyID uuid.NullUUID
}

// ReplaceDeclaredFindingCWEs makes ids the author-declared CWE set of a
// manual finding. Only manual findings read declarations (the finding_cwes
// view); a surviving pair keeps its original declarer.
func (q *Queries) ReplaceDeclaredFindingCWEs(ctx context.Context, repoID uuid.UUID, fingerprint string, ids []int, by FindingCWEDeclarer) error {
	if !by.UserID.Valid && !by.APIKeyID.Valid {
		return errors.New("declared cwes need an accountable principal")
	}
	return q.db.SyncDeclaredFindingCWEs(ctx, dbgen.SyncDeclaredFindingCWEsParams{
		RepoID:           repoID,
		Fingerprint:      fingerprint,
		CweIds:           toInt32s(ids),
		DeclaredBy:       by.UserID,
		DeclaredApiKeyID: by.APIKeyID,
	})
}

// ReplaceSnapshotSARIFResultCWEs makes every fingerprint one artifact
// reports carry exactly the CWEs its SARIF result.taxa list (ADR-037 §2.2),
// clearing them for fingerprints that no longer list any.
func (q *Queries) ReplaceSnapshotSARIFResultCWEs(ctx context.Context, snapshotID uuid.UUID, fingerprints []string, cwes map[string][]int) error {
	if len(fingerprints) == 0 {
		return nil
	}
	pairFingerprints := make([]string, 0, len(cwes))
	pairCWEs := make([]int32, 0, len(cwes))
	// A fingerprint repeats when one artifact reports it twice; pair it once.
	paired := make(map[string]struct{}, len(cwes))
	for _, fingerprint := range fingerprints {
		if _, done := paired[fingerprint]; done {
			continue
		}
		paired[fingerprint] = struct{}{}
		for _, id := range toInt32s(cwes[fingerprint]) {
			pairFingerprints = append(pairFingerprints, fingerprint)
			pairCWEs = append(pairCWEs, id)
		}
	}
	return q.db.SyncSnapshotSARIFResultCWEs(ctx, dbgen.SyncSnapshotSARIFResultCWEsParams{
		SnapshotID:       snapshotID,
		Fingerprints:     fingerprints,
		PairFingerprints: pairFingerprints,
		PairCweIds:       pairCWEs,
	})
}

func toInt32s(ids []int) []int32 {
	out := make([]int32, 0, len(ids))
	for _, id := range cwe.Dedupe(ids) {
		out = append(out, int32(id)) // #nosec G115 -- cwe.Parse bounds ids far below int32 max.
	}
	return out
}

func fromInt32s(ids []int32) []int {
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		out = append(out, int(id))
	}
	return out
}
