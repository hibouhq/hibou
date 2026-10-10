package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/distro"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/version"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	batchSize      = 1000
	hydrateWorkers = 8
)

var internalToOSVEcosystem = map[string]string{
	"go":        "Go",
	"npm":       "npm",
	"pypi":      "PyPI",
	"maven":     "Maven",
	"cargo":     "crates.io",
	"nuget":     "NuGet",
	"rubygems":  "RubyGems",
	"packagist": "Packagist",
}

var osvToInternalEcosystem = map[string]string{
	"Go":          "go",
	"npm":         "npm",
	"PyPI":        "pypi",
	"Maven":       "maven",
	"crates.io":   "cargo",
	"NuGet":       "nuget",
	"RubyGems":    "rubygems",
	"Packagist":   "packagist",
	"Debian":      "deb",
	"Alpine":      "apk",
	"Rocky Linux": "rpm",
	"AlmaLinux":   "rpm",
	"SUSE":        "rpm",
	"Red Hat":     "rpm",
}

type Provider struct {
	baseURL    string
	httpClient *http.Client
	log        zerolog.Logger
}

type queryBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package queryPackage `json:"package"`
	Version string       `json:"version,omitempty"`
}

type queryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type queryBatchResponse struct {
	Results []queryResult `json:"results"`
}

type queryResult struct {
	Vulns []vulnerability `json:"vulns"`
}

type vulnerability struct {
	ID               string                  `json:"id"`
	Aliases          []string                `json:"aliases"`
	Summary          string                  `json:"summary"`
	Details          string                  `json:"details"`
	Severity         []severityEntry         `json:"severity"`
	Affected         []affectedPackage       `json:"affected"`
	Published        string                  `json:"published"`
	Modified         string                  `json:"modified"`
	Withdrawn        string                  `json:"withdrawn"`
	DatabaseSpecific vulnerabilityDBSpecific `json:"database_specific"`
}

type severityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type affectedPackage struct {
	Package           queryPackage       `json:"package"`
	Ranges            []affectedRange    `json:"ranges"`
	EcosystemSpecific *ecosystemSpecific `json:"ecosystem_specific"`
}

// ecosystemSpecific carries Go's vulnerable-symbol declarations
// (affected[].ecosystem_specific.imports[].symbols in the OSV schema).
type ecosystemSpecific struct {
	Imports []ecosystemImport `json:"imports"`
}

type ecosystemImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

type affectedRange struct {
	Type   string       `json:"type"`
	Events []rangeEvent `json:"events"`
}

type rangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
}

type vulnerabilityDBSpecific struct {
	Severity    string   `json:"severity"`
	Type        string   `json:"type"`
	MalwareType string   `json:"malware_type"`
	CWEIDs      []string `json:"cwe_ids"`
}

func New(baseURL string, log zerolog.Logger) *Provider {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}

	return &Provider{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		log: log,
	}
}

func (p *Provider) Name() string {
	return "osv"
}

func (p *Provider) SupportedEcosystems() []string {
	// rpm is deliberately absent: OSV's Red Hat-family data carries stream
	// qualifiers that cannot be matched to purl distro releases; the Trivy
	// provider owns rpm. apk/deb are queried release-qualified via the distro
	// package and require the component's distro qualifier.
	return []string{"go", "npm", "pypi", "maven", "cargo", "nuget", "rubygems", "packagist", "deb", "apk"}
}

func (p *Provider) BatchSize() int {
	return batchSize
}

// QueryPackages returns all advisories for queried packages regardless of version.
// Version matching is performed downstream by the scan orchestrator.
func (p *Provider) QueryPackages(ctx context.Context, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	var allResults []provider.AdvisoryResult
	for start := 0; start < len(queries); start += p.BatchSize() {
		end := start + p.BatchSize()
		if end > len(queries) {
			end = len(queries)
		}

		results, err := p.queryBatch(ctx, queries[start:end])
		if err != nil {
			return nil, err
		}
		allResults = append(allResults, results...)
	}

	return allResults, nil
}

func (p *Provider) queryBatch(ctx context.Context, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	reqBody, expandedQueries, err := buildOSVBatchRequest(queries)
	if err != nil {
		return nil, err
	}
	if len(expandedQueries) == 0 {
		return nil, nil
	}
	batchResp, err := p.executeQueryBatch(ctx, reqBody, len(expandedQueries))
	if err != nil {
		return nil, err
	}
	hydrated, err := p.hydrateVulns(ctx, batchResp)
	if err != nil {
		return nil, err
	}
	return collectBatchResults(batchResp, expandedQueries, hydrated)
}

func buildOSVBatchRequest(queries []provider.PackageQuery) (queryBatchRequest, []provider.PackageQuery, error) {
	reqBody := queryBatchRequest{Queries: make([]osvQuery, 0, len(queries))}
	expandedQueries := make([]provider.PackageQuery, 0, len(queries))
	for _, query := range queries {
		var osvEcosystems []string
		if distro.IsDistroEcosystem(query.Ecosystem) {
			// Distro advisories are release-scoped; without the component's
			// release a bare-ecosystem query returns ranges from every release
			// and guarantees false positives. Fail closed instead.
			qualified, ok := distro.OSVEcosystemFor(query.Ecosystem, query.Distro)
			if !ok {
				continue
			}
			osvEcosystems = []string{qualified}
		} else if mapped, ok := toOSVEcosystems(query.Ecosystem); ok {
			osvEcosystems = mapped
		} else {
			// Unknown/unsupported ecosystem: skip this package entirely instead of
			// failing the whole batch. It simply yields no advisories.
			continue
		}
		for _, osvEcosystem := range osvEcosystems {
			// Version deliberately omitted: all of the package's advisories are
			// fetched and their ranges stored, and the vulnerability matcher does
			// the version comparison. OSV's server-side matching would also choke
			// on RPM epoch formats.
			reqBody.Queries = append(reqBody.Queries, osvQuery{Package: queryPackage{Name: query.Name, Ecosystem: osvEcosystem}})
			expandedQueries = append(expandedQueries, provider.PackageQuery{
				Ecosystem: strings.ToLower(strings.TrimSpace(query.Ecosystem)),
				Name:      query.Name,
				Version:   query.Version,
			})
		}
	}
	return reqBody, expandedQueries, nil
}

func (p *Provider) executeQueryBatch(ctx context.Context, reqBody queryBatchRequest, expectedResults int) (*queryBatchResponse, error) {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("osv: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/querybatch", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("osv: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: query packages: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: query packages returned status %d", resp.StatusCode)
	}
	var batchResp queryBatchResponse
	limitedBody := io.LimitReader(resp.Body, 50<<20)
	if err := json.NewDecoder(limitedBody).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("osv: decode response: %w", err)
	}
	if len(batchResp.Results) != expectedResults {
		return nil, fmt.Errorf("osv: unexpected result count %d for %d queries", len(batchResp.Results), expectedResults)
	}
	return &batchResp, nil
}

// ErrVulnNotFound reports that OSV serves no record under an ID.
var ErrVulnNotFound = errors.New("osv: vulnerability not found")

func (p *Provider) fetchVuln(ctx context.Context, id string) (vulnerability, error) {
	// baseURL is operator-configured and id is path-escaped, so neither the host
	// nor the scheme can be influenced by the OSV response payload.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/v1/vulns/"+url.PathEscape(id), nil) //nolint:gosec // trusted operator-configured baseURL with path-escaped id
	if err != nil {
		return vulnerability{}, fmt.Errorf("osv: create vuln request: %w", err)
	}
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := p.httpClient.Do(req) //nolint:gosec // request built from trusted baseURL with path-escaped id
	if err != nil {
		return vulnerability{}, fmt.Errorf("osv: fetch vuln %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// Distinguished from a failure on purpose: OSV not having a record is
		// the ordinary answer for a CPE-only advisory, and a caller that counted
		// it as an error would report every such advisory as a broken lookup.
		return vulnerability{}, ErrVulnNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return vulnerability{}, fmt.Errorf("osv: fetch vuln %s returned status %d", id, resp.StatusCode)
	}
	var vuln vulnerability
	limitedBody := io.LimitReader(resp.Body, 10<<20)
	if err := json.NewDecoder(limitedBody).Decode(&vuln); err != nil {
		return vulnerability{}, fmt.Errorf("osv: decode vuln %s: %w", id, err)
	}
	return vuln, nil
}

func uniqueVulnIDs(batchResp *queryBatchResponse) []string {
	seen := make(map[string]struct{})
	ids := make([]string, 0)
	for _, result := range batchResp.Results {
		for _, vuln := range result.Vulns {
			if vuln.ID == "" {
				continue
			}
			if _, ok := seen[vuln.ID]; ok {
				continue
			}
			seen[vuln.ID] = struct{}{}
			ids = append(ids, vuln.ID)
		}
	}
	return ids
}

func (p *Provider) hydrateVulns(ctx context.Context, batchResp *queryBatchResponse) (map[string]vulnerability, error) {
	ids := uniqueVulnIDs(batchResp)
	hydrated := make(map[string]vulnerability, len(ids))
	if len(ids) == 0 {
		return hydrated, nil
	}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	sem := make(chan struct{}, hydrateWorkers)
	for _, id := range ids {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(id string) {
			defer wg.Done()
			defer func() { <-sem }()

			vuln, err := p.fetchVuln(ctx, id)
			if err != nil {
				p.log.Warn().Err(err).Str("vuln_id", id).Msg("osv: skip vuln that failed to hydrate")
				return
			}

			mu.Lock()
			hydrated[id] = vuln
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return hydrated, nil
}

func collectBatchResults(batchResp *queryBatchResponse, expandedQueries []provider.PackageQuery, hydrated map[string]vulnerability) ([]provider.AdvisoryResult, error) {
	results := make([]provider.AdvisoryResult, 0)
	rpmResults := make([]provider.AdvisoryResult, 0)
	for idx, result := range batchResp.Results {
		mapped, rpmMapped, err := collectQueryResultMatches(result, expandedQueries[idx], hydrated)
		if err != nil {
			return nil, err
		}
		results = append(results, mapped...)
		rpmResults = append(rpmResults, rpmMapped...)
	}
	results = append(results, dedupeAdvisoryResultsByID(rpmResults)...)
	return results, nil
}

func collectQueryResultMatches(result queryResult, query provider.PackageQuery, hydrated map[string]vulnerability) ([]provider.AdvisoryResult, []provider.AdvisoryResult, error) {
	results := make([]provider.AdvisoryResult, 0, len(result.Vulns))
	rpmResults := make([]provider.AdvisoryResult, 0)
	for _, vuln := range result.Vulns {
		full, ok := hydrated[vuln.ID]
		if !ok {
			continue
		}
		mapped, err := mapVulnerability(full)
		if err != nil {
			return nil, nil, err
		}
		if !resultMatchesPackageQuery(query, mapped) {
			continue
		}
		if query.Ecosystem == "rpm" {
			rpmResults = append(rpmResults, mapped)
			continue
		}
		results = append(results, mapped)
	}
	return results, rpmResults, nil
}

func toOSVEcosystems(ecosystem string) ([]string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(ecosystem))
	mapped, ok := internalToOSVEcosystem[normalized]
	if !ok {
		return nil, false
	}
	return []string{mapped}, true
}

func mapVulnerability(vuln vulnerability) (provider.AdvisoryResult, error) {
	rawData, err := json.Marshal(vuln)
	if err != nil {
		return provider.AdvisoryResult{}, fmt.Errorf("osv: marshal raw vulnerability %s: %w", vuln.ID, err)
	}

	result := provider.AdvisoryResult{
		ProviderName:   "osv",
		ProviderID:     vuln.ID,
		Aliases:        append([]string(nil), vuln.Aliases...),
		Title:          vuln.Summary,
		Description:    vuln.Details,
		Ratings:        ratingsFor(vuln),
		CWEIDs:         append([]string(nil), vuln.DatabaseSpecific.CWEIDs...),
		AffectedRanges: mapAffectedRanges(vuln.Affected),
		RawData:        rawData,
	}

	if publishedAt, ok := parseTimestamp(vuln.Published); ok {
		result.PublishedAt = publishedAt
	}
	if withdrawnAt, ok := parseTimestamp(vuln.Withdrawn); ok {
		result.WithdrawnAt = withdrawnAt
	}

	if isMalware(vuln) {
		result.IsMalware = true
		if vuln.DatabaseSpecific.MalwareType != "" {
			malwareType := vuln.DatabaseSpecific.MalwareType
			result.MalwareType = &malwareType
		}
	}

	return result, nil
}

// RatingsFromRaw rebuilds a stored record's ratings (ADR-038 §8): raw_data
// is the record as mapVulnerability received it.
func RatingsFromRaw(raw json.RawMessage) ([]advisory.Rating, error) {
	var vuln vulnerability
	if err := json.Unmarshal(raw, &vuln); err != nil {
		return nil, fmt.Errorf("osv: decode stored record: %w", err)
	}
	return ratingsFor(vuln), nil
}

// ratingsFor maps every severity statement of a record (ADR-038 §2). The OSV
// schema makes severity[].score a CVSS vector, never a number: scoring it is
// internal/cvss's job. The rater is the database that published the record;
// GitHub's database_specific.severity is that rater's own label.
func ratingsFor(vuln vulnerability) []advisory.Rating {
	rater := raterFor(vuln.ID)
	ratings := make([]advisory.Rating, 0, len(vuln.Severity)+1)
	for _, entry := range vuln.Severity {
		score := strings.TrimSpace(entry.Score)
		switch strings.ToUpper(entry.Type) {
		case "CVSS_V2", "CVSS_V3", "CVSS_V4":
			var supplied *float64
			if value, err := strconv.ParseFloat(score, 64); err == nil {
				supplied, score = &value, ""
			}
			if rating, ok := advisory.NewRating(rater, score, supplied, nil); ok {
				if rating.Version == nil {
					// A bare number: only the entry type says which version.
					rating.Version = versionForType(entry.Type)
				}
				ratings = append(ratings, rating)
			}
		case "UBUNTU":
			// Ubuntu's priority word ("negligible" ... "critical").
			if rating, ok := advisory.NewRating("ubuntu", "", nil, advisory.ParseLabel(score)); ok {
				ratings = append(ratings, rating)
			}
		}
	}
	if label := advisory.ParseLabel(vuln.DatabaseSpecific.Severity); label != nil {
		if rating, ok := advisory.NewRating(rater, "", nil, label); ok {
			ratings = append(ratings, rating)
		}
	}
	return ratings
}

func versionForType(severityType string) *advisory.CVSSVersion {
	var version advisory.CVSSVersion
	switch strings.ToUpper(severityType) {
	case "CVSS_V2":
		version = advisory.CVSSVersionV2
	case "CVSS_V3":
		version = advisory.CVSSVersionV31
	case "CVSS_V4":
		version = advisory.CVSSVersionV40
	default:
		return nil
	}
	return &version
}

// raterFor names who published an OSV record, from its ID prefix.
func raterFor(id string) string {
	prefix, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(id)), "-")
	switch prefix {
	case "GHSA":
		return "ghsa"
	case "PYSEC":
		return "pypa"
	case "CVE":
		return "nvd"
	case "DSA", "DLA", "DTSA", "DEBIAN":
		return "debian"
	case "UBUNTU", "USN":
		return "ubuntu"
	case "RHSA", "RHBA", "RHEA":
		return "redhat"
	case "ALSA":
		return "alma"
	case "RLSA":
		return "rocky"
	case "MAL":
		return "ossf"
	}
	return strings.ToLower(prefix)
}

func mapAffectedRanges(affected []affectedPackage) []advisory.AffectedRange {
	ranges := make([]advisory.AffectedRange, 0)
	for _, pkg := range affected {
		ranges = append(ranges, mapAffectedPackageRanges(pkg)...)
	}

	return ranges
}

func mapAffectedPackageRanges(pkg affectedPackage) []advisory.AffectedRange {
	ecosystem := normalizeOSVEcosystem(pkg.Package.Ecosystem)
	release := ""
	if internalEco, rel, ok := distro.ParseOSVEcosystem(pkg.Package.Ecosystem); ok {
		ecosystem, release = internalEco, rel
	} else if distro.IsDistroEcosystem(ecosystem) {
		// Bare or stream-qualified distro ecosystem: no release to scope by, so
		// the range cannot be matched safely. Drop it (see google/osv.dev#5199 —
		// distro records also ship introduced:0, which turns an unscoped range
		// into a match for every version).
		return nil
	}
	// Vulnerable symbols, qualified by import path ("gopkg.in/yaml.v2.Unmarshal",
	// "path.Type.Method") — the key the reachability inventory also speaks.
	symbols := []string{}
	if pkg.EcosystemSpecific != nil {
		for _, imported := range pkg.EcosystemSpecific.Imports {
			path := strings.TrimSpace(imported.Path)
			if path == "" {
				path = pkg.Package.Name
			}
			for _, symbol := range imported.Symbols {
				if symbol = strings.TrimSpace(symbol); symbol != "" {
					symbols = append(symbols, path+"."+symbol)
				}
			}
		}
	}

	ranges := make([]advisory.AffectedRange, 0)
	for _, osvRange := range pkg.Ranges {
		// ECOSYSTEM and SEMVER both carry introduced/fixed version events; GHSA
		// uses SEMVER for npm/Go/cargo, so accepting only ECOSYSTEM silently
		// dropped nearly every advisory in those ecosystems. GIT ranges are
		// commit hashes, not versions, and stay excluded.
		if !strings.EqualFold(osvRange.Type, "ECOSYSTEM") && !strings.EqualFold(osvRange.Type, "SEMVER") {
			continue
		}
		for _, mapped := range mapAffectedRangeEvents(pkg.Package.Name, ecosystem, osvRange.Events) {
			// Distro records pair introduced:0 with a per-release fixed event; an
			// entry with no upper bound would match every version of the package
			// in that release forever. Language ecosystems legitimately use
			// open-ended ranges (unfixed advisories), so only distro ranges are
			// held to this.
			if release != "" && mapped.Fixed == "" && mapped.LastAffected == "" {
				continue
			}
			mapped.Release = release
			mapped.VulnerableSymbols = symbols
			ranges = append(ranges, mapped)
		}
	}
	return ranges
}

func mapAffectedRangeEvents(packageName, ecosystem string, events []rangeEvent) []advisory.AffectedRange {
	ranges := make([]advisory.AffectedRange, 0)
	introduced := ""
	for _, event := range events {
		if event.Introduced != "" {
			introduced = event.Introduced
			continue
		}
		if event.Fixed == "" && event.LastAffected == "" {
			continue
		}
		ranges = append(ranges, buildAffectedRange(packageName, ecosystem, introduced, event.Fixed, event.LastAffected))
		introduced = ""
	}
	if introduced != "" {
		ranges = append(ranges, buildAffectedRange(packageName, ecosystem, introduced, "", ""))
	}
	return ranges
}

func buildAffectedRange(packageName, ecosystem, introduced, fixed, lastAffected string) advisory.AffectedRange {
	return advisory.AffectedRange{
		Ecosystem:    ecosystem,
		PackageName:  packageName,
		Introduced:   introduced,
		Fixed:        fixed,
		LastAffected: lastAffected,
		Source:       "osv",
	}
}

func resultMatchesPackageQuery(query provider.PackageQuery, result provider.AdvisoryResult) bool {
	for _, affected := range result.AffectedRanges {
		if strings.EqualFold(affected.Ecosystem, query.Ecosystem) && affected.PackageName == query.Name {
			return true
		}
	}
	return false
}

func dedupeAdvisoryResultsByID(results []provider.AdvisoryResult) []provider.AdvisoryResult {
	if len(results) < 2 {
		return results
	}

	deduped := make([]provider.AdvisoryResult, 0, len(results))
	seen := make(map[string]bool, len(results))
	for _, result := range results {
		if result.ProviderID != "" {
			if seen[result.ProviderID] {
				continue
			}
			seen[result.ProviderID] = true
		}
		deduped = append(deduped, result)
	}

	return deduped
}

func normalizeOSVEcosystem(ecosystem string) string {
	if mapped, ok := osvToInternalEcosystem[ecosystem]; ok {
		return mapped
	}
	return strings.ToLower(strings.TrimSpace(ecosystem))
}

func parseTimestamp(value string) (*time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, false
	}
	return &parsed, true
}

func isMalware(vuln vulnerability) bool {
	if strings.HasPrefix(strings.ToUpper(vuln.ID), "MAL-") {
		return true
	}
	return strings.EqualFold(vuln.DatabaseSpecific.Type, "MALWARE")
}
