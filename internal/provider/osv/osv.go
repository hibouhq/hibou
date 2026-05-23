package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/advisory"
	"github.com/hibouhq/lehibou/internal/provider"
	"github.com/hibouhq/lehibou/internal/version"
)

const (
	defaultBaseURL = "https://api.osv.dev"
	batchSize      = 1000
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
	"deb":       "Debian",
	"apk":       "Alpine",
}

var rpmOSVEcosystems = []string{"Red Hat", "Rocky Linux", "AlmaLinux", "SUSE"}

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
	Package queryPackage    `json:"package"`
	Ranges  []affectedRange `json:"ranges"`
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
	return []string{"go", "npm", "pypi", "maven", "cargo", "nuget", "rubygems", "packagist", "deb", "apk", "rpm"}
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
	reqBody := queryBatchRequest{Queries: make([]osvQuery, 0, len(queries))}
	expandedQueries := make([]provider.PackageQuery, 0, len(queries))
	for _, query := range queries {
		osvEcosystems, ok := toOSVEcosystems(query.Ecosystem)
		if !ok {
			return nil, fmt.Errorf("osv: unsupported ecosystem %q", query.Ecosystem)
		}
		for _, osvEcosystem := range osvEcosystems {
			reqBody.Queries = append(reqBody.Queries, osvQuery{
				Package: queryPackage{Name: query.Name, Ecosystem: osvEcosystem},
			})
			expandedQueries = append(expandedQueries, provider.PackageQuery{
				Ecosystem: strings.ToLower(strings.TrimSpace(query.Ecosystem)),
				Name:      query.Name,
				Version:   query.Version,
			})
		}
	}

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
	if len(batchResp.Results) != len(expandedQueries) {
		return nil, fmt.Errorf("osv: unexpected result count %d for %d queries", len(batchResp.Results), len(expandedQueries))
	}

	results := make([]provider.AdvisoryResult, 0)
	rpmResults := make([]provider.AdvisoryResult, 0)
	for idx, result := range batchResp.Results {
		for _, vuln := range result.Vulns {
			mapped, err := mapVulnerability(vuln)
			if err != nil {
				return nil, err
			}
			if resultMatchesPackageQuery(expandedQueries[idx], mapped) {
				if expandedQueries[idx].Ecosystem == "rpm" {
					rpmResults = append(rpmResults, mapped)
					continue
				}
				results = append(results, mapped)
			}
		}
	}
	results = append(results, dedupeAdvisoryResultsByID(rpmResults)...)

	return results, nil
}

func toOSVEcosystems(ecosystem string) ([]string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(ecosystem))
	if normalized == "rpm" {
		return rpmOSVEcosystems, true
	}
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

	severity, cvssScore, cvssVersion, cvssVector := parseCVSS(vuln.Severity)
	if severity == nil {
		severity = normalizeDBSeverity(vuln.DatabaseSpecific.Severity)
	}

	result := provider.AdvisoryResult{
		ProviderName:   "osv",
		ProviderID:     vuln.ID,
		Aliases:        append([]string(nil), vuln.Aliases...),
		Title:          vuln.Summary,
		Description:    vuln.Details,
		Severity:       severity,
		CVSSScore:      cvssScore,
		CVSSVersion:    cvssVersion,
		CVSSVector:     cvssVector,
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

func parseCVSS(entries []severityEntry) (*advisory.Severity, *float64, *advisory.CVSSVersion, string) {
	var preferred *severityEntry
	for i := range entries {
		entry := &entries[i]
		switch strings.ToUpper(entry.Type) {
		case "CVSS_V3", "CVSS_V31", "CVSS_V30", "CVSS_V4":
			preferred = entry
			goto done
		case "CVSS_V2":
			if preferred == nil {
				preferred = entry
			}
		}
	}

done:
	if preferred == nil {
		return nil, nil, nil, ""
	}

	version := detectCVSSVersion(preferred.Type, preferred.Score)
	vector := ""
	if strings.Contains(preferred.Score, "/") || strings.HasPrefix(strings.ToUpper(preferred.Score), "CVSS:") {
		vector = preferred.Score
	}

	if score, err := strconv.ParseFloat(preferred.Score, 64); err == nil {
		sev := advisory.NormalizeSeverity(score)
		return &sev, &score, version, vector
	}

	return nil, nil, version, vector
}

func detectCVSSVersion(severityType, score string) *advisory.CVSSVersion {
	scoreUpper := strings.ToUpper(score)
	var version advisory.CVSSVersion
	switch {
	case strings.HasPrefix(scoreUpper, "CVSS:4.0/") || strings.EqualFold(severityType, "CVSS_V4"):
		version = advisory.CVSSVersionV40
	case strings.HasPrefix(scoreUpper, "CVSS:3.1/") || strings.EqualFold(severityType, "CVSS_V31"):
		version = advisory.CVSSVersionV31
	case strings.HasPrefix(scoreUpper, "CVSS:3.0/") || strings.EqualFold(severityType, "CVSS_V30"):
		version = advisory.CVSSVersionV30
	case strings.EqualFold(severityType, "CVSS_V3"):
		version = advisory.CVSSVersionV31
	case strings.EqualFold(severityType, "CVSS_V2"):
		version = advisory.CVSSVersionV2
	default:
		return nil
	}
	return &version
}

func normalizeDBSeverity(raw string) *advisory.Severity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		severity := advisory.SeverityCritical
		return &severity
	case "high":
		severity := advisory.SeverityHigh
		return &severity
	case "medium", "moderate":
		severity := advisory.SeverityMedium
		return &severity
	case "low":
		severity := advisory.SeverityLow
		return &severity
	case "info", "informational":
		severity := advisory.SeverityInfo
		return &severity
	default:
		return nil
	}
}

func mapAffectedRanges(affected []affectedPackage) []advisory.AffectedRange {
	ranges := make([]advisory.AffectedRange, 0)
	for _, pkg := range affected {
		ecosystem := normalizeOSVEcosystem(pkg.Package.Ecosystem)
		for _, osvRange := range pkg.Ranges {
			if !strings.EqualFold(osvRange.Type, "ECOSYSTEM") {
				continue
			}

			introduced := ""
			for _, event := range osvRange.Events {
				if event.Introduced != "" {
					introduced = event.Introduced
					continue
				}

				if event.Fixed != "" || event.LastAffected != "" {
					ranges = append(ranges, advisory.AffectedRange{
						Ecosystem:    ecosystem,
						PackageName:  pkg.Package.Name,
						Introduced:   introduced,
						Fixed:        event.Fixed,
						LastAffected: event.LastAffected,
						Source:       "osv",
					})
					introduced = ""
				}
			}

			if introduced != "" {
				ranges = append(ranges, advisory.AffectedRange{
					Ecosystem:   ecosystem,
					PackageName: pkg.Package.Name,
					Introduced:  introduced,
					Source:      "osv",
				})
			}
		}
	}

	return ranges
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
