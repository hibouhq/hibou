// Package trivy implements an AdvisoryProvider backed by a Trivy server's Twirp
// API. Components are uploaded to the server's cache (PutArtifact + PutBlob) and
// scanned (Scanner.Scan); detected vulnerabilities are mapped into the canonical
// advisory model. Version matching is performed server-side by Trivy; we
// synthesize affected ranges so the downstream scan orchestrator attributes each
// advisory to the right package.
package trivy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/distro"
	"github.com/hibouhq/hibou/internal/provider"
	"github.com/hibouhq/hibou/internal/version"
	"github.com/hibouhq/hibou/internal/versioncmp"
)

const (
	defaultBaseURL    = "http://localhost:4954"
	blobSchemaVersion = 2
	scanTarget        = "hibou-components"
	batchSize         = 1000
	requestTimeout    = 120 * time.Second
)

// ecosystemToTrivyType maps our internal ecosystem identifiers to the Trivy
// language application type used in BlobInfo.Applications.
var ecosystemToTrivyType = map[string]string{
	"npm":       "npm",
	"pypi":      "pip",
	"maven":     "pom",
	"cargo":     "cargo",
	"nuget":     "nuget",
	"rubygems":  "bundler",
	"go":        "gomod",
	"golang":    "gomod",
	"packagist": "composer",
	"composer":  "composer",
}

// trivyTypeFilePath gives each Trivy application type a representative lock-file
// path. Trivy keys some library detectors off the file name.
var trivyTypeFilePath = map[string]string{
	"npm":      "package-lock.json",
	"pip":      "requirements.txt",
	"pom":      "pom.xml",
	"cargo":    "Cargo.lock",
	"nuget":    "packages.lock.json",
	"bundler":  "Gemfile.lock",
	"gomod":    "go.mod",
	"composer": "composer.lock",
}

// trivyTypeToEcosystem maps Trivy result types back to internal ecosystems, used
// as a fallback when a returned package cannot be matched to an input query.
var trivyTypeToEcosystem = map[string]string{
	"npm":        "npm",
	"pip":        "pypi",
	"python-pkg": "pypi",
	"pom":        "maven",
	"jar":        "maven",
	"gradle":     "maven",
	"cargo":      "cargo",
	"nuget":      "nuget",
	"bundler":    "rubygems",
	"gemspec":    "rubygems",
	"gomod":      "go",
	"gobinary":   "go",
	"composer":   "packagist",
}

// osFamilyToEcosystem maps Trivy OS result types / purl distro families to the
// internal distro ecosystem.
var osFamilyToEcosystem = map[string]string{
	"alpine":      "apk",
	"debian":      "deb",
	"ubuntu":      "deb",
	"redhat":      "rpm",
	"rhel":        "rpm",
	"centos":      "rpm",
	"rocky":       "rpm",
	"alma":        "rpm",
	"almalinux":   "rpm",
	"fedora":      "rpm",
	"oracle":      "rpm",
	"ol":          "rpm",
	"amazon":      "rpm",
	"suse":        "rpm",
	"opensuse":    "rpm",
	"photon":      "rpm",
	"azurelinux":  "rpm",
	"cbl-mariner": "rpm",
}

// resultTypeToUploadType normalizes the result types Trivy may report (including
// aliases such as python-pkg/jar/gemspec/gobinary) back to the application type
// we uploaded under, so query reattribution keyed on the upload type still hits.
var resultTypeToUploadType = map[string]string{
	"npm":        "npm",
	"pip":        "pip",
	"python-pkg": "pip",
	"pom":        "pom",
	"jar":        "pom",
	"gradle":     "pom",
	"cargo":      "cargo",
	"nuget":      "nuget",
	"bundler":    "bundler",
	"gemspec":    "bundler",
	"gomod":      "gomod",
	"gobinary":   "gomod",
	"composer":   "composer",
}

// Provider queries a Trivy server over its Twirp (JSON) API.
type Provider struct {
	baseURL    string
	httpClient *http.Client
	log        zerolog.Logger
}

// New constructs a Trivy provider pointed at the given server base URL.
func New(baseURL string, log zerolog.Logger) *Provider {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultBaseURL
	}
	return &Provider{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		httpClient: &http.Client{Timeout: requestTimeout},
		log:        log.With().Str("provider", "trivy").Logger(),
	}
}

func (p *Provider) Name() string { return "trivy" }

func (p *Provider) BatchSize() int { return batchSize }

func (p *Provider) SupportedEcosystems() []string {
	return []string{"npm", "pypi", "maven", "cargo", "nuget", "rubygems", "go", "packagist", "apk", "deb", "rpm"}
}

// QueryPackages uploads the queried packages to the Trivy server and returns the
// detected advisories. Unknown/unsupported ecosystems are skipped.
func (p *Provider) QueryPackages(ctx context.Context, queries []provider.PackageQuery) ([]provider.AdvisoryResult, error) {
	if len(queries) == 0 {
		return nil, nil
	}

	var results []provider.AdvisoryResult

	applications, queryRefs := buildApplications(queries)
	if len(applications) > 0 {
		blob := blobInfo{SchemaVersion: blobSchemaVersion, Applications: applications}
		resp, err := p.scanBlob(ctx, blob, []string{"library"})
		if err != nil {
			return nil, err
		}
		results = append(results, mapScanResponse(resp, queryRefs, "")...)
	}

	// OS packages: one artifact per distro release, because a blob carries a
	// single os identity and the server's detectors are release-aware.
	for _, group := range buildOSGroups(queries) {
		blob := blobInfo{
			SchemaVersion: blobSchemaVersion,
			OS:            &osInfo{Family: group.family, Name: group.version},
			PackageInfos:  []packageInfo{{Packages: group.packages}},
		}
		resp, err := p.scanBlob(ctx, blob, []string{"os"})
		if err != nil {
			return nil, err
		}
		results = append(results, mapScanResponse(resp, group.refs, group.releaseKey)...)
	}

	return results, nil
}

// scanBlob uploads a synthesized blob and scans it for vulnerabilities.
func (p *Provider) scanBlob(ctx context.Context, blob blobInfo, pkgTypes []string) (*scanResponse, error) {
	blobPayload, err := json.Marshal(blob)
	if err != nil {
		return nil, fmt.Errorf("trivy: marshal blob: %w", err)
	}
	diffID := digest(blobPayload)
	artifactID := digest([]byte(diffID))

	if err := p.putArtifact(ctx, artifactID); err != nil {
		return nil, err
	}
	if err := p.putBlob(ctx, diffID, blob); err != nil {
		return nil, err
	}
	return p.scan(ctx, artifactID, diffID, pkgTypes)
}

// osGroup is one distro release's worth of OS package queries.
type osGroup struct {
	family     string
	version    string
	releaseKey string
	packages   []osPkg
	refs       map[string]queryRef
}

// buildOSGroups partitions distro-ecosystem queries by (family, release).
// Queries whose purl carried no distro qualifier are skipped: without the
// release the scan result cannot be scoped and would risk false positives.
func buildOSGroups(queries []provider.PackageQuery) []osGroup {
	groups := make(map[string]*osGroup)
	order := make([]string, 0)
	for _, query := range queries {
		ecosystem := strings.ToLower(strings.TrimSpace(query.Ecosystem))
		if _, ok := osFamilyToEcosystem[familyOf(query.Distro)]; !ok || !distro.IsDistroEcosystem(ecosystem) {
			continue
		}
		family, version := splitDistroQualifier(query.Distro)
		if family == "" || version == "" || strings.TrimSpace(query.Name) == "" {
			continue
		}
		key := family + "\x00" + version
		group, ok := groups[key]
		if !ok {
			group = &osGroup{
				family:     family,
				version:    version,
				releaseKey: distro.ReleaseKey(ecosystem, version),
				refs:       make(map[string]queryRef),
			}
			groups[key] = group
			order = append(order, key)
		}
		group.packages = append(group.packages, buildOSPkg(ecosystem, query.Name, query.Version))
		group.refs[family+"\x00"+strings.ToLower(query.Name)] = queryRef{ecosystem: ecosystem, name: query.Name}
	}
	sort.Strings(order)
	out := make([]osGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	return out
}

func familyOf(distroQualifier string) string {
	family, _ := splitDistroQualifier(distroQualifier)
	return family
}

// splitDistroQualifier parses "alpine-3.18.4" into ("alpine", "3.18.4").
func splitDistroQualifier(value string) (string, string) {
	value = strings.ToLower(strings.TrimSpace(value))
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' && i > 0 && value[i-1] == '-' {
			return value[:i-1], value[i:]
		}
	}
	return "", ""
}

// buildOSPkg shapes one OS package for the blob. RPM versions carry
// epoch:version-release split into fields; apk and dpkg detectors take the
// full version string as-is. Source fields mirror the binary package so
// src-keyed detectors (Alpine secdb) still match.
func buildOSPkg(ecosystem, name, version string) osPkg {
	out := osPkg{Name: name, Version: version, SrcName: name, SrcVersion: version}
	if ecosystem != "rpm" {
		return out
	}
	rest := version
	if epochStr, tail, ok := strings.Cut(rest, ":"); ok {
		if epoch, err := strconv.Atoi(epochStr); err == nil {
			out.Epoch = epoch
			out.SrcEpoch = epoch
			rest = tail
		}
	}
	if idx := strings.LastIndex(rest, "-"); idx > 0 {
		out.Version, out.Release = rest[:idx], rest[idx+1:]
		out.SrcVersion, out.SrcRelease = out.Version, out.Release
	} else {
		out.Version, out.SrcVersion = rest, rest
	}
	return out
}

// queryRef records the originating query's internal ecosystem and exact package
// name so detected vulnerabilities can be re-associated to the query. Cache
// attribution requires an exact package-name match, so we never rely on the
// (possibly normalized) name Trivy echoes back.
type queryRef struct {
	ecosystem string
	name      string
}

// buildApplications groups queries into Trivy applications by language type and
// returns a lookup of (trivyType\x00lowerName) -> originating query reference so
// detected vulnerabilities can be attributed back to the query.
func buildApplications(queries []provider.PackageQuery) ([]application, map[string]queryRef) {
	packagesByType := make(map[string][]pkg)
	queryRefs := make(map[string]queryRef)
	typeOrder := make([]string, 0)

	for _, query := range queries {
		ecosystem := strings.ToLower(strings.TrimSpace(query.Ecosystem))
		trivyType, ok := ecosystemToTrivyType[ecosystem]
		if !ok || strings.TrimSpace(query.Name) == "" {
			continue
		}
		if _, seen := packagesByType[trivyType]; !seen {
			typeOrder = append(typeOrder, trivyType)
		}
		packagesByType[trivyType] = append(packagesByType[trivyType], pkg{Name: query.Name, Version: query.Version})
		queryRefs[trivyType+"\x00"+strings.ToLower(query.Name)] = queryRef{ecosystem: ecosystem, name: query.Name}
	}

	sort.Strings(typeOrder)
	applications := make([]application, 0, len(typeOrder))
	for _, trivyType := range typeOrder {
		applications = append(applications, application{
			Type:     trivyType,
			FilePath: trivyTypeFilePath[trivyType],
			Packages: packagesByType[trivyType],
		})
	}
	return applications, queryRefs
}

func (p *Provider) putArtifact(ctx context.Context, artifactID string) error {
	req := putArtifactRequest{ArtifactID: artifactID, ArtifactInfo: artifactInfo{SchemaVersion: 1}}
	return p.callTwirp(ctx, "trivy.cache.v1.Cache", "PutArtifact", req, nil)
}

func (p *Provider) putBlob(ctx context.Context, diffID string, blob blobInfo) error {
	req := putBlobRequest{DiffID: diffID, BlobInfo: blob}
	return p.callTwirp(ctx, "trivy.cache.v1.Cache", "PutBlob", req, nil)
}

func (p *Provider) scan(ctx context.Context, artifactID, diffID string, pkgTypes []string) (*scanResponse, error) {
	req := scanRequest{
		Target:     scanTarget,
		ArtifactID: artifactID,
		BlobIDs:    []string{diffID},
		Options:    scanOptions{PkgTypes: pkgTypes, Scanners: []string{"vuln"}},
	}
	var resp scanResponse
	if err := p.callTwirp(ctx, "trivy.scanner.v1.Scanner", "Scan", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// callTwirp issues a JSON Twirp request to {baseURL}/twirp/{service}/{method}.
// When out is nil the response body is discarded (for Empty responses).
func (p *Provider) callTwirp(ctx context.Context, service, method string, in, out any) error {
	payload, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("trivy: marshal %s request: %w", method, err)
	}
	url := p.baseURL + "/twirp/" + service + "/" + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("trivy: create %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hibou/"+version.Version)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("trivy: %s request: %w", method, err)
	}
	defer resp.Body.Close()

	body := io.LimitReader(resp.Body, 100<<20)
	if resp.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(body, 4<<10))
		return fmt.Errorf("trivy: %s returned status %d: %s", method, resp.StatusCode, strings.TrimSpace(string(message)))
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, body)
		return nil
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("trivy: decode %s response: %w", method, err)
	}
	return nil
}

func mapScanResponse(resp *scanResponse, queryRefs map[string]queryRef, release string) []provider.AdvisoryResult {
	if resp == nil {
		return nil
	}
	results := make([]provider.AdvisoryResult, 0)
	for _, result := range resp.Results {
		for _, vuln := range result.Vulnerabilities {
			mapped, ok := mapVulnerability(result.Type, vuln, queryRefs, release)
			if !ok {
				continue
			}
			results = append(results, mapped)
		}
	}
	return results
}

func mapVulnerability(resultType string, vuln trivyVulnerability, queryRefs map[string]queryRef, release string) (provider.AdvisoryResult, bool) {
	if strings.TrimSpace(vuln.VulnerabilityID) == "" || strings.TrimSpace(vuln.PkgName) == "" {
		return provider.AdvisoryResult{}, false
	}
	// Prefer the originating query's ecosystem and exact package name so the
	// downstream cache can re-associate the advisory; fall back to deriving from
	// the Trivy result type when the package was not part of our query set.
	uploadType := resultTypeToUploadType[resultType]
	if uploadType == "" {
		uploadType = resultType
	}
	var ecosystem string
	packageName := vuln.PkgName
	if ref, ok := queryRefs[uploadType+"\x00"+strings.ToLower(vuln.PkgName)]; ok {
		ecosystem = ref.ecosystem
		packageName = ref.name
	} else if eco, ok := trivyTypeToEcosystem[resultType]; ok {
		ecosystem = eco
	} else {
		ecosystem = osFamilyToEcosystem[strings.ToLower(resultType)]
	}
	if ecosystem == "" {
		return provider.AdvisoryResult{}, false
	}

	rawData, _ := json.Marshal(vuln)
	severity, cvssScore, cvssVersion, cvssVector := mapCVSS(vuln)

	result := provider.AdvisoryResult{
		ProviderName:   "trivy",
		ProviderID:     vuln.VulnerabilityID,
		Title:          vuln.Title,
		Description:    vuln.Description,
		Severity:       severity,
		CVSSScore:      cvssScore,
		CVSSVersion:    cvssVersion,
		CVSSVector:     cvssVector,
		CWEIDs:         append([]string(nil), vuln.CweIDs...),
		AffectedRanges: []advisory.AffectedRange{buildAffectedRange(ecosystem, packageName, release, vuln)},
		RawData:        rawData,
	}
	if publishedAt, ok := parseTimestamp(vuln.PublishedDate); ok {
		result.PublishedAt = publishedAt
	}
	return result, true
}

// buildAffectedRange synthesizes a range that matches the vulnerable version.
// When Trivy reports fixed version(s) we use [0, fixed) where fixed is the
// smallest fix strictly greater than the installed version (the correct upper
// bound for the installed version's release branch); otherwise we bound the
// range to the installed version so only that exact version is matched.
func buildAffectedRange(ecosystem, packageName, release string, vuln trivyVulnerability) advisory.AffectedRange {
	rng := advisory.AffectedRange{
		Ecosystem:   ecosystem,
		PackageName: packageName,
		Introduced:  "0",
		Source:      "trivy",
		Release:     release,
	}
	if fixed := selectFixedVersion(ecosystem, vuln.InstalledVersion, vuln.FixedVersion); fixed != "" {
		rng.Fixed = fixed
		return rng
	}
	rng.LastAffected = strings.TrimSpace(vuln.InstalledVersion)
	return rng
}

func mapCVSS(vuln trivyVulnerability) (*advisory.Severity, *float64, *advisory.CVSSVersion, string) {
	entry, ok := preferredCVSS(vuln.CVSS)
	severity := mapSeverity(vuln.Severity)
	if !ok {
		return severity, nil, nil, ""
	}
	if entry.V40Score > 0 {
		ver := advisory.CVSSVersionV40
		score := entry.V40Score
		return severityFromScore(severity, score), &score, &ver, entry.V40Vector
	}
	if entry.V3Score > 0 {
		ver := advisory.CVSSVersionV31
		score := entry.V3Score
		return severityFromScore(severity, score), &score, &ver, entry.V3Vector
	}
	if entry.V2Score > 0 {
		ver := advisory.CVSSVersionV2
		score := entry.V2Score
		return severityFromScore(severity, score), &score, &ver, entry.V2Vector
	}
	return severity, nil, nil, ""
}

// preferredCVSS picks a stable CVSS source, preferring nvd then redhat, then any.
func preferredCVSS(cvss map[string]trivyCVSS) (trivyCVSS, bool) {
	if len(cvss) == 0 {
		return trivyCVSS{}, false
	}
	for _, source := range []string{"nvd", "redhat", "ghsa"} {
		if entry, ok := cvss[source]; ok {
			return entry, true
		}
	}
	sources := make([]string, 0, len(cvss))
	for source := range cvss {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return cvss[sources[0]], true
}

func severityFromScore(fallback *advisory.Severity, score float64) *advisory.Severity {
	if score > 0 {
		sev := advisory.NormalizeSeverity(score)
		return &sev
	}
	return fallback
}

func mapSeverity(raw string) *advisory.Severity {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "CRITICAL":
		sev := advisory.SeverityCritical
		return &sev
	case "HIGH":
		sev := advisory.SeverityHigh
		return &sev
	case "MEDIUM":
		sev := advisory.SeverityMedium
		return &sev
	case "LOW":
		sev := advisory.SeverityLow
		return &sev
	default:
		return nil
	}
}

// selectFixedVersion chooses the fixed version to use as the exclusive upper
// bound. When the advisory lists multiple fix branches (e.g. "1.2.5, 2.0.1") we
// pick the smallest fix strictly greater than the installed version so the
// installed (vulnerable) version still falls inside [0, fixed). Falls back to the
// first listed version when comparison is not possible.
func selectFixedVersion(ecosystem, installed, rawFixed string) string {
	candidates := splitVersions(rawFixed)
	if len(candidates) == 0 {
		return ""
	}
	cmp, ok := versioncmp.Get(ecosystem)
	installed = strings.TrimSpace(installed)
	if !ok || installed == "" || !cmp.Valid(installed) {
		// Without a usable comparator we cannot reason about ordering; use the
		// first listed fix as a best effort.
		return candidates[0]
	}
	best := ""
	for _, candidate := range candidates {
		if !cmp.Valid(candidate) || cmp.Compare(candidate, installed) <= 0 {
			continue
		}
		if best == "" || cmp.Compare(candidate, best) < 0 {
			best = candidate
		}
	}
	// best may be empty when no fix is strictly greater than the installed
	// version. Returning "" makes the caller bound the range by LastAffected so
	// the installed (vulnerable) version still matches instead of being excluded
	// by a fixed bound at or below it.
	return best
}

// splitVersions splits a raw fixed-version string on commas/spaces and strips any
// range comparators (>=, >, <=, <, =, ^, ~, v) from each token.
func splitVersions(raw string) []string {
	versions := make([]string, 0)
	for _, candidate := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' }) {
		if cleaned := stripComparator(candidate); cleaned != "" {
			versions = append(versions, cleaned)
		}
	}
	return versions
}

// stripComparator removes leading range operators (>=, >, <=, <, =, ^, ~, v) that
// some advisory sources attach to fixed versions (e.g. ">=4.17.19"), leaving a
// bare version that versioncmp can parse.
func stripComparator(raw string) string {
	return strings.TrimLeft(strings.TrimSpace(raw), "<>=~^v ")
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

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
