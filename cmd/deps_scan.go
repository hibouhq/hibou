package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/advisorydb"
	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/depinventory"
)

// hibou deps scan (ADR-046 §2): local extraction, stateless matching.

var (
	scanImageRef   string
	scanGitRef     string
	scanOffline    bool
	scanFormat     string
	scanFilter     string
	scanSeverity   string
	scanKEVOnly    bool
	scanFixable    bool
	scanFailOn     string
	scanRelease    string
	scanExclude    []string
	scanQuiet      bool
	scanFailOnExit = 1
	// scanAdvisoryDB matches against an exported database instead of the
	// server (ADR-046 step 6).
	scanAdvisoryDB string
	// scanMavenCentral sends the SHA-1 of jars without Maven metadata to
	// Maven Central (opt-in: a hash leaves the machine).
	scanMavenCentral bool
	// scanNoAttachedSBOM skips the SBOMs the registry holds for an image.
	scanNoAttachedSBOM bool
)

var depsScanCmd = &cobra.Command{
	Use:   "deps scan [TARGET...]",
	Short: "Analyse a directory, lockfile, archive, binary or image locally; nothing is stored",
	Long: `Extracts the dependency inventory locally with the same library and rules
as the server, then asks the server which advisories, cooldowns and triage
decisions apply (purls and versions only; never file contents). Exit 0
whatever is found; --fail-on returns 1 when something matches; 2 on error.

Targets: a directory (default .), a lockfile or manifest, an archive
(jar/war/ear, zip, tar, tgz, wheel, nupkg), a binary, an SBOM file;
--image for a container image reference or tarball; --git-ref for a tag,
branch or commit of the local clone, checked out in a temporary worktree.

Examples:
  hibou deps scan
  hibou deps scan --git-ref v1.2.3
  hibou deps scan dist/app.war --repo api --release v1.2.3
  hibou deps scan --image registry.example/app:1.2.3 --format cyclonedx > app.cdx.json
  hibou deps scan --fail-on 'severity:critical shipped:yes'
  hibou deps scan --advisory-db advisories.ndjson    # air-gapped: hibou vulns db export wrote the file
  hibou deps scan dist/ --maven-central              # identify jars without metadata by SHA-1`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		report, err := runDepsScan(cmd.Context(), args)
		if err != nil {
			return exitError{code: 2, err: err}
		}
		if err := writeScanReport(os.Stdout, report, scanFormat); err != nil {
			return exitError{code: 2, err: err}
		}
		if scanFailOn != "" {
			filter, err := parseLocalFilter(scanFailOn)
			if err != nil {
				return exitError{code: 2, err: fmt.Errorf("--fail-on: %w", err)}
			}
			matched := 0
			for _, row := range report.Rows {
				if filter.matches(row) {
					matched++
				}
			}
			if matched > 0 {
				return exitError{code: scanFailOnExit, err: fmt.Errorf("%d component(s) match --fail-on %q", matched, scanFailOn)}
			}
		}
		return nil
	},
}

// exitError carries the exit code of ADR-046 §2: 1 for --fail-on, 2 for
// errors.
type exitError struct {
	code int
	err  error
}

func (e exitError) Error() string { return e.err.Error() }
func (e exitError) Unwrap() error { return e.err }

// ExitCode reports the process exit code an error asks for.
func ExitCode(err error) int {
	var exit exitError
	if errors.As(err, &exit) {
		return exit.code
	}
	if err != nil {
		return 1
	}
	return 0
}

func init() {
	depsScanCmd.Use = "scan [TARGET...]"
	depsScanCmd.Flags().StringVar(&scanImageRef, "image", "", "Container image reference or tarball (docker save / OCI layout) to analyse with your own registry credentials")
	depsScanCmd.Flags().StringVar(&scanGitRef, "git-ref", "", "Tag, branch or commit of the local clone to analyse in a temporary worktree")
	depsScanCmd.Flags().BoolVar(&scanOffline, "offline", false, "Inventory only: no server call, no vulnerabilities")
	depsScanCmd.Flags().StringVar(&scanFormat, "format", "table", "Output: table, json, cyclonedx, sarif")
	depsScanCmd.Flags().StringVar(&scanFilter, "filter", "", "Filter expression, e.g. 'severity:high shipped:yes relationship:direct'")
	depsScanCmd.Flags().StringVar(&scanSeverity, "severity", "", "Shortcut: keep components with a finding at or above this severity")
	depsScanCmd.Flags().BoolVar(&scanKEVOnly, "kev", false, "Shortcut: keep components with a known-exploited finding")
	depsScanCmd.Flags().BoolVar(&scanFixable, "fixable", false, "Shortcut: keep components with a finding that has a fix")
	depsScanCmd.Flags().StringVar(&scanFailOn, "fail-on", "", "Exit 1 when a component matches this filter, e.g. 'severity:critical shipped:yes' or 'cooldown:true'")
	depsScanCmd.Flags().StringVar(&scanRelease, "release", "", "Release version the scan is about (read-only context, named in the audit entry)")
	depsScanCmd.Flags().StringArrayVar(&scanExclude, "exclude", nil, "Path globs not inventoried (repeatable), e.g. examples/**")
	depsScanCmd.Flags().BoolVar(&scanQuiet, "quiet", false, "Table output: components with findings only")
	depsScanCmd.Flags().StringVar(&scanAdvisoryDB, "advisory-db", "", "Match against an exported advisory database (hibou vulns db export) instead of the server: no network, no triage context")
	depsScanCmd.Flags().BoolVar(&scanMavenCentral, "maven-central", false, "Identify jars without Maven metadata by their SHA-1 against Maven Central (sends hashes to search.maven.org, or HIBOU_MAVEN_CENTRAL_URL)")
	depsScanCmd.Flags().BoolVar(&scanNoAttachedSBOM, "no-attached-sbom", false, "Do not read the SBOMs attached to the image in its registry (referrers, cosign tags, BuildKit attestations)")
}

// mavenCentralLookup is the jar lookup when the user opted in.
func mavenCentralLookup(enabled bool) depinventory.JarLookup {
	if !enabled {
		return nil
	}
	return depinventory.MavenCentralLookup(os.Getenv("HIBOU_MAVEN_CENTRAL_URL"), nil)
}

// scanRow is one component with everything the server said about it.
type scanRow struct {
	depinventory.Component
	Supported     bool           `json:"supported"`
	Shipped       bool           `json:"shipped"`
	ShippedReason string         `json:"shipped_reason,omitempty"`
	Decision      string         `json:"decision,omitempty"`
	DecisionNote  string         `json:"decision_reason,omitempty"`
	InCooldown    bool           `json:"in_cooldown,omitempty"`
	CooldownUntil string         `json:"cooldown_until,omitempty"`
	Deprecated    bool           `json:"deprecated,omitempty"`
	Unpublished   bool           `json:"unpublished,omitempty"`
	LowUsage      bool           `json:"low_usage,omitempty"`
	Advisories    []scanAdvisory `json:"advisories"`
}

type scanAdvisory struct {
	ID            string   `json:"id"`
	CanonicalID   string   `json:"canonical_id"`
	Title         string   `json:"title,omitempty"`
	Severity      string   `json:"severity"`
	CVSS          *float64 `json:"cvss,omitempty"`
	IsMalware     bool     `json:"is_malware,omitempty"`
	KEV           bool     `json:"kev,omitempty"`
	EPSS          *float64 `json:"epss,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	VEXStatus     string   `json:"vex_status,omitempty"`
}

// scanReport is the whole result.
type scanReport struct {
	Targets           []depinventory.TargetSummary `json:"targets"`
	Rows              []scanRow                    `json:"components"`
	Unidentified      []depinventory.Unidentified  `json:"unidentified"`
	UnidentifiedCount int                          `json:"unidentified_count"`
	Modules           []depinventory.Module        `json:"modules"`
	Files             int                          `json:"files"`
	Matched           bool                         `json:"matched"`
	Offline           bool                         `json:"offline"`
	Repo              string                       `json:"repo,omitempty"`
	Summary           scanSummary                  `json:"summary"`
	Image             *depinventory.ImageInventory `json:"image,omitempty"`
	// AdvisoryDB names the local database the rows were matched against,
	// with its export time, when --advisory-db was used.
	AdvisoryDB           string        `json:"advisory_db,omitempty"`
	AdvisoryDBExportedAt string        `json:"advisory_db_exported_at,omitempty"`
	AdvisoryDBAdvisories int           `json:"advisory_db_advisories,omitempty"`
	Duration             time.Duration `json:"duration"`
}

type scanSummary struct {
	Components   int `json:"components"`
	Shipped      int `json:"shipped"`
	Vulnerable   int `json:"vulnerable"`
	Findings     int `json:"findings"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Malware      int `json:"malware"`
	KEV          int `json:"kev"`
	InCooldown   int `json:"in_cooldown"`
	Unresolved   int `json:"unresolved"`
	Unidentified int `json:"unidentified"`
}

// Response shapes of POST /orgs/{org}/advisories/match.
type matchResponse struct {
	Matches []struct {
		Purl          string `json:"purl"`
		Supported     bool   `json:"supported"`
		Shipped       bool   `json:"shipped"`
		ShippedReason string `json:"shipped_reason"`
		Decision      string `json:"decision"`
		Reason        string `json:"reason"`
		Signals       *struct {
			InCooldown    bool   `json:"in_cooldown"`
			CooldownUntil string `json:"cooldown_until"`
			Deprecated    bool   `json:"deprecated"`
			Unpublished   bool   `json:"unpublished"`
			LowUsage      bool   `json:"low_usage"`
		} `json:"signals"`
		Advisories []scanAdvisory `json:"advisories"`
	} `json:"matches"`
}

func runDepsScan(ctx context.Context, targets []string) (*scanReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	started := time.Now()
	warn := func(message string) { fmt.Fprintln(os.Stderr, "warning:", message) }
	opts := depinventory.ScanOptions{Exclude: scanExclude, Warn: warn, JarLookup: mavenCentralLookup(scanMavenCentral), SkipAttachedSBOMs: scanNoAttachedSBOM}
	var inv *depinventory.ArtifactInventory
	report := &scanReport{Offline: scanOffline}
	if scanAdvisoryDB != "" && scanOffline {
		return nil, errors.New("--advisory-db and --offline exclude each other: the database is the offline match")
	}
	switch {
	case scanImageRef != "":
		if len(targets) > 0 || scanGitRef != "" {
			return nil, errors.New("--image takes no other target")
		}
		image, err := depinventory.ScanImage(ctx, scanImageRef, opts)
		if err != nil {
			return nil, err
		}
		report.Image = image
		inv = image.Inventory
	case scanGitRef != "":
		if len(targets) > 0 {
			return nil, errors.New("--git-ref takes no other target")
		}
		worktree, cleanup, err := gitWorktree(scanGitRef)
		if err != nil {
			return nil, err
		}
		defer cleanup()
		inv, err = depinventory.ScanTargets(ctx, []string{worktree}, opts)
		if err != nil {
			return nil, err
		}
		for i := range inv.Components {
			inv.Components[i].Path = strings.TrimPrefix(inv.Components[i].Path, filepath.ToSlash(worktree)+"/")
		}
		for i := range inv.Targets {
			inv.Targets[i].Path = scanGitRef
		}
	default:
		var err error
		inv, err = depinventory.ScanTargets(ctx, targets, opts)
		if err != nil {
			return nil, err
		}
	}
	report.Targets, report.Modules, report.Files = inv.Targets, inv.Modules, inv.Files
	report.Unidentified, report.UnidentifiedCount = inv.Unidentified, inv.UnidentifiedCount
	report.Rows = make([]scanRow, 0, len(inv.Components))
	for _, component := range inv.Components {
		report.Rows = append(report.Rows, scanRow{Component: component, Shipped: true, Advisories: []scanAdvisory{}})
	}

	switch {
	case len(report.Rows) == 0:
	case scanAdvisoryDB != "":
		if err := matchRowsOffline(report, scanAdvisoryDB, warn); err != nil {
			return nil, err
		}
	case !scanOffline:
		if err := matchRows(report); err != nil {
			return nil, err
		}
	}
	applyShortcutFilters(report)
	if scanFilter != "" {
		filter, err := parseLocalFilter(scanFilter)
		if err != nil {
			return nil, fmt.Errorf("--filter: %w", err)
		}
		kept := report.Rows[:0]
		for _, row := range report.Rows {
			if filter.matches(row) {
				kept = append(kept, row)
			}
		}
		report.Rows = kept
	}
	report.Summary = summarize(report)
	report.Duration = time.Since(started)
	return report, nil
}

// matchRows asks the server about every purl with a version, in batches.
func matchRows(report *scanReport) error {
	client, err := depsClient()
	if err != nil {
		return fmt.Errorf("%w (use --offline for the inventory alone)", err)
	}
	org, err := depsOrgSlug()
	if err != nil {
		return fmt.Errorf("%w (use --offline for the inventory alone)", err)
	}
	repo := strings.TrimSpace(depsRepo)
	if repo == "" {
		repo = gitRemoteRepoSlug(".")
	}
	report.Repo = repo
	purls := make([]string, 0, len(report.Rows))
	seen := map[string]bool{}
	for _, row := range report.Rows {
		if row.Version == "" || seen[row.Purl] {
			continue
		}
		seen[row.Purl] = true
		purls = append(purls, row.Purl)
	}
	byPurl := map[string]int{}
	for i, row := range report.Rows {
		byPurl[row.Purl] = i
	}
	const batch = 1000
	for start := 0; start < len(purls); start += batch {
		end := start + batch
		if end > len(purls) {
			end = len(purls)
		}
		body := map[string]any{"purls": purls[start:end]}
		if repo != "" {
			body["repo"] = repo
		}
		if scanRelease != "" {
			body["release"] = scanRelease
		}
		var response matchResponse
		if err := client.Post(fmt.Sprintf("/orgs/%s/advisories/match", org), body, &response); err != nil {
			return fmt.Errorf("match advisories: %w", err)
		}
		for _, match := range response.Matches {
			for i := range report.Rows {
				if report.Rows[i].Purl != match.Purl {
					continue
				}
				row := &report.Rows[i]
				row.Supported = match.Supported
				row.Shipped, row.ShippedReason = match.Shipped, match.ShippedReason
				row.Decision, row.DecisionNote = match.Decision, match.Reason
				if match.Signals != nil {
					row.InCooldown, row.CooldownUntil = match.Signals.InCooldown, match.Signals.CooldownUntil
					row.Deprecated, row.Unpublished, row.LowUsage = match.Signals.Deprecated, match.Signals.Unpublished, match.Signals.LowUsage
				}
				row.Advisories = match.Advisories
				if row.Advisories == nil {
					row.Advisories = []scanAdvisory{}
				}
			}
		}
	}
	report.Matched = true
	return nil
}

// matchRowsOffline matches against an exported advisory database
// (ADR-046 step 6). What the file cannot carry stays unknown: triage, VEX,
// not-shipped lists and package signals need the server.
func matchRowsOffline(report *scanReport, path string, warn func(string)) error {
	db, err := advisorydb.Load(path)
	if err != nil {
		return fmt.Errorf("advisory database: %w", err)
	}
	now := time.Now()
	if db.Stale(now) {
		warn(fmt.Sprintf("advisory database exported %s ago (%s): re-export it with 'hibou vulns db export'", humanAge(db.Age(now)), db.Header.ExportedAt.Format("2 Jan 2006")))
	}
	for i := range report.Rows {
		row := &report.Rows[i]
		if row.Version == "" {
			continue
		}
		match := db.Match(row.Purl)
		row.Supported = match.Supported
		row.Advisories = make([]scanAdvisory, 0, len(match.Advisories))
		for _, a := range match.Advisories {
			row.Advisories = append(row.Advisories, scanAdvisory{
				ID: a.ID, CanonicalID: a.CanonicalID, Title: a.Title, Severity: a.Severity, CVSS: a.CVSS,
				IsMalware: a.IsMalware, KEV: a.KEV, EPSS: a.EPSS, FixedVersions: a.FixedVersions,
			})
		}
	}
	report.Matched = true
	report.AdvisoryDB = path
	report.AdvisoryDBExportedAt = db.Header.ExportedAt.UTC().Format(time.RFC3339)
	report.AdvisoryDBAdvisories = db.Advisories()
	return nil
}

func humanAge(age time.Duration) string {
	days := int(age.Hours() / 24)
	switch {
	case days >= 2:
		return fmt.Sprintf("%d days", days)
	case age >= time.Hour:
		return fmt.Sprintf("%d hours", int(age.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(age.Minutes()))
	}
}

func applyShortcutFilters(report *scanReport) {
	if scanSeverity == "" && !scanKEVOnly && !scanFixable {
		return
	}
	minimum := severityRankCLI(scanSeverity)
	kept := report.Rows[:0]
	for _, row := range report.Rows {
		keep := false
		for _, advisory := range row.Advisories {
			if scanSeverity != "" && severityRankCLI(advisory.Severity) < minimum {
				continue
			}
			if scanKEVOnly && !advisory.KEV {
				continue
			}
			if scanFixable && len(advisory.FixedVersions) == 0 {
				continue
			}
			keep = true
			break
		}
		if keep {
			kept = append(kept, row)
		}
	}
	report.Rows = kept
}

func summarize(report *scanReport) scanSummary {
	var s scanSummary
	s.Components = len(report.Rows)
	s.Unidentified = report.UnidentifiedCount
	for _, row := range report.Rows {
		if row.Shipped {
			s.Shipped++
		}
		if row.InCooldown {
			s.InCooldown++
		}
		if row.Resolution == depinventory.ResolutionUnresolved {
			s.Unresolved++
		}
		if len(row.Advisories) > 0 {
			s.Vulnerable++
		}
		for _, advisory := range row.Advisories {
			s.Findings++
			switch strings.ToLower(advisory.Severity) {
			case "critical":
				s.Critical++
			case "high":
				s.High++
			}
			if advisory.IsMalware {
				s.Malware++
			}
			if advisory.KEV {
				s.KEV++
			}
		}
	}
	return s
}

func severityRankCLI(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

// ---- Local filter expressions (ADR-013 vocabulary, evaluated here) ----

type localFilter struct {
	terms map[string][]string
	text  []string
}

// parseLocalFilter reads "key:value key:a,b free text"; terms AND, values
// of one key OR.
func parseLocalFilter(input string) (*localFilter, error) {
	filter := &localFilter{terms: map[string][]string{}}
	for _, token := range strings.Fields(input) {
		key, value, ok := strings.Cut(token, ":")
		if !ok {
			filter.text = append(filter.text, strings.ToLower(token))
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch key {
		case "severity", "shipped", "relationship", "ecosystem", "kev", "fixable", "malware", "cooldown", "vulnerable", "resolution", "deprecated", "unpublished", "decision", "module", "name":
		default:
			return nil, fmt.Errorf("unknown qualifier %q (severity, shipped, relationship, ecosystem, kev, fixable, malware, cooldown, vulnerable, resolution, deprecated, unpublished, decision, module, name)", key)
		}
		for _, v := range strings.Split(strings.ToLower(value), ",") {
			if v = strings.TrimSpace(v); v != "" {
				filter.terms[key] = append(filter.terms[key], v)
			}
		}
	}
	return filter, nil
}

func (f *localFilter) matches(row scanRow) bool {
	for key, values := range f.terms {
		if !f.matchTerm(row, key, values) {
			return false
		}
	}
	for _, text := range f.text {
		if !strings.Contains(strings.ToLower(row.Name), text) && !strings.Contains(strings.ToLower(row.Purl), text) {
			return false
		}
	}
	return true
}

func boolValue(values []string, actual bool) bool {
	for _, v := range values {
		want := v == "true" || v == "yes"
		if want == actual {
			return true
		}
	}
	return false
}

func anyValue(values []string, actual string) bool {
	actual = strings.ToLower(actual)
	for _, v := range values {
		if v == actual {
			return true
		}
	}
	return false
}

func (f *localFilter) matchTerm(row scanRow, key string, values []string) bool {
	switch key {
	case "severity":
		// At or above the lowest named severity.
		minimum := 99
		for _, v := range values {
			if rank := severityRankCLI(v); rank > 0 && rank < minimum {
				minimum = rank
			}
		}
		for _, advisory := range row.Advisories {
			if severityRankCLI(advisory.Severity) >= minimum {
				return true
			}
		}
		return false
	case "shipped":
		return boolValue(values, row.Shipped)
	case "relationship":
		return anyValue(values, string(row.Relationship))
	case "ecosystem":
		return anyValue(values, row.Ecosystem)
	case "resolution":
		return anyValue(values, string(row.Resolution))
	case "module":
		return anyValue(values, row.Module)
	case "name":
		return anyValue(values, row.Name)
	case "decision":
		return anyValue(values, row.Decision)
	case "cooldown":
		return boolValue(values, row.InCooldown)
	case "deprecated":
		return boolValue(values, row.Deprecated)
	case "unpublished":
		return boolValue(values, row.Unpublished)
	case "vulnerable":
		return boolValue(values, len(row.Advisories) > 0)
	case "kev", "fixable", "malware":
		for _, advisory := range row.Advisories {
			switch key {
			case "kev":
				if boolValue(values, advisory.KEV) {
					return true
				}
			case "fixable":
				if boolValue(values, len(advisory.FixedVersions) > 0) {
					return true
				}
			case "malware":
				if boolValue(values, advisory.IsMalware) {
					return true
				}
			}
		}
		return len(row.Advisories) == 0 && boolValue(values, false)
	}
	return true
}

// ---- Output ----

func writeScanReport(w *os.File, report *scanReport, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "table":
		return writeScanTable(w, report)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "cyclonedx":
		document, err := scanReportCycloneDX(report)
		if err != nil {
			return err
		}
		_, err = w.Write(document)
		return err
	case "sarif":
		document, err := scanReportSARIF(report)
		if err != nil {
			return err
		}
		_, err = w.Write(document)
		return err
	}
	return fmt.Errorf("unknown format %q: table, json, cyclonedx, sarif", format)
}

func writeScanTable(w *os.File, report *scanReport) error {
	s := report.Summary
	for _, target := range report.Targets {
		fmt.Fprintf(w, "%s: %s, %d components", target.Path, target.Kind, target.Components)
		if target.Files > 0 {
			fmt.Fprintf(w, ", %d files", target.Files)
		}
		if v := target.Metadata["version"]; v != "" {
			fmt.Fprintf(w, ", version %s", v)
		}
		if r := target.Metadata["revision"]; r != "" {
			fmt.Fprintf(w, ", revision %s", shortDigest(r))
		}
		fmt.Fprintln(w)
	}
	for _, module := range report.Modules {
		if !module.Complete {
			fmt.Fprintf(w, "note: %s: %s\n", module.Path, module.Reason)
		}
	}
	if s.Unidentified > 0 {
		fmt.Fprintf(w, "%d file(s) not identified (listed at the end)\n", s.Unidentified)
	}
	if image := report.Image; image != nil {
		if image.BaseImage != "" {
			fmt.Fprintf(w, "base image: %s\n", image.BaseImage)
		}
		baseLayers, appLayers := 0, 0
		for _, layer := range image.Layers {
			if layer.Empty {
				continue
			}
			if layer.BaseImage {
				baseLayers++
			} else {
				appLayers++
			}
		}
		fmt.Fprintf(w, "layers: %d in the base image, %d of the application", baseLayers, appLayers)
		if baseLayers+appLayers > 0 && baseLayers == 0 {
			fmt.Fprint(w, " (no CMD or ENTRYPOINT in the history to tell the base image apart)")
		}
		fmt.Fprintln(w)
		for _, attached := range image.AttachedSBOMs {
			signed := "unsigned"
			if attached.Signed {
				signed = "signed, not verified here (hibou deps verify --key)"
			}
			fmt.Fprintf(w, "attached SBOM (%s, %s, %s): %d components, %d not seen by the scan\n", attached.Source, attached.Format, signed, attached.Components, attached.Added)
		}
	}
	switch {
	case report.AdvisoryDB != "":
		fmt.Fprintf(w, "matched against %s: %d advisories exported %s\n", report.AdvisoryDB, report.AdvisoryDBAdvisories, shortDate(report.AdvisoryDBExportedAt))
		fmt.Fprintln(w, "no triage context: VEX statements, not-shipped lists and package signals need the server")
	case !report.Matched:
		fmt.Fprintln(w, "inventory only: no server match (offline)")
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "STATUS\tCOMPONENT\tVERSION\tRELATIONSHIP\tSHIPPED\tFINDINGS\tDETAIL")
	for _, row := range report.Rows {
		if scanQuiet && len(row.Advisories) == 0 && !row.InCooldown && row.Decision != "deny" {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", rowStatus(row), row.Name, rowVersion(row), rowRelationship(row), rowShipped(row), rowFindings(row), rowDetail(row))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d components · %d shipped · %d vulnerable (%d findings: %d critical, %d high", s.Components, s.Shipped, s.Vulnerable, s.Findings, s.Critical, s.High)
	if s.Malware > 0 {
		fmt.Fprintf(w, ", %d malicious", s.Malware)
	}
	if s.KEV > 0 {
		fmt.Fprintf(w, ", %d exploited", s.KEV)
	}
	fmt.Fprint(w, ")")
	if s.InCooldown > 0 {
		fmt.Fprintf(w, " · %d in cooldown", s.InCooldown)
	}
	if s.Unresolved > 0 {
		fmt.Fprintf(w, " · %d unresolved ranges", s.Unresolved)
	}
	fmt.Fprintln(w)
	if len(report.Unidentified) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Not identified (%d):\n", report.UnidentifiedCount)
		for _, u := range report.Unidentified {
			fmt.Fprintf(w, "  %s  %s  %d bytes\n", u.Path, u.Type, u.Size)
		}
		if report.UnidentifiedCount > len(report.Unidentified) {
			fmt.Fprintf(w, "  … and %d more\n", report.UnidentifiedCount-len(report.Unidentified))
		}
	}
	return nil
}

func rowStatus(row scanRow) string {
	switch {
	case row.Decision == "deny":
		return "✖ deny"
	case hasMalware(row):
		return "✖ malware"
	case hasKEV(row):
		return "✖ exploited"
	case len(row.Advisories) > 0 && !row.Shipped:
		return "⚠ info"
	case len(row.Advisories) > 0:
		return "✖ " + worstSeverity(row)
	case row.InCooldown:
		return "⏳ cooldown"
	case row.Resolution == depinventory.ResolutionUnresolved:
		return "? unresolved"
	case !row.Supported && row.Version != "":
		return "- unchecked"
	}
	return "✓"
}

func hasMalware(row scanRow) bool {
	for _, a := range row.Advisories {
		if a.IsMalware {
			return true
		}
	}
	return false
}

func hasKEV(row scanRow) bool {
	for _, a := range row.Advisories {
		if a.KEV {
			return true
		}
	}
	return false
}

func worstSeverity(row scanRow) string {
	worst := ""
	for _, a := range row.Advisories {
		if severityRankCLI(a.Severity) > severityRankCLI(worst) {
			worst = strings.ToLower(a.Severity)
		}
	}
	return worst
}

func rowVersion(row scanRow) string {
	if row.Resolution == depinventory.ResolutionUnresolved {
		return row.Constraint + " (unresolved)"
	}
	return row.Version
}

func rowRelationship(row scanRow) string {
	out := string(row.Relationship)
	if row.Module != "." && row.Module != "" && !strings.Contains(row.Module, "!") {
		out += " · " + row.Module
	}
	return out
}

func rowShipped(row scanRow) string {
	if !row.Shipped {
		return "no"
	}
	return "yes"
}

func rowFindings(row scanRow) string {
	if len(row.Advisories) == 0 {
		return "-"
	}
	ids := make([]string, 0, len(row.Advisories))
	for i, a := range row.Advisories {
		if i == 3 {
			ids = append(ids, fmt.Sprintf("+%d", len(row.Advisories)-3))
			break
		}
		id := a.CanonicalID
		if a.KEV {
			id += " (KEV)"
		}
		ids = append(ids, id)
	}
	return strings.Join(ids, ", ")
}

func rowDetail(row scanRow) string {
	parts := []string{}
	if row.InCooldown {
		parts = append(parts, "in cooldown until "+shortDate(row.CooldownUntil))
	}
	if row.Decision == "deny" || row.Decision == "hold" {
		parts = append(parts, row.DecisionNote)
	}
	if !row.Shipped && row.ShippedReason != "" {
		parts = append(parts, row.ShippedReason)
	}
	fixes := []string{}
	for _, a := range row.Advisories {
		fixes = append(fixes, a.FixedVersions...)
	}
	if len(fixes) > 0 {
		sort.Strings(fixes)
		parts = append(parts, "fix: "+strings.Join(uniqueStrings(fixes), ", "))
	}
	if row.Deprecated {
		parts = append(parts, "deprecated")
	}
	if row.Unpublished {
		parts = append(parts, "unpublished")
	}
	if row.Layer != nil {
		if row.Layer.BaseImage {
			parts = append(parts, fmt.Sprintf("layer %d (base image)", row.Layer.Index))
		} else {
			parts = append(parts, fmt.Sprintf("layer %d", row.Layer.Index))
		}
	}
	return strings.Join(parts, "; ")
}

func shortDate(value string) string {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t.Format("2 Jan 2006")
	}
	return value
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// scanReportCycloneDX renders the inventory with its findings as CycloneDX
// VEX, so the output is a valid SBOM `hibou upload` accepts.
func scanReportCycloneDX(report *scanReport) ([]byte, error) {
	components := make([]depinventory.Component, 0, len(report.Rows))
	for _, row := range report.Rows {
		components = append(components, row.Component)
	}
	inv := &depinventory.Inventory{Components: components, Modules: report.Modules}
	document, err := depinventory.ToCycloneDX(inv, "hibou-deps-scan", depinventory.Version, time.Now())
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, err
	}
	vulnerabilities := make([]map[string]any, 0)
	for _, row := range report.Rows {
		for _, a := range row.Advisories {
			entry := map[string]any{
				"id":      a.CanonicalID,
				"source":  map[string]any{"name": "hibou"},
				"affects": []map[string]any{{"ref": row.Purl}},
				"ratings": []map[string]any{{"severity": strings.ToLower(a.Severity), "method": "other", "source": map[string]any{"name": "hibou"}}},
			}
			if a.CVSS != nil {
				entry["ratings"].([]map[string]any)[0]["score"] = *a.CVSS
			}
			if a.Title != "" {
				entry["description"] = a.Title
			}
			if len(a.FixedVersions) > 0 {
				entry["recommendation"] = "Upgrade to " + strings.Join(a.FixedVersions, " or ")
			}
			if a.VEXStatus != "" {
				entry["analysis"] = map[string]any{"state": a.VEXStatus}
			}
			props := []map[string]string{}
			if a.KEV {
				props = append(props, map[string]string{"name": "hibou:kev", "value": "true"})
			}
			if a.IsMalware {
				props = append(props, map[string]string{"name": "hibou:malware", "value": "true"})
			}
			if len(props) > 0 {
				entry["properties"] = props
			}
			vulnerabilities = append(vulnerabilities, entry)
		}
	}
	doc["vulnerabilities"] = vulnerabilities
	return json.MarshalIndent(doc, "", "  ")
}

// scanReportSARIF renders one result per finding on the manifest or
// deliverable path, for CI annotations.
func scanReportSARIF(report *scanReport) ([]byte, error) {
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription map[string]string `json:"shortDescription"`
		Properties       map[string]any    `json:"properties,omitempty"`
	}
	rules := map[string]rule{}
	results := make([]map[string]any, 0)
	for _, row := range report.Rows {
		for _, a := range row.Advisories {
			if _, ok := rules[a.CanonicalID]; !ok {
				rules[a.CanonicalID] = rule{ID: a.CanonicalID, Name: a.CanonicalID, ShortDescription: map[string]string{"text": firstNonEmptyCLI(a.Title, a.CanonicalID)}, Properties: map[string]any{"security-severity": cvssText(a.CVSS, a.Severity)}}
			}
			level := "warning"
			switch strings.ToLower(a.Severity) {
			case "critical", "high":
				level = "error"
			case "low":
				level = "note"
			}
			message := fmt.Sprintf("%s %s: %s", row.Name, row.Version, firstNonEmptyCLI(a.Title, a.CanonicalID))
			if !row.Shipped {
				message += " (not shipped)"
			}
			if len(a.FixedVersions) > 0 {
				message += ". Fixed in " + strings.Join(a.FixedVersions, ", ")
			}
			location := row.Path
			if idx := strings.Index(location, "!/"); idx >= 0 {
				location = location[:idx]
			}
			result := map[string]any{
				"ruleId":  a.CanonicalID,
				"level":   level,
				"message": map[string]string{"text": message},
				"properties": map[string]any{
					"purl": row.Purl, "shipped": row.Shipped, "kev": a.KEV, "malware": a.IsMalware,
				},
			}
			if location != "" {
				region := map[string]any{}
				if row.Line > 0 {
					region["startLine"] = row.Line
				}
				physical := map[string]any{"artifactLocation": map[string]string{"uri": location}}
				if len(region) > 0 {
					physical["region"] = region
				}
				result["locations"] = []map[string]any{{"physicalLocation": physical}}
			}
			results = append(results, result)
		}
	}
	ruleList := make([]rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "hibou-deps", "version": depinventory.Version, "rules": ruleList}},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func cvssText(score *float64, severity string) string {
	if score != nil {
		return fmt.Sprintf("%.1f", *score)
	}
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.0"
	case "low":
		return "2.0"
	}
	return "0.0"
}

func firstNonEmptyCLI(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// gitWorktree checks a ref out into a temporary worktree of the current
// clone, so an old tag is inspected without touching the working copy.
func gitWorktree(ref string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "hibou-worktree-")
	if err != nil {
		return "", nil, err
	}
	output, code, err := execCommandOutput(".", "git", "worktree", "add", "--detach", dir, ref)
	if err != nil || code != 0 {
		_ = os.RemoveAll(dir)
		return "", nil, fmt.Errorf("git worktree add %s: %s", ref, strings.TrimSpace(string(output)))
	}
	cleanup := func() {
		_, _, _ = execCommandOutput(".", "git", "worktree", "remove", "--force", dir)
		_ = os.RemoveAll(dir)
	}
	return dir, cleanup, nil
}

var _ = cliclient.New
