package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/depinventory"
)

// Reading stored data (ADR-046 §3): the same endpoints, filters and
// triage states as the web UI.

var (
	readRef     string
	readTag     string
	readRelease string
	readPR      string
	readFilter  string
	readFormat  string
	readFailOn  string
)

func addReadFlags(c *cobra.Command) {
	c.Flags().StringVar(&readRef, "ref", "", "Branch or ref (default: the repository's default branch)")
	c.Flags().StringVar(&readTag, "tag", "", "Tag")
	c.Flags().StringVar(&readRelease, "release", "", "Release version (its pinned snapshot)")
	c.Flags().StringVar(&readPR, "pr", "", "Pull request number")
	c.Flags().StringVar(&readFilter, "filter", "", "Filter expression in the UI's vocabulary")
	c.Flags().StringVar(&readFormat, "format", "table", "Output: table, json")
	c.Flags().StringVar(&readFailOn, "fail-on", "", "Exit 1 when a row matches this filter")
}

// readScope resolves --ref/--tag/--release/--pr into query parameters.
func readScope() (url.Values, string, error) {
	query := url.Values{}
	set := 0
	for _, v := range []string{readRef, readTag, readRelease, readPR} {
		if strings.TrimSpace(v) != "" {
			set++
		}
	}
	if set > 1 {
		return nil, "", errors.New("give one of --ref, --tag, --release, --pr")
	}
	switch {
	case readTag != "":
		query.Set("ref", readTag)
		return query, readTag, nil
	case readPR != "":
		query.Set("ref", "refs/pull/"+strings.TrimPrefix(readPR, "#"))
		return query, "PR #" + readPR, nil
	case readRelease != "":
		client, err := depsClient()
		if err != nil {
			return nil, "", err
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return nil, "", err
		}
		release, err := findRelease(client, repoPath, readRelease)
		if err != nil {
			return nil, "", err
		}
		if release.SnapshotID == nil {
			return nil, "", fmt.Errorf("release %s has no analysed snapshot yet", readRelease)
		}
		query.Set("snapshot", *release.SnapshotID)
		query.Set("ref", release.RefName)
		return query, "release " + readRelease, nil
	case readRef != "":
		query.Set("ref", readRef)
		return query, readRef, nil
	}
	return query, "default branch", nil
}

type releaseSummary struct {
	ID          string  `json:"id"`
	Version     string  `json:"version"`
	RefName     string  `json:"ref_name"`
	SnapshotID  *string `json:"snapshot_id"`
	CommitSHA   string  `json:"commit_sha"`
	PublishedAt *string `json:"published_at"`
}

// findRelease looks a release up by its exact version.
func findRelease(client interface {
	Get(path string, out any) error
}, repoPath, version string) (*releaseSummary, error) {
	var releases []releaseSummary
	if err := client.Get(repoPath+"/releases?per_page=100&q="+url.QueryEscape(version), &releases); err != nil {
		return nil, err
	}
	for i := range releases {
		if releases[i].Version == version || strings.TrimPrefix(releases[i].Version, "v") == strings.TrimPrefix(version, "v") {
			return &releases[i], nil
		}
	}
	return nil, fmt.Errorf("release %s not found", version)
}

// storedComponent mirrors the components endpoint.
type storedComponent struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Ecosystem       string   `json:"ecosystem"`
	Purl            string   `json:"purl"`
	VulnCount       int      `json:"vuln_count"`
	HighestSeverity *string  `json:"highest_severity"`
	Relationship    string   `json:"relationship"`
	Scopes          []string `json:"scopes"`
	Modules         []string `json:"modules"`
	Resolution      string   `json:"resolution"`
	Constraint      string   `json:"constraint"`
	Shipped         bool     `json:"shipped"`
	ShippedReason   string   `json:"shipped_reason"`
	Licenses        []string `json:"licenses"`
	Signals         *struct {
		InCooldown    bool   `json:"in_cooldown"`
		CooldownUntil string `json:"cooldown_until"`
		Deprecated    bool   `json:"deprecated"`
		Unpublished   bool   `json:"unpublished"`
	} `json:"signals"`
	Advisories []struct {
		CanonicalID string `json:"canonical_id"`
		Severity    string `json:"severity"`
	} `json:"advisories"`
}

var depsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Components Hibou stores for a ref, tag, release or pull request",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		query, label, err := readScope()
		if err != nil {
			return exitError{2, err}
		}
		var components []storedComponent
		if err := client.Get(repoPath+"/components?"+query.Encode(), &components); err != nil {
			return exitError{2, err}
		}
		if len(components) == 0 {
			fmt.Printf("No components stored for %s yet (a lazy ref is extracted on first read; try again in a moment).\n", label)
			return nil
		}
		rows := make([]scanRow, 0, len(components))
		for _, c := range components {
			row := scanRow{Shipped: c.Shipped, ShippedReason: c.ShippedReason, Supported: true, Advisories: []scanAdvisory{}}
			row.Name, row.Version, row.Ecosystem, row.Purl = c.Name, c.Version, c.Ecosystem, c.Purl
			row.Relationship, row.Resolution, row.Constraint = relationshipOf(c.Relationship), resolutionOf(c.Resolution), c.Constraint
			if len(c.Modules) > 0 {
				row.Module = c.Modules[0]
			}
			row.Scopes = c.Scopes
			if c.Signals != nil {
				row.InCooldown, row.CooldownUntil, row.Deprecated, row.Unpublished = c.Signals.InCooldown, c.Signals.CooldownUntil, c.Signals.Deprecated, c.Signals.Unpublished
			}
			for _, a := range c.Advisories {
				row.Advisories = append(row.Advisories, scanAdvisory{CanonicalID: a.CanonicalID, Severity: a.Severity})
			}
			rows = append(rows, row)
		}
		report := &scanReport{Rows: rows, Matched: true}
		if readFilter != "" {
			filter, err := parseLocalFilter(readFilter)
			if err != nil {
				return exitError{2, err}
			}
			kept := rows[:0]
			for _, row := range rows {
				if filter.matches(row) {
					kept = append(kept, row)
				}
			}
			report.Rows = kept
		}
		report.Summary = summarize(report)
		report.Targets = nil
		fmt.Printf("%s · %s\n", repoPath, label)
		if err := writeScanReport(os.Stdout, report, readFormat); err != nil {
			return exitError{2, err}
		}
		return failOnRows(report.Rows, readFailOn)
	},
}

func failOnRows(rows []scanRow, expression string) error {
	if expression == "" {
		return nil
	}
	filter, err := parseLocalFilter(expression)
	if err != nil {
		return exitError{2, fmt.Errorf("--fail-on: %w", err)}
	}
	matched := 0
	for _, row := range rows {
		if filter.matches(row) {
			matched++
		}
	}
	if matched > 0 {
		return exitError{1, fmt.Errorf("%d row(s) match --fail-on %q", matched, expression)}
	}
	return nil
}

// storedFinding mirrors the vulnerabilities endpoint.
type storedFinding struct {
	Type             string  `json:"type"`
	Title            string  `json:"title"`
	Severity         string  `json:"severity"`
	Status           string  `json:"status"`
	PrimaryID        string  `json:"primary_identifier_value"`
	ScannerName      string  `json:"scanner_name"`
	FilePath         *string `json:"file_path"`
	StartLine        *int    `json:"start_line"`
	ComponentName    *string `json:"component_name"`
	ComponentVersion *string `json:"component_version"`
	KEV              bool    `json:"kev"`
	Shipped          *bool   `json:"shipped"`
	HasRemediation   bool    `json:"has_remediation"`
	Fingerprint      string  `json:"fingerprint"`
}

var vulnsListCmd = &cobra.Command{
	Use:   "list",
	Short: "Findings of a ref, tag, release or pull request, every producer",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		query, label, err := readScope()
		if err != nil {
			return exitError{2, err}
		}
		query.Set("per_page", "200")
		if readFilter != "" {
			query.Set("q", readFilter)
		}
		var findings []storedFinding
		page := 1
		for {
			query.Set("page", strconv.Itoa(page))
			var batch []storedFinding
			if err := client.Get(repoPath+"/vulnerabilities?"+query.Encode(), &batch); err != nil {
				return exitError{2, err}
			}
			findings = append(findings, batch...)
			if len(batch) < 200 || page >= 50 {
				break
			}
			page++
		}
		fmt.Printf("%s · %s · %d findings\n\n", repoPath, label, len(findings))
		if strings.EqualFold(readFormat, "json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(findings); err != nil {
				return exitError{2, err}
			}
		} else {
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "SEVERITY\tTYPE\tID\tWHERE\tTITLE\tFLAGS")
			for _, f := range findings {
				where := ""
				switch {
				case f.ComponentName != nil && *f.ComponentName != "":
					where = *f.ComponentName
					if f.ComponentVersion != nil {
						where += "@" + *f.ComponentVersion
					}
				case f.FilePath != nil:
					where = *f.FilePath
					if f.StartLine != nil {
						where += fmt.Sprintf(":%d", *f.StartLine)
					}
				}
				flags := []string{}
				if f.KEV {
					flags = append(flags, "KEV")
				}
				if f.Shipped != nil && !*f.Shipped {
					flags = append(flags, "not shipped")
				}
				if f.HasRemediation {
					flags = append(flags, "fixable")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Severity, f.Type, f.PrimaryID, where, truncate(f.Title, 70), strings.Join(flags, ", "))
			}
			if err := tw.Flush(); err != nil {
				return exitError{2, err}
			}
		}
		if readFailOn != "" {
			filter, err := parseLocalFilter(readFailOn)
			if err != nil {
				return exitError{2, err}
			}
			matched := 0
			for _, f := range findings {
				row := scanRow{Shipped: f.Shipped == nil || *f.Shipped, Advisories: []scanAdvisory{{CanonicalID: f.PrimaryID, Severity: f.Severity, KEV: f.KEV, IsMalware: f.Type == "malware", FixedVersions: fixedIf(f.HasRemediation)}}}
				if f.ComponentName != nil {
					row.Name = *f.ComponentName
				}
				if filter.matches(row) {
					matched++
				}
			}
			if matched > 0 {
				return exitError{1, fmt.Errorf("%d finding(s) match --fail-on %q", matched, readFailOn)}
			}
		}
		return nil
	},
}

func fixedIf(has bool) []string {
	if has {
		return []string{"available"}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var depsDiffCmd = &cobra.Command{
	Use:   "diff BASE HEAD",
	Short: "What changed in the inventory between two refs, tags or releases",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		query := url.Values{}
		for i, side := range []string{"base", "head"} {
			value := args[i]
			if release, err := findRelease(client, repoPath, value); err == nil && release.SnapshotID != nil {
				query.Set(side+"_snapshot", *release.SnapshotID)
			} else {
				query.Set(side, value)
			}
		}
		var result struct {
			Components struct {
				Added []struct {
					Name, Version, Ecosystem string
					VulnCount                int `json:"vuln_count"`
				} `json:"added"`
				Removed []struct {
					Name, Version, Ecosystem string
				} `json:"removed"`
				Updated []struct {
					Name        string `json:"name"`
					BaseVersion string `json:"base_version"`
					HeadVersion string `json:"head_version"`
					HeadVulns   int    `json:"head_vuln_count"`
				} `json:"updated"`
				Unchanged int `json:"unchanged"`
			} `json:"components"`
		}
		if err := client.Get(repoPath+"/compare?"+query.Encode(), &result); err != nil {
			return exitError{2, err}
		}
		if strings.EqualFold(readFormat, "json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(result.Components)
		}
		c := result.Components
		fmt.Printf("%s: %s → %s\n%d added, %d updated, %d removed, %d unchanged\n\n", repoPath, args[0], args[1], len(c.Added), len(c.Updated), len(c.Removed), c.Unchanged)
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, a := range c.Added {
			fmt.Fprintf(tw, "+ %s\t%s\t%s\t%d findings\n", a.Name, a.Version, a.Ecosystem, a.VulnCount)
		}
		for _, u := range c.Updated {
			fmt.Fprintf(tw, "~ %s\t%s → %s\t\t%d findings\n", u.Name, u.BaseVersion, u.HeadVersion, u.HeadVulns)
		}
		for _, r := range c.Removed {
			fmt.Fprintf(tw, "- %s\t%s\t%s\t\n", r.Name, r.Version, r.Ecosystem)
		}
		return tw.Flush()
	},
}

func init() {
	addReadFlags(depsListCmd)
	addReadFlags(vulnsListCmd)
	depsDiffCmd.Flags().StringVar(&readFormat, "format", "table", "Output: table, json")
}

func relationshipOf(value string) depinventory.Relationship {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "direct":
		return depinventory.RelationshipDirect
	case "indirect":
		return depinventory.RelationshipIndirect
	}
	return depinventory.RelationshipUnknown
}

func resolutionOf(value string) depinventory.Resolution {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "recorded":
		return depinventory.ResolutionRecorded
	case "declared":
		return depinventory.ResolutionDeclared
	case "unresolved":
		return depinventory.ResolutionUnresolved
	case "artifact":
		return depinventory.ResolutionArtifact
	}
	return ""
}
