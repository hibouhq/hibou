package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/cliclient"
	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/version"
)

// hibou release scan (ADR-046 §4): scanning a release and keeping the
// result. Without files the server extracts the tag; with files or an
// image the CLI analyses them locally and records the inventory on the
// release, additively, after plausibility checks and a preview.

var (
	releaseScanRepo   string
	releaseScanImage  string
	releaseScanYes    bool
	releaseScanReason string
	releaseScanForce  bool
	releaseScanAll    bool
)

var releaseScanCmd = &cobra.Command{
	Use:   "scan VERSION [FILES...]",
	Short: "Scan a release: the server extracts its tag, or deliverables are analysed locally and recorded",
	Long: `  hibou release scan v1.2.3                        the server extracts the tag's lockfiles and manifests
  hibou release scan v1.2.3 dist/app.war [--image REF]   files analysed locally, recorded on the release
  hibou release scan --all                         every release without an inventory

With files, the CLI checks the deliverable's own metadata against the
release (Go build info, JAR Implementation-Version, image labels, package
versions), shows what the release already has and what recording changes,
and asks for confirmation (--yes skips it). A mismatch stops the scan;
--force --reason "..." overrides it and the reason is stored. Recording is
additive and idempotent: existing sources are never replaced, a file whose
sha256 is already a source is a no-op.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		if repo := strings.TrimSpace(releaseScanRepo); repo != "" {
			depsRepo = repo
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		if releaseScanAll {
			var result struct {
				Queued  int `json:"queued"`
				Skipped int `json:"skipped"`
			}
			if err := client.Post(repoPath+"/releases/extract-all", nil, &result); err != nil {
				return exitError{2, err}
			}
			fmt.Printf("Queued %d release extraction(s) on the server, %d already had an inventory.\n", result.Queued, result.Skipped)
			return nil
		}
		if len(args) == 0 {
			return exitError{2, errors.New("a release version is required (or --all)")}
		}
		versionArg := args[0]
		files := args[1:]
		release, err := findRelease(client, repoPath, versionArg)
		if err != nil {
			return exitError{2, err}
		}
		if len(files) == 0 && releaseScanImage == "" {
			fmt.Printf("Analysing tag %s on the server (release %s, commit %s)\n", release.RefName, release.Version, shortDigest(release.CommitSHA))
			var job struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			}
			if err := client.Post(fmt.Sprintf("%s/releases/%s/extract", repoPath, release.ID), nil, &job); err != nil {
				return exitError{2, err}
			}
			fmt.Printf("Extraction queued (%s); the Releases tab and 'hibou deps list --release %s' show the result.\n", job.Status, release.Version)
			return nil
		}
		return recordReleaseDeliverables(cmd.Context(), client, repoPath, release, files)
	},
}

// releaseSource mirrors GET releases/{id}/sources.
type releaseSource struct {
	ID               string            `json:"id"`
	Filename         string            `json:"filename"`
	Tool             string            `json:"tool"`
	ToolVersion      string            `json:"tool_version"`
	Origin           string            `json:"origin"`
	SHA256           string            `json:"sha256"`
	Components       int               `json:"components"`
	CreatedAt        time.Time         `json:"created_at"`
	AfterRelease     bool              `json:"after_release"`
	Revoked          bool              `json:"revoked"`
	RevokeReason     string            `json:"revoke_reason"`
	Metadata         map[string]string `json:"metadata"`
	ComponentCount   int               `json:"component_count"`
	Discrepancies    int               `json:"discrepancies"`
	ExtractorVersion string            `json:"extractor_version"`
}

type releaseSourcesResponse struct {
	Sources    []releaseSource `json:"sources"`
	Components []struct {
		Purl    string `json:"purl"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
	CurrentExtractorVersion string `json:"current_extractor_version"`
}

func recordReleaseDeliverables(ctx context.Context, client *cliclient.Client, repoPath string, release *releaseSummary, files []string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	warn := func(message string) { fmt.Fprintln(os.Stderr, "warning:", message) }
	opts := depinventory.ScanOptions{Warn: warn}
	targets := []depinventory.TargetSummary{}
	var components []depinventory.Component
	if len(files) > 0 {
		fmt.Printf("Analysing %d file(s) locally\n", len(files))
		inv, err := depinventory.ScanTargets(ctx, files, opts)
		if err != nil {
			return exitError{2, err}
		}
		components = append(components, inv.Components...)
		targets = append(targets, inv.Targets...)
		if inv.UnidentifiedCount > 0 {
			fmt.Printf("%d file(s) not identified; the inventory covers what the extractors recognised.\n", inv.UnidentifiedCount)
		}
	}
	if releaseScanImage != "" {
		fmt.Printf("Analysing image %s locally\n", releaseScanImage)
		image, err := depinventory.ScanImage(ctx, releaseScanImage, opts)
		if err != nil {
			return exitError{2, err}
		}
		components = append(components, image.Inventory.Components...)
		targets = append(targets, image.Inventory.Targets...)
	}
	if len(components) == 0 {
		return exitError{2, errors.New("no component found in the deliverables; nothing to record")}
	}

	// Plausibility checks (ADR-046 §4.3, point 3): the deliverable's own
	// metadata against the release.
	problems, checks := plausibility(release, targets)
	for _, check := range checks {
		fmt.Println("check:", check)
	}
	if len(problems) > 0 && !releaseScanForce {
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "mismatch:", p)
		}
		return exitError{2, errors.New("the deliverable does not match the release; --force --reason \"...\" records it anyway")}
	}
	if len(problems) > 0 && strings.TrimSpace(releaseScanReason) == "" {
		return exitError{2, errors.New("--force needs --reason")}
	}

	// Preview (point 4): what the release has, what recording changes.
	var existing releaseSourcesResponse
	if err := client.Get(fmt.Sprintf("%s/releases/%s/sources", repoPath, release.ID), &existing); err != nil {
		return exitError{2, err}
	}
	for _, target := range targets {
		for _, source := range existing.Sources {
			if target.SHA256 != "" && source.SHA256 == target.SHA256 && !source.Revoked {
				fmt.Printf("%s is already a source of release %s (sha256 %s): nothing to do\n", target.Path, release.Version, shortDigest(target.SHA256))
				return nil
			}
		}
	}
	known := map[string]string{}
	for _, c := range existing.Components {
		known[strings.ToLower(c.Name)] = c.Version
	}
	added, differ, same := 0, 0, 0
	examples := []string{}
	for _, c := range components {
		version, ok := known[strings.ToLower(c.Name)]
		switch {
		case !ok:
			added++
		case version != c.Version:
			differ++
			if len(examples) < 3 {
				examples = append(examples, fmt.Sprintf("%s %s → %s", c.Name, version, c.Version))
			}
		default:
			same++
		}
	}
	fmt.Printf("\nRelease %s (commit %s) already has:\n", release.Version, shortDigest(release.CommitSHA))
	if len(existing.Sources) == 0 {
		fmt.Println("  no inventory source")
	}
	for _, source := range existing.Sources {
		state := ""
		if source.Revoked {
			state = ", revoked"
		}
		fmt.Printf("  %s (%s%s)  %d components\n", source.Filename, source.Origin, state, source.ComponentCount)
	}
	fmt.Printf("Scanned locally: %d components\n  + %d not known for this release\n  ~ %d at a different version than recorded", len(components), added, differ)
	if len(examples) > 0 {
		fmt.Printf(" (e.g. %s)", strings.Join(examples, ", "))
	}
	fmt.Printf("\n  = %d already known\n", same)
	if differ > 0 {
		fmt.Println("Version differences against existing sources are the typical sign of a wrong file; recorded, they become discrepancies.")
	}
	if !releaseScanYes {
		fmt.Printf("Record on release %s? [y/N] ", release.Version)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Not recorded.")
			return nil
		}
	}

	inv := &depinventory.Inventory{Components: components, Modules: depinventory.RebuildModules(components)}
	document, err := depinventory.ToCycloneDX(inv, release.Version, depinventory.Version, time.Now())
	if err != nil {
		return exitError{2, err}
	}
	name := "deliverables.cdx.json"
	if len(targets) == 1 {
		name = filepath.Base(targets[0].Path) + ".cdx.json"
	}
	payload := map[string]any{
		"filename":       name,
		"content_base64": base64.StdEncoding.EncodeToString(document),
		"cli_version":    version.Version,
		"extractor":      depinventory.Version,
		"deliverables":   targets,
		"checks":         checks,
		"problems":       problems,
		"reason":         strings.TrimSpace(releaseScanReason),
		"force":          releaseScanForce,
	}
	var recorded struct {
		ID         string `json:"id"`
		Components int    `json:"components"`
		Duplicate  bool   `json:"duplicate"`
	}
	if err := client.Post(fmt.Sprintf("%s/releases/%s/sources", repoPath, release.ID), payload, &recorded); err != nil {
		return exitError{2, err}
	}
	if recorded.Duplicate {
		fmt.Println("Already recorded (same digest): nothing changed.")
		return nil
	}
	fmt.Printf("Recorded source %s on release %s: %d components.\n", recorded.ID, release.Version, recorded.Components)
	return nil
}

// plausibility compares each deliverable's metadata with the release.
func plausibility(release *releaseSummary, targets []depinventory.TargetSummary) (problems, checks []string) {
	for _, target := range targets {
		if len(target.Metadata) == 0 {
			checks = append(checks, target.Path+": no version metadata inside the file, the check was not possible")
			continue
		}
		if revision := target.Metadata["revision"]; revision != "" && release.CommitSHA != "" {
			if strings.HasPrefix(release.CommitSHA, revision) || strings.HasPrefix(revision, release.CommitSHA) {
				checks = append(checks, fmt.Sprintf("%s: revision %s matches the release commit", target.Path, shortDigest(revision)))
			} else {
				problems = append(problems, fmt.Sprintf("%s: built from %s, the release is at %s", target.Path, shortDigest(revision), shortDigest(release.CommitSHA)))
			}
		}
		if v := firstNonEmptyCLI(target.Metadata["version"], target.Metadata["pom_version"]); v != "" {
			want := strings.TrimPrefix(release.Version, "v")
			got := strings.TrimPrefix(v, "v")
			if got == want || strings.HasPrefix(got, want+"-") || strings.HasPrefix(got, want+"+") {
				checks = append(checks, fmt.Sprintf("%s: version %s matches release %s", target.Path, v, release.Version))
			} else if target.Metadata["revision"] == "" {
				problems = append(problems, fmt.Sprintf("%s: version %s, the release is %s", target.Path, v, release.Version))
			}
		}
	}
	return problems, checks
}

// ---- hibou release sources ----

var (
	releaseSourcesReason string
)

var releaseSourcesCmd = &cobra.Command{
	Use:   "sources VERSION",
	Short: "Inventory sources of a release, with revoke and restore",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		if repo := strings.TrimSpace(releaseScanRepo); repo != "" {
			depsRepo = repo
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		release, err := findRelease(client, repoPath, args[0])
		if err != nil {
			return exitError{2, err}
		}
		var response releaseSourcesResponse
		if err := client.Get(fmt.Sprintf("%s/releases/%s/sources", repoPath, release.ID), &response); err != nil {
			return exitError{2, err}
		}
		if strings.EqualFold(readFormat, "json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(response)
		}
		fmt.Printf("Release %s (commit %s): %d source(s), %d components\n", release.Version, shortDigest(release.CommitSHA), len(response.Sources), len(response.Components))
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tFILE\tORIGIN\tTOOL\tCOMPONENTS\tADDED\tSTATE")
		for _, s := range response.Sources {
			state := "active"
			if s.Revoked {
				state = "revoked: " + s.RevokeReason
			}
			added := s.CreatedAt.Format("2006-01-02")
			if s.AfterRelease {
				added += " (after the release)"
			}
			tool := s.Tool
			if s.ToolVersion != "" {
				tool += " " + s.ToolVersion
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", s.ID, s.Filename, s.Origin, tool, s.ComponentCount, added, state)
		}
		return tw.Flush()
	},
}

func releaseSourceAction(action string) *cobra.Command {
	return &cobra.Command{
		Use:   action + " VERSION SOURCE_ID",
		Short: strings.ToUpper(action[:1]) + action[1:] + " a release source (admins, with a reason)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if action == "revoke" && strings.TrimSpace(releaseSourcesReason) == "" {
				return exitError{2, errors.New("--reason is required")}
			}
			client, err := depsClient()
			if err != nil {
				return exitError{2, err}
			}
			if repo := strings.TrimSpace(releaseScanRepo); repo != "" {
				depsRepo = repo
			}
			repoPath, err := depsRepoPath()
			if err != nil {
				return exitError{2, err}
			}
			release, err := findRelease(client, repoPath, args[0])
			if err != nil {
				return exitError{2, err}
			}
			if err := client.Post(fmt.Sprintf("%s/releases/%s/sources/%s/%s", repoPath, release.ID, args[1], action), map[string]string{"reason": releaseSourcesReason}, nil); err != nil {
				return exitError{2, err}
			}
			fmt.Printf("%sd source %s of release %s\n", action, args[1], release.Version)
			return nil
		},
	}
}

func init() {
	releaseScanCmd.Flags().StringVar(&releaseScanRepo, "repo", "", "Repository slug (default: the git remote)")
	releaseScanCmd.Flags().StringVar(&releaseScanImage, "image", "", "Container image reference or tarball analysed locally")
	releaseScanCmd.Flags().BoolVar(&releaseScanYes, "yes", false, "Record without asking")
	releaseScanCmd.Flags().StringVar(&releaseScanReason, "reason", "", "Why the deliverable is recorded despite a mismatch (stored with the source)")
	releaseScanCmd.Flags().BoolVar(&releaseScanForce, "force", false, "Record despite a plausibility mismatch (needs --reason)")
	releaseScanCmd.Flags().BoolVar(&releaseScanAll, "all", false, "Queue the server extraction of every release without an inventory")
	releaseSourcesCmd.Flags().StringVar(&releaseScanRepo, "repo", "", "Repository slug (default: the git remote)")
	releaseSourcesCmd.Flags().StringVar(&readFormat, "format", "table", "Output: table, json")
	revoke := releaseSourceAction("revoke")
	restore := releaseSourceAction("restore")
	for _, c := range []*cobra.Command{revoke, restore} {
		c.Flags().StringVar(&releaseSourcesReason, "reason", "", "Why (audit-logged)")
		c.Flags().StringVar(&releaseScanRepo, "repo", "", "Repository slug (default: the git remote)")
	}
	releaseSourcesCmd.AddCommand(revoke, restore)
	for _, c := range []*cobra.Command{releaseScanCmd, releaseSourcesCmd, revoke, restore} {
		c.Flags().StringVar(&depsOrg, "org", "", "Organization (provider/slug)")
		c.Flags().StringVar(&depsServer, "server", "", "Hibou server URL")
		c.Flags().StringVar(&depsToken, "token", "", "API token")
	}
	releaseCmd.AddCommand(releaseScanCmd, releaseSourcesCmd)
}
