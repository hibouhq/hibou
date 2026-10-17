package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/depinventory"
	"github.com/hibouhq/hibou/internal/sbom"
)

// ---- hibou deps verify (ADR-046 §5): offline, no server ----

var (
	verifySBOM   string
	verifyFormat string
	verifyFailOn string
)

var depsVerifyCmd = &cobra.Command{
	Use:   "verify DELIVERABLE --sbom FILE",
	Short: "Does an SBOM describe this deliverable? Fully offline",
	Long: `Compares what hibou finds inside a deliverable with what an SBOM declares.
Undeclared (found, absent from the SBOM) is strong evidence; not found
(declared, absent from the deliverable) is weak, since extraction has
known blind spots, and is reported with the blind spot that applies.
Exit 0 by default; --fail-on undeclared|mismatch|integrity returns 1.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if verifySBOM == "" {
			return exitError{2, errors.New("--sbom is required")}
		}
		result, err := verifyDeliverable(cmd.Context(), args[0], verifySBOM)
		if err != nil {
			return exitError{2, err}
		}
		if strings.EqualFold(verifyFormat, "json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(result)
		} else {
			printVerify(result)
		}
		for _, fail := range strings.Split(strings.ToLower(verifyFailOn), ",") {
			switch strings.TrimSpace(fail) {
			case "undeclared":
				if len(result.Undeclared) > 0 {
					return exitError{1, fmt.Errorf("%d undeclared component(s)", len(result.Undeclared))}
				}
			case "mismatch":
				if len(result.Mismatched) > 0 {
					return exitError{1, fmt.Errorf("%d version mismatch(es)", len(result.Mismatched))}
				}
			case "integrity":
				if result.Integrity == "mismatch" {
					return exitError{1, errors.New("the deliverable's digest does not match the SBOM")}
				}
			}
		}
		return nil
	},
}

type verifyEntry struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Found     string `json:"found,omitempty"`
	Declared  string `json:"declared,omitempty"`
	Path      string `json:"path,omitempty"`
	Note      string `json:"note,omitempty"`
}

type verifyResult struct {
	Deliverable  string        `json:"deliverable"`
	SBOM         string        `json:"sbom"`
	Matched      int           `json:"matched"`
	Undeclared   []verifyEntry `json:"undeclared"`
	Mismatched   []verifyEntry `json:"mismatched"`
	NotFound     []verifyEntry `json:"not_found"`
	Integrity    string        `json:"integrity"`
	Unidentified int           `json:"unidentified"`
	BlindSpots   []string      `json:"blind_spots,omitempty"`
}

func verifyDeliverable(ctx context.Context, deliverable, sbomPath string) (*verifyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := os.ReadFile(sbomPath) // #nosec G304 -- a file the user named
	if err != nil {
		return nil, err
	}
	var declared []sbom.ParsedComponent
	var probe struct {
		BomFormat string `json:"bomFormat"`
		Metadata  struct {
			Component struct {
				Hashes []struct {
					Alg     string `json:"alg"`
					Content string `json:"content"`
				} `json:"hashes"`
			} `json:"component"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(data, &probe)
	if probe.BomFormat == "CycloneDX" {
		declared, err = sbom.ParseCycloneDXJSON(data)
	} else {
		declared, err = sbom.ParseSPDXJSON(data)
	}
	if err != nil {
		return nil, fmt.Errorf("parse SBOM: %w", err)
	}
	inv, err := depinventory.ScanTargets(ctx, []string{deliverable}, depinventory.ScanOptions{Warn: func(string) {}})
	if err != nil {
		return nil, err
	}
	result := &verifyResult{Deliverable: deliverable, SBOM: sbomPath, Undeclared: []verifyEntry{}, Mismatched: []verifyEntry{}, NotFound: []verifyEntry{}, Unidentified: inv.UnidentifiedCount, Integrity: "not declared"}

	identity := func(ecosystem, name string) string {
		return strings.ToLower(ecosystem) + "|" + strings.ToLower(name)
	}
	found := map[string]depinventory.Component{}
	for _, c := range inv.Components {
		found[identity(c.Ecosystem, c.Name)] = c
	}
	declaredBy := map[string]sbom.ParsedComponent{}
	for _, d := range declared {
		if d.PURL == "" && d.Name == "" {
			continue
		}
		declaredBy[identity(d.Ecosystem, d.Name)] = d
	}
	for key, c := range found {
		d, ok := declaredBy[key]
		switch {
		case !ok:
			result.Undeclared = append(result.Undeclared, verifyEntry{Name: c.Name, Ecosystem: c.Ecosystem, Found: c.Version, Path: c.Path})
		case strings.TrimPrefix(d.Version, "v") != strings.TrimPrefix(c.Version, "v"):
			result.Mismatched = append(result.Mismatched, verifyEntry{Name: c.Name, Ecosystem: c.Ecosystem, Found: c.Version, Declared: d.Version, Path: c.Path})
		default:
			result.Matched++
		}
	}
	blind := map[string]bool{}
	for key, d := range declaredBy {
		if _, ok := found[key]; ok {
			continue
		}
		note := blindSpotFor(d.Ecosystem, inv)
		if note != "" {
			blind[note] = true
		}
		result.NotFound = append(result.NotFound, verifyEntry{Name: d.Name, Ecosystem: d.Ecosystem, Declared: d.Version, Note: note})
	}
	for note := range blind {
		result.BlindSpots = append(result.BlindSpots, note)
	}
	sort.Strings(result.BlindSpots)
	sort.Slice(result.Undeclared, func(i, j int) bool { return result.Undeclared[i].Name < result.Undeclared[j].Name })
	sort.Slice(result.Mismatched, func(i, j int) bool { return result.Mismatched[i].Name < result.Mismatched[j].Name })
	sort.Slice(result.NotFound, func(i, j int) bool { return result.NotFound[i].Name < result.NotFound[j].Name })

	// Integrity: the file's sha256 against metadata.component.hashes.
	for _, hash := range probe.Metadata.Component.Hashes {
		if strings.EqualFold(hash.Alg, "SHA-256") {
			digest, err := sha256File(deliverable)
			if err == nil && strings.EqualFold(digest, hash.Content) {
				result.Integrity = "ok"
			} else {
				result.Integrity = "mismatch"
			}
		}
	}
	return result, nil
}

func blindSpotFor(ecosystem string, inv *depinventory.ArtifactInventory) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "a minified JavaScript bundle carries no package identity"
	case "maven":
		return "shaded or relocated jars lose their Maven metadata"
	case "cargo":
		return "a Rust binary not built with cargo auditable carries no dependency list"
	case "pypi":
		return "a single wheel lists only its own requirements, not what is installed"
	}
	if inv.UnidentifiedCount > 0 {
		return "files no extractor recognised are listed as not identified"
	}
	return ""
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a file the user named
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func printVerify(result *verifyResult) {
	fmt.Printf("%s against %s\n", result.Deliverable, result.SBOM)
	fmt.Printf("matched %d · undeclared %d · version mismatch %d · not found %d · integrity %s", result.Matched, len(result.Undeclared), len(result.Mismatched), len(result.NotFound), result.Integrity)
	if result.Unidentified > 0 {
		fmt.Printf(" · %d files not identified", result.Unidentified)
	}
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, e := range result.Undeclared {
		fmt.Fprintf(tw, "UNDECLARED\t%s\t%s\tin the deliverable (%s), absent from the SBOM\n", e.Name, e.Found, e.Path)
	}
	for _, e := range result.Mismatched {
		fmt.Fprintf(tw, "MISMATCH\t%s\t%s\tSBOM declares %s\n", e.Name, e.Found, e.Declared)
	}
	for _, e := range result.NotFound {
		fmt.Fprintf(tw, "NOT FOUND\t%s\t%s\t%s\n", e.Name, e.Declared, e.Note)
	}
	_ = tw.Flush()
	if len(result.BlindSpots) > 0 {
		fmt.Println("\nNot found is weak evidence:")
		for _, b := range result.BlindSpots {
			fmt.Println("  -", b)
		}
	}
}

// ---- hibou deps check (ADR-048 §3.1): the CI pre-install step ----

var (
	checkFailOn string
	checkFormat string
)

var depsCheckCmd = &cobra.Command{
	Use:   "check [DIR]",
	Short: "Ask the package policy about every version this tree declares, before installing anything",
	Long: `Reads the lockfiles and manifests of the tree and asks the organization's
package policy (cooldown, malicious packages, acceptances) about each
version. Nothing is installed or stored. Run it before "npm ci", "pip
install" or "mvn package" so a fresh or malicious version never reaches the
runner: exit 1 with --fail-on hold,deny (default: deny).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		inv, err := depinventory.Extract(cmd.Context(), dir, depinventory.Options{})
		if err != nil {
			return exitError{2, err}
		}
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		org, err := depsOrgSlug()
		if err != nil {
			return exitError{2, err}
		}
		repo := strings.TrimSpace(depsRepo)
		if repo == "" {
			repo = gitRemoteRepoSlug(dir)
		}
		purls := make([]string, 0, len(inv.Components))
		seen := map[string]bool{}
		for _, c := range inv.Components {
			if c.Version == "" || seen[c.Purl] || c.Registry == depinventory.RegistryPrivate {
				continue
			}
			seen[c.Purl] = true
			purls = append(purls, c.Purl)
		}
		if len(purls) == 0 {
			fmt.Println("No versioned dependency found; nothing to check.")
			return nil
		}
		type decision struct {
			Purl      string   `json:"purl"`
			Decision  string   `json:"decision"`
			Reason    string   `json:"reason"`
			Until     string   `json:"until"`
			Evaluated bool     `json:"evaluated"`
			Warnings  []string `json:"warnings"`
		}
		var response struct {
			Decisions []decision `json:"decisions"`
			Policy    struct {
				Window string `json:"window"`
			} `json:"policy"`
		}
		holds, denies := []decision{}, []decision{}
		for start := 0; start < len(purls); start += 1000 {
			end := start + 1000
			if end > len(purls) {
				end = len(purls)
			}
			body := map[string]any{"purls": purls[start:end]}
			if repo != "" {
				body["repo"] = repo
			}
			var page struct {
				Decisions []decision `json:"decisions"`
				Policy    struct {
					Window string `json:"window"`
				} `json:"policy"`
			}
			if err := client.Post(fmt.Sprintf("/orgs/%s/policy/packages", org), body, &page); err != nil {
				return exitError{2, err}
			}
			response.Decisions = append(response.Decisions, page.Decisions...)
			response.Policy = page.Policy
		}
		for _, d := range response.Decisions {
			switch d.Decision {
			case "hold":
				holds = append(holds, d)
			case "deny":
				denies = append(denies, d)
			}
		}
		if strings.EqualFold(checkFormat, "json") {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(response)
		} else {
			fmt.Printf("%d versions checked against the package policy (window %s): %d held, %d denied\n", len(response.Decisions), response.Policy.Window, len(holds), len(denies))
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			for _, d := range denies {
				fmt.Fprintf(tw, "✖ deny\t%s\t%s\n", d.Purl, d.Reason)
			}
			for _, d := range holds {
				fmt.Fprintf(tw, "⏳ hold\t%s\t%s\n", d.Purl, d.Reason)
			}
			_ = tw.Flush()
			if len(holds) > 0 {
				fmt.Println("A hold ends on its own; an organization admin can record an acceptance for the exact version.")
			}
		}
		for _, fail := range strings.Split(strings.ToLower(checkFailOn), ",") {
			switch strings.TrimSpace(fail) {
			case "deny":
				if len(denies) > 0 {
					return exitError{1, fmt.Errorf("%d denied version(s)", len(denies))}
				}
			case "hold":
				if len(holds) > 0 {
					return exitError{1, fmt.Errorf("%d version(s) in cooldown", len(holds))}
				}
			}
		}
		return nil
	},
}

// ---- hibou deps cooldown init (ADR-048 §3.1): the generator ----

var (
	cooldownWindow  string
	cooldownTools   []string
	cooldownUpdater string
	cooldownDir     string
	cooldownDryRun  bool
)

var depsCooldownCmd = &cobra.Command{
	Use:   "cooldown",
	Short: "Install-time cooldown settings",
}

var depsCooldownInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write the install-time cooldown setting of every package manager this tree uses",
	Long: `Writes or updates the committed setting that keeps a freshly published
version off every machine and runner (ADR-048 §3.1): npm min-release-age
(.npmrc), pnpm minimumReleaseAge (pnpm-workspace.yaml), Yarn
npmMinimalAgeGate (.yarnrc.yml), Bun install.minimumReleaseAge
(bunfig.toml), uv exclude-newer (pyproject.toml), pip uploaded-prior-to
(pip.conf), and the updater's cooldown (Renovate minimumReleaseAge,
Dependabot cooldown.default-days). Existing values are replaced only when
shorter than the window. Nothing is sent anywhere.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		window, err := parseCooldownDays(cooldownWindow)
		if err != nil {
			return exitError{2, err}
		}
		dir := cooldownDir
		inv, err := depinventory.Extract(cmd.Context(), dir, depinventory.Options{})
		if err != nil {
			return exitError{2, err}
		}
		changes, err := depinventory.GenerateInstallConfig(dir, inv.Modules, window, cooldownTools, cooldownUpdater, cooldownDryRun)
		if err != nil {
			return exitError{2, err}
		}
		if len(changes) == 0 {
			fmt.Println("Nothing to write: every package manager in this tree already waits at least", cooldownWindow)
			return nil
		}
		verb := "wrote"
		if cooldownDryRun {
			verb = "would write"
		}
		for _, change := range changes {
			fmt.Printf("%s %s: %s\n", verb, change.Path, change.Change)
		}
		return nil
	},
}

func parseCooldownDays(value string) (int, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, "d")
	var days int
	if _, err := fmt.Sscanf(value, "%d", &days); err != nil || days <= 0 {
		return 0, fmt.Errorf("--window must be a number of days such as 7d, got %q", cooldownWindow)
	}
	return days, nil
}

// ---- hibou deps not-shipped (ADR-045 §6) ----

var (
	notShippedReason string
)

var depsNotShippedCmd = &cobra.Command{
	Use:   "not-shipped",
	Short: "The repository's not-shipped list: components that never reach clients",
}

var depsNotShippedListCmd = &cobra.Command{
	Use:   "list",
	Short: "Every entry that applies to the repository, with its source",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		var info struct {
			Entries []struct {
				ID         *string `json:"id"`
				Pattern    string  `json:"pattern"`
				Reason     string  `json:"reason"`
				Source     string  `json:"source"`
				Overridden bool    `json:"overridden"`
			} `json:"entries"`
			UploadedSBOM bool     `json:"uploaded_sbom"`
			Undeclared   []string `json:"undeclared_modules"`
		}
		if err := client.Get(repoPath+"/dependencies/shipping", &info); err != nil {
			return exitError{2, err}
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SOURCE\tPATTERN\tREASON\tID")
		for _, e := range info.Entries {
			id := ""
			if e.ID != nil {
				id = *e.ID
			}
			pattern := e.Pattern
			if e.Overridden {
				pattern += " (cancelled by dependencies.shipped)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Source, pattern, e.Reason, id)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
		if info.UploadedSBOM {
			fmt.Println("\nAn uploaded SBOM decides what ships for this repository; the lists apply outside its coverage.")
		}
		if len(info.Undeclared) > 0 {
			fmt.Printf("Not in the uploaded SBOM, undeclared: %s (set dependencies.sbom_covers)\n", strings.Join(info.Undeclared, ", "))
		}
		return nil
	},
}

var depsNotShippedAddCmd = &cobra.Command{
	Use:   "add PATTERN [PATTERN...]",
	Short: "Record patterns as not shipped (admins and release managers)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.TrimSpace(notShippedReason) == "" {
			return exitError{2, errors.New("--reason is required")}
		}
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		entries := make([]map[string]string, 0, len(args))
		for _, pattern := range args {
			entries = append(entries, map[string]string{"pattern": pattern, "reason": notShippedReason})
		}
		var created []struct {
			ID      string `json:"id"`
			Pattern string `json:"pattern"`
		}
		if err := client.Post(repoPath+"/dependencies/not-shipped", map[string]any{"entries": entries}, &created); err != nil {
			return exitError{2, err}
		}
		for _, entry := range created {
			fmt.Printf("recorded %s (%s)\n", entry.Pattern, entry.ID)
		}
		return nil
	},
}

var depsNotShippedRemoveCmd = &cobra.Command{
	Use:   "remove ID",
	Short: "Remove a repository entry by id",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := depsClient()
		if err != nil {
			return exitError{2, err}
		}
		repoPath, err := depsRepoPath()
		if err != nil {
			return exitError{2, err}
		}
		if err := client.Delete(repoPath + "/dependencies/not-shipped/" + args[0]); err != nil {
			return exitError{2, err}
		}
		fmt.Println("removed", args[0])
		return nil
	},
}

func init() {
	depsVerifyCmd.Flags().StringVar(&verifySBOM, "sbom", "", "The SBOM (CycloneDX or SPDX JSON) to verify against")
	depsVerifyCmd.Flags().StringVar(&verifyFormat, "format", "table", "Output: table, json")
	depsVerifyCmd.Flags().StringVar(&verifyFailOn, "fail-on", "", "Exit 1 on: undeclared, mismatch, integrity (comma-separated)")
	depsCheckCmd.Flags().StringVar(&checkFailOn, "fail-on", "deny", "Exit 1 on: deny, hold (comma-separated)")
	depsCheckCmd.Flags().StringVar(&checkFormat, "format", "table", "Output: table, json")
	depsCooldownInitCmd.Flags().StringVar(&cooldownWindow, "window", "7d", "Cooldown window in days")
	depsCooldownInitCmd.Flags().StringArrayVar(&cooldownTools, "tool", nil, "Limit to these package managers (npm, pnpm, yarn, bun, uv, pip); default: every one the tree uses")
	depsCooldownInitCmd.Flags().StringVar(&cooldownUpdater, "updater", "", "Also set the updater's cooldown: renovate or dependabot")
	depsCooldownInitCmd.Flags().StringVar(&cooldownDir, "dir", ".", "Repository root")
	depsCooldownInitCmd.Flags().BoolVar(&cooldownDryRun, "dry-run", false, "Show the changes without writing")
	depsCooldownCmd.AddCommand(depsCooldownInitCmd)
	depsNotShippedAddCmd.Flags().StringVar(&notShippedReason, "reason", "", "Why the packages never reach clients (recorded, audit-logged)")
	depsNotShippedCmd.AddCommand(depsNotShippedListCmd, depsNotShippedAddCmd, depsNotShippedRemoveCmd)
	_ = filepath.Base
}
