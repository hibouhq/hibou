package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hibouhq/hibou/internal/callgraph"
	"github.com/hibouhq/hibou/internal/cliclient"
)

var (
	analyzeLangs []string
	analyzeDir   string
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Run CI-side analyses whose results enrich uploaded findings",
}

// analyzeReachabilityCmd computes which known-vulnerable symbols the built
// code can actually call, and posts the verdicts to the snapshot the CI run
// uploaded. Compute happens here in CI — where the source and build context
// are — never on the server.
var analyzeReachabilityCmd = &cobra.Command{
	Use:   "reachability",
	Short: "Mark which dependency vulnerabilities are actually reachable from the code",
	Long: `Runs a language-specific call-graph analysis and reports, per advisory, whether
the vulnerable code is reachable from this repository. Unreachable findings can
be down-weighted by the quality gate (org setting).

Supported languages, each at its honest precision:
  go     govulncheck — SYMBOL-level call graph (the vulnerable function is
         provably on/off the call path)
  java   bytecode constant-pool scan — CLASS-level (which packages the
         compiled app references). Build-tool agnostic: --dir points at any
         compiled output — Maven target/classes, Gradle
         build/classes/java/main, or a jar/war.
  rust   cargo metadata + source scan — CRATE-level (which crates the
         workspace source names)

Multi-module / monorepo:
  go     one invocation per Go module (nested go.mod); ./... covers a module fully
  java   point --dir at the REPO ROOT — the scan recurses and finds every
         module's compiled classes (target/classes, build/classes/…) and
         jars/wars; no per-module path list to maintain
  rust   cargo metadata enumerates all workspace members from the root, so a
         single --dir at the workspace covers every crate

Java/Rust also store their reference inventory server-side, so a CVE
published AFTER this run is classified against unchanged code immediately.
Go additionally stores its reachable-symbol inventory, so a Go advisory
published later gets a symbol-level verdict on frozen refs without a rebuild.

Run after 'hibou upload' in the same CI job — the results attach to the
snapshot of the current commit.

Examples:
  hibou analyze reachability --lang go
  hibou analyze reachability --lang go --dir ./service
  hibou analyze reachability --lang java --dir .            # monorepo: scan all modules
  hibou analyze reachability --lang rust --dir rust`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cmd.SilenceUsage = true

		if len(analyzeLangs) == 0 {
			return errors.New("--lang is required (supported: go, java, rust)")
		}

		base, err := resolveUploadBase()
		if err != nil {
			return err
		}
		ci := resolveUploadContext()
		if strings.TrimSpace(ci.commitSHA) == "" {
			return errors.New("commit SHA is required (set --sha or run in CI)")
		}
		client, err := resolveUploadClient()
		if err != nil {
			return err
		}

		for _, lang := range analyzeLangs {
			switch strings.ToLower(strings.TrimSpace(lang)) {
			case "go":
				target := analyzeDir
				if target == "" {
					target = "."
				}
				fmt.Printf("running govulncheck -json ./... in %s\n", target)
				report, err := callgraph.RunGovulncheck(cmd.Context(), analyzeDir)
				if err != nil {
					return err
				}
				reachable, unreachable := report.ReachabilityVerdicts()
				if len(reachable) == 0 && len(unreachable) == 0 {
					fmt.Println("govulncheck: no known vulnerabilities in the dependency graph — nothing to report")
					continue
				}
				// The durable half: the VTA reachable-symbol inventory lets the
				// server give SYMBOL-level verdicts to advisories published
				// AFTER this run — releases and main branches stay covered
				// without a rebuild. Best-effort: verdicts alone still work.
				symbols, symbolsErr := callgraph.GoReachableSymbols(cmd.Context(), analyzeDir)
				if symbolsErr != nil {
					fmt.Printf("note: reachable-symbol inventory skipped: %v\n", symbolsErr)
				}
				if err := submitReachability(client, base, ci.commitSHA, "govulncheck", map[string]any{
					"reachable":   reachable,
					"unreachable": unreachable,
					"go_symbols":  symbols,
				}); err != nil {
					return err
				}
				fmt.Printf("reachability (go, symbol-level): %d reachable, %d unreachable advisories, %d-symbol inventory posted\n",
					len(reachable), len(unreachable), len(symbols))
			case "java":
				target := analyzeDir
				if target == "" {
					target = "."
				}
				fmt.Printf("scanning Java bytecode class references in %s\n", target)
				packages, err := callgraph.ScanJavaClassReferences(target)
				if err != nil {
					return err
				}
				if err := submitReachability(client, base, ci.commitSHA, "bytecode-classrefs", map[string]any{
					"java_packages": packages,
				}); err != nil {
					return err
				}
				fmt.Printf("reachability (java, class-level): %d referenced packages posted\n", len(packages))
			case "rust":
				target := analyzeDir
				if target == "" {
					target = "."
				}
				fmt.Printf("scanning Rust crate usage in %s\n", target)
				usage, err := callgraph.ScanRustCrateUsage(cmd.Context(), analyzeDir)
				if err != nil {
					return err
				}
				if err := submitReachability(client, base, ci.commitSHA, "cargo-craterefs", map[string]any{
					"rust_referenced": usage.Referenced,
					"rust_present":    usage.Present,
				}); err != nil {
					return err
				}
				fmt.Printf("reachability (rust, crate-level): %d referenced, %d present-unreferenced crates posted\n", len(usage.Referenced), len(usage.Present))
			default:
				return fmt.Errorf("unsupported --lang %q (supported: go, java, rust)", lang)
			}
		}
		return nil
	},
}

// submitReachability posts one analyzer's payload to the snapshot of the
// current commit and prints the server's application counts.
func submitReachability(client *cliclient.Client, base uploadBase, commitSHA, analyzer string, payload map[string]any) error {
	body := map[string]any{"commit_sha": commitSHA, "analyzer": analyzer}
	for key, value := range payload {
		body[key] = value
	}
	var response struct {
		Data struct {
			SnapshotID         string `json:"snapshot_id"`
			ReachableUpdated   int64  `json:"reachable_updated"`
			UnreachableUpdated int64  `json:"unreachable_updated"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/orgs/%s/repos/%s/reachability", base.org, base.repo)
	if err := client.Post(path, body, &response); err != nil {
		return fmt.Errorf("submit reachability: %w", err)
	}
	fmt.Printf("→ snapshot %s: %d findings marked reachable, %d not_reachable\n",
		response.Data.SnapshotID, response.Data.ReachableUpdated, response.Data.UnreachableUpdated)
	return nil
}

func init() {
	analyzeReachabilityCmd.Flags().StringSliceVar(&analyzeLangs, "lang", nil, "languages to analyze (go, java, rust)")
	analyzeReachabilityCmd.Flags().StringVar(&analyzeDir, "dir", "", "directory to analyze (default: current)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadOrg, "org", uploadOrg, "organization as provider/slug (auto-detected in CI)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadRepo, "repo", uploadRepo, "repository slug (auto-detected in CI)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadRef, "ref", uploadRef, "git ref (auto-detected in CI)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadCommitSHA, "sha", uploadCommitSHA, "commit SHA (auto-detected in CI)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadServer, "server", uploadServer, "Hibou server URL (or HIBOU_SERVER)")
	analyzeReachabilityCmd.Flags().StringVar(&uploadToken, "token", uploadToken, "API token (or HIBOU_TOKEN)")
	analyzeCmd.AddCommand(analyzeReachabilityCmd)
	rootCmd.AddCommand(analyzeCmd)
}
