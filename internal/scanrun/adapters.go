package scanrun

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hibouhq/hibou/internal/scancatalog"
	"github.com/hibouhq/hibou/internal/scanplan"
)

// ResolvedDistribution is a catalog artifact with the location the server
// resolved under its distribution policy (GET /scanner-catalog).
type ResolvedDistribution struct {
	scancatalog.Distribution
	Location    *scancatalog.Location `json:"location,omitempty"`
	Unavailable string                `json:"unavailable,omitempty"`
}

// CatalogEntry is one scanner as the server's catalog endpoint returns it.
type CatalogEntry struct {
	scancatalog.Scanner
	Distributions []ResolvedDistribution `json:"distributions"`
}

// Environment is what an adapter runs with.
type Environment struct {
	SourceRoot string
	OutDir     string
	Fetcher    *Fetcher
	// OpenGrepRules is an operator-supplied local rules file or directory,
	// used while no catalog ruleset is approved. Runs with it are not bound
	// to the plan.
	OpenGrepRules string
	// MavenRepository is the local Maven repository the build resolves into
	// (default ~/.m2/repository), checked against the catalog digests.
	MavenRepository string
	// Command runs a program; tests replace it. Never a shell.
	Command func(ctx context.Context, dir, name string, args ...string) ([]byte, int, error)
}

// Result is one job's output.
type Result struct {
	SARIFPaths []string
	// ConfigDigest identifies the rules actually run, when they did not come
	// from the plan.
	ConfigDigest string
	// Unbound: the run deviates from the plan (local rules) and must be
	// uploaded without plan binding.
	Unbound bool
	Notes   []string
}

// ErrPrerequisite: something the job waits for is missing (a compiled
// module); it is a prerequisite failure, never a zero-finding pass.
var ErrPrerequisite = errors.New("prerequisite missing")

// Run executes one ready (or ruleset-blocked, with local rules) job.
func Run(ctx context.Context, job scanplan.Job, entry CatalogEntry, env Environment) (Result, error) {
	if env.Command == nil {
		env.Command = execCommand
	}
	// Defence in depth: Resolver already refused these, but Run must never
	// pass a path that reads as an option or leaves the checkout.
	if err := ValidatePlanPaths(job.Targets, job.Exclusions); err != nil {
		return Result{}, fmt.Errorf("job %s: %w", job.ID, err)
	}
	switch entry.Engine {
	case "opengrep":
		return runOpenGrep(ctx, job, entry, env)
	case "spotbugs":
		return runSpotBugsMaven(ctx, job, entry, env)
	}
	return Result{}, fmt.Errorf("no adapter for engine %q", entry.Engine)
}

func runOpenGrep(ctx context.Context, job scanplan.Job, entry CatalogEntry, env Environment) (Result, error) {
	result := Result{}
	if job.Artifact == nil {
		return result, fmt.Errorf("job %s has no artifact: %s", job.ID, job.BlockedReason)
	}
	var rules string
	switch {
	case job.Ruleset != "":
		return result, fmt.Errorf("ruleset %s: fetching catalog rulesets is not implemented yet; pass local rules to run unbound", job.Ruleset)
	case env.OpenGrepRules != "":
		rules = env.OpenGrepRules
		digest, err := pathDigest(rules)
		if err != nil {
			return result, fmt.Errorf("local rules: %w", err)
		}
		result.ConfigDigest = digest
		result.Unbound = true
		result.Notes = append(result.Notes, "local rules: the report is uploaded without plan binding")
	default:
		return result, errors.New("no ruleset: the plan has no approved OpenGrep ruleset and no local rules were given")
	}
	binary, err := env.Fetcher.Fetch(ctx, *job.Artifact, "opengrep", true)
	if err != nil {
		return result, err
	}
	sarifPath := filepath.Join(env.OutDir, safeName(job.ID)+".sarif")
	args := make([]string, 0, len(entry.Command.Args)+len(job.Exclusions)+len(job.Targets)+1)
	for _, arg := range entry.Command.Args {
		switch arg {
		case "{targets}":
			// "--exclude=<value>" keeps the value bound to its option, and
			// "--" ends options before the positional targets (Q14): a
			// module named "--exclude=*" must never reach opengrep as one.
			for _, exclusion := range job.Exclusions {
				args = append(args, "--exclude="+exclusion)
			}
			args = append(args, "--")
			args = append(args, job.Targets...)
		default:
			arg = strings.ReplaceAll(arg, "{sarif}", sarifPath)
			arg = strings.ReplaceAll(arg, "{rules}", rules)
			args = append(args, arg)
		}
	}
	output, code, err := env.Command(ctx, env.SourceRoot, binary, args...)
	if err != nil && code < 0 {
		return result, fmt.Errorf("run opengrep: %w", err)
	}
	if outcome := exitOutcome(entry.ExitCodes, code); outcome == "error" {
		return result, fmt.Errorf("opengrep exited %d: %s", code, tail(output))
	}
	result.SARIFPaths = []string{sarifPath}
	return result, nil
}

func runSpotBugsMaven(ctx context.Context, job scanplan.Job, entry CatalogEntry, env Environment) (Result, error) {
	result := Result{}
	var plugin, pluginLocation *ResolvedDistribution
	for i := range entry.Distributions {
		d := &entry.Distributions[i]
		switch {
		case strings.HasPrefix(d.Coordinates, "com.github.spotbugs:spotbugs-maven-plugin:"):
			plugin = d
		case strings.HasPrefix(d.Coordinates, "com.h3xstream.findsecbugs:findsecbugs-plugin:"):
			pluginLocation = d
		}
	}
	if plugin == nil || pluginLocation == nil {
		return result, errors.New("catalog entry lacks the SpotBugs Maven plugin or the Find Security Bugs plugin")
	}
	if pluginLocation.Location == nil {
		return result, fmt.Errorf("find security bugs plugin unavailable: %s", pluginLocation.Unavailable)
	}
	findSecBugs, err := env.Fetcher.Fetch(ctx, *pluginLocation.Location, "findsecbugs-plugin.jar", false)
	if err != nil {
		return result, err
	}
	goal := plugin.Coordinates + ":spotbugs"
	for index, module := range job.Targets {
		moduleDir, err := withinRoot(env.SourceRoot, module)
		if err != nil {
			return result, fmt.Errorf("spotbugs on %s: %w", module, err)
		}
		if _, err := os.Stat(filepath.Join(moduleDir, "target", "classes")); err != nil {
			return result, fmt.Errorf("%w: compile %s first (no target/classes): bytecode analysis needs the build's classes", ErrPrerequisite, module)
		}
		args := []string{
			"-B", "-q", "-f", filepath.Join(moduleDir, "pom.xml"), goal,
			"-Dspotbugs.sarifOutput=true", "-Dspotbugs.effort=Max", "-Dspotbugs.threshold=Low",
			"-Dspotbugs.includeTests=false", "-Dspotbugs.failOnError=false",
			"-Dspotbugs.pluginList=" + findSecBugs,
		}
		output, code, err := env.Command(ctx, moduleDir, "mvn", args...)
		if err != nil {
			return result, fmt.Errorf("spotbugs on %s: %w", module, err)
		}
		if code != 0 {
			return result, fmt.Errorf("spotbugs on %s exited %d: %s", module, code, tail(output))
		}
		produced := filepath.Join(moduleDir, "target", "spotbugsSarif.json")
		destination := filepath.Join(env.OutDir, fmt.Sprintf("%s-%d.sarif", safeName(job.ID), index))
		if err := copyFile(produced, destination); err != nil {
			return result, fmt.Errorf("spotbugs on %s produced no SARIF: %w", module, err)
		}
		result.SARIFPaths = append(result.SARIFPaths, destination)
	}
	// Maven resolved the plugin itself: check what it resolved is what the
	// catalog pinned (ADR-035 §7, no unverified executables).
	notes, err := verifyMavenResolved(entry, env.MavenRepository)
	result.Notes = append(result.Notes, notes...)
	return result, err
}

// verifyMavenResolved compares the jars Maven resolved with the catalog's
// sha256. A mismatch fails the job; a jar not found in the local repository
// is reported, not failed (a custom repository layout).
func verifyMavenResolved(entry CatalogEntry, repository string) ([]string, error) {
	if repository == "" {
		return []string{"maven repository unknown: resolved plugin jars not verified"}, nil
	}
	notes := []string{}
	for _, distribution := range entry.Distributions {
		if distribution.Kind != scancatalog.KindMaven || strings.Contains(distribution.Coordinates, "findsecbugs") {
			continue
		}
		jar, err := mavenJarPath(repository, distribution.Coordinates)
		if err != nil {
			return notes, err
		}
		digest, err := FileSHA256(jar)
		if err != nil {
			notes = append(notes, "not found in the local Maven repository, not verified: "+distribution.Coordinates)
			continue
		}
		if digest != distribution.SHA256 {
			return notes, fmt.Errorf("%w: Maven resolved %s with sha256 %s, pinned %s", ErrDigestMismatch, distribution.Coordinates, digest, distribution.SHA256)
		}
	}
	return notes, nil
}

// mavenJarPath is where a group:artifact:version jar sits in a local Maven
// repository. Malformed coordinates are an error, never a panic or a path
// outside the repository.
func mavenJarPath(repository, coordinates string) (string, error) {
	parts := strings.Split(coordinates, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("maven coordinates %q: want group:artifact:version", coordinates)
	}
	segments := append(strings.Split(parts[0], "."), parts[1], parts[2])
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) || strings.HasPrefix(segment, "-") {
			return "", fmt.Errorf("maven coordinates %q: invalid segment %q", coordinates, segment)
		}
	}
	return filepath.Join(append([]string{repository}, append(segments, parts[1]+"-"+parts[2]+".jar")...)...), nil
}

func exitOutcome(codes map[string]string, code int) string {
	if outcome, ok := codes[strconv.Itoa(code)]; ok {
		return outcome
	}
	if outcome, ok := codes["default"]; ok {
		return outcome
	}
	if code == 0 {
		return "ok"
	}
	return "error"
}

func execCommand(ctx context.Context, dir, name string, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, name, args...) // #nosec G204 -- catalog-pinned scanner, arguments never pass through a shell
	command.Dir = dir
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return output.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return output.Bytes(), -1, err
	}
	return output.Bytes(), 0, nil
}

func pathDigest(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	if !info.IsDir() {
		digest, err := FileSHA256(path)
		return "sha256:" + digest, err
	}
	err = filepath.WalkDir(path, func(file string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, _ := filepath.Rel(path, file)
		digest, err := FileSHA256(file)
		if err != nil {
			return err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(relative)+"\x00"+digest+"\n")
		return nil
	})
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), err
}

func copyFile(source, destination string) error {
	data, err := os.ReadFile(source) // #nosec G304 -- the scanner's own output path
	if err != nil {
		return err
	}
	// #nosec G703 -- destination is OutDir joined with safeName(job id)
	return os.WriteFile(destination, data, 0o600)
}

// safeName keeps a plan job id usable as a file name: the id comes from the
// server, and a path separator in it must not escape the output directory.
func safeName(id string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		}
		return '_'
	}, id)
	if cleaned == "" {
		return "job"
	}
	return cleaned
}

func tail(output []byte) string {
	text := strings.TrimSpace(string(output))
	if len(text) > 600 {
		text = "…" + text[len(text)-600:]
	}
	return text
}
