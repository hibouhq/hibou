package remediation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	purl "github.com/package-url/packageurl-go"
)

type npmManifest struct {
	Name                 string            `json:"name,omitempty"`
	Version              string            `json:"version,omitempty"`
	PackageManager       string            `json:"packageManager,omitempty"`
	Workspaces           json.RawMessage   `json:"workspaces,omitempty"`
	Dependencies         map[string]string `json:"dependencies,omitempty"`
	DevDependencies      map[string]string `json:"devDependencies,omitempty"`
	OptionalDependencies map[string]string `json:"optionalDependencies,omitempty"`
	PeerDependencies     map[string]string `json:"peerDependencies,omitempty"`
	Engines              map[string]string `json:"engines,omitempty"`
	DevEngines           json.RawMessage   `json:"devEngines,omitempty"`
	Volta                json.RawMessage   `json:"volta,omitempty"`
	Overrides            json.RawMessage   `json:"overrides,omitempty"`
	Resolutions          json.RawMessage   `json:"resolutions,omitempty"`
}

type npmLock struct {
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]npmLockedPackage `json:"packages"`
}

type npmLockedPackage struct {
	npmManifest
	Resolved  string `json:"resolved,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	Link      bool   `json:"link,omitempty"`
}

type npmPackage struct {
	Path    string
	Name    string
	Version string
	Purl    string
}

type NPMBackend struct {
	Tool  Tool
	Match MatchPackages
	// ResolverFactory is replaceable for approved mirrors and offline snapshots.
	// LocalRegistryResolver reads the trusted user's registry settings.
	ResolverFactory func(string) (resolve.Client, error)
	RegistryClient  *http.Client
}

func (b NPMBackend) Validate(u Unit) error {
	if b.Match == nil {
		return errors.New("npm remediation requires authoritative advisory/policy matching and registry metadata")
	}
	if u.Manager != "npm" || filepath.Base(u.Manifest) != "package.json" || filepath.Base(u.Lockfile) != "package-lock.json" {
		return errors.New("this adapter supports npm package-lock v3 projects only")
	}
	if _, err := upgradeLevel(u.UpgradeLevel); err != nil {
		return err
	}
	for _, file := range u.RequiredFiles {
		switch filepath.Base(file) {
		case ".nvmrc", ".node-version", ".tool-versions":
			return errors.New("this runtime pin format needs a validated toolchain-profile adapter")
		case ".npmrc":
			return errors.New("repository npmrc requires an approved registry-configuration adapter")
		}
	}
	return (NativeRelocker{Manager: "npm", Tool: b.Tool}).Validate(u)
}

func (b NPMBackend) Generate(ctx context.Context, root string, u Unit) (UnitResult, error) {
	if err := b.Validate(u); err != nil {
		return UnitResult{}, err
	}
	before, err := readNPMProject(root, u, b.Tool)
	if err != nil {
		return UnitResult{}, err
	}
	matches, err := b.matchInventory(ctx, before)
	if err != nil {
		return UnitResult{}, err
	}
	names := map[string]bool{}
	for _, pkg := range before {
		for _, advisory := range matches[pkg.Purl].Advisories {
			if slices.Contains(u.Vulns, advisory.CanonicalID) && advisory.VEXStatus != "not_affected" && advisory.VEXStatus != "fixed" {
				names[pkg.Name] = true
			}
		}
	}
	if len(names) == 0 {
		return UnitResult{}, errors.New("selected vulnerabilities are not present at this committed base")
	}
	// Prove the original lockfile is consistent before attempting changes.
	if b.ResolverFactory == nil {
		if err := publicNPMConfigAllowed(filepath.Join(root, filepath.FromSlash(filepath.Dir(u.Manifest)))); err != nil {
			return UnitResult{}, err
		}
	}
	if err := b.strictCheck(ctx, root, u); err != nil {
		return UnitResult{}, fmt.Errorf("baseline dependency verification: %w", err)
	}
	declarations, err := pinNPMTargets(ctx, root, u, before, matches, b.Match)
	if err != nil {
		return UnitResult{}, err
	}
	var client resolve.Client
	var finish func() error
	if b.ResolverFactory != nil {
		client, err = b.ResolverFactory(filepath.Join(root, filepath.FromSlash(filepath.Dir(u.Manifest))))
	} else {
		client, finish, err = publicNPMResolver(ctx, b.Match, b.RegistryClient)
		if err == nil {
			defer func() { _ = finish() }()
		}
	}
	if err != nil {
		return UnitResult{}, err
	}
	client = &namespaceGuardResolver{Client: client, match: b.Match, checked: map[string]bool{}}
	s := SCALIBR{
		Resolver: client, Enricher: MatchEnricher{Match: b.Match},
		VerifyFiles: func(context.Context, string, Unit, UnitResult) (Verification, error) {
			return Verification{}, errors.New("verification is owned by npm adapter")
		},
		Relocker: targetedNPMRelocker{tool: b.Tool, names: names, match: b.Match, targets: u.VersionTargets, declarations: declarations, registryClient: b.RegistryClient},
	}
	planningUnit := u
	planningUnit.VersionTargets = nil
	result, err := s.Generate(ctx, root, planningUnit)
	if finish != nil {
		err = errors.Join(err, finish())
	}
	if err != nil {
		return UnitResult{}, err
	}
	after, err := readNPMProject(root, u, b.Tool)
	if err != nil {
		return UnitResult{}, err
	}
	byPath := map[string]npmPackage{}
	for _, p := range before {
		byPath[p.Path] = p
	}
	result.Updates = nil
	for _, p := range after {
		if old, ok := byPath[p.Path]; ok && old.Version != p.Version {
			result.Updates = append(result.Updates, Update{Name: p.Name, From: old.Version, To: p.Version})
		}
	}
	result.baseline = before
	result.RequestedTargets = slices.Clone(u.VersionTargets)
	return result, nil
}

func (b NPMBackend) Verify(ctx context.Context, root string, u Unit, result UnitResult) (Verification, error) {
	if len(result.baseline) == 0 {
		return Verification{}, errors.New("npm verification has no baseline graph")
	}
	after, err := readNPMProject(root, u, b.Tool)
	if err != nil {
		return Verification{}, err
	}
	if err := b.strictCheck(ctx, root, u); err != nil {
		return Verification{}, err
	}
	return b.verifyGraph(ctx, u, result, after)
}

func (b NPMBackend) verifyGraph(ctx context.Context, u Unit, result UnitResult, after []npmPackage) (Verification, error) {
	beforeByPath := map[string]npmPackage{}
	beforeByNameVersion := map[string]bool{}
	beforeNames := map[string]bool{}
	for _, p := range result.baseline {
		beforeByPath[p.Path] = p
		beforeNames[p.Name] = true
		beforeByNameVersion[p.Name+"\x00"+p.Version] = true
	}
	level, err := upgradeLevel(u.UpgradeLevel)
	if err != nil {
		return Verification{}, err
	}
	for _, p := range after {
		if old, exists := beforeByPath[p.Path]; exists && old.Name == p.Name {
			cmp, diff, err := semver.NPM.Difference(old.Version, p.Version)
			if err != nil || cmp > 0 || !level.Allows(diff) {
				return Verification{}, fmt.Errorf("resolved upgrade for %s violates the requested upgrade level", p.Name)
			}
			for _, target := range u.VersionTargets {
				found := false
				for _, p := range after {
					if p.Path == "node_modules/"+target.Name && p.Version == target.Version {
						found = true
					}
				}
				if !found {
					return Verification{}, fmt.Errorf("resolved version for %s does not equal requested target %s", target.Name, target.Version)
				}
			}
		} else if beforeNames[p.Name] && !beforeByNameVersion[p.Name+"\x00"+p.Version] {
			return Verification{}, fmt.Errorf("cannot prove upgrade level across changed dependency layout for %s", p.Name)
		}
	}
	all := append(append([]npmPackage(nil), result.baseline...), after...)
	matches, err := b.matchInventory(ctx, all)
	if err != nil {
		return Verification{}, err
	}
	beforeVulns := map[string]int{}
	beforePurls := map[string]bool{}
	for _, p := range result.baseline {
		beforePurls[p.Purl] = true
		for _, a := range matches[p.Purl].Advisories {
			if a.VEXStatus != "not_affected" && a.VEXStatus != "fixed" {
				beforeVulns[p.Name+"\x00"+a.CanonicalID]++
			}
		}
	}
	afterVulns := map[string]int{}
	for _, p := range after {
		entry := matches[p.Purl]
		if !beforePurls[p.Purl] && entry.Decision != "allow" {
			return Verification{}, fmt.Errorf("package policy did not approve %s: %s", p.Name, entry.Reason)
		}
		for _, a := range entry.Advisories {
			if a.VEXStatus == "not_affected" || a.VEXStatus == "fixed" {
				continue
			}
			if slices.Contains(u.Vulns, a.CanonicalID) {
				return Verification{}, fmt.Errorf("selected advisory %s remains in the locked graph", a.CanonicalID)
			}
			key := p.Name + "\x00" + a.CanonicalID
			afterVulns[key]++
			if afterVulns[key] > beforeVulns[key] {
				return Verification{}, fmt.Errorf("new advisory %s introduced in locked graph", a.CanonicalID)
			}
		}
	}
	return Verification{true, true, true}, nil
}

func (b NPMBackend) matchInventory(ctx context.Context, packages []npmPackage) (map[string]AdvisoryMatch, error) {
	purls := make([]string, 0, len(packages))
	for _, p := range packages {
		purls = append(purls, p.Purl)
	}
	results, err := checkedMatches(ctx, b.Match, purls)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAdvisoryEvidence, err)
	}
	return results, nil
}

func (b NPMBackend) strictCheck(ctx context.Context, root string, u Unit) error {
	temp, err := os.MkdirTemp("", "hibou-npm-verify-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(temp) }()
	home, dir := filepath.Join(temp, "home"), filepath.Join(temp, "repo")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	outputRoot, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer outputRoot.Close()
	before := map[string]string{}
	module := filepath.Dir(u.Manifest)
	for _, file := range u.RequiredFiles {
		relative, err := filepath.Rel(module, file)
		if err != nil || !safePath(filepath.ToSlash(relative)) {
			return errors.New("npm verification requires a complete module boundary")
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
		if err != nil {
			return err
		}
		if err := outputRoot.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return err
		}
		if err := outputRoot.WriteFile(relative, data, 0o600); err != nil {
			return err
		}
		before[relative] = digest(data)
	}
	proxy, err := startNPMProxyWithClient(ctx, b.Match, b.RegistryClient)
	if err != nil {
		return err
	}
	defer func() { _ = proxy.close() }()
	tool := b.Tool
	tool.RegistryURL = proxy.URL
	if tool.RegistryOrigin != "" {
		lockfile := filepath.Base(u.Lockfile)
		if err := rewriteNPMLocations(dir, lockfile, []string{"https://registry.npmjs.org/", tool.RegistryOrigin}, proxy.URL); err != nil {
			return err
		}
		data, err := outputRoot.ReadFile(lockfile)
		if err != nil {
			return err
		}
		before[lockfile] = digest(data)
	}
	if err := errors.Join(tool.Run(ctx, dir, home, "ci", "--ignore-scripts", "--no-audit", "--no-fund"), proxy.close()); err != nil {
		return fmt.Errorf("npm ci consistency verification: %w", err)
	}
	for file, hash := range before {
		data, err := outputRoot.ReadFile(file)
		if err != nil || digest(data) != hash {
			return fmt.Errorf("strict npm verification changed required file %s", file)
		}
	}
	return nil
}

type targetedNPMRelocker struct {
	tool           Tool
	names          map[string]bool
	match          MatchPackages
	targets        []VersionTarget
	declarations   map[string]string
	registryClient *http.Client
}

func (r targetedNPMRelocker) Validate(u Unit) error {
	return (NativeRelocker{Manager: "npm", Tool: r.tool}).Validate(u)
}
func (r targetedNPMRelocker) Relock(ctx context.Context, root string, u Unit) error {
	if err := r.Validate(u); err != nil {
		return err
	}
	var names []string
	for name := range r.names {
		if strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\r\n\\") {
			return errors.New("invalid npm package identity")
		}
		manual := false
		for _, target := range r.targets {
			if target.Name == name {
				manual = true
			}
		}
		if !manual {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	home, err := os.MkdirTemp("", "hibou-npm-update-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(home) }()
	proxy, err := startNPMProxyWithClient(ctx, r.match, r.registryClient)
	if err != nil {
		return err
	}
	defer func() { _ = proxy.close() }()
	tool := r.tool
	tool.RegistryURL = proxy.URL
	dir := filepath.Join(root, filepath.FromSlash(filepath.Dir(u.Manifest)))
	if tool.RegistryOrigin != "" {
		if err := rewriteNPMLocations(root, u.Lockfile, []string{"https://registry.npmjs.org/", tool.RegistryOrigin}, proxy.URL); err != nil {
			return err
		}
	}
	if len(names) > 0 {
		args := append([]string{"update", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--save=false", "--"}, names...)
		if err := tool.Run(ctx, dir, home, args...); err != nil {
			return errors.Join(err, proxy.close())
		}
	}
	if len(r.targets) > 0 {
		if err := restoreNPMDeclarations(root, u, r.declarations); err != nil {
			return err
		}
		args := []string{"install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--save=false", "--"}
		for _, target := range r.targets {
			args = append(args, target.Name+"@"+target.Version)
		}
		if err := tool.Run(ctx, dir, home, args...); err != nil {
			return errors.Join(err, proxy.close())
		}
		// npm's --save=false can retain old lockfile root declarations. A
		// normal lock-only install reconciles them with the restored manifest.
		if err := tool.Run(ctx, dir, home, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"); err != nil {
			return errors.Join(err, proxy.close())
		}
	}
	if err := proxy.close(); err != nil {
		return err
	}
	if err := canonicalizeProxyLocations(root, u, proxy.URL, r.tool.RegistryOrigin); err != nil {
		return err
	}
	return nil
}

func readNPMProject(root string, u Unit, tool Tool) ([]npmPackage, error) {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(u.Manifest)))
	if err != nil {
		return nil, err
	}
	lockData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(u.Lockfile)))
	if err != nil {
		return nil, err
	}
	return parseNPMProject(data, lockData, tool)
}

func parseNPMProject(data, lockData []byte, tool Tool) ([]npmPackage, error) {
	var manifest npmManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	if len(manifest.Workspaces) != 0 && string(manifest.Workspaces) != "null" {
		return nil, errors.New("npm workspaces require a separately validated adapter")
	}
	if (len(manifest.DevEngines) > 0 && string(manifest.DevEngines) != "null") || (len(manifest.Volta) > 0 && string(manifest.Volta) != "null") {
		return nil, errors.New("devEngines/Volta pins need a validated toolchain-profile adapter")
	}
	for _, configuration := range []json.RawMessage{manifest.Overrides, manifest.Resolutions} {
		if len(configuration) > 0 && string(configuration) != "null" && string(configuration) != "{}" {
			return nil, errors.New("dependency overrides/resolutions require a separately validated adapter")
		}
	}
	if manifest.PackageManager != "" && manifest.PackageManager != "npm@"+tool.VersionOutput {
		return nil, errors.New("installed npm does not match the repository packageManager pin")
	}
	for _, requirements := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies, manifest.PeerDependencies} {
		for name, constraint := range requirements {
			if !validNPMName(name) {
				return nil, errors.New("invalid npm package name")
			}
			if _, err := semver.NPM.ParseConstraint(constraint); err != nil {
				return nil, fmt.Errorf("non-registry dependency %s is not supported by this adapter", name)
			}
		}
	}
	for name, version := range map[string]string{"npm": tool.VersionOutput, "node": strings.TrimPrefix(tool.RuntimeVersionOutput, "v")} {
		if constraint := manifest.Engines[name]; constraint != "" {
			parsed, err := semver.NPM.ParseConstraint(constraint)
			if err != nil || version == "" || !parsed.Match(version) {
				return nil, fmt.Errorf("installed %s does not satisfy the repository engines constraint", name)
			}
		}
	}
	var lock npmLock
	if err := json.Unmarshal(lockData, &lock); err != nil {
		return nil, err
	}
	base, exists := lock.Packages[""]
	if lock.LockfileVersion != 3 || !exists {
		return nil, errors.New("only npm package-lock format 3 is validated by this adapter")
	}
	if !maps.Equal(base.Dependencies, manifest.Dependencies) || !maps.Equal(base.DevDependencies, manifest.DevDependencies) ||
		!maps.Equal(base.OptionalDependencies, manifest.OptionalDependencies) || !maps.Equal(base.PeerDependencies, manifest.PeerDependencies) {
		return nil, errors.New("manifest and lockfile root requirements differ")
	}
	var packages []npmPackage
	for location, p := range lock.Packages {
		if location == "" {
			continue
		}
		if p.Link || !safePath(location) || !strings.Contains("/"+location, "/node_modules/") {
			return nil, fmt.Errorf("unsupported local/workspace dependency %q", location)
		}
		name := location[strings.LastIndex("/"+location, "/node_modules/")+len("/node_modules/")-1:]
		if !validNPMName(name) {
			return nil, errors.New("unsupported locked package identity")
		}
		if (p.Name != "" && p.Name != name) || strings.Contains(name, "/node_modules/") {
			return nil, errors.New("aliased lockfile entries require a separately validated adapter")
		}
		if _, err := semver.NPM.Parse(p.Version); err != nil {
			return nil, err
		}
		parsed, err := url.Parse(p.Resolved)
		if err != nil || !approvedNPMLocation(parsed, tool.RegistryOrigin) || !validIntegrity(p.Integrity) {
			return nil, fmt.Errorf("dependency %s lacks a supported registry source/integrity hash", name)
		}

		key, err := purl.FromString("pkg:npm/" + name + "@" + p.Version)
		if err != nil {
			return nil, err
		}
		packages = append(packages, npmPackage{Path: location, Name: name, Version: p.Version, Purl: key.ToString()})
	}
	slices.SortFunc(packages, func(a, b npmPackage) int { return strings.Compare(a.Path, b.Path) })
	return packages, nil
}

func (b NPMBackend) Prepare(ctx context.Context, repository, sha, manifest string, selected []string, level string) (Unit, error) {
	u, err := b.PrepareMetadata(ctx, repository, sha, manifest, selected, level)
	if err != nil {
		return Unit{}, err
	}
	if err := b.Validate(u); err != nil {
		return Unit{}, err
	}
	return u, nil
}

// PrepareMetadata reads committed dependency data and authoritative policy only.
// Controllers can discover units without installing or executing native tools.
func (b NPMBackend) PrepareMetadata(ctx context.Context, repository, sha, manifest string, selected []string, level string) (Unit, error) {
	if b.Match == nil {
		return Unit{}, ErrAdvisoryEvidence
	}
	u, err := PrepareNPM(ctx, repository, sha, manifest, selected, level)
	if err != nil {
		return Unit{}, err
	}
	for _, file := range u.RequiredFiles {
		if name := path.Base(file); name != "package.json" && name != "package-lock.json" {
			return Unit{}, errors.New("managed npm metadata requires an independent module without repository manager/runtime controls")
		}
	}
	home, err := os.MkdirTemp("", "hibou-npm-prepare-")
	if err != nil {
		return Unit{}, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	manifestData, err := gitOutput(ctx, repository, home, "cat-file", "blob", sha+":"+u.Manifest)
	if err != nil {
		return Unit{}, err
	}
	lockData, err := gitOutput(ctx, repository, home, "cat-file", "blob", sha+":"+u.Lockfile)
	if err != nil {
		return Unit{}, err
	}
	packages, err := parseNPMProject(manifestData, lockData, b.Tool)
	if err != nil {
		return Unit{}, err
	}
	matches, err := b.matchInventory(ctx, packages)
	if err != nil {
		return Unit{}, err
	}
	u.DirectPackages, err = directNPMPackages(manifestData, packages, matches)
	if err != nil {
		return Unit{}, err
	}
	ids := map[string]bool{}
	for _, entry := range matches {
		for _, a := range entry.Advisories {
			if a.VEXStatus == "not_affected" || a.VEXStatus == "fixed" {
				continue
			}
			if len(selected) == 0 || slices.Contains(selected, a.CanonicalID) {
				if _, err := a.OSV(); err != nil {
					return Unit{}, fmt.Errorf("%w: %w", ErrAdvisoryEvidence, err)
				}
				ids[a.CanonicalID] = true
			}
		}
	}
	u.Vulns = nil
	for id := range ids {
		u.Vulns = append(u.Vulns, id)
	}
	slices.Sort(u.Vulns)
	if len(u.Vulns) == 0 {
		return Unit{}, errors.New("no actionable selected advisories in this committed module")
	}
	return u, nil
}

func DiscoverNPMManifests(ctx context.Context, repository, sha string) ([]string, error) {
	if !validSHA(sha) {
		return nil, errors.New("full commit SHA required")
	}
	home, err := os.MkdirTemp("", "hibou-module-discovery-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	out, err := gitOutput(ctx, repository, home, "ls-tree", "-r", "--name-only", "-z", sha)
	if err != nil {
		return nil, err
	}
	var manifests []string
	for _, file := range strings.Split(string(out), "\x00") {
		if path.Base(file) == "package.json" && safePath(file) && !strings.Contains("/"+file, "/node_modules/") && !strings.Contains("/"+file, "/vendor/") {
			manifests = append(manifests, file)
			if len(manifests) > MaxUnits {
				return nil, errors.New("too many npm modules; narrow the selected manifest paths")
			}
		}
	}
	slices.Sort(manifests)
	return manifests, nil
}

func validIntegrity(value string) bool {
	for _, hash := range strings.Fields(value) {
		kind, encoded, ok := strings.Cut(hash, "-")
		if !ok {
			return false
		}
		data, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return false
		}
		if (kind == "sha512" && len(data) == 64) || (kind == "sha256" && len(data) == 32) || (kind == "sha1" && len(data) == 20) {
			return true
		}
	}
	return false
}

// PrepareNPM binds one selected independent module to committed inputs. It does
// not read dirty working-tree files or execute a package manager.
func PrepareNPM(ctx context.Context, repository, sha, manifest string, vulns []string, level string) (Unit, error) {
	if !validSHA(sha) || !safePath(manifest) || path.Base(manifest) != "package.json" {
		return Unit{}, errors.New("invalid npm source target")
	}
	home, err := os.MkdirTemp("", "hibou-remediation-discovery-")
	if err != nil {
		return Unit{}, err
	}
	defer func() { _ = os.RemoveAll(home) }()
	u := Unit{ID: path.Dir(manifest), Manager: "npm", Manifest: manifest,
		Lockfile: path.Join(path.Dir(manifest), "package-lock.json"), Vulns: slices.Clone(vulns), UpgradeLevel: level, InputSHA256: map[string]string{}}
	listing, err := gitOutput(ctx, repository, home, "ls-tree", "-r", "--name-only", "-z", sha, "--", path.Dir(manifest))
	if err != nil {
		return Unit{}, err
	}
	for _, file := range strings.Split(string(listing), "\x00") {
		if !dependencyControlFile(path.Base(file)) {
			continue
		}
		if path.Dir(file) != path.Dir(manifest) {
			return Unit{}, errors.New("nested/workspace dependency inputs need a separately validated module boundary")
		}
		content, err := gitOutput(ctx, repository, home, "cat-file", "blob", sha+":"+file)
		if err != nil {
			return Unit{}, err
		}
		if len(content) > MaxFileBytes {
			return Unit{}, errors.New("dependency input exceeds size limit")
		}
		u.RequiredFiles = append(u.RequiredFiles, file)
		u.InputSHA256[file] = digest(content)
	}
	if !slices.Contains(u.RequiredFiles, manifest) || !slices.Contains(u.RequiredFiles, u.Lockfile) {
		return Unit{}, errors.New("npm manifest and package-lock.json are required")
	}
	u.WritableFiles = []string{u.Manifest, u.Lockfile}
	slices.Sort(u.RequiredFiles)
	return u, nil
}
