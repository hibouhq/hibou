package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"deps.dev/util/semver"
	purl "github.com/package-url/packageurl-go"
	"github.com/tidwall/sjson"
)

type VersionTarget struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	Version         string `json:"version"`
	AllowPrerelease bool   `json:"allow_prerelease,omitempty"`
}

type DirectPackage struct {
	Name                    string    `json:"name"`
	Version                 string    `json:"version"`
	RecommendedVersion      string    `json:"recommended_version,omitempty"`
	CanSelectVersion        bool      `json:"can_select_version"`
	Declared                string    `json:"declared"`
	RecommendationFetchedAt time.Time `json:"recommendation_fetched_at,omitzero"`
}

var exactNPMVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

func directNPMPackages(manifestData []byte, packages []npmPackage, matches map[string]AdvisoryMatch) ([]DirectPackage, error) {
	var manifest npmManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	declared := map[string][]string{}
	for _, deps := range []map[string]string{manifest.Dependencies, manifest.DevDependencies, manifest.OptionalDependencies} {
		for name, constraint := range deps {
			base := strings.TrimPrefix(strings.TrimPrefix(constraint, "^"), "~")
			simple := exactNPMVersion.MatchString(base)
			if previous, exists := names[name]; exists {
				simple = simple && previous
			}
			names[name] = simple
			declared[name] = append(declared[name], constraint)
		}
	}
	var result []DirectPackage
	for _, p := range packages {
		canSelect, exists := names[p.Name]
		if !exists || p.Path != "node_modules/"+p.Name {
			continue
		}
		entry := DirectPackage{Name: p.Name, Version: p.Version, CanSelectVersion: canSelect, Declared: strings.Join(declared[p.Name], " / ")}
		if signal := matches[p.Purl].Signals; freshRecommendation(signal) {
			entry.RecommendedVersion = signal.RecommendedVersion
			entry.RecommendationFetchedAt = signal.FetchedAt
		}
		result = append(result, entry)
	}
	slices.SortFunc(result, func(a, b DirectPackage) int { return strings.Compare(a.Name, b.Name) })
	return result, nil
}

// pinNPMTargets constrains planning to exact targets, retaining the original
// declaration style for restoration before the final native install. It never
// rewrites locked versions by string replacement.
func pinNPMTargets(ctx context.Context, root string, u Unit, baseline []npmPackage, matches map[string]AdvisoryMatch, match MatchPackages) (map[string]string, error) {
	if len(u.VersionTargets) == 0 {
		return nil, nil
	}
	fsRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer fsRoot.Close()
	data, err := fsRoot.ReadFile(u.Manifest)
	if err != nil {
		return nil, err
	}
	var manifest npmManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	byName := map[string]npmPackage{}
	for _, p := range baseline {
		if p.Path == "node_modules/"+p.Name {
			byName[p.Name] = p
		}
	}
	seen := map[string]bool{}
	declarations := map[string]string{}
	var targetPurls []string
	for _, target := range u.VersionTargets {
		current, ok := byName[target.Name]
		if !ok || seen[target.Name] {
			return nil, errors.New("version targets must identify distinct direct dependencies")
		}
		seen[target.Name] = true
		if (target.Mode != "exact" && target.Mode != "gossip") || !exactNPMVersion.MatchString(target.Version) {
			return nil, errors.New("version target must be an exact published version, not a range or tag")
		}
		parsed, err := semver.NPM.Parse(target.Version)
		if err != nil {
			return nil, err
		}
		if parsed.IsPrerelease() && !target.AllowPrerelease {
			return nil, errors.New("prerelease targets need explicit acknowledgment")
		}
		cmp, diff, err := semver.NPM.Difference(current.Version, target.Version)
		level, levelErr := upgradeLevel(u.UpgradeLevel)
		if err != nil || levelErr != nil || cmp > 0 || !level.Allows(diff) {
			return nil, fmt.Errorf("version target for %s violates upgrade policy or downgrades the package", target.Name)
		}
		if target.Mode == "gossip" {
			signal := matches[current.Purl].Signals
			if !freshRecommendation(signal) || signal.RecommendedVersion != target.Version {
				return nil, errors.New("deps.dev suggestion is missing, stale or changed; refresh the draft")
			}
		}
		found := false
		for group, deps := range map[string]map[string]string{"dependencies": manifest.Dependencies, "devDependencies": manifest.DevDependencies, "optionalDependencies": manifest.OptionalDependencies} {
			original, ok := deps[target.Name]
			if !ok {
				continue
			}
			prefix := ""
			base := original
			if strings.HasPrefix(original, "^") || strings.HasPrefix(original, "~") {
				prefix, base = original[:1], original[1:]
			}
			if !exactNPMVersion.MatchString(base) {
				return nil, errors.New("manual version selection for complex declared ranges is not yet supported")
			}
			key := group + "." + strings.NewReplacer("\\", "\\\\", ".", "\\.").Replace(target.Name)
			declarations[key] = prefix + target.Version
			data, err = sjson.SetBytes(data, key, target.Version)
			if err != nil {
				return nil, err
			}
			found = true
		}
		if !found {
			return nil, errors.New("manual target is not a direct declared dependency")
		}
		key, err := purl.FromString(current.Purl)
		if err != nil {
			return nil, err
		}
		key.Version = target.Version
		targetPurls = append(targetPurls, key.ToString())
	}
	approved, err := checkedMatches(ctx, match, targetPurls)
	if err != nil {
		return nil, err
	}
	for _, entry := range approved {
		if entry.Decision != "allow" {
			return nil, fmt.Errorf("chosen target violates package policy: %s", entry.Reason)
		}
		for _, advisory := range entry.Advisories {
			if slices.Contains(u.Vulns, advisory.CanonicalID) && advisory.VEXStatus != "not_affected" && advisory.VEXStatus != "fixed" {
				return nil, errors.New("chosen version still has a selected vulnerability")
			}
		}
	}
	if err := fsRoot.WriteFile(u.Manifest, data, 0o600); err != nil {
		return nil, err
	}
	return declarations, nil
}

func restoreNPMDeclarations(root string, u Unit, declarations map[string]string) error {
	fsRoot, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer fsRoot.Close()
	data, err := fsRoot.ReadFile(u.Manifest)
	if err != nil {
		return err
	}
	for key, value := range declarations {
		data, err = sjson.SetBytes(data, key, value)
		if err != nil {
			return err
		}
	}
	return fsRoot.WriteFile(u.Manifest, data, 0o600)
}

func freshRecommendation(signal *MatchSignals) bool {
	if signal == nil || signal.FetchedAt.IsZero() {
		return false
	}
	age := time.Since(signal.FetchedAt)
	return age >= -5*time.Minute && age <= 24*time.Hour
}
