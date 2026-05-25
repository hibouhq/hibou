package versioncmp

import "strings"

// NuGet compares 4-part numeric versions with semver-like prerelease handling.
type NuGet struct{}

type nugetVersion struct {
	parts      [4]int
	prerelease []string
	valid      bool
}

func (n *NuGet) Compare(a, b string) int {
	av := parseNuGet(a)
	bv := parseNuGet(b)
	for i := 0; i < len(av.parts); i++ {
		if cmp := cmpInts(av.parts[i], bv.parts[i]); cmp != 0 {
			return cmp
		}
	}
	return compareSemverPrerelease(lowerSlice(av.prerelease), lowerSlice(bv.prerelease))
}

func (n *NuGet) Valid(v string) bool {
	return parseNuGet(v).valid
}

func parseNuGet(v string) nugetVersion {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "v"), "V")
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}
	parts := strings.SplitN(v, "-", 2)
	nums := strings.Split(parts[0], ".")
	if len(nums) < 3 || len(nums) > 4 {
		return nugetVersion{}
	}
	parsed := nugetVersion{valid: true}
	for i := 0; i < len(nums); i++ {
		if !isDigits(nums[i]) {
			return nugetVersion{}
		}
		parsed.parts[i] = parseIntDefault(nums[i])
	}
	if len(parts) == 2 {
		ids := strings.Split(parts[1], ".")
		for _, id := range ids {
			if id == "" {
				return nugetVersion{}
			}
		}
		parsed.prerelease = ids
	}
	return parsed
}

func lowerSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = strings.ToLower(value)
	}
	return out
}
