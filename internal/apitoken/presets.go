package apitoken

// Preset names a fixed permission set offered by the device login flow
// (ADR-043). The approval page offers only these, so the safe token is the one
// a user mints without thinking about scopes.
type Preset string

const (
	// PresetCLI is what the CLI's subcommands need: upload, plan scans,
	// pre-commit secret checks, read back gates and findings.
	PresetCLI Preset = "cli"
	// PresetReadOnly matches the web UI's "Read-only agent" preset
	// (site/src/lib/tokenPresets.ts): observe everything, change nothing.
	PresetReadOnly Preset = "read-only"
)

// Permissions returns the preset's grants and whether the preset is known.
// A fresh map is returned on every call, so callers may keep it.
func (p Preset) Permissions() (map[Capability]AccessLevel, bool) {
	switch p {
	case PresetCLI:
		return map[Capability]AccessLevel{
			CapUploads:         AccessWrite,
			CapSecrets:         AccessRead,
			CapVulnerabilities: AccessRead,
			CapCoverage:        AccessRead,
			CapComponents:      AccessRead,
			CapQualityGates:    AccessRead,
		}, true
	case PresetReadOnly:
		return map[Capability]AccessLevel{
			CapCoverage:        AccessRead,
			CapVulnerabilities: AccessRead,
			CapComponents:      AccessRead,
			CapTriage:          AccessRead,
			CapQualityGates:    AccessRead,
			CapSecrets:         AccessRead,
			CapUploads:         AccessRead,
		}, true
	default:
		return nil, false
	}
}

// MembershipScope builds the membership-wide, all-repos scope a device login
// mints for a user (ADR-043 §4).
func MembershipScope(ownerUserID string, preset Preset) (Scope, bool) {
	permissions, ok := preset.Permissions()
	if !ok {
		return Scope{}, false
	}
	return Scope{
		Owner:       Owner{Type: OwnerUser, ID: ownerUserID},
		Orgs:        &OrgSelector{Mode: OrgMemberships},
		Repos:       RepoSelector{Mode: RepoAll},
		Permissions: permissions,
	}, true
}
