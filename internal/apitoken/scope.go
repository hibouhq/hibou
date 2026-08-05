package apitoken

import (
	"encoding/json"
	"errors"
	"fmt"
)

// AccessLevel is the granted level for a capability, ordered none < read < write.
type AccessLevel string

const (
	AccessNone  AccessLevel = "none"
	AccessRead  AccessLevel = "read"
	AccessWrite AccessLevel = "write"
)

func (a AccessLevel) rank() int {
	switch a {
	case AccessWrite:
		return 2
	case AccessRead:
		return 1
	default:
		return 0
	}
}

// Grants reports whether this level satisfies a required level. AccessNone never
// grants anything, including a required AccessNone.
func (a AccessLevel) Grants(need AccessLevel) bool {
	return need.rank() > 0 && a.rank() >= need.rank()
}

// Capability is a product surface a token can be granted access to. The set maps
// to surfaces, not routes, so it stays stable as the API grows.
type Capability string

const (
	CapCoverage        Capability = "coverage"
	CapVulnerabilities Capability = "vulnerabilities"
	CapTriage          Capability = "triage"
	CapQualityGates    Capability = "quality_gates"
	CapComponents      Capability = "components"
	CapSecrets         Capability = "secrets"
	CapUploads         Capability = "uploads"
	CapAdmin           Capability = "admin"
)

// OwnerType is who a token belongs to: a user (dies with the account) or an org
// (survives member departure, managed by admins).
type OwnerType string

const (
	OwnerUser OwnerType = "user"
	OwnerOrg  OwnerType = "org"
)

type Owner struct {
	Type OwnerType `json:"type"`
	ID   string    `json:"id"`
}

// RepoMode selects all repositories in the org or an explicit allowlist.
type RepoMode string

const (
	RepoAll  RepoMode = "all"
	RepoList RepoMode = "list"
)

type RepoSelector struct {
	Mode  RepoMode `json:"mode"`
	Slugs []string `json:"slugs,omitempty"`
}

// Includes reports whether the selector covers a repo slug.
func (r RepoSelector) Includes(slug string) bool {
	if r.Mode == RepoAll {
		return true
	}
	for _, s := range r.Slugs {
		if s == slug {
			return true
		}
	}
	return false
}

// Scope is the enforced authority of a token: one org, a repo selection, and a
// per-capability access level.
type Scope struct {
	Owner       Owner                      `json:"owner"`
	Org         string                     `json:"org"`
	Repos       RepoSelector               `json:"repos"`
	Permissions map[Capability]AccessLevel `json:"permissions"`
}

// Parse decodes a scope document from the stored JSON.
func Parse(data []byte) (Scope, error) {
	if len(data) == 0 {
		return Scope{}, errors.New("empty token scope")
	}
	var scope Scope
	if err := json.Unmarshal(data, &scope); err != nil {
		return Scope{}, err
	}
	if scope.Repos.Mode == "" {
		scope.Repos.Mode = RepoList
	}
	if scope.Repos.Mode != RepoAll && scope.Repos.Mode != RepoList {
		return Scope{}, fmt.Errorf("unknown repository mode %q", scope.Repos.Mode)
	}
	if scope.Owner.Type != "" && scope.Owner.Type != OwnerUser && scope.Owner.Type != OwnerOrg {
		return Scope{}, fmt.Errorf("unknown owner type %q", scope.Owner.Type)
	}
	for capability, level := range scope.Permissions {
		if !isKnownCapability(capability) {
			return Scope{}, fmt.Errorf("unknown capability %q", capability)
		}
		if level != AccessNone && level != AccessRead && level != AccessWrite {
			return Scope{}, fmt.Errorf("unknown access level %q", level)
		}
	}
	return scope, nil
}

func isKnownCapability(capability Capability) bool {
	switch capability {
	case CapCoverage, CapVulnerabilities, CapTriage, CapQualityGates, CapComponents, CapSecrets, CapUploads, CapAdmin:
		return true
	default:
		return false
	}
}

func (s Scope) level(capability Capability) AccessLevel {
	if s.Permissions == nil {
		return AccessNone
	}
	if level, ok := s.Permissions[capability]; ok {
		return level
	}
	return AccessNone
}

// Allows reports whether the scope grants `need` on `capability` for the given
// org and repo. Empty org/repo skip that dimension of the check.
func (s Scope) Allows(capability Capability, need AccessLevel, org, repoSlug string) bool {
	if org != "" && s.Org != org {
		return false
	}
	if repoSlug != "" && !s.Repos.Includes(repoSlug) {
		return false
	}
	return s.level(capability).Grants(need)
}

// AllowsOrgWide reports whether the scope grants a capability across every
// repository in an organization.
func (s Scope) AllowsOrgWide(capability Capability, need AccessLevel, org string) bool {
	return s.Repos.Mode == RepoAll && s.Allows(capability, need, org, "")
}

// IsReadOnly reports whether no capability is granted write — the shape of a
// safe read-only agent token.
func (s Scope) IsReadOnly() bool {
	for _, level := range s.Permissions {
		if level == AccessWrite {
			return false
		}
	}
	return true
}

// HasPermissions reports whether the scope grants at least one capability.
func (s Scope) HasPermissions() bool {
	for _, level := range s.Permissions {
		if level.rank() > 0 {
			return true
		}
	}
	return false
}
