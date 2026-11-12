package server

import (
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/remediation"
)

// ManagedRemediationPrepareRequest pins either an existing branch head or the
// exact shipped snapshot of a release. No local-artifact upload is accepted.
type ManagedRemediationPrepareRequest struct {
	ReleaseID    string `json:"release_id,omitempty"`
	TargetBranch string `json:"target_branch,omitempty"`
	// MaintenanceTarget requires an explicit existing TargetBranch when true.
	MaintenanceTarget bool `json:"maintenance_target,omitempty"`
	// ExpectedHeadSHA is optional for branch-source drafts, must be a full
	// 40- or 64-character hexadecimal SHA, and returns 409 on a stale head.
	// It is rejected for exact shipped-release sources.
	ExpectedHeadSHA string   `json:"expected_head_sha,omitempty"`
	Vulns           []string `json:"vulns,omitempty" maxItems:"5000"`
}

// ManagedRemediationGenerateRequest selects server-discovered units. File paths,
// hashes, manager identity and source SHA cannot be supplied by the caller.
type ManagedRemediationGenerateRequest struct {
	Revision int                `json:"revision"`
	Units    []managedSelection `json:"units" minItems:"1" maxItems:"50"`
}

// ManagedRemediationRevisionRequest binds publication to the reviewed revision.
type ManagedRemediationRevisionRequest struct {
	Revision int `json:"revision"`
}

// ManagedRemediationConsent is the organization-wide admin consent payload.
type ManagedRemediationConsent struct {
	Enabled bool `json:"enabled"`
}

// ManagedMaintenanceCreateRequest explicitly confirms a mapped target and its
// exact release source. It never accepts arbitrary repository or commit input.
type ManagedMaintenanceCreateRequest struct {
	ReleaseID    uuid.UUID `json:"release_id"`
	MappingID    string    `json:"mapping_id"`
	TargetBranch string    `json:"target_branch"`
	SourceTag    string    `json:"source_tag"`
	SourceSHA    string    `json:"source_sha"`
}

// ManagedRemediationJobResponse documents the public durable job projection.
// Private storage keys, request inputs and lease tokens are never returned.
type ManagedRemediationJobResponse struct {
	ID           uuid.UUID                        `json:"id"`
	RepoID       uuid.UUID                        `json:"repo_id"`
	BaseSHA      string                           `json:"base_sha"`
	SourceRef    string                           `json:"source_ref"`
	TargetBranch string                           `json:"target_branch"`
	Revision     int                              `json:"revision"`
	State        string                           `json:"state" enums:"queued_prepare,preparing,awaiting_selection,queued_generate,generating,ready,failed,cancelled,expired"`
	Result       ManagedRemediationResultResponse `json:"result"`
	Error        string                           `json:"error,omitempty"`
	ExpiresAt    time.Time                        `json:"expires_at"`
}

// ManagedRemediationResultResponse is empty while queued; normalized modules
// appear after preparation and the artifact summary after verified generation.
type ManagedRemediationResultResponse struct {
	Modules     []remediation.ManagedModule         `json:"modules,omitempty"`
	Artifact    *ManagedRemediationArtifactResponse `json:"artifact,omitempty"`
	Unavailable string                              `json:"unavailable,omitempty"`
	Error       string                              `json:"error,omitempty"`
}

// ManagedRemediationArtifactResponse exposes verification and digests, not the
// private complete-file publication payload. Only state=ready is downloadable.
type ManagedRemediationArtifactResponse struct {
	BaseSHA string `json:"base_sha"`
	SHA256  string `json:"sha256"`
	// Patch is always null in a job response. Download the raw UTF-8 unified
	// diff from GET /remediation/{jobID}/patch; it is not a JSON envelope.
	Patch        *string                    `json:"patch" extensions:"x-nullable"`
	Changes      []remediation.Change       `json:"changes"`
	Units        []remediation.UnitResult   `json:"units"`
	Verification []remediation.Verification `json:"verification"`
}

// ManagedRemediationCapabilitiesResponse separates operational availability from
// caller permissions and optional forge publication/maintenance capabilities.
type ManagedRemediationCapabilitiesResponse struct {
	Available                    bool     `json:"available"`
	Reason                       string   `json:"reason"`
	Profile                      string   `json:"profile"`
	CanGenerate                  bool     `json:"can_generate"`
	GenerationReason             string   `json:"generation_reason"`
	CanConsent                   bool     `json:"can_consent"`
	PublicationAvailable         bool     `json:"publication_available"`
	PublicationReason            string   `json:"publication_reason"`
	MaintenanceCreationAvailable bool     `json:"maintenance_creation_available"`
	MaintenanceCreationReason    string   `json:"maintenance_creation_reason"`
	TargetSuggestionsURL         string   `json:"target_suggestions_url"`
	TargetSuggestionsReason      string   `json:"target_suggestions_reason"`
	Limits                       []string `json:"limits"`
}

// ManagedRemediationCancelResponse confirms lease revocation, not removal of
// previously published forge branches or pull requests.
type ManagedRemediationCancelResponse struct {
	State string `json:"state" enums:"cancelled"`
}

// ManagedMaintenanceSettingsResponse carries organization configuration and
// current admin authority. Creation availability/reason are returned by GET;
// PUT returns the saved settings, can_configure and branch_pr_consent.
type ManagedMaintenanceSettingsResponse struct {
	Settings          managedMaintenanceSettings `json:"settings"`
	CanConfigure      bool                       `json:"can_configure"`
	BranchPRConsent   bool                       `json:"branch_pr_consent"`
	CreationAvailable bool                       `json:"creation_available,omitempty"`
	CreationReason    string                     `json:"creation_reason,omitempty"`
}

// ManagedMaintenanceSuggestionsResponse pairs declared mappings with live tag
// and ancestry evidence. No suggestion or branch creation is inferred silently.
type ManagedMaintenanceSuggestionsResponse struct {
	Source         managedReleaseSource           `json:"source"`
	Suggestions    []managedMaintenanceSuggestion `json:"suggestions"`
	Reason         string                         `json:"reason"`
	CreationReason string                         `json:"creation_reason"`
}
