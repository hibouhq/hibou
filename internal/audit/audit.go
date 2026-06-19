package audit

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// Action constants for audit log entries.
const (
	ActionScanTrigger       = "scan.trigger"
	ActionSecretDiscovered  = "secret.discovered"
	ActionVEXCreate         = "vex.create"
	ActionVEXUpdate         = "vex.update"
	ActionVEXRevoke         = "vex.revoke"
	ActionVEXImport         = "vex.import"
	ActionVEXExport         = "vex.export"
	ActionReleaseCreate     = "release.create"
	ActionReleaseUpdate     = "release.update"
	ActionReleaseDelete     = "release.delete"
	ActionClientCreate      = "client.create"
	ActionClientUpdate      = "client.update"
	ActionClientDelete      = "client.delete"
	ActionGateOverride      = "gate.override"
	ActionGateCreate        = "gate.create"
	ActionGateUpdate        = "gate.update"
	ActionGateDelete        = "gate.delete"
	ActionConfigChange      = "config.change"
	ActionOnboardingPR      = "onboarding.pr"
	ActionIntegrationCreate = "integration.create"
	ActionIntegrationUpdate = "integration.update"
	ActionIntegrationDelete = "integration.delete"
	ActionRepoEnrolled      = "repo.enrolled"
	ActionRepoDetected      = "repo.detected"
	ActionRepoArchived      = "repo.archived"
	ActionRepoUnarchived    = "repo.unarchived"
	ActionRepoRenamed       = "repo.renamed"
	ActionRepoDeleted       = "repo.deleted"
	ActionRepoUpdated       = "repo.updated"
	ActionRepoRemoved       = "repo.removed"
	ActionRepoCreate        = "repo.create"
	ActionRepoUpdate        = "repo.update"
	ActionRepoDelete        = "repo.delete"
	ActionSettingUpdate     = "setting.update"
	ActionRetentionArchive  = "retention.archive"
	ActionRetentionPurge    = "retention.purge"
)

// ActorType constants.
const (
	ActorUser    = "user"
	ActorAPIKey  = "api_key"
	ActorSystem  = "system"
	ActorWebhook = "webhook"
)

// Entry represents an audit log entry.
type Entry struct {
	ID           uuid.UUID
	ActorID      *uuid.UUID
	ActorType    string
	ActorDisplay string
	Action       string
	ResourceType string
	ResourceID   string
	OrgID        *uuid.UUID
	Context      json.RawMessage
	IPAddress    string
	UserAgent    string
	CreatedAt    time.Time
}

// RequestContext extracts IP and user agent from an HTTP request.
func RequestContext(r *http.Request) (ip, userAgent string) {
	if clientIP := middleware.GetClientIP(r.Context()); clientIP != "" {
		ip = clientIP
	} else {
		ip = r.RemoteAddr
	}
	return ip, r.UserAgent()
}
