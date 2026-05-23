package audit

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Action constants for audit log entries.
const (
	ActionScanTrigger       = "scan.trigger"
	ActionVulnSuppress      = "vuln.suppress"
	ActionVulnUnsuppress    = "vuln.unsuppress"
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
	ActionRepoCreate        = "repo.create"
	ActionRepoUpdate        = "repo.update"
	ActionRepoDelete        = "repo.delete"
	ActionSettingUpdate     = "setting.update"
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
	ip = r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = forwarded
	}
	return ip, r.UserAgent()
}
