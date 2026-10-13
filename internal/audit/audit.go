package audit

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

// Action constants for audit log entries.
const (
	ActionScanTrigger       = "scan.trigger"
	ActionSecretDiscovered  = "secret.discovered"
	ActionSecretRevoked     = "secret.revoked"
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
	ActionFindingAcceptance = "finding.acceptance"
	ActionFindingCreate     = "finding.create"
	ActionFindingCWEs       = "finding.cwes"
	ActionFindingDispute    = "finding.dispute"
	ActionFindingRekeyed    = "finding.rekeyed"
	ActionFindingReassert   = "finding.reassert"
	ActionFindingRetract    = "finding.retract"
	ActionFindingResolve    = "finding.resolve"
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
	ActionTokenCreate       = "token.create"
	ActionTokenUpdate       = "token.update"
	ActionTokenApprove      = "token.approve"
	ActionTokenReject       = "token.reject"
	ActionTokenRotate       = "token.rotate"
	ActionTokenRevoke       = "token.revoke"
	ActionDeviceApprove     = "device.approve"
	ActionDeviceDeny        = "device.deny"
	ActionRetentionArchive  = "retention.archive"
	ActionRetentionPurge    = "retention.purge"

	ActionOrgUpdate              = "org.update"
	ActionOrgDelete              = "org.delete"
	ActionTeamCreate             = "team.create"
	ActionTeamUpdate             = "team.update"
	ActionTeamDelete             = "team.delete"
	ActionNotificationRuleCreate = "notification_rule.create"
	ActionNotificationRuleUpdate = "notification_rule.update"
	ActionNotificationRuleDelete = "notification_rule.delete"
	ActionIPAllowlistChange      = "ip_allowlist.change"
	ActionUserAnonymize          = "user.anonymize"
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

// ChangedFields lists the top-level JSON fields whose values differ between
// two snapshots of a resource, sorted. Audit entries record these names —
// what changed, never the values — so a secret field can be reported as
// changed without being written to the log. Fields in ignore (timestamps
// that move on every write) are skipped. Values that do not encode to JSON
// objects yield nil.
func ChangedFields(before, after any, ignore ...string) []string {
	left, okLeft := jsonObject(before)
	right, okRight := jsonObject(after)
	if !okLeft || !okRight {
		return nil
	}
	skip := make(map[string]bool, len(ignore))
	for _, field := range ignore {
		skip[field] = true
	}
	changed := make([]string, 0)
	for key, value := range right {
		if skip[key] {
			continue
		}
		if previous, ok := left[key]; !ok || string(previous) != string(value) {
			changed = append(changed, key)
		}
	}
	for key := range left {
		if _, ok := right[key]; !ok && !skip[key] {
			changed = append(changed, key)
		}
	}
	sort.Strings(changed)
	return changed
}

func jsonObject(value any) (map[string]json.RawMessage, bool) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, false
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}
