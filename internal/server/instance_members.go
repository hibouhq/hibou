package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/rbac"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The cross-org view of who can do what.
//
// Every existing members surface is scoped to one organization, which cannot
// answer the question an operator actually has before granting a role whose
// blast radius crosses orgs: *what does this person already hold everywhere?*
// A user can belong to several forges and hold different standing in each org
// within them, so that answer is unobtainable one page at a time.
//
// It is also the only place local-only roles can be granted. No forge has an
// opinion about who may author advisory data, so those grants exist outside
// every forge's vocabulary and have no other home.

type instanceMember struct {
	UserID      uuid.UUID `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	// Memberships are forge-derived and read-only here: the sync owns them, and
	// showing them as editable would invite operators to fight it.
	Memberships []instanceMembership `json:"memberships"`
	// Grants are operator-owned. The sync never writes them.
	Grants []instanceGrant `json:"grants"`
}

type instanceMembership struct {
	OrgID    uuid.UUID `json:"org_id"`
	OrgSlug  string    `json:"org_slug"`
	Provider string    `json:"provider"`
	Role     string    `json:"role"`
}

type instanceGrant struct {
	Role string `json:"role"`
	// OrgSlug empty means the grant applies across the instance.
	OrgSlug string     `json:"org_slug"`
	OrgID   *uuid.UUID `json:"org_id"`
	// Suspended grants are shown rather than hidden: an operator needs to see
	// what a forge change took away, and why, to decide whether to restore it.
	Suspended bool   `json:"suspended"`
	Reason    string `json:"reason"`
}

type grantRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	// OrgID empty grants across the instance.
	OrgID string `json:"org_id"`
}

// grantableRoles is the closed set an operator may grant here.
//
// Closed rather than free-form: a role name that does not match a seeded policy
// grants nothing while looking like it worked, which is the worst failure an
// access-control UI can have.
var grantableRoles = map[string]bool{
	rbac.RoleCVETriager:         true,
	rbac.RoleSubscriptionWriter: true,
	rbac.RoleAdvisoryPromoter:   true,
}

func (s *Server) handleListInstanceMembers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireInstanceAuthority(w, r); !ok {
		return
	}
	members, err := s.queries.ListInstanceMembers(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list members")
		return
	}
	grants, err := s.queries.ListActiveLocalRoleGrants(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list grants")
		return
	}

	// One row per person, not per forge account: identity is the human, and
	// grouping by account would ask an operator to reconcile the same person
	// across GitHub and GitLab by eye.
	byUser := map[uuid.UUID]*instanceMember{}
	order := []uuid.UUID{}
	for _, row := range members {
		member, seen := byUser[row.UserID]
		if !seen {
			member = &instanceMember{
				UserID:      row.UserID,
				Email:       row.Email,
				DisplayName: row.DisplayName,
				Memberships: []instanceMembership{},
				Grants:      []instanceGrant{},
			}
			byUser[row.UserID] = member
			order = append(order, row.UserID)
		}
		member.Memberships = append(member.Memberships, instanceMembership{
			OrgID:    row.OrgID,
			OrgSlug:  row.Slug,
			Provider: row.Provider,
			Role:     row.Role,
		})
	}
	for _, grant := range grants {
		member, seen := byUser[grant.UserID]
		if !seen {
			continue
		}
		entry := instanceGrant{Role: grant.Role}
		if grant.OrgID.Valid {
			orgID := grant.OrgID.UUID
			entry.OrgID = &orgID
		}
		member.Grants = append(member.Grants, entry)
	}

	out := make([]instanceMember, 0, len(order))
	for _, userID := range order {
		out = append(out, *byUser[userID])
	}
	api.JSON(w, http.StatusOK, out)
}

func (s *Server) handleGrantLocalRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireInstanceAuthority(w, r)
	if !ok {
		return
	}
	var input grantRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(input.UserID))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	role := strings.TrimSpace(input.Role)
	if !grantableRoles[role] {
		api.JSONError(w, http.StatusBadRequest, "not a grantable role")
		return
	}
	orgID, ok := parseOptionalOrgID(input.OrgID, w)
	if !ok {
		return
	}
	// The promoter role decides what every org sees, so it has no org-scoped
	// form: granting it for one org would be a name that promises less than it
	// delivers.
	if role == rbac.RoleAdvisoryPromoter && orgID != nil {
		api.JSONError(w, http.StatusBadRequest, "that role is instance-wide only")
		return
	}

	if err := s.queries.GrantLocalRole(r.Context(), userID, role, orgID, actor.ID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the grant")
		return
	}
	if err := s.applyLocalRolePolicy(userID, role, orgID, true); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to apply the grant")
		return
	}
	s.auditGrant(r, actor.ID, userID, role, orgID, "rbac.local_role.granted")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeLocalRole(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireInstanceAuthority(w, r)
	if !ok {
		return
	}
	var input grantRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	userID, err := uuid.Parse(strings.TrimSpace(input.UserID))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user id")
		return
	}
	role := strings.TrimSpace(input.Role)
	orgID, ok := parseOptionalOrgID(input.OrgID, w)
	if !ok {
		return
	}

	// Policy first: if the record write fails afterwards the grant is already
	// unenforceable, which is the safe direction to fail in.
	if err := s.applyLocalRolePolicy(userID, role, orgID, false); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to revoke the policy")
		return
	}
	if err := s.queries.RevokeLocalRole(r.Context(), userID, role, orgID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to record the revocation")
		return
	}
	s.auditGrant(r, actor.ID, userID, role, orgID, "rbac.local_role.revoked")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) applyLocalRolePolicy(userID uuid.UUID, role string, orgID *uuid.UUID, grant bool) error {
	switch {
	case orgID == nil && grant:
		return s.enforcer.AddLocalRoleForUserOnInstance(userID, role)
	case orgID == nil:
		return s.enforcer.RemoveLocalRoleForUserOnInstance(userID, role)
	case grant:
		return s.enforcer.AddLocalRoleForUserInOrg(userID, role, *orgID)
	default:
		return s.enforcer.RemoveLocalRoleForUserInOrg(userID, role, *orgID)
	}
}

func parseOptionalOrgID(raw string, w http.ResponseWriter) (*uuid.UUID, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, true
	}
	parsed, err := uuid.Parse(trimmed)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid org id")
		return nil, false
	}
	return &parsed, true
}

// auditGrant records who changed someone's capabilities.
//
// Every grant here is audited without exception, including revocations: the
// question an incident asks is "who could author advisory data on the third of
// August", and only a complete record answers it.
func (s *Server) auditGrant(r *http.Request, actorID, subjectID uuid.UUID, role string, orgID *uuid.UUID, action string) {
	ipAddress, userAgent := audit.RequestContext(r)
	scope := "instance"
	if orgID != nil {
		scope = orgID.String()
	}
	context := json.RawMessage(`{}`)
	if encoded, err := json.Marshal(map[string]any{
		"subject_user_id": subjectID.String(),
		"role":            role,
		"scope":           scope,
	}); err == nil {
		context = encoded
	}
	if _, err := s.queries.CreateAuditLog(r.Context(), dbgen.CreateAuditLogParams{
		ActorID:      uuid.NullUUID{UUID: actorID, Valid: true},
		ActorType:    audit.ActorUser,
		Action:       action,
		ResourceType: "user",
		ResourceID:   subjectID.String(),
		OrgID:        toNullOrgID(orgID),
		Context:      context,
		IpAddress:    ipAddress,
		UserAgent:    userAgent,
	}); err != nil {
		s.log.Error().Err(err).Str("action", action).Str("role", role).
			Msg("failed to audit a local role change")
	}
}

func toNullOrgID(orgID *uuid.UUID) uuid.NullUUID {
	if orgID == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *orgID, Valid: true}
}
