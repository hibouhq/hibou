package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/audit"
)

// anonymizedUserLabel is what an anonymized account is called from then on,
// in its display name and its forge identity alike.
func anonymizedUserLabel(userID uuid.UUID) string {
	return "deleted-" + userID.String()
}

// anonymizeUserResult counts what an anonymization removed, for the audit
// record and the response.
type anonymizeUserResult struct {
	UserID                 string `json:"user_id"`
	APIKeysRevoked         int64  `json:"api_keys_revoked"`
	OrgMembershipsRemoved  int64  `json:"org_memberships_removed"`
	TeamMembershipsRemoved int64  `json:"team_memberships_removed"`
	RepoGrantsRemoved      int64  `json:"repo_access_removed"`
	LocalRolesRevoked      int64  `json:"local_roles_revoked"`
	OrgAPIKeysDetached     int64  `json:"org_api_keys_detached"`

	// orgRoles are the memberships removed, for dropping their RBAC roles
	// once the transaction commits.
	orgRoles []anonymizedOrgRole
}

type anonymizedOrgRole struct {
	orgID uuid.UUID
	role  string
}

var errAnonymizeUserNotFound = errors.New("user not found")

// lastAdminError refuses an anonymization that would leave orgs with no
// admin: nobody could manage them from inside Hibou any more.
type lastAdminError struct {
	orgs []string
}

func (e *lastAdminError) Error() string {
	return "the user is the last admin of: " + strings.Join(e.orgs, ", ") +
		"; make someone else an admin of these organizations first"
}

// queryer is what lastAdminOrgs reads through: the DB, or the transaction.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// lastAdminOrgs names the orgs where userID is the only admin.
func lastAdminOrgs(ctx context.Context, db queryer, userID uuid.UUID) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT o.name
		FROM org_members om
		JOIN organizations o ON o.id = om.org_id
		WHERE om.user_id = $1 AND om.role = 'admin'
		  AND NOT EXISTS (
		      SELECT 1 FROM org_members other
		      WHERE other.org_id = om.org_id AND other.role = 'admin' AND other.user_id <> $1
		  )
		ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// handleAnonymizeUser erases a person from the instance while keeping the
// records that refer to them (findings they triaged, audit entries) intact:
// the account row stays, so foreign keys hold, but nothing on it identifies
// anyone any more.
//
// It revokes every session (epoch bump) and every user-owned API key,
// removes org/team memberships, repository grants and local role grants,
// blanks email, name, avatar, the recorded forge login and the allowlist
// confirmation, and replaces the forge identity with deleted-<id> so the next
// sign-in through the forge creates a new, unrelated account instead of
// re-hydrating this one. Open websockets are closed and the RBAC roles of the
// removed memberships dropped.
//
// Org-owned tokens the user once created belong to the org and keep working
// (ADR-022): their creator is detached (user_id set NULL), exactly as when a
// user row is deleted, so the "creator left the org" check does not kill the
// org's CI. Org admins who want them gone revoke them as usual.
//
// Refused with 409 while the user is the last admin of any org.
//
// POST /api/v1/instance/users/{userID}/anonymize — instance admin only.
func (s *Server) handleAnonymizeUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireInstanceAuthority(w, r)
	if !ok {
		return
	}
	userID, err := parseUUIDParam(r, "userID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	if userID == actor.ID {
		api.JSONError(w, http.StatusBadRequest, "an administrator cannot anonymize their own account")
		return
	}

	orphaned, err := lastAdminOrgs(r.Context(), s.db, userID)
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID.String()).Msg("anonymize user: check last admins")
		api.JSONError(w, http.StatusInternalServerError, "failed to anonymize user")
		return
	}
	if len(orphaned) > 0 {
		api.JSONError(w, http.StatusConflict, (&lastAdminError{orgs: orphaned}).Error())
		return
	}

	// Policy first, as in handleRevokeLocalRole: a grant that outlives its
	// record must at least be unenforceable.
	if err := s.dropLocalRolePolicies(r.Context(), userID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to revoke local roles")
		return
	}

	result, err := s.anonymizeUser(r.Context(), userID)
	if errors.Is(err, errAnonymizeUserNotFound) {
		api.JSONError(w, http.StatusNotFound, "user not found")
		return
	}
	var lastAdmin *lastAdminError
	if errors.As(err, &lastAdmin) {
		api.JSONError(w, http.StatusConflict, lastAdmin.Error())
		return
	}
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID.String()).Msg("anonymize user")
		api.JSONError(w, http.StatusInternalServerError, "failed to anonymize user")
		return
	}
	s.dropAnonymizedOrgRoles(userID, result.orgRoles)
	// The epoch was bumped in the transaction; this runs the revoke hooks
	// (closing the user's websockets on every replica that registered one).
	if s.authMgr != nil {
		if err := s.authMgr.RevokeSessions(r.Context(), userID); err != nil {
			s.log.Warn().Err(err).Str("user_id", userID.String()).Msg("anonymize user: run session revoke hooks")
		}
	}

	s.writeAuditLog(r, actor, uuid.NullUUID{}, auditEntry{
		Action:       audit.ActionUserAnonymize,
		ResourceType: "user",
		ResourceID:   userID.String(),
		Context: map[string]any{
			"api_keys_revoked":         result.APIKeysRevoked,
			"org_memberships_removed":  result.OrgMembershipsRemoved,
			"team_memberships_removed": result.TeamMembershipsRemoved,
			"repo_access_removed":      result.RepoGrantsRemoved,
			"local_roles_revoked":      result.LocalRolesRevoked,
			"org_api_keys_detached":    result.OrgAPIKeysDetached,
			"sessions_revoked":         true,
		},
	})
	api.JSON(w, http.StatusOK, result)
}

// dropLocalRolePolicies removes the enforcer policies behind a user's local
// role grants; anonymizeUser deletes the grant records.
func (s *Server) dropLocalRolePolicies(ctx context.Context, userID uuid.UUID) error {
	if s.enforcer == nil {
		return nil
	}
	grants, err := s.queries.ListActiveLocalRoleGrants(ctx)
	if err != nil {
		return err
	}
	for _, grant := range grants {
		if grant.UserID != userID {
			continue
		}
		var orgID *uuid.UUID
		if grant.OrgID.Valid {
			id := grant.OrgID.UUID
			orgID = &id
		}
		if err := s.applyLocalRolePolicy(userID, grant.Role, orgID, false); err != nil {
			return err
		}
	}
	return nil
}

// dropAnonymizedOrgRoles removes the RBAC roles of the memberships the
// anonymization deleted. Failures are logged: the membership rows are gone,
// so the role no longer reaches any org data through a membership check, but
// the policy must not linger.
func (s *Server) dropAnonymizedOrgRoles(userID uuid.UUID, roles []anonymizedOrgRole) {
	if s.enforcer == nil {
		return
	}
	for _, membership := range roles {
		if err := s.enforcer.RemoveRoleForUserInOrg(userID, membership.role, membership.orgID); err != nil {
			s.log.Warn().Err(err).Str("user_id", userID.String()).Str("org_id", membership.orgID.String()).
				Str("role", membership.role).Msg("anonymize user: drop org role policy")
		}
	}
}

// anonymizeUser applies every database change in one transaction.
func (s *Server) anonymizeUser(ctx context.Context, userID uuid.UUID) (anonymizeUserResult, error) {
	result := anonymizeUserResult{UserID: userID.String()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	label := anonymizedUserLabel(userID)
	// session_epoch + 1 invalidates every cookie issued to the account. The
	// recorded forge login and allowlist confirmation identify the person
	// and would let the allowlist admit the shell account.
	updated, err := tx.ExecContext(ctx, `
		UPDATE users
		SET email = '', display_name = $2, avatar_url = NULL, provider_id = $2,
		    forge_login = NULL, signin_allowed_at = NULL,
		    session_epoch = session_epoch + 1, updated_at = NOW()
		WHERE id = $1`, userID, label)
	if err != nil {
		return result, err
	}
	if rows, _ := updated.RowsAffected(); rows == 0 {
		return result, errAnonymizeUserNotFound
	}

	// Re-checked under the transaction: an admin demoted since the handler's
	// check must not leave an org without one.
	orphaned, err := lastAdminOrgs(ctx, tx, userID)
	if err != nil {
		return result, err
	}
	if len(orphaned) > 0 {
		return result, &lastAdminError{orgs: orphaned}
	}

	rows, err := tx.QueryContext(ctx, `DELETE FROM org_members WHERE user_id = $1 RETURNING org_id, role`, userID)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var membership anonymizedOrgRole
		if err := rows.Scan(&membership.orgID, &membership.role); err != nil {
			_ = rows.Close()
			return result, err
		}
		result.orgRoles = append(result.orgRoles, membership)
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	result.OrgMembershipsRemoved = int64(len(result.orgRoles))

	steps := []struct {
		query string
		count *int64
	}{
		{`DELETE FROM api_keys WHERE user_id = $1 AND owner_type = 'user'`, &result.APIKeysRevoked},
		// ADR-022: an org-owned key outlives its creator; detach it as a
		// user deletion would (ON DELETE SET NULL).
		{`UPDATE api_keys SET user_id = NULL WHERE user_id = $1 AND owner_type = 'org'`, &result.OrgAPIKeysDetached},
		{`DELETE FROM team_members WHERE user_id = $1`, &result.TeamMembershipsRemoved},
		{`DELETE FROM user_repo_access WHERE user_id = $1`, &result.RepoGrantsRemoved},
		{`DELETE FROM local_role_grants WHERE user_id = $1`, &result.LocalRolesRevoked},
	}
	for _, step := range steps {
		res, err := tx.ExecContext(ctx, step.query, userID)
		if err != nil {
			return result, fmt.Errorf("anonymize user: %w", err)
		}
		*step.count, _ = res.RowsAffected()
	}

	return result, tx.Commit()
}
