package server

import (
	"context"
	"errors"
	"net/http"

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
}

var errAnonymizeUserNotFound = errors.New("user not found")

// handleAnonymizeUser erases a person from the instance while keeping the
// records that refer to them (findings they triaged, audit entries) intact:
// the account row stays, so foreign keys hold, but nothing on it identifies
// anyone any more.
//
// It revokes every session (epoch bump) and every user-owned API key,
// removes org/team memberships, repository grants and local role grants,
// blanks email, name and avatar, and replaces the forge identity with
// deleted-<id> so the next sign-in through the forge creates a new,
// unrelated account instead of re-hydrating this one. Org-owned tokens the
// user once created belong to the org and keep working.
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
	if err != nil {
		s.log.Error().Err(err).Str("user_id", userID.String()).Msg("anonymize user")
		api.JSONError(w, http.StatusInternalServerError, "failed to anonymize user")
		return
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

// anonymizeUser applies every database change in one transaction.
func (s *Server) anonymizeUser(ctx context.Context, userID uuid.UUID) (anonymizeUserResult, error) {
	result := anonymizeUserResult{UserID: userID.String()}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	label := anonymizedUserLabel(userID)
	// session_epoch + 1 invalidates every cookie issued to the account.
	updated, err := tx.ExecContext(ctx, `
		UPDATE users
		SET email = '', display_name = $2, avatar_url = NULL, provider_id = $2,
		    session_epoch = session_epoch + 1, updated_at = NOW()
		WHERE id = $1`, userID, label)
	if err != nil {
		return result, err
	}
	if rows, _ := updated.RowsAffected(); rows == 0 {
		return result, errAnonymizeUserNotFound
	}

	steps := []struct {
		query string
		count *int64
	}{
		{`DELETE FROM api_keys WHERE user_id = $1 AND owner_type = 'user'`, &result.APIKeysRevoked},
		{`DELETE FROM org_members WHERE user_id = $1`, &result.OrgMembershipsRemoved},
		{`DELETE FROM team_members WHERE user_id = $1`, &result.TeamMembershipsRemoved},
		{`DELETE FROM user_repo_access WHERE user_id = $1`, &result.RepoGrantsRemoved},
		{`DELETE FROM local_role_grants WHERE user_id = $1`, &result.LocalRolesRevoked},
	}
	for _, step := range steps {
		res, err := tx.ExecContext(ctx, step.query, userID)
		if err != nil {
			return result, err
		}
		*step.count, _ = res.RowsAffected()
	}

	return result, tx.Commit()
}
