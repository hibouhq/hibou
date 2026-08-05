package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type addMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type updateMemberRoleRequest struct {
	Role string `json:"role"`
}

func (s *Server) handleListOrgMembers(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	members, total, err := s.queries.ListOrgMembers(r.Context(), org.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list organization members")
		return
	}

	api.JSONList(w, members, pagination.Page, pagination.PerPage, total)
}

func (s *Server) handleAddOrgMember(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}

	var input addMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	memberUserID, role, ok := parseMemberInput(input.UserID, input.Role, w)
	if !ok {
		return
	}

	if err := s.queries.AddOrgMember(r.Context(), org.ID, memberUserID, role); err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "member already exists")
			return
		}
		if isForeignKeyViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "user not found")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to add organization member")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.add",
		ResourceType: "organization",
		ResourceID:   org.ID.String(),
		Context: map[string]any{
			"scope":   "org",
			"user_id": memberUserID.String(),
			"role":    role,
		},
	})

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleRemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}

	memberUserID, err := parseUUIDParam(r, "userID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	protected, err := s.rejectLastOrgAdminRemovalOrDemotion(r.Context(), org.ID, memberUserID, "")
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to validate organization admins")
		return
	}
	if protected {
		api.JSONError(w, http.StatusConflict, "cannot remove or demote the last organization admin")
		return
	}

	if err := s.queries.RemoveOrgMember(r.Context(), org.ID, memberUserID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to remove organization member")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.remove",
		ResourceType: "organization",
		ResourceID:   org.ID.String(),
		Context: map[string]any{
			"scope":   "org",
			"user_id": memberUserID.String(),
		},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUpdateOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	org, user, ok := s.loadOrgAdminUser(r, w)
	if !ok {
		return
	}

	memberUserID, err := parseUUIDParam(r, "userID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	var input updateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	role, ok := normalizeMemberRole(input.Role)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid role")
		return
	}

	protected, err := s.rejectLastOrgAdminRemovalOrDemotion(r.Context(), org.ID, memberUserID, role)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to validate organization admins")
		return
	}
	if protected {
		api.JSONError(w, http.StatusConflict, "cannot remove or demote the last organization admin")
		return
	}

	if err := s.replaceOrgMemberRole(r.Context(), org.ID, memberUserID, role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.JSONError(w, http.StatusNotFound, "member not found")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to update organization member role")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.role.update",
		ResourceType: "organization",
		ResourceID:   org.ID.String(),
		Context: map[string]any{
			"scope":   "org",
			"user_id": memberUserID.String(),
			"role":    role,
		},
	})

	w.WriteHeader(http.StatusNoContent)
}

type auditEntry struct {
	Action       string
	ResourceType string
	ResourceID   string
	Context      map[string]any
}

func (s *Server) loadOrgAdminUser(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.User, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return nil, nil, false
	}
	// Nil for a service principal — attribution only (ADR-022).
	return org, UserFromContext(r.Context()), true
}

func parseMemberInput(rawUserID, rawRole string, w http.ResponseWriter) (uuid.UUID, string, bool) {
	userID, err := uuid.Parse(strings.TrimSpace(rawUserID))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user_id")
		return uuid.Nil, "", false
	}
	role, ok := normalizeMemberRole(rawRole)
	if !ok {
		api.JSONError(w, http.StatusBadRequest, "invalid role")
		return uuid.Nil, "", false
	}
	return userID, role, true
}

func normalizeMemberRole(value string) (string, bool) {
	switch dbgen.MemberRole(strings.ToLower(strings.TrimSpace(value))) {
	case dbgen.MemberRoleAdmin:
		return string(dbgen.MemberRoleAdmin), true
	case dbgen.MemberRoleDeveloper:
		return string(dbgen.MemberRoleDeveloper), true
	case dbgen.MemberRoleAuditor:
		return string(dbgen.MemberRoleAuditor), true
	case dbgen.MemberRoleReleaseManager:
		return string(dbgen.MemberRoleReleaseManager), true
	case dbgen.MemberRoleViewer:
		return string(dbgen.MemberRoleViewer), true
	default:
		return "", false
	}
}

func (s *Server) replaceOrgMemberRole(ctx context.Context, orgID, userID uuid.UUID, role string) error {
	if currentRole, err := s.queries.GetOrgMemberRole(ctx, orgID, userID); err != nil {
		return err
	} else if currentRole == "" {
		return sql.ErrNoRows
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	queries := s.queries.WithTx(tx)
	if err := queries.RemoveOrgMember(ctx, orgID, userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := queries.AddOrgMember(ctx, orgID, userID, role); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Server) rejectLastOrgAdminRemovalOrDemotion(ctx context.Context, orgID, userID uuid.UUID, nextRole string) (bool, error) {
	currentRole, err := s.queries.GetOrgMemberRole(ctx, orgID, userID)
	if err != nil {
		return false, err
	}
	if currentRole == "" || currentRole != string(dbgen.MemberRoleAdmin) {
		return false, nil
	}
	if nextRole == "" || nextRole != string(dbgen.MemberRoleAdmin) {
		adminCount, err := s.queries.CountOrgAdmins(ctx, orgID)
		if err != nil {
			return false, err
		}
		if adminCount <= 1 {
			return true, nil
		}
	}

	return false, nil
}

func (s *Server) writeMemberAuditLog(r *http.Request, user *store.User, orgID uuid.UUID, entry auditEntry) {
	s.writeAuditLog(r, user, orgAuditID(orgID), entry)
}
