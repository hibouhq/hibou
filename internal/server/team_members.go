package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

func (s *Server) handleListTeamMembers(w http.ResponseWriter, r *http.Request) {
	_, team, ok := s.loadAuthorizedTeam(r, w)
	if !ok {
		return
	}

	pagination := api.ParsePagination(r)
	members, total, err := s.queries.ListTeamMembers(r.Context(), team.ID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list team members")
		return
	}

	api.JSONList(w, members, pagination.Page, pagination.PerPage, total)
}

func (s *Server) handleAddTeamMember(w http.ResponseWriter, r *http.Request) {
	org, team, user, ok := s.loadTeamAdminUser(r, w)
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

	if err := s.queries.AddTeamMember(r.Context(), team.ID, memberUserID, role); err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "member already exists")
			return
		}
		if isForeignKeyViolation(err) {
			api.JSONError(w, http.StatusBadRequest, "user not found")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to add team member")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.add",
		ResourceType: "team",
		ResourceID:   team.ID.String(),
		Context: map[string]any{
			"scope":   "team",
			"team_id": team.ID.String(),
			"user_id": memberUserID.String(),
			"role":    role,
		},
	})

	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleRemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	org, team, user, ok := s.loadTeamAdminUser(r, w)
	if !ok {
		return
	}

	memberUserID, err := parseUUIDParam(r, "userID")
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	if err := s.queries.RemoveTeamMember(r.Context(), team.ID, memberUserID); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to remove team member")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.remove",
		ResourceType: "team",
		ResourceID:   team.ID.String(),
		Context: map[string]any{
			"scope":   "team",
			"team_id": team.ID.String(),
			"user_id": memberUserID.String(),
		},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUpdateTeamMemberRole(w http.ResponseWriter, r *http.Request) {
	org, team, user, ok := s.loadTeamAdminUser(r, w)
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

	if err := s.replaceTeamMemberRole(r.Context(), team.ID, memberUserID, role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			api.JSONError(w, http.StatusNotFound, "member not found")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to update team member role")
		return
	}

	s.writeMemberAuditLog(r, user, org.ID, auditEntry{
		Action:       "member.role.update",
		ResourceType: "team",
		ResourceID:   team.ID.String(),
		Context: map[string]any{
			"scope":   "team",
			"team_id": team.ID.String(),
			"user_id": memberUserID.String(),
			"role":    role,
		},
	})

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) loadAuthorizedTeam(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.Team, bool) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return nil, nil, false
	}

	team, err := s.queries.GetTeamBySlug(r.Context(), org.ID, chi.URLParam(r, "teamSlug"))
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load team")
		return nil, nil, false
	}
	if team == nil {
		api.JSONError(w, http.StatusNotFound, "team not found")
		return nil, nil, false
	}

	return org, team, true
}

func (s *Server) loadTeamAdminUser(r *http.Request, w http.ResponseWriter) (*store.Organization, *store.Team, *store.User, bool) {
	org, team, ok := s.loadAuthorizedTeam(r, w)
	if !ok {
		return nil, nil, nil, false
	}
	if !s.requireOrgAdmin(r, w, org.ID) {
		return nil, nil, nil, false
	}
	// Nil for a service principal — attribution only (ADR-022).
	return org, team, UserFromContext(r.Context()), true
}

func (s *Server) replaceTeamMemberRole(ctx context.Context, teamID, userID uuid.UUID, role string) error {
	currentRole, err := s.queries.GetTeamMemberRole(ctx, teamID, userID)
	if err != nil {
		return err
	}
	if currentRole == "" {
		return sql.ErrNoRows
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	queries := s.queries.WithTx(tx)
	if err := queries.RemoveTeamMember(ctx, teamID, userID); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := queries.AddTeamMember(ctx, teamID, userID, role); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
