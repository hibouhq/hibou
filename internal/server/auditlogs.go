package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store"
)

const defaultAuditLogsPerPage = 50

type auditLogEntryResponse struct {
	ID           uuid.UUID       `json:"id"`
	ActorType    string          `json:"actor_type"`
	ActorDisplay string          `json:"actor_display"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Context      json.RawMessage `json:"context,omitempty"`
	IPAddress    string          `json:"ip_address"`
	CreatedAt    time.Time       `json:"created_at"`
}

// @Summary      List audit logs
// @Description  List audit log entries for an organization. Restricted to organization admins; audit context can carry admin-only detail.
// @Tags         audit
// @Produce      json
// @Param        provider       path      string  true   "Forge provider"
// @Param        slug           path      string  true   "Organization slug"
// @Param        action         query     string  false  "Action filter"
// @Param        resource_type  query     string  false  "Resource type filter"
// @Param        repo           query     string  false  "Repository slug; limits entries to that repository"
// @Param        page           query     int     false  "Page number"
// @Param        per_page       query     int     false  "Items per page"
// @Success      200            {object}  api.ListResponse{data=[]server.auditLogEntryResponse}
// @Failure      401            {object}  api.Response
// @Failure      404            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/audit-logs [get]
func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	// Audit entries carry admin-scoped context (token provenance, member/role
	// changes, settings diffs), so the log is admin-only — a member must not be
	// able to tell the log apart from a missing org. Exception: the repo-scoped
	// listing is also open to admins of the team owning that repository.
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	pagination := parseAuditLogPagination(r)
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type"))

	repoID := ""
	if repoSlug := strings.TrimSpace(r.URL.Query().Get("repo")); repoSlug != "" {
		repo, repoErr := s.queries.GetRepositoryBySlug(r.Context(), org.ID, repoSlug)
		if repoErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to load repository")
			return
		}
		if repo == nil {
			api.JSONError(w, http.StatusNotFound, "repository not found")
			return
		}
		allowed, adminErr := s.canViewRepoAudit(r, role, repo)
		if adminErr != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to resolve permissions")
			return
		}
		if !allowed {
			api.JSONError(w, http.StatusNotFound, "organization not found")
			return
		}
		repoID = repo.ID.String()
	} else if role != "admin" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	entries, total, err := s.listFilteredAuditLogs(r.Context(), org.ID, action, resourceType, repoID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	api.JSONList(w, entries, pagination.Page, pagination.PerPage, total)
}

// canViewRepoAudit reports whether the requesting principal may read the
// repo-scoped audit log: org admins always, and users who are admins of the
// team owning the repository (the closest thing to a repo-level admin).
func (s *Server) canViewRepoAudit(r *http.Request, orgRole string, repo *store.Repository) (bool, error) {
	if orgRole == "admin" {
		return true, nil
	}
	user := UserFromContext(r.Context())
	if user == nil || repo.TeamID == nil {
		return false, nil
	}
	teamRole, err := s.queries.GetTeamMemberRole(r.Context(), *repo.TeamID, user.ID)
	if err != nil {
		return false, err
	}
	return teamRole == "admin", nil
}

// buildAuditLogFilter assembles the WHERE clause for audit-log listing from
// fixed predicates and positional placeholders only; every user-supplied value
// travels as a bound argument.
func buildAuditLogFilter(orgID uuid.UUID, action, resourceType, repoID string) (string, []any) {
	whereParts := []string{"org_id = $1"}
	args := []any{orgID}

	if action != "" {
		whereParts = append(whereParts, fmt.Sprintf("action = $%d", len(args)+1))
		args = append(args, action)
	}
	if resourceType != "" {
		whereParts = append(whereParts, fmt.Sprintf("resource_type = $%d", len(args)+1))
		args = append(args, resourceType)
	}
	if repoID != "" {
		// Repository actions land either as the resource itself or with the
		// repo carried in the context (suppressions, finding acceptance, ...).
		whereParts = append(whereParts, fmt.Sprintf("((resource_type = 'repository' AND resource_id = $%d) OR context->>'repo_id' = $%d)", len(args)+1, len(args)+1))
		args = append(args, repoID)
	}

	return strings.Join(whereParts, " AND "), args
}

func (s *Server) listFilteredAuditLogs(ctx context.Context, orgID uuid.UUID, action, resourceType, repoID string, limit, offset int) ([]auditLogEntryResponse, int, error) {
	whereClause, args := buildAuditLogFilter(orgID, action, resourceType, repoID)

	countQuery := "SELECT COUNT(*) FROM audit_logs WHERE " + whereClause
	var total int
	// countQuery only contains trusted SQL fragments and bound parameters.
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), limit, offset)
	// #nosec G201 -- whereClause is assembled from fixed predicates with positional placeholders only.
	listQuery := fmt.Sprintf(`
SELECT id, actor_type, actor_display, action, resource_type, resource_id, context, ip_address, created_at
FROM audit_logs
WHERE %s
ORDER BY created_at DESC
LIMIT $%d OFFSET $%d
`, whereClause, len(args)+1, len(args)+2)

	// listQuery only contains trusted SQL fragments and bound parameters.
	rows, err := s.db.QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]auditLogEntryResponse, 0, limit)
	for rows.Next() {
		var entry auditLogEntryResponse
		if err := rows.Scan(
			&entry.ID,
			&entry.ActorType,
			&entry.ActorDisplay,
			&entry.Action,
			&entry.ResourceType,
			&entry.ResourceID,
			&entry.Context,
			&entry.IPAddress,
			&entry.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		entries = append(entries, entry)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return entries, total, nil
}

func parseAuditLogPagination(r *http.Request) api.PaginationParams {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = api.DefaultPage
	}

	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 {
		perPage = defaultAuditLogsPerPage
	}
	if perPage > api.MaxPerPage {
		perPage = api.MaxPerPage
	}

	return api.PaginationParams{
		Page:    page,
		PerPage: perPage,
		Offset:  (page - 1) * perPage,
	}
}
