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

	"github.com/hibouhq/lehibou/internal/api"
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
// @Description  List audit log entries for an organization visible to organization members
// @Tags         audit
// @Produce      json
// @Param        provider       path      string  true   "Forge provider"
// @Param        slug           path      string  true   "Organization slug"
// @Param        action         query     string  false  "Action filter"
// @Param        resource_type  query     string  false  "Resource type filter"
// @Param        page           query     int     false  "Page number"
// @Param        per_page       query     int     false  "Items per page"
// @Success      200            {object}  api.ListResponse{data=[]server.auditLogEntryResponse}
// @Failure      401            {object}  api.Response
// @Failure      404            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/audit-logs [get]
func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
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

	role, err := s.queries.GetOrgMemberRole(r.Context(), org.ID, user.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}

	pagination := parseAuditLogPagination(r)
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type"))

	var entries []auditLogEntryResponse
	var total int

	if action == "" && resourceType == "" {
		entries, total, err = s.listFilteredAuditLogs(r.Context(), org.ID, "", "", pagination.PerPage, pagination.Offset)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list audit logs")
			return
		}
	} else {
		entries, total, err = s.listFilteredAuditLogs(r.Context(), org.ID, action, resourceType, pagination.PerPage, pagination.Offset)
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to list audit logs")
			return
		}
	}

	api.JSONList(w, entries, pagination.Page, pagination.PerPage, total)
}

func (s *Server) listFilteredAuditLogs(ctx context.Context, orgID uuid.UUID, action, resourceType string, limit, offset int) ([]auditLogEntryResponse, int, error) {
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

	whereClause := strings.Join(whereParts, " AND ")

	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_logs WHERE %s", whereClause)
	var total int
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), limit, offset)
	listQuery := fmt.Sprintf(`
SELECT id, actor_type, actor_display, action, resource_type, resource_id, context, ip_address, created_at
FROM audit_logs
WHERE %s
ORDER BY created_at DESC
LIMIT $%d OFFSET $%d
`, whereClause, len(args)+1, len(args)+2)

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