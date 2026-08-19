package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
)

// instanceAuditLogEntryResponse is an audit row as seen from the instance-wide
// log: the org-scoped shape plus the owning organization (nil for
// instance-level events such as banner updates and admin grants).
type instanceAuditLogEntryResponse struct {
	auditLogEntryResponse
	OrgProvider *string `json:"org_provider,omitempty"`
	OrgSlug     *string `json:"org_slug,omitempty"`
}

// @Summary      Instance audit logs
// @Description  Audit log entries across the whole instance: every organization plus instance-level events (org-less rows). Instance admins only.
// @Tags         instance
// @Produce      json
// @Param        action         query     string  false  "Action filter"
// @Param        resource_type  query     string  false  "Resource type filter"
// @Param        scope          query     string  false  "'instance' limits to instance-level (org-less) entries"
// @Param        org            query     string  false  "Organization ID; limits entries to that organization"
// @Param        page           query     int     false  "Page number"
// @Param        per_page       query     int     false  "Items per page"
// @Success      200            {object}  api.ListResponse{data=[]server.instanceAuditLogEntryResponse}
// @Failure      401            {object}  api.Response
// @Failure      403            {object}  api.Response
// @Failure      500            {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/audit-logs [get]
func (s *Server) handleListInstanceAuditLogs(w http.ResponseWriter, r *http.Request) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !s.isInstanceAdmin(r) {
		api.JSONError(w, http.StatusForbidden, "instance admin required")
		return
	}

	pagination := parseAuditLogPagination(r)
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	resourceType := strings.TrimSpace(r.URL.Query().Get("resource_type"))
	scope := strings.TrimSpace(r.URL.Query().Get("scope"))

	var orgID uuid.NullUUID
	if rawOrg := strings.TrimSpace(r.URL.Query().Get("org")); rawOrg != "" {
		parsed, err := uuid.Parse(rawOrg)
		if err != nil {
			api.JSONError(w, http.StatusBadRequest, "invalid org filter")
			return
		}
		orgID = uuid.NullUUID{UUID: parsed, Valid: true}
	}

	entries, total, err := s.listInstanceAuditLogs(r.Context(), action, resourceType, scope, orgID, pagination.PerPage, pagination.Offset)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}

	api.JSONList(w, entries, pagination.Page, pagination.PerPage, total)
}

// buildInstanceAuditLogFilter mirrors buildAuditLogFilter without the org
// restriction: fixed predicates and positional placeholders only; every
// user-supplied value travels as a bound argument.
func buildInstanceAuditLogFilter(action, resourceType, scope string, orgID uuid.NullUUID) (string, []any) {
	whereParts := []string{"TRUE"}
	args := []any{}

	if action != "" {
		whereParts = append(whereParts, fmt.Sprintf("a.action = $%d", len(args)+1))
		args = append(args, action)
	}
	if resourceType != "" {
		whereParts = append(whereParts, fmt.Sprintf("a.resource_type = $%d", len(args)+1))
		args = append(args, resourceType)
	}
	if scope == "instance" {
		whereParts = append(whereParts, "a.org_id IS NULL")
	} else if orgID.Valid {
		whereParts = append(whereParts, fmt.Sprintf("a.org_id = $%d", len(args)+1))
		args = append(args, orgID.UUID)
	}

	return strings.Join(whereParts, " AND "), args
}

func (s *Server) listInstanceAuditLogs(ctx context.Context, action, resourceType, scope string, orgID uuid.NullUUID, limit, offset int) ([]instanceAuditLogEntryResponse, int, error) {
	whereClause, args := buildInstanceAuditLogFilter(action, resourceType, scope, orgID)

	countQuery := "SELECT COUNT(*) FROM audit_logs a WHERE " + whereClause
	var total int
	// countQuery only contains trusted SQL fragments and bound parameters.
	if err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listArgs := append(append([]any{}, args...), limit, offset)
	// #nosec G201 -- whereClause is assembled from fixed predicates with positional placeholders only.
	listQuery := fmt.Sprintf(`
SELECT a.id, a.actor_type, a.actor_display, a.action, a.resource_type, a.resource_id, a.context, a.ip_address, a.created_at, o.provider, o.slug
FROM audit_logs a
LEFT JOIN organizations o ON o.id = a.org_id
WHERE %s
ORDER BY a.created_at DESC
LIMIT $%d OFFSET $%d
`, whereClause, len(args)+1, len(args)+2)

	// listQuery only contains trusted SQL fragments and bound parameters.
	rows, err := s.db.QueryContext(ctx, listQuery, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]instanceAuditLogEntryResponse, 0, limit)
	for rows.Next() {
		var entry instanceAuditLogEntryResponse
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
			&entry.OrgProvider,
			&entry.OrgSlug,
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
