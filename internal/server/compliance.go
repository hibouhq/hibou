package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/hibouhq/lehibou/internal/api"
	"github.com/hibouhq/lehibou/internal/compliance"
)

func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	if user == nil {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if s.complianceSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "compliance export unavailable")
		return
	}

	org, err := s.queries.GetOrganizationBySlug(r.Context(), chi.URLParam(r, "slug"))
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
	allowed, err := s.enforcer.CheckPermission(user.ID.String(), fmt.Sprintf("org:%s/compliance", org.ID), "export")
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to authorize compliance export")
		return
	}
	if !allowed {
		api.JSONError(w, http.StatusForbidden, "insufficient permissions")
		return
	}

	repoSlug := strings.TrimSpace(r.URL.Query().Get("repo"))
	if repoSlug == "" {
		api.JSONError(w, http.StatusBadRequest, "repo is required")
		return
	}
	asOfDate, err := parseComplianceDate(strings.TrimSpace(r.URL.Query().Get("date")))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "date must be RFC3339 or YYYY-MM-DD")
		return
	}

	report, err := s.complianceSvc.GenerateReport(r.Context(), org.ID, repoSlug, asOfDate)
	if errors.Is(err, compliance.ErrReportNotFound) || errors.Is(err, sql.ErrNoRows) {
		api.JSONError(w, http.StatusNotFound, "compliance report not found")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate compliance report")
		return
	}

	api.JSON(w, http.StatusOK, report)
}

func parseComplianceDate(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, errors.New("missing date")
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed, nil
	}
	parsed, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, err
	}
	return parsed.Add(23*time.Hour + 59*time.Minute + 59*time.Second), nil
}
