package server

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/compliance"
	"github.com/hibouhq/hibou/internal/store"
)

func (s *Server) handleComplianceExport(w http.ResponseWriter, r *http.Request) {
	org, ok := s.requireComplianceAccess(w, r)
	if !ok {
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

func (s *Server) handleISO27001Export(w http.ResponseWriter, r *http.Request) {
	org, ok := s.requireComplianceAccess(w, r)
	if !ok {
		return
	}
	asOfDate, err := parseOptionalComplianceDate(strings.TrimSpace(r.URL.Query().Get("date")))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "date must be RFC3339 or YYYY-MM-DD")
		return
	}
	report, err := s.complianceSvc.GenerateISO27001Report(r.Context(), org.ID, asOfDate)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, compliance.ErrReportNotFound) {
		api.JSONError(w, http.StatusNotFound, "compliance evidence not found")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate ISO 27001 report")
		return
	}
	api.JSON(w, http.StatusOK, report)
}

func (s *Server) handleSoAExport(w http.ResponseWriter, r *http.Request) {
	org, ok := s.requireComplianceAccess(w, r)
	if !ok {
		return
	}
	asOfDate, err := parseOptionalComplianceDate(strings.TrimSpace(r.URL.Query().Get("date")))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "date must be RFC3339 or YYYY-MM-DD")
		return
	}
	report, err := s.complianceSvc.GenerateStatementOfApplicability(r.Context(), org.ID, asOfDate)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, compliance.ErrReportNotFound) {
		api.JSONError(w, http.StatusNotFound, "statement of applicability not found")
		return
	}
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to generate statement of applicability")
		return
	}
	api.JSON(w, http.StatusOK, report)
}

func (s *Server) requireComplianceAccess(w http.ResponseWriter, r *http.Request) (*store.Organization, bool) {
	if !s.hasPrincipal(r) {
		api.JSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	user := UserFromContext(r.Context())
	if s.complianceSvc == nil {
		api.JSONError(w, http.StatusServiceUnavailable, "compliance export unavailable")
		return nil, false
	}
	org, err := s.resolveOrg(r)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load organization")
		return nil, false
	}
	if org == nil {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, false
	}
	role, err := s.principalOrgRole(r, org.ID)
	if err != nil || role == "" {
		api.JSONError(w, http.StatusNotFound, "organization not found")
		return nil, false
	}
	// The casbin grant is a user-RBAC refinement; a service principal's
	// authority is its org ownership (checked above) plus the route scope
	// (vulnerabilities:read org-wide), so it has no casbin subject to check.
	if user != nil {
		allowed, err := s.enforcer.CheckPermission(user.ID.String(), fmt.Sprintf("org:%s/compliance", org.ID), "export")
		if err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to authorize compliance export")
			return nil, false
		}
		if !allowed {
			api.JSONError(w, http.StatusForbidden, "insufficient permissions")
			return nil, false
		}
	}
	return org, true
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

func parseOptionalComplianceDate(raw string) (time.Time, error) {
	if strings.TrimSpace(raw) == "" {
		return time.Now().UTC(), nil
	}
	return parseComplianceDate(raw)
}
