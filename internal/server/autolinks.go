package server

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Autolink references (ADR-053): an organisation's tracker prefixes, turned
// into links wherever people write ("SEC-7" → the ticket). The matching is
// done in the browser; the server keeps the list and validates it.

type autolinkRequest struct {
	Prefix       string `json:"prefix"`
	URLTemplate  string `json:"url_template"`
	Alphanumeric bool   `json:"alphanumeric"`
}

var autolinkPrefixPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func (in *autolinkRequest) validate() string {
	in.Prefix = strings.TrimSpace(in.Prefix)
	in.URLTemplate = strings.TrimSpace(in.URLTemplate)
	switch {
	case !autolinkPrefixPattern.MatchString(in.Prefix):
		return "prefix must be 1–64 letters, digits, dots, dashes or underscores"
	case !strings.Contains(in.URLTemplate, "<num>"):
		return "the URL must contain <num> for the reference"
	case !strings.HasPrefix(in.URLTemplate, "https://") && !strings.HasPrefix(in.URLTemplate, "http://"):
		return "the URL must start with https:// or http://"
	case len(in.URLTemplate) > 2048:
		return "the URL is too long"
	}
	return ""
}

// @Summary      List autolink references
// @Tags         organizations
// @Produce      json
// @Param        provider path string true "Provider"
// @Param        slug path string true "Organization slug"
// @Success      200 {array} dbgen.OrgAutolink
// @Router       /orgs/{provider}/{slug}/autolinks [get]
func (s *Server) handleListAutolinks(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok {
		return
	}
	rows, err := s.queries.Incidents().ListOrgAutolinks(r.Context(), org.ID)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to list autolinks")
		return
	}
	if rows == nil {
		rows = []dbgen.OrgAutolink{}
	}
	api.JSON(w, http.StatusOK, rows)
}

// @Summary      Add an autolink reference
// @Description  A prefix ("SEC-") and a URL with <num>: "SEC-7" becomes a link in notes, reasons, comments and references.
// @Tags         organizations
// @Accept       json
// @Produce      json
// @Param        provider path string true "Provider"
// @Param        slug path string true "Organization slug"
// @Param        request body autolinkRequest true "Autolink"
// @Success      201 {object} dbgen.OrgAutolink
// @Router       /orgs/{provider}/{slug}/autolinks [post]
func (s *Server) handleCreateAutolink(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok || !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	var input autolinkRequest
	if !decodeIncidentBody(w, r, &input) {
		return
	}
	if msg := input.validate(); msg != "" {
		api.JSONError(w, http.StatusBadRequest, msg)
		return
	}
	var createdBy uuid.NullUUID
	if user := UserFromContext(r.Context()); user != nil {
		createdBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	row, err := s.queries.Incidents().CreateOrgAutolink(r.Context(), dbgen.CreateOrgAutolinkParams{
		OrgID: org.ID, Prefix: input.Prefix, UrlTemplate: input.URLTemplate, Alphanumeric: input.Alphanumeric, CreatedBy: createdBy,
	})
	if err != nil {
		if isUniqueViolation(err) {
			api.JSONError(w, http.StatusConflict, "an autolink with this prefix already exists")
			return
		}
		api.JSONError(w, http.StatusInternalServerError, "failed to save the autolink")
		return
	}
	api.JSON(w, http.StatusCreated, row)
}

// @Summary      Remove an autolink reference
// @Tags         organizations
// @Param        provider path string true "Provider"
// @Param        slug path string true "Organization slug"
// @Param        autolinkID path string true "Autolink id"
// @Success      204
// @Router       /orgs/{provider}/{slug}/autolinks/{autolinkID} [delete]
func (s *Server) handleDeleteAutolink(w http.ResponseWriter, r *http.Request) {
	org, ok := s.loadAuthorizedOrg(r, w)
	if !ok || !s.requireOrgAdmin(r, w, org.ID) {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "autolinkID"))
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid autolink id")
		return
	}
	n, err := s.queries.Incidents().DeleteOrgAutolink(r.Context(), dbgen.DeleteOrgAutolinkParams{ID: id, OrgID: org.ID})
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to delete the autolink")
		return
	}
	if n == 0 {
		api.JSONError(w, http.StatusNotFound, "autolink not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
