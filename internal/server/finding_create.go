package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type createFindingRequest struct {
	// Ref selects the branch whose latest snapshot the finding attaches to.
	// Defaults to the repository's default branch.
	Ref         string `json:"ref"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	// RuleID is the caller's identifier for what was found ("manual/sql-injection").
	RuleID    string `json:"rule_id"`
	FilePath  string `json:"file_path"`
	StartLine int32  `json:"start_line"`
	EndLine   int32  `json:"end_line"`
	Solution  string `json:"solution"`
	// CWEs classify the finding (ADR-037) in any spelling the normalizer
	// accepts ("CWE-89", "89"). Unlike scanner claims they must exist in the
	// CWE catalog: typed or agent-generated input is validated.
	CWEs []string `json:"cwes,omitempty"`
}

type updateFindingCWEsRequest struct {
	CWEs []string `json:"cwes"`
}

// declaredCWEs validates a declared CWE list against the catalog.
func declaredCWEs(values []string) ([]int, error) {
	catalog := cwe.Default()
	ids := make([]int, 0, len(values))
	for _, value := range values {
		id, ok := cwe.Parse(value)
		if !ok {
			return nil, fmt.Errorf("cwes: %q is not a CWE id", value)
		}
		if _, known := catalog.Lookup(id); !known {
			return nil, fmt.Errorf("cwes: %s is not in the CWE catalog (version %s)", cwe.Format(id), catalog.Version)
		}
		ids = append(ids, id)
	}
	return cwe.Dedupe(ids), nil
}

func findingCWEDeclarer(origin findingOrigin) store.FindingCWEDeclarer {
	return store.FindingCWEDeclarer{UserID: origin.CreatedBy, APIKeyID: origin.APIKeyID}
}

// @Summary      File a finding
// @Description  Creates a manual finding on the latest snapshot of a ref. The finding records its origin — the human or the API token that filed it — derived from the authenticated principal, so it is never indistinguishable from scanner output.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider  path  string  true  "Forge provider"
// @Param        slug      path  string  true  "Organization slug"
// @Param        repoSlug  path  string  true  "Repository slug"
// @Param        payload   body  server.createFindingRequest  true  "Finding"
// @Success      201  {object}  api.Response{data=store.Vulnerability}
// @Failure      400  {object}  api.Response
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      409  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings [post]
func (s *Server) handleCreateFinding(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}

	var input createFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	params, status, message := s.buildManualFindingParams(r, repo, input)
	if params == nil {
		api.JSONError(w, status, message)
		return
	}
	cwes, err := declaredCWEs(input.CWEs)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	origin := resolveFindingOrigin(r.Context(), user)
	params.Origin = origin.Origin
	params.OriginApiKeyID = origin.APIKeyID
	params.OriginTokenName = origin.TokenName
	params.OriginOwnerType = origin.OwnerType
	params.OriginOwnerID = origin.OwnerID
	params.CreatedBy = origin.CreatedBy

	// The finding and its declared CWEs land together or not at all.
	tx, err := s.queries.BeginTx(r.Context())
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create finding")
		return
	}
	defer func() { _ = tx.Rollback() }()
	txQueries := s.queries.WithTx(tx)
	finding, err := txQueries.CreateVulnerability(r.Context(), *params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create finding")
		return
	}
	if len(cwes) > 0 {
		if err := txQueries.ReplaceDeclaredFindingCWEs(r.Context(), repo.ID, finding.Fingerprint, cwes, findingCWEDeclarer(origin)); err != nil {
			api.JSONError(w, http.StatusInternalServerError, "failed to store finding cwes")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create finding")
		return
	}
	created := []store.Vulnerability{*finding}
	if err := s.queries.AttachFindingCWEs(r.Context(), created); err == nil {
		finding = &created[0]
	}
	// Filing is the first confirmation, and filing the same finding again is
	// a re-assert (ADR-034 §4): no duplicate, "last confirmed" moves, and a
	// resolved or retracted assertion reopens.
	userID, apiKeyID := principalIDs(r, user)
	if previous, err := s.queries.GetFindingAssertion(r.Context(), repo.ID, finding.Fingerprint); err == nil {
		if _, err := s.queries.ConfirmFindingAssertion(r.Context(), repo.ID, finding.Fingerprint, userID, apiKeyID); err != nil {
			s.log.Warn().Err(err).Str("fingerprint", finding.Fingerprint).Msg("record assertion confirmation")
		} else if previous != nil && previous.ClosedKind != "" {
			if err := s.reopenAssertion(r, finding); err != nil {
				s.log.Warn().Err(err).Str("fingerprint", finding.Fingerprint).Msg("reopen re-filed assertion")
			}
		}
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingCreate, map[string]any{
		"finding_id":  finding.ID.String(),
		"fingerprint": finding.Fingerprint,
		"severity":    string(finding.Severity),
		"origin":      finding.Origin,
		"token_name":  finding.OriginTokenName,
		"cwes":        cwe.FormatAll(cwes),
	})

	api.JSON(w, http.StatusCreated, finding)
}

// @Summary      Set a manual finding's CWEs
// @Description  Replaces the CWEs declared on a manual finding (ADR-037). Scanner and dependency findings take their CWEs from the scanner rule or the advisory and cannot be reclassified here. Ids must exist in the CWE catalog; an empty list clears the declaration.
// @Tags         vulnerabilities
// @Accept       json
// @Produce      json
// @Param        provider     path  string  true  "Forge provider"
// @Param        slug         path  string  true  "Organization slug"
// @Param        repoSlug     path  string  true  "Repository slug"
// @Param        fingerprint  path  string  true  "Finding fingerprint"
// @Param        payload      body  server.updateFindingCWEsRequest  true  "CWEs"
// @Success      200  {object}  api.Response{data=store.Vulnerability}
// @Failure      400  {object}  api.Response
// @Failure      404  {object}  api.Response
// @Failure      409  {object}  api.Response
// @Security     BearerAuth
// @Router       /orgs/{provider}/{slug}/repos/{repoSlug}/findings/{fingerprint}/cwes [put]
func (s *Server) handleSetFindingCWEs(w http.ResponseWriter, r *http.Request) {
	org, repo, user, ok := s.loadAuthorizedRepoWithUser(w, r, false)
	if !ok {
		return
	}
	if !s.enforceTokenCapability(w, r, apitoken.CapVulnerabilities, apitoken.AccessWrite, org.Slug, repo.Slug) {
		return
	}
	fingerprint := pathFingerprint(r)
	var input updateFindingCWEsRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		api.JSONError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	cwes, err := declaredCWEs(input.CWEs)
	if err != nil {
		api.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	finding, err := s.queries.GetLatestVulnerabilityByFingerprint(r.Context(), repo.ID, fingerprint)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding")
		return
	}
	if finding == nil {
		api.JSONError(w, http.StatusNotFound, "finding not found")
		return
	}
	if finding.Type != string(store.VulnerabilityTypeManual) {
		api.JSONError(w, http.StatusConflict, "only manual findings take declared CWEs: this finding's CWEs come from its scanner rule or advisory")
		return
	}
	origin := resolveFindingOrigin(r.Context(), user)
	if err := s.queries.ReplaceDeclaredFindingCWEs(r.Context(), repo.ID, finding.Fingerprint, cwes, findingCWEDeclarer(origin)); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to store finding cwes")
		return
	}
	updated := []store.Vulnerability{*finding}
	if err := s.queries.AttachFindingCWEs(r.Context(), updated); err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to load finding cwes")
		return
	}
	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingCWEs, map[string]any{
		"finding_id":  finding.ID.String(),
		"fingerprint": finding.Fingerprint,
		"cwes":        cwe.FormatAll(cwes),
		"origin":      string(origin.Origin),
	})
	api.JSON(w, http.StatusOK, updated[0])
}

// buildManualFindingParams validates the request and resolves the snapshot it
// attaches to. A nil result carries the status and message to return.
func (s *Server) buildManualFindingParams(r *http.Request, repo *store.Repository, input createFindingRequest) (*dbgen.CreateVulnerabilityParams, int, string) {
	title := strings.TrimSpace(input.Title)
	if title == "" {
		return nil, http.StatusBadRequest, "title is required"
	}
	severity, err := manualFindingSeverity(input.Severity)
	if err != nil {
		return nil, http.StatusBadRequest, err.Error()
	}
	if input.StartLine < 0 || input.EndLine < 0 {
		return nil, http.StatusBadRequest, "line numbers must be positive"
	}
	if input.StartLine > 0 && input.EndLine > 0 && input.EndLine < input.StartLine {
		return nil, http.StatusBadRequest, "end_line must not precede start_line"
	}

	snapshot, status, message := s.resolveManualFindingSnapshot(r, repo, input.Ref)
	if snapshot == nil {
		return nil, status, message
	}

	ruleID := strings.TrimSpace(input.RuleID)
	filePath := strings.TrimSpace(input.FilePath)
	fingerprint := manualFindingFingerprint(ruleID, filePath, input.StartLine, title)

	return &dbgen.CreateVulnerabilityParams{
		Type:                   string(store.VulnerabilityTypeManual),
		SnapshotID:             snapshot.ID,
		Title:                  truncateFindingTitle(title),
		Description:            strings.TrimSpace(input.Description),
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: ruleID,
		OriginalSeverity:       severity,
		Severity:               severity,
		Status:                 string(store.VulnerabilityStatusDetected),
		FilePath:               nullFindingString(filePath),
		StartLine:              sql.NullInt32{Int32: input.StartLine, Valid: input.StartLine > 0},
		EndLine:                sql.NullInt32{Int32: input.EndLine, Valid: input.EndLine > 0},
		LocationHash:           nullFindingString(fingerprint),
		Fingerprint:            fingerprint,
		Solution:               nullFindingString(strings.TrimSpace(input.Solution)),
		Metadata:               json.RawMessage(`{}`),
	}, 0, ""
}

func (s *Server) resolveManualFindingSnapshot(r *http.Request, repo *store.Repository, refName string) (*store.Snapshot, int, string) {
	name := strings.TrimSpace(refName)
	if name == "" {
		name = repo.DefaultBranch
	}
	if name == "" {
		return nil, http.StatusBadRequest, "ref is required: the repository has no default branch"
	}

	ref, err := s.queries.GetRefByRepoAndName(r.Context(), repo.ID, name, store.RefTypeBranch)
	if err != nil {
		return nil, http.StatusInternalServerError, "failed to load ref"
	}
	if ref == nil {
		return nil, http.StatusNotFound, "ref not found"
	}

	snapshot, err := s.queries.GetLatestSnapshotByRef(r.Context(), ref.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, "failed to load snapshot"
	}
	if snapshot == nil {
		return nil, http.StatusConflict, "ref has no snapshot to attach a finding to"
	}
	return snapshot, 0, ""
}

func manualFindingSeverity(value string) (store.SeverityLevel, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return store.SeverityLevelCritical, nil
	case "high":
		return store.SeverityLevelHigh, nil
	case "medium":
		return store.SeverityLevelMedium, nil
	case "low":
		return store.SeverityLevelLow, nil
	case "info", "informational":
		return store.SeverityLevelInfo, nil
	default:
		return "", errors.New("severity must be one of critical, high, medium, low, info")
	}
}

// manualFindingFingerprint keys the finding so re-filing the same thing updates
// the existing row instead of piling up duplicates, matching how scanner
// ingestion is deduplicated.
func manualFindingFingerprint(ruleID, filePath string, startLine int32, title string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		"manual", ruleID, filePath, strconv.Itoa(int(startLine)), title,
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func truncateFindingTitle(title string) string {
	const maxTitleLength = 200
	if len(title) <= maxTitleLength {
		return title
	}
	return title[:maxTitleLength]
}

func nullFindingString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
