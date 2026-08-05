package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/apitoken"
	"github.com/hibouhq/hibou/internal/audit"
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

	origin := resolveFindingOrigin(r.Context(), user)
	params.Origin = origin.Origin
	params.OriginApiKeyID = origin.APIKeyID
	params.OriginTokenName = origin.TokenName
	params.OriginOwnerType = origin.OwnerType
	params.OriginOwnerID = origin.OwnerID
	params.CreatedBy = origin.CreatedBy

	finding, err := s.queries.CreateVulnerability(r.Context(), *params)
	if err != nil {
		api.JSONError(w, http.StatusInternalServerError, "failed to create finding")
		return
	}

	s.writeRepositoryAuditLog(r, user, org.ID, repo.ID, audit.ActionFindingCreate, map[string]any{
		"finding_id":  finding.ID.String(),
		"fingerprint": finding.Fingerprint,
		"severity":    string(finding.Severity),
		"origin":      finding.Origin,
		"token_name":  finding.OriginTokenName,
	})

	api.JSON(w, http.StatusCreated, finding)
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
