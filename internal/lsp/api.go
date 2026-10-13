package lsp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// apiClient is the language server's view of the hibou REST API. It only
// decodes the fields the IDE shows.
type apiClient struct {
	server string // base URL without /api/v1
	token  string
	http   *http.Client
	agent  string
}

// apiError is a non-2xx answer from the server.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("hibou API returned HTTP %d", e.Status)
	}
	return fmt.Sprintf("hibou API returned HTTP %d: %s", e.Status, e.Message)
}

func isStatus(err error, status int) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.Status == status
}

type pagination struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

// maxResponseBytes bounds one decoded response page.
const maxResponseBytes = 32 << 20

func (c *apiClient) do(ctx context.Context, method, path string, query url.Values, body, out any, page *pagination) error {
	u := c.server + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.send(req, out, page)
}

// send authenticates req, runs it and decodes the response envelope.
func (c *apiClient) send(req *http.Request, out any, page *pagination) error {
	path := req.URL.Path
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.agent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error json.RawMessage `json:"error"`
		}
		apiErr := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(data, &envelope) == nil && len(envelope.Error) > 0 {
			var structured struct {
				Message string `json:"message"`
			}
			var plain string
			switch {
			case json.Unmarshal(envelope.Error, &structured) == nil && structured.Message != "":
				apiErr.Message = structured.Message
			case json.Unmarshal(envelope.Error, &plain) == nil:
				apiErr.Message = plain
			}
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	var envelope struct {
		Data       json.RawMessage `json:"data"`
		Pagination *pagination     `json:"pagination"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	if page != nil && envelope.Pagination != nil {
		*page = *envelope.Pagination
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil
	}
	return json.Unmarshal(envelope.Data, out)
}

// postRaw sends a non-JSON body (a unified diff for the secret check).
func (c *apiClient) postRaw(ctx context.Context, path, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+"/api/v1"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	return c.send(req, out, nil)
}

func (c *apiClient) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, query, nil, out, nil)
}

// getAll pages through a list endpoint, at most maxPages pages of 100.
func getAll[T any](ctx context.Context, c *apiClient, path string, query url.Values, maxPages int) ([]T, bool, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("per_page", "100")
	var all []T
	for p := 1; p <= maxPages; p++ {
		query.Set("page", strconv.Itoa(p))
		var items []T
		var page pagination
		if err := c.do(ctx, http.MethodGet, path, query, nil, &items, &page); err != nil {
			return nil, false, err
		}
		all = append(all, items...)
		if len(items) == 0 || page.Total <= len(all) {
			return all, false, nil
		}
	}
	return all, true, nil
}

func repoPath(r repoRef) string {
	return "/orgs/" + url.PathEscape(r.Provider) + "/" + url.PathEscape(r.Org) + "/repos/" + url.PathEscape(r.Repo)
}

// repoRef identifies a repository on the hibou server.
type repoRef struct {
	Provider string `json:"provider"`
	Org      string `json:"org"`
	Repo     string `json:"repo"`
}

type apiUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	// Service-token principals carry these instead.
	Principal string `json:"principal"`
	TokenName string `json:"token_name"`
}

func (u apiUser) label() string {
	switch {
	case u.DisplayName != "":
		return u.DisplayName
	case u.Email != "":
		return u.Email
	case u.TokenName != "":
		return u.TokenName
	}
	return "unknown user"
}

type apiRepo struct {
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	DefaultBranch string `json:"default_branch"`
}

type apiSnapshot struct {
	ID        string    `json:"id"`
	CommitSHA string    `json:"commit_sha"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

type apiRef struct {
	Name                 string     `json:"name"`
	RefType              string     `json:"ref_type"`
	PRNumber             string     `json:"pr_number"`
	PRState              string     `json:"pr_state"`
	PRSourceBranch       string     `json:"pr_source_branch"`
	LatestSnapshotID     string     `json:"latest_snapshot_id"`
	LatestSnapshotStatus string     `json:"latest_snapshot_status"`
	LatestSnapshotDate   *time.Time `json:"latest_snapshot_date"`
}

type apiCWE struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type apiFinding struct {
	ID                     string          `json:"id"`
	Type                   string          `json:"type"`
	Title                  string          `json:"title"`
	Description            string          `json:"description"`
	Severity               string          `json:"severity"`
	Status                 string          `json:"status"`
	PrimaryIdentifierKind  string          `json:"primary_identifier_kind"`
	PrimaryIdentifierValue string          `json:"primary_identifier_value"`
	ScannerName            string          `json:"scanner_name"`
	FilePath               string          `json:"file_path"`
	StartLine              int             `json:"start_line"`
	EndLine                int             `json:"end_line"`
	Fingerprint            string          `json:"fingerprint"`
	ComponentName          string          `json:"component_name"`
	ComponentVersion       string          `json:"component_version"`
	ComponentPurl          string          `json:"component_purl"`
	AdvisoryID             string          `json:"advisory_id"`
	Solution               string          `json:"solution"`
	RemediationLink        string          `json:"remediation_link"`
	Reachability           string          `json:"reachability"`
	FirstSeenAt            *time.Time      `json:"first_seen_at"`
	Metadata               json.RawMessage `json:"metadata"`
	KEV                    bool            `json:"kev"`
	CWEs                   []apiCWE        `json:"cwes"`
	CVSS                   *struct {
		Score   *float64 `json:"score"`
		Version string   `json:"version"`
	} `json:"cvss"`
	EPSS *struct {
		Score      float64 `json:"score"`
		Percentile float64 `json:"percentile"`
	} `json:"epss"`
	Acceptance *struct {
		ReasonKind string     `json:"reason_kind"`
		Reason     string     `json:"reason"`
		ExpiresAt  *time.Time `json:"expires_at"`
	} `json:"acceptance"`
	Dispute *struct {
		Reason string `json:"reason"`
	} `json:"dispute"`
}

// suppressionJustification returns the in-source justification ADR-026
// records in metadata.suppression.
func (f apiFinding) suppressionJustification() string {
	var meta struct {
		Suppression struct {
			Justification string `json:"justification"`
		} `json:"suppression"`
	}
	if len(f.Metadata) == 0 || json.Unmarshal(f.Metadata, &meta) != nil {
		return ""
	}
	return meta.Suppression.Justification
}

// ruleID is the scanner rule for SAST and secret findings.
func (f apiFinding) ruleID() string {
	if f.PrimaryIdentifierKind == "rule" {
		return f.PrimaryIdentifierValue
	}
	return ""
}

type apiGate struct {
	PRNumber    int      `json:"pr_number"`
	HeadSHA     string   `json:"head_sha"`
	State       string   `json:"state"`
	Conclusion  string   `json:"conclusion"`
	Enforcement string   `json:"enforcement"`
	Passed      bool     `json:"passed"`
	Reasons     []string `json:"reasons"`
	TargetURL   string   `json:"target_url"`
}

type apiCoverageLine struct {
	Number          int `json:"number"`
	Hits            int `json:"hits"`
	BranchesCovered int `json:"branches_covered"`
	BranchesValid   int `json:"branches_valid"`
}

type apiCoverageSource struct {
	Path      string            `json:"path"`
	CommitSHA string            `json:"commit_sha"`
	Lines     []apiCoverageLine `json:"lines"`
}

func (c *apiClient) me(ctx context.Context) (apiUser, error) {
	var u apiUser
	return u, c.get(ctx, "/users/me", nil, &u)
}

func (c *apiClient) repo(ctx context.Context, r repoRef) (apiRepo, error) {
	var out apiRepo
	return out, c.get(ctx, repoPath(r), nil, &out)
}

// snapshots lists a ref's snapshots, newest first, at most limit of them.
func (c *apiClient) snapshots(ctx context.Context, r repoRef, ref string, pages int) ([]apiSnapshot, error) {
	q := url.Values{}
	if ref != "" {
		q.Set("ref", ref)
	}
	snaps, _, err := getAll[apiSnapshot](ctx, c, repoPath(r)+"/snapshots", q, pages)
	return snaps, err
}

func (c *apiClient) refs(ctx context.Context, r repoRef) ([]apiRef, error) {
	refs, _, err := getAll[apiRef](ctx, c, repoPath(r)+"/refs/enhanced", nil, 20)
	return refs, err
}

// maxFindingPages caps one snapshot fetch at 10,000 findings.
const maxFindingPages = 100

// findings returns the open and suppressed findings of a snapshot. Resolved
// findings are not shown in the editor.
func (c *apiClient) findings(ctx context.Context, r repoRef, snapshotID string) ([]apiFinding, bool, error) {
	q := url.Values{}
	q.Set("snapshot", snapshotID)
	q.Set("status", "detected,suppressed")
	q.Set("sort", "severity_desc")
	return getAll[apiFinding](ctx, c, repoPath(r)+"/findings", q, maxFindingPages)
}

func (c *apiClient) gate(ctx context.Context, r repoRef, pr string) (apiGate, error) {
	var g apiGate
	return g, c.get(ctx, repoPath(r)+"/pulls/"+url.PathEscape(pr)+"/gate", nil, &g)
}

func (c *apiClient) coverageSource(ctx context.Context, r repoRef, snapshotID, path string) (apiCoverageSource, error) {
	var out apiCoverageSource
	q := url.Values{}
	q.Set("path", path)
	return out, c.get(ctx, repoPath(r)+"/snapshots/"+url.PathEscape(snapshotID)+"/coverage-source", q, &out)
}

type acceptanceRequest struct {
	Status     string     `json:"status"`
	ReasonKind string     `json:"reason_kind,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

func (c *apiClient) setAcceptance(ctx context.Context, r repoRef, vulnID string, body acceptanceRequest) error {
	return c.do(ctx, http.MethodPut, repoPath(r)+"/vulnerabilities/"+url.PathEscape(vulnID)+"/acceptance", nil, body, nil, nil)
}

func (c *apiClient) setDispute(ctx context.Context, r repoRef, vulnID, reason string) error {
	return c.do(ctx, http.MethodPut, repoPath(r)+"/vulnerabilities/"+url.PathEscape(vulnID)+"/dispute", nil, map[string]string{"reason": reason}, nil, nil)
}

func (c *apiClient) deleteDispute(ctx context.Context, r repoRef, vulnID string) error {
	return c.do(ctx, http.MethodDelete, repoPath(r)+"/vulnerabilities/"+url.PathEscape(vulnID)+"/dispute", nil, nil, nil, nil)
}

// revokeCurrentToken revokes the calling token (ADR-043 §6). Older servers
// answer 404 or 405; the caller then only forgets the token locally.
func (c *apiClient) revokeCurrentToken(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/users/me/api-keys/current", nil, nil, nil, nil)
}

// webURL builds a link into the SPA.
func webURL(server string, r repoRef, query url.Values) string {
	u := strings.TrimRight(server, "/") + "/orgs/" + url.PathEscape(r.Provider) + "/" + url.PathEscape(r.Org) + "/repos/" + url.PathEscape(r.Repo) + "/vulnerabilities"
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}
