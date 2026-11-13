package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var ErrMaintenanceTargetCollision = errors.New("maintenance target already exists; it was not changed")

type MaintenanceEvidence struct {
	SourceTag      string `json:"source_tag"`
	SourceSHA      string `json:"source_sha"`
	TagSHA         string `json:"tag_sha"`
	TagConfirmed   bool   `json:"tag_confirmed"`
	TargetBranch   string `json:"target_branch"`
	Exists         bool   `json:"exists"`
	HeadSHA        string `json:"head_sha,omitempty"`
	SourceAncestor bool   `json:"source_ancestor"`
}

type MaintenanceCreation struct {
	SourceTag, SourceSHA, TargetBranch string
	ApprovedPatterns                   []string
	ReconcileExisting                  bool
	Audit                              func(string, any) error
}

type MaintenanceCreated struct {
	TargetBranch string `json:"target_branch"`
	SourceTag    string `json:"source_tag"`
	SourceSHA    string `json:"source_sha"`
	Created      bool   `json:"created"`
	Reconciled   bool   `json:"reconciled"`
}

type MaintenanceProvider interface {
	InspectMaintenanceTarget(context.Context, string, string, string, string, string) (*MaintenanceEvidence, error)
	CheckMaintenanceCreation(context.Context, string, string) error
	CreateApprovedMaintenanceTarget(context.Context, string, string, MaintenanceCreation) (*MaintenanceCreated, error)
}

var maintenanceRefName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)
var maintenanceCommitSHA = regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`)

func ValidateMaintenanceRef(name string) error {
	if len(name) > 200 || !maintenanceRefName.MatchString(name) || name == "HEAD" || strings.HasPrefix(name, "refs/") ||
		strings.Contains(name, "..") || strings.Contains(name, "//") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") {
		return errors.New("unsupported maintenance branch or source tag name")
	}
	for _, segment := range strings.Split(name, "/") {
		if strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, ".lock") {
			return errors.New("unsafe maintenance ref segment")
		}
	}
	return nil
}

// CheckMaintenanceBranch is separate from CheckWriteBranch: this permission
// applies only to create-at-confirmed-release operations, never general writes.
func CheckMaintenanceBranch(branch string, patterns []string) error {
	if err := ValidateMaintenanceRef(branch); err != nil {
		return err
	}
	if err := ValidateMaintenancePatterns(patterns); err != nil {
		return err
	}
	if strings.HasPrefix(branch, WriteBranchPrefix) {
		return CheckWriteBranch(branch)
	}
	for _, pattern := range patterns {
		matched, err := path.Match(pattern, branch)
		if err != nil {
			return errors.New("invalid operator maintenance-branch allowlist pattern")
		}
		if matched {
			return nil
		}
	}
	return errors.New("maintenance branch is outside the operator creation allowlist")
}

func ValidateMaintenancePatterns(patterns []string) error {
	if len(patterns) == 0 {
		return errors.New("operator maintenance-branch creation allowlist is empty")
	}
	if len(patterns) > 50 {
		return errors.New("operator maintenance-branch allowlist exceeds 50 patterns")
	}
	for _, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > 200 || strings.ContainsAny(pattern, "\x00\r\n") {
			return errors.New("invalid operator maintenance-branch allowlist")
		}
		if _, err := path.Match(pattern, "release/example"); err != nil {
			return errors.New("invalid operator maintenance-branch allowlist pattern")
		}
	}
	return nil
}

func (g *GitHub) CheckMaintenanceCreation(ctx context.Context, owner, repo string) error {
	if g.appID == 0 || g.tier != TierPropose {
		return errors.New("maintenance creation requires GitHub App propose tier")
	}
	_, err := g.scopedInstallationToken(ctx, owner, TokenScope{Repo: repo, Permissions: map[string]string{"contents": "write"}})
	return err
}

func (g *GitHub) maintenanceRef(ctx context.Context, owner, prefix, kind, name string) (sha, objectType string, exists bool, err error) {
	req, err := g.newRequest(ctx, http.MethodGet, prefix+"/git/ref/"+kind+"/"+url.PathEscape(name), nil)
	if err != nil {
		return "", "", false, err
	}
	if err := g.authorizeForOwner(ctx, req, owner); err != nil {
		return "", "", false, err
	}
	var response struct {
		Object struct {
			SHA  string `json:"sha"`
			Type string `json:"type"`
		} `json:"object"`
	}
	status, err := g.doWithStatus(req, &response)
	if status == http.StatusNotFound {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	if !maintenanceCommitSHA.MatchString(response.Object.SHA) {
		return "", "", false, errors.New("forge returned an invalid object SHA")
	}
	return response.Object.SHA, response.Object.Type, true, nil
}

func (g *GitHub) confirmedMaintenanceSource(ctx context.Context, owner, prefix, tag, expected string) (string, error) {
	if err := ValidateMaintenanceRef(tag); err != nil {
		return "", err
	}
	if !maintenanceCommitSHA.MatchString(expected) {
		return "", errors.New("full pinned release SHA required")
	}
	sha, kind, exists, err := g.maintenanceRef(ctx, owner, prefix, "tags", tag)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", errors.New("source release tag no longer exists")
	}
	seen := map[string]bool{}
	for depth := 0; kind == "tag"; depth++ {
		if depth >= 8 || seen[sha] {
			return "", errors.New("source tag annotation chain is unsupported")
		}
		seen[sha] = true
		var annotation struct {
			Object struct {
				SHA  string `json:"sha"`
				Type string `json:"type"`
			} `json:"object"`
		}
		if err := g.doJSONOwner(ctx, owner, http.MethodGet, prefix+"/git/tags/"+sha, nil, &annotation); err != nil {
			return "", err
		}
		sha, kind = annotation.Object.SHA, annotation.Object.Type
		if !maintenanceCommitSHA.MatchString(sha) {
			return "", errors.New("source tag contains an invalid object SHA")
		}
	}
	if kind != "commit" || sha != expected {
		return sha, errors.New("live source tag differs from the exact pinned shipped commit")
	}
	return sha, nil
}

func (g *GitHub) InspectMaintenanceTarget(ctx context.Context, owner, repo, tag, source, target string) (*MaintenanceEvidence, error) {
	if err := ValidateMaintenanceRef(target); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	evidence := &MaintenanceEvidence{SourceTag: tag, SourceSHA: source, TargetBranch: target}
	tagSHA, err := g.confirmedMaintenanceSource(ctx, owner, prefix, tag, source)
	evidence.TagSHA = tagSHA
	if err != nil {
		return evidence, err
	}
	evidence.TagConfirmed = true
	sha, kind, exists, err := g.maintenanceRef(ctx, owner, prefix, "heads", target)
	if err != nil {
		return evidence, err
	}
	evidence.Exists, evidence.HeadSHA = exists, sha
	if !exists {
		return evidence, nil
	}
	if kind != "commit" {
		return evidence, errors.New("target branch does not reference a commit")
	}
	if sha == source {
		evidence.SourceAncestor = true
		return evidence, nil
	}
	var compared struct {
		Status string `json:"status"`
	}
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, prefix+"/compare/"+source+"..."+sha, nil, &compared); err != nil {
		return evidence, err
	}
	switch compared.Status {
	case "ahead", "identical":
		evidence.SourceAncestor = true
	case "behind", "diverged":
	default:
		return evidence, errors.New("forge returned incomplete tag ancestry evidence")
	}
	return evidence, nil
}

// CreateApprovedMaintenanceTarget never updates, deletes, or repoints a ref.
// The exceptional namespace permission is bounded by an operator allowlist and
// a freshly revalidated release tag, not a general branch-write bypass.
func (g *GitHub) CreateApprovedMaintenanceTarget(ctx context.Context, owner, repo string, r MaintenanceCreation) (*MaintenanceCreated, error) {
	if err := CheckMaintenanceBranch(r.TargetBranch, r.ApprovedPatterns); err != nil {
		return nil, err
	}
	if r.Audit == nil {
		return nil, errors.New("durable maintenance creation audit is required")
	}
	if err := g.CheckMaintenanceCreation(ctx, owner, repo); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	if _, err := g.confirmedMaintenanceSource(ctx, owner, prefix, r.SourceTag, r.SourceSHA); err != nil {
		return nil, err
	}
	head, kind, exists, err := g.maintenanceRef(ctx, owner, prefix, "heads", r.TargetBranch)
	if err != nil {
		return nil, err
	}
	result := &MaintenanceCreated{TargetBranch: r.TargetBranch, SourceTag: r.SourceTag, SourceSHA: r.SourceSHA}
	if exists {
		if !r.ReconcileExisting || kind != "commit" || head != r.SourceSHA {
			return nil, ErrMaintenanceTargetCollision
		}
		result.Reconciled = true
		if err := r.Audit("reconciled", result); err != nil {
			return nil, err
		}
		return result, nil
	}
	if err := r.Audit("ref_intent", result); err != nil {
		return nil, err
	}
	err = g.doJSONOwner(ctx, owner, http.MethodPost, prefix+"/git/refs", map[string]string{"ref": "refs/heads/" + r.TargetBranch, "sha": r.SourceSHA}, nil)
	if err != nil {
		head, kind, exists, lookupErr := g.maintenanceRef(ctx, owner, prefix, "heads", r.TargetBranch)
		if lookupErr != nil || !exists || kind != "commit" || head != r.SourceSHA {
			return nil, err
		}
		result.Reconciled = true
	} else {
		result.Created = true
	}
	if err := r.Audit("created", result); err != nil {
		return nil, err
	}
	return result, nil
}
