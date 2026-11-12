package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

type AtomicRemediationRequest struct {
	BaseSHA, Target, Branch, ArtifactSHA string
	Files                                map[string][]byte
	// Audit must persist the intent before each side effect, and its outcome.
	Audit func(string, any) error
}

type AtomicRemediationPublisher interface {
	PublishRemediation(context.Context, string, string, AtomicRemediationRequest) (*PullRequest, error)
}

type RemediationPublicationCapability interface {
	CheckRemediationPublication(context.Context, string, string) error
}

func (g *GitHub) CheckRemediationPublication(ctx context.Context, owner, repo string) error {
	if g.appID == 0 || g.tier != TierPropose {
		return errors.New("managed publication requires GitHub App propose tier")
	}
	_, err := g.scopedInstallationToken(ctx, owner, TokenScope{Repo: repo,
		Permissions: map[string]string{"contents": "write", "pull_requests": "write"}})
	return err
}

func (g *GitHub) PublishRemediation(ctx context.Context, owner, repo string, r AtomicRemediationRequest) (*PullRequest, error) {
	if err := CheckWriteBranch(r.Branch); err != nil {
		return nil, err
	}
	if err := g.CheckRemediationPublication(ctx, owner, repo); err != nil {
		return nil, err
	}
	if r.Audit == nil {
		return nil, errors.New("durable publication audit required")
	}
	if !regexp.MustCompile(`^[a-f0-9]{40}([a-f0-9]{24})?$`).MatchString(r.BaseSHA) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(r.ArtifactSHA) {
		return nil, errors.New("full base and artifact digests required")
	}
	if len(r.Files) == 0 || len(r.Files) > 200 {
		return nil, errors.New("complete dependency file set required")
	}
	var names []string
	var size int
	for file, data := range r.Files {
		if _, err := checkedContentPath(file); err != nil {
			return nil, err
		}
		if file != path.Clean(file) || strings.HasPrefix(file, "/") || strings.ContainsAny(file, "\x00\r\n") ||
			(path.Base(file) != "package.json" && path.Base(file) != "package-lock.json") || len(data) > 16<<20 || !utf8.Valid(data) {
			return nil, errors.New("unsupported publication file")
		}
		size += len(data)
		names = append(names, file)
	}
	if size > 64<<20 {
		return nil, errors.New("publication exceeds size limit")
	}
	slices.Sort(names)
	head, err := g.GetBranch(ctx, owner, repo, r.Target)
	if err != nil || head == nil || head.SHA != r.BaseSHA {
		return nil, errors.New("target head moved; prepare a new draft for this existing branch")
	}
	prefix := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	var parent struct {
		Tree struct {
			SHA string `json:"sha"`
		} `json:"tree"`
	}
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, prefix+"/git/commits/"+r.BaseSHA, nil, &parent); err != nil {
		return nil, err
	}
	if parent.Tree.SHA == "" {
		return nil, errors.New("base commit tree unavailable")
	}
	type entry struct {
		Path    string `json:"path"`
		Mode    string `json:"mode"`
		Type    string `json:"type"`
		Content string `json:"content"`
	}
	tree := make([]entry, 0, len(names))
	for _, name := range names {
		tree = append(tree, entry{name, "100644", "blob", string(r.Files[name])})
	}
	var createdTree struct {
		SHA string `json:"sha"`
	}
	if err := r.Audit("git_tree_intent", map[string]any{"paths": names, "artifact_sha": r.ArtifactSHA}); err != nil {
		return nil, err
	}
	if err := g.doJSONOwner(ctx, owner, http.MethodPost, prefix+"/git/trees", map[string]any{"base_tree": parent.Tree.SHA, "tree": tree}, &createdTree); err != nil {
		return nil, err
	}
	if createdTree.SHA == "" {
		return nil, errors.New("forge returned no complete tree")
	}
	if err := r.Audit("git_tree_created", map[string]string{"sha": createdTree.SHA}); err != nil {
		return nil, err
	}
	// Fixed author/committer identity and timestamp make retries produce the
	// same commit for the same verified tree, rather than a new branch head.
	identity := map[string]string{"name": "Hibou", "email": "noreply@hibou.dev", "date": "2000-01-01T00:00:00Z"}
	var commit struct {
		SHA string `json:"sha"`
	}
	if err := r.Audit("git_commit_intent", map[string]string{"tree": createdTree.SHA, "base": r.BaseSHA}); err != nil {
		return nil, err
	}
	if err := g.doJSONOwner(ctx, owner, http.MethodPost, prefix+"/git/commits", map[string]any{
		"message": "fix(deps): verified Hibou remediation\n\nArtifact-SHA256: " + r.ArtifactSHA,
		"tree":    createdTree.SHA, "parents": []string{r.BaseSHA}, "author": identity, "committer": identity,
	}, &commit); err != nil {
		return nil, err
	}
	if commit.SHA == "" {
		return nil, errors.New("forge returned no commit")
	}
	if err := r.Audit("git_commit_created", map[string]string{"sha": commit.SHA}); err != nil {
		return nil, err
	}
	if err := g.ensureRemediationBranch(ctx, owner, prefix, r, commit.SHA); err != nil {
		return nil, err
	}
	pullsPath := prefix + "/pulls?state=all&head=" + url.QueryEscape(owner+":"+r.Branch) + "&base=" + url.QueryEscape(r.Target) + "&per_page=100"
	var existing []struct {
		Number  int    `json:"number"`
		Title   string `json:"title"`
		HTMLURL string `json:"html_url"`
	}
	if err := g.doJSONOwner(ctx, owner, http.MethodGet, pullsPath, nil, &existing); err != nil {
		return nil, err
	}
	if len(existing) > 0 {
		p := existing[0]
		if err := r.Audit("pull_request_reused", map[string]any{"number": p.Number}); err != nil {
			return nil, err
		}
		return &PullRequest{Number: p.Number, Title: p.Title, HTMLURL: p.HTMLURL}, nil
	}
	// Recheck immediately before the final visible side effect.
	head, err = g.GetBranch(ctx, owner, repo, r.Target)
	if err != nil || head == nil || head.SHA != r.BaseSHA {
		return nil, errors.New("target head moved before pull request publication")
	}
	if err := r.Audit("pull_request_intent", map[string]string{"head": r.Branch, "base": r.Target}); err != nil {
		return nil, err
	}
	pr, err := g.CreatePullRequest(ctx, owner, repo, CreatePROptions{
		Title: "fix(deps): verified dependency remediation", Head: r.Branch, Base: r.Target,
		Body: "Verified dependency-only changes generated by Hibou.\n\nBase: `" + r.BaseSHA + "`\nArtifact SHA256: `" + r.ArtifactSHA + "`\n\nLockfile consistency, selected advisories and introduced-advisory policy were checked. Builds and tests were not run. Review before merging. No release, tag or merge is performed automatically.",
	})
	if err != nil {
		return nil, err
	}
	if err := r.Audit("pull_request_created", map[string]any{"number": pr.Number, "url": pr.HTMLURL}); err != nil {
		return nil, err
	}
	return pr, nil
}

func (g *GitHub) ensureRemediationBranch(ctx context.Context, owner, prefix string, r AtomicRemediationRequest, commit string) error {
	refPath := prefix + "/git/ref/heads/" + url.PathEscape(r.Branch)
	get := func() (string, int, error) {
		req, err := g.newRequest(ctx, http.MethodGet, refPath, nil)
		if err != nil {
			return "", 0, err
		}
		if err := g.authorizeForOwner(ctx, req, owner); err != nil {
			return "", 0, err
		}
		var ref struct {
			Object struct {
				SHA string `json:"sha"`
			} `json:"object"`
		}
		status, err := g.doWithStatus(req, &ref)
		return ref.Object.SHA, status, err
	}
	sha, status, err := get()
	if err == nil {
		if sha != commit {
			return errors.New("deterministic remediation branch contains different or user-authored commits; never overwritten")
		}
		return r.Audit("branch_reused", map[string]string{"branch": r.Branch, "sha": sha})
	}
	if status != http.StatusNotFound {
		return err
	}
	if err := r.Audit("branch_intent", map[string]string{"branch": r.Branch, "sha": commit}); err != nil {
		return err
	}
	// One atomic ref creation points directly to the complete-file commit.
	err = g.doJSONOwner(ctx, owner, http.MethodPost, prefix+"/git/refs", map[string]string{"ref": "refs/heads/" + r.Branch, "sha": commit}, nil)
	if err != nil {
		sha, _, lookupErr := get()
		if lookupErr != nil || sha != commit {
			return err
		}
	}
	return r.Audit("branch_created", map[string]string{"branch": r.Branch, "sha": commit})
}
