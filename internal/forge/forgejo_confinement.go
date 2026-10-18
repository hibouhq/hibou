package forge

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
)

// CheckConfinement implements ConfinementChecker for Forgejo (the latest
// release; Gitea shares the API). The server token is a user token: it may
// push to any branch of a repository where that user has write access,
// unless a branch protection rule stops it. For each repository the user can
// push to, the branch list says whether the token can push each existing
// branch, and the protection rules say whether it could create others.
// Listing protections needs repository admin; without it, new branches are
// reported as unverifiable.
func (f *Forgejo) CheckConfinement(ctx context.Context) ([]ConfinementFinding, error) {
	if strings.TrimSpace(f.token) == "" {
		return []ConfinementFinding{{
			Severity: ConfinementInfo, Code: ConfinementCodeNoServerToken,
			Message: "No server token (HIBOU_FORGE_N_TOKEN): Hibou cannot write to this forge.",
		}}, nil
	}
	var user struct {
		Login string `json:"login"`
	}
	if err := f.doJSON(ctx, http.MethodGet, "/api/v1/user", nil, &user); err != nil {
		return nil, fmt.Errorf("read the token's user: %w", err)
	}
	var findings []ConfinementFinding
	readOnly := 0
	for page := 1; page <= maxConfinementRepositories/50; page++ {
		var repos []struct {
			FullName      string `json:"full_name"`
			Name          string `json:"name"`
			DefaultBranch string `json:"default_branch"`
			Owner         struct {
				Login string `json:"login"`
			} `json:"owner"`
			Permissions struct {
				Admin bool `json:"admin"`
				Push  bool `json:"push"`
			} `json:"permissions"`
		}
		if err := f.doJSON(ctx, http.MethodGet, "/api/v1/user/repos?limit=50&page="+strconv.Itoa(page), nil, &repos); err != nil {
			return findings, fmt.Errorf("list the token's repositories: %w", err)
		}
		for _, repo := range repos {
			if err := ctx.Err(); err != nil {
				return findings, err
			}
			if !repo.Permissions.Push {
				readOnly++
				continue
			}
			repoFindings := f.checkRepositoryConfinement(ctx, user.Login, repo.Owner.Login, repo.Name, repo.FullName, repo.DefaultBranch)
			if repo.Permissions.Admin {
				repoFindings = withAdminFinding(repoFindings, ConfinementFinding{
					Repository: repo.FullName, Severity: ConfinementError, Code: ConfinementCodeAdmin,
					Message: "The token's user " + user.Login + " is an admin of this repository (or of the site), so it can change or delete the branch protection rules. Use a dedicated user with Write access only.",
				})
			}
			findings = append(findings, repoFindings...)
		}
		if len(repos) < 50 {
			break
		}
	}
	if readOnly > 0 {
		findings = append(findings, ConfinementFinding{
			Severity: ConfinementOK, Code: ConfinementCodeNoWrite,
			Message: fmt.Sprintf("The token cannot push to %d repositories it reads.", readOnly),
		})
	}
	return findings, nil
}

type forgejoBranchProtection struct {
	RuleName              string   `json:"rule_name"`
	BranchName            string   `json:"branch_name"`
	EnablePush            bool     `json:"enable_push"`
	EnablePushWhitelist   bool     `json:"enable_push_whitelist"`
	PushWhitelistUsers    []string `json:"push_whitelist_usernames"`
	PushWhitelistTeams    []string `json:"push_whitelist_teams"`
	PushWhitelistDeployKs bool     `json:"push_whitelist_deploy_keys"`
	Priority              int64    `json:"priority"`
}

func (rule forgejoBranchProtection) pattern() string {
	if rule.RuleName != "" {
		return rule.RuleName
	}
	return rule.BranchName
}

func (rule forgejoBranchProtection) isPlainName() bool {
	return !strings.ContainsAny(rule.pattern(), "*?[{")
}

// pushVerdict says whether the token's user may push to a branch name.
type pushVerdict int

const (
	pushAllowed pushVerdict = iota
	pushBlocked
	pushUnknown // a team allowlist: membership is not visible here
)

func (f *Forgejo) checkRepositoryConfinement(ctx context.Context, login, owner, name, full, defaultBranch string) []ConfinementFinding {
	if full == "" {
		full = owner + "/" + name
	}
	finding := func(severity ConfinementSeverity, code, message string) ConfinementFinding {
		return ConfinementFinding{Repository: full, Severity: severity, Code: code, Message: message}
	}
	var findings []ConfinementFinding

	// Existing branches: the branch API says, for the token's own user,
	// whether it may push. Any token can read it, including the
	// repository-specific tokens of Forgejo 15+.
	branches, err := f.listBranchPushRights(ctx, owner, name)
	if err != nil {
		return []ConfinementFinding{finding(ConfinementInfo, ConfinementCodeUnverifiable, "Could not read the branches: "+err.Error())}
	}
	var pushable []string
	for _, branch := range branches {
		inside := strings.HasPrefix(branch.Name, WriteBranchPrefix)
		switch {
		case branch.Name == defaultBranch && branch.UserCanPush:
			findings = append(findings, finding(ConfinementError, ConfinementCodeDefaultBranch,
				"The token can push to the default branch "+branch.Name+" directly: protect it and keep the token's user out of its push allowlist."))
		case !inside && branch.UserCanPush && branch.Name != defaultBranch:
			pushable = append(pushable, branch.Name)
		case inside && !branch.UserCanPush:
			findings = append(findings, finding(ConfinementWarning, ConfinementCodeNamespaceBlocked,
				"The token cannot push to "+branch.Name+": a protection rule covers hibou/* branches, so onboarding and fix pull requests will fail."))
		}
	}
	if len(pushable) > 0 {
		shown := pushable
		if len(shown) > 5 {
			shown = shown[:5]
		}
		findings = append(findings, finding(ConfinementError, ConfinementCodeUnrestricted,
			fmt.Sprintf("The token can push to %d branches other than hibou/* (%s): protect them with a \"**\" rule limited to maintainers, after a \"hibou/**\" rule allowing the token (docs/DEPLOYMENT.md).", len(pushable), strings.Join(shown, ", "))))
	}

	// Branches that do not exist yet: only the protection rules say whether
	// the token could create one. Reading them needs repository admin, which
	// a repository-specific token never has.
	rules, readable := f.branchProtections(ctx, owner, name)
	// The worst of the two probes: allowed, else unknown, else blocked.
	verdict := pushBlocked
	for _, probe := range []string{confinementProbeOutside, confinementProbeOutsideNested} {
		switch forgejoPushVerdict(rules, login, probe) {
		case pushAllowed:
			verdict = pushAllowed
		case pushUnknown:
			if verdict == pushBlocked {
				verdict = pushUnknown
			}
		case pushBlocked:
		}
	}
	switch {
	case !readable:
		findings = append(findings, finding(ConfinementInfo, ConfinementCodeUnverifiable,
			"Whether the token can create new branches other than hibou/* cannot be checked: reading branch protection rules needs repository admin."))
	case verdict == pushAllowed && len(pushable) == 0:
		findings = append(findings, finding(ConfinementError, ConfinementCodeUnrestricted,
			"The token can create branches other than hibou/*: no protection rule covers them. Add a \"**\" rule limited to maintainers, after a \"hibou/**\" rule allowing the token."))
	case verdict == pushUnknown:
		findings = append(findings, finding(ConfinementInfo, ConfinementCodeUnverifiable,
			"New branches other than hibou/* are protected by a team allowlist; whether the token's user is in the team is not visible."))
	}

	if !hasSeverity(findings, ConfinementError, ConfinementWarning) && !hasCode(findings, ConfinementCodeUnverifiable) {
		findings = append(findings, finding(ConfinementOK, ConfinementCodeNoWrite,
			"Confined: the token can push only hibou/* branches."))
	}
	return findings
}

type forgejoBranchPushRight struct {
	Name        string `json:"name"`
	UserCanPush bool   `json:"user_can_push"`
}

// listBranchPushRights lists a repository's branches with the token user's
// push right on each.
func (f *Forgejo) listBranchPushRights(ctx context.Context, owner, name string) ([]forgejoBranchPushRight, error) {
	var all []forgejoBranchPushRight
	for page := 1; page <= 20; page++ {
		var branches []forgejoBranchPushRight
		requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/branches?limit=50&page=%d", url.PathEscape(owner), url.PathEscape(name), page)
		if err := f.doJSON(ctx, http.MethodGet, requestPath, nil, &branches); err != nil {
			return nil, err
		}
		all = append(all, branches...)
		if len(branches) < 50 {
			break
		}
	}
	return all, nil
}

// branchProtections reads the protection rules, when the token may.
func (f *Forgejo) branchProtections(ctx context.Context, owner, name string) ([]forgejoBranchProtection, bool) {
	requestPath := fmt.Sprintf("/api/v1/repos/%s/%s/branch_protections", url.PathEscape(owner), url.PathEscape(name))
	request, err := f.newRequest(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, false
	}
	var rules []forgejoBranchProtection
	if _, err := f.doWithStatus(request, &rules); err != nil {
		return nil, false
	}
	return rules, true
}

// forgejoPushVerdict applies the first protection rule matching the branch,
// as Forgejo does: rules naming a branch exactly first, then by priority,
// then in the order the API lists them.
func forgejoPushVerdict(rules []forgejoBranchProtection, login, branch string) pushVerdict {
	ordered := slices.Clone(rules)
	slices.SortStableFunc(ordered, func(a, b forgejoBranchProtection) int {
		if plainA, plainB := a.isPlainName(), b.isPlainName(); plainA != plainB {
			if plainA {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Priority, b.Priority)
	})
	for _, rule := range ordered {
		pattern := rule.pattern()
		if pattern == "" || !branchPatternMatches(pattern, branch) {
			continue
		}
		if !rule.EnablePush {
			return pushBlocked
		}
		if !rule.EnablePushWhitelist {
			return pushAllowed
		}
		for _, user := range rule.PushWhitelistUsers {
			if strings.EqualFold(user, login) {
				return pushAllowed
			}
		}
		if len(rule.PushWhitelistTeams) > 0 {
			return pushUnknown
		}
		return pushBlocked
	}
	return pushAllowed
}

// branchPatternMatches approximates Forgejo's branch globs ("/" separates,
// "*" stays within a segment, "**" crosses segments).
func branchPatternMatches(pattern, branch string) bool {
	if pattern == branch {
		return true
	}
	if prefix, _, ok := strings.Cut(pattern, "**"); ok {
		return strings.HasPrefix(branch, prefix)
	}
	matched, err := path.Match(pattern, branch)
	return err == nil && matched
}

func hasCode(findings []ConfinementFinding, code string) bool {
	for _, finding := range findings {
		if finding.Code == code {
			return true
		}
	}
	return false
}

// CheckConfinement implements ConfinementChecker for GitLab: Hibou's GitLab
// provider holds no server token (only OAuth for sign-in), so it cannot
// write.
func (g *GitLab) CheckConfinement(context.Context) ([]ConfinementFinding, error) {
	return []ConfinementFinding{{
		Severity: ConfinementInfo, Code: ConfinementCodeNoServerToken,
		Message: "Hibou holds no GitLab server token (sign-in only): it cannot write to this forge.",
	}}, nil
}
