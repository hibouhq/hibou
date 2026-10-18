package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// maxConfinementRepositories bounds one check run per installation.
const maxConfinementRepositories = 1000

// CheckConfinement implements ConfinementChecker for GitHub App mode. Per
// installation: without Contents: write the App cannot write code anywhere.
// With it, for every repository the installation reaches, the forge is
// asked which rules apply to a branch outside hibou/*, to the default branch
// and to a hibou/* branch, and whether the App itself may bypass them
// (current_user_can_bypass, answered for the caller). Everything here needs
// only Metadata: read.
func (g *GitHub) CheckConfinement(ctx context.Context) ([]ConfinementFinding, error) {
	if !g.isAppMode() {
		return []ConfinementFinding{{
			Severity: ConfinementInfo, Code: ConfinementCodeNoServerToken,
			Message: "No GitHub App credentials: Hibou holds no installation token here and cannot write.",
		}}, nil
	}
	installations, err := g.listInstallations(ctx)
	if err != nil {
		return nil, err
	}
	var findings []ConfinementFinding
	for _, installation := range installations {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		account := installation.Account.Login
		if installation.SuspendedAt != nil {
			continue
		}
		if permissionRank(installation.Permissions["contents"]) < permissionRank("write") {
			findings = append(findings, ConfinementFinding{
				Repository: account, Severity: ConfinementOK, Code: ConfinementCodeNoWrite,
				Message: "The App cannot write repository contents on " + account + ": nothing to confine.",
			})
			continue
		}
		canAdminister := permissionRank(installation.Permissions["administration"]) >= permissionRank("write")
		if canAdminister {
			findings = append(findings, ConfinementFinding{
				Repository: account, Severity: ConfinementError, Code: ConfinementCodeAdmin,
				Message: "The App holds Administration: write on " + account + ", so it can change or delete the rulesets that confine it. Remove that permission from the App.",
			})
		}
		token, err := g.createInstallationTokenWith(ctx, installation.ID, &installationTokenRequest{Permissions: map[string]string{"metadata": "read"}})
		if err != nil {
			findings = append(findings, ConfinementFinding{
				Repository: account, Severity: ConfinementInfo, Code: ConfinementCodeUnverifiable,
				Message: "Could not mint a read token for " + account + ": " + err.Error(),
			})
			continue
		}
		repositories, err := g.listInstallationRepositoriesWith(ctx, token.Token)
		if err != nil {
			findings = append(findings, ConfinementFinding{
				Repository: account, Severity: ConfinementInfo, Code: ConfinementCodeUnverifiable,
				Message: "Could not list the repositories the App reaches on " + account + ": " + err.Error(),
			})
			continue
		}
		if len(repositories) > maxConfinementRepositories {
			repositories = repositories[:maxConfinementRepositories]
		}
		bypass := map[int64]githubRulesetBypass{}
		for _, repository := range repositories {
			if err := ctx.Err(); err != nil {
				return findings, err
			}
			if repository.Archived {
				continue // read-only on GitHub: nothing to confine
			}
			repoFindings := g.checkRepositoryConfinement(ctx, token.Token, repository, bypass)
			if canAdminister {
				repoFindings = withoutConfined(repoFindings)
			}
			findings = append(findings, repoFindings...)
		}
	}
	return findings, nil
}

type githubBranchRule struct {
	Type      string `json:"type"`
	RulesetID int64  `json:"ruleset_id"`
}

type githubRulesetBypass struct {
	Name   string
	Bypass string
	Err    error
}

func (g *GitHub) checkRepositoryConfinement(ctx context.Context, token string, repository Repository, bypass map[int64]githubRulesetBypass) []ConfinementFinding {
	owner, name := repository.Owner, repository.Name
	full := repository.FullName
	if full == "" {
		full = owner + "/" + name
	}
	if owner == "" || name == "" {
		if o, n, ok := strings.Cut(full, "/"); ok {
			owner, name = o, n
		}
	}
	finding := func(severity ConfinementSeverity, code, message, ruleset string) ConfinementFinding {
		return ConfinementFinding{Repository: full, Severity: severity, Code: code, Message: message, Ruleset: ruleset}
	}
	lookup := func(id int64) githubRulesetBypass {
		if cached, ok := bypass[id]; ok {
			return cached
		}
		result := g.rulesetBypass(ctx, token, owner, name, id)
		bypass[id] = result
		return result
	}
	// Bypass findings for the rulesets behind the given rules.
	bypassFindings := func(rules []githubBranchRule, types map[string]bool, scope string) (out []ConfinementFinding, bound bool) {
		seen := map[int64]bool{}
		for _, rule := range rules {
			if !types[rule.Type] || seen[rule.RulesetID] {
				continue
			}
			seen[rule.RulesetID] = true
			result := lookup(rule.RulesetID)
			switch {
			case result.Err != nil:
				out = append(out, finding(ConfinementInfo, ConfinementCodeUnverifiable, "Could not read ruleset "+strconv.FormatInt(rule.RulesetID, 10)+": "+result.Err.Error(), result.Name))
			case result.Bypass == "always" || result.Bypass == "exempt":
				out = append(out, finding(ConfinementError, ConfinementCodeBypass, "The App can bypass ruleset \""+result.Name+"\" ("+result.Bypass+"), so it is not bound on "+scope+". Remove it from the ruleset's bypass list.", result.Name))
			case result.Bypass == "pull_requests_only":
				out = append(out, finding(ConfinementWarning, ConfinementCodeBypassPR, "The App can bypass ruleset \""+result.Name+"\" through pull requests on "+scope+".", result.Name))
				bound = true
			default:
				bound = true
			}
		}
		return out, bound
	}

	var findings []ConfinementFinding
	restrict := map[string]bool{"creation": true, "update": true}

	outside, err := g.branchRules(ctx, token, owner, name, confinementProbeOutside)
	if err != nil {
		return []ConfinementFinding{finding(ConfinementInfo, ConfinementCodeUnverifiable, "Could not read the branch rules: "+err.Error(), "")}
	}
	if !hasRuleType(outside, restrict) {
		findings = append(findings, finding(ConfinementError, ConfinementCodeUnrestricted,
			"The App can create and push branches other than hibou/*: no ruleset restricts them. Add the hibou-confine ruleset (docs/DEPLOYMENT.md).", ""))
	} else {
		extra, _ := bypassFindings(outside, restrict, "branches other than hibou/*")
		findings = append(findings, extra...)
	}

	if branch := strings.TrimSpace(repository.DefaultBranch); branch != "" {
		rules, err := g.branchRules(ctx, token, owner, name, branch)
		switch {
		case err != nil:
			findings = append(findings, finding(ConfinementInfo, ConfinementCodeUnverifiable, "Could not read the default branch's rules: "+err.Error(), ""))
		case !hasRuleType(rules, map[string]bool{"pull_request": true}):
			if g.branchProtected(ctx, token, owner, name, branch) {
				findings = append(findings, finding(ConfinementInfo, ConfinementCodeClassic,
					"The default branch "+branch+" has a classic branch protection rule; Hibou cannot read who may push to it. Prefer a ruleset requiring pull requests.", ""))
			} else {
				findings = append(findings, finding(ConfinementError, ConfinementCodeDefaultBranch,
					"The App can push to the default branch "+branch+" directly: no rule requires a pull request.", ""))
			}
		default:
			extra, _ := bypassFindings(rules, map[string]bool{"pull_request": true, "update": true}, "the default branch")
			findings = append(findings, extra...)
		}
	}

	inside, err := g.branchRules(ctx, token, owner, name, confinementProbeInside)
	if err == nil && hasRuleType(inside, restrict) {
		if _, bound := bypassFindings(inside, restrict, "hibou/* branches"); bound {
			findings = append(findings, finding(ConfinementWarning, ConfinementCodeNamespaceBlocked,
				"A ruleset restricts hibou/* branches too: onboarding and fix pull requests will fail. Exclude refs/heads/hibou/** from it.", ""))
		}
	}

	if !hasSeverity(findings, ConfinementError, ConfinementWarning) {
		findings = append(findings, finding(ConfinementOK, ConfinementCodeNoWrite,
			"Confined: outside hibou/* the App's writes are restricted by rules it cannot bypass.", ""))
	}
	return findings
}

func hasRuleType(rules []githubBranchRule, types map[string]bool) bool {
	for _, rule := range rules {
		if types[rule.Type] {
			return true
		}
	}
	return false
}

func hasSeverity(findings []ConfinementFinding, severities ...ConfinementSeverity) bool {
	for _, finding := range findings {
		for _, severity := range severities {
			if finding.Severity == severity {
				return true
			}
		}
	}
	return false
}

// branchRules lists the active rules that would apply to a branch name, from
// repository and organization rulesets. The branch need not exist.
func (g *GitHub) branchRules(ctx context.Context, token, owner, repo, branch string) ([]githubBranchRule, error) {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/rules/branches/" + url.PathEscape(branch) + "?per_page=100"
	request, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	var rules []githubBranchRule
	if err := g.do(request, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

// rulesetBypass reads a ruleset's name and whether the caller (the App) may
// bypass it.
func (g *GitHub) rulesetBypass(ctx context.Context, token, owner, repo string, id int64) githubRulesetBypass {
	path := fmt.Sprintf("/repos/%s/%s/rulesets/%d?includes_parents=true", url.PathEscape(owner), url.PathEscape(repo), id)
	request, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return githubRulesetBypass{Err: err}
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	var payload struct {
		Name                 string `json:"name"`
		CurrentUserCanBypass string `json:"current_user_can_bypass"`
	}
	if err := g.do(request, &payload); err != nil {
		return githubRulesetBypass{Name: strconv.FormatInt(id, 10), Err: err}
	}
	return githubRulesetBypass{Name: payload.Name, Bypass: payload.CurrentUserCanBypass}
}

// branchProtected reports a classic branch protection rule on an existing
// branch (the branch endpoint's "protected" flag, readable with Metadata).
func (g *GitHub) branchProtected(ctx context.Context, token, owner, repo, branch string) bool {
	path := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/branches/" + url.PathEscape(branch)
	request, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	var payload struct {
		Protected bool `json:"protected"`
	}
	if err := g.do(request, &payload); err != nil {
		return false
	}
	return payload.Protected
}

// listInstallationRepositoriesWith lists the installation's repositories
// with an already-minted token.
func (g *GitHub) listInstallationRepositoriesWith(ctx context.Context, token string) ([]Repository, error) {
	var repositories []Repository
	path := "/installation/repositories?per_page=100"
	for path != "" {
		request, err := g.newRequest(ctx, http.MethodGet, path, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Authorization", githubBearerPrefix+token)
		var payload struct {
			Repositories []githubRepository `json:"repositories"`
		}
		response, err := g.doWithResponse(request, &payload)
		if err != nil {
			return nil, fmt.Errorf("list installation repositories: %w", err)
		}
		for _, repo := range payload.Repositories {
			repositories = append(repositories, repo.toRepository())
		}
		path = nextPagePath(response)
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
	}
	return repositories, nil
}
