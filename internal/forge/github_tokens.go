package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Installation tokens are minted per operation (ADR-052 §1): for the one
// repository a call acts on, with only the permissions it needs, capped by
// the forge's tier. A bug that acts on the wrong repository, or writes where
// it meant to read, holds a token that cannot.

// Tier is the most a forge's tokens may ask for (ADR-052 §2).
type Tier string

const (
	// TierUnset keeps the installation's own permissions as the cap. It is
	// what existing configurations get until they choose a tier.
	TierUnset   Tier = ""
	TierRead    Tier = "read"
	TierReport  Tier = "report"
	TierPropose Tier = "propose"
)

// ParseTier validates a configured tier.
func ParseTier(value string) (Tier, error) {
	switch tier := Tier(strings.ToLower(strings.TrimSpace(value))); tier {
	case TierUnset, TierRead, TierReport, TierPropose:
		return tier, nil
	default:
		return "", fmt.Errorf("forge tier %q: want read, report or propose", value)
	}
}

// tierPermissions is each tier's cap, in GitHub App permission names.
var tierPermissions = map[Tier]map[string]string{
	TierRead: {
		"contents": "read", "metadata": "read", "members": "read",
	},
	TierReport: {
		"contents": "read", "metadata": "read", "members": "read",
		"checks": "write", "statuses": "write", "pull_requests": "write",
	},
	TierPropose: {
		"contents": "write", "metadata": "read", "members": "read",
		"checks": "write", "statuses": "write", "pull_requests": "write",
	},
}

// ErrTierForbids is an operation the forge's tier does not allow.
var ErrTierForbids = errors.New("forge: the configured tier does not allow this operation")

// requireDeclaredScopes refuses repository calls whose permissions
// scopeForRequest does not know. The package's tests turn it on (TestMain),
// so a new GitHub call without declared needs fails there instead of
// silently getting the tier's cap (ADR-052 §1).
var requireDeclaredScopes bool

// ErrUndeclaredScope is a repository call with no declared permissions,
// refused only while requireDeclaredScopes is on.
var ErrUndeclaredScope = errors.New("forge: GitHub call without declared token permissions; add it to scopeForRequest")

// ErrInstallationLacksPermission is an operation the App installation was
// not granted; the message names the permission to add.
var ErrInstallationLacksPermission = errors.New("forge: the App installation lacks a permission this operation needs")

// TokenScope is what one operation needs: the repository it acts on (empty
// for account-level calls) and its permissions. Nil Permissions means "not
// declared": the token gets the tier's cap for that repository.
type TokenScope struct {
	Repo        string
	Permissions map[string]string
}

func permissionRank(level string) int {
	switch level {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	default:
		return 0
	}
}

// resolveTokenPermissions turns an operation's needs into the permissions to
// request: refused when the tier forbids a need or the installation lacks
// it; an undeclared need gets the tier's cap, trimmed to what the
// installation holds (asking for a missing permission fails the request).
func resolveTokenPermissions(tier Tier, installed map[string]string, needs map[string]string) (map[string]string, error) {
	tierCap := tierPermissions[tier]
	if needs == nil {
		if tierCap == nil {
			return nil, nil // unset tier, undeclared need: the installation's own permissions
		}
		out := map[string]string{}
		for name, level := range tierCap {
			if have := installed[name]; permissionRank(have) > 0 {
				if permissionRank(have) < permissionRank(level) {
					level = have
				}
				out[name] = level
			}
		}
		return out, nil
	}
	out := make(map[string]string, len(needs))
	for name, level := range needs {
		if tierCap != nil && permissionRank(tierCap[name]) < permissionRank(level) {
			return nil, fmt.Errorf("%w: %s: %s needs tier %s", ErrTierForbids, name, level, minimumTier(name, level))
		}
		if installed != nil && permissionRank(installed[name]) < permissionRank(level) {
			return nil, fmt.Errorf("%w: %s: %s (the installation has %q)", ErrInstallationLacksPermission, name, level, installed[name])
		}
		out[name] = level
	}
	return out, nil
}

func minimumTier(name, level string) Tier {
	for _, tier := range []Tier{TierRead, TierReport, TierPropose} {
		if permissionRank(tierPermissions[tier][name]) >= permissionRank(level) {
			return tier
		}
	}
	return TierPropose
}

// scopeForRequest derives a REST call's needs from its method and path:
// /repos/{owner}/{repo}/{resource}/... names the repository and the
// resource. Paths it does not recognize get the repository and no declared
// permissions (the tier's cap): narrowing by repository still applies.
func scopeForRequest(request *http.Request) TokenScope {
	if request == nil || request.URL == nil {
		return TokenScope{}
	}
	path := request.URL.EscapedPath()
	rest, ok := strings.CutPrefix(path, "/repos/")
	if !ok {
		return TokenScope{}
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 {
		return TokenScope{}
	}
	repo, err := url.PathUnescape(parts[1])
	if err != nil || repo == "" {
		return TokenScope{}
	}
	scope := TokenScope{Repo: repo}
	level := "read"
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		level = "write"
	}
	resource := ""
	if len(parts) > 2 {
		resource = parts[2]
	}
	switch {
	case resource == "":
		scope.Permissions = map[string]string{"metadata": "read"}
	case resource == "commits" && len(parts) > 4 && (parts[4] == "status" || parts[4] == "statuses"):
		scope.Permissions = map[string]string{"statuses": level}
	case resource == "commits" && len(parts) > 4 && (parts[4] == "check-runs" || parts[4] == "check-suites"):
		scope.Permissions = map[string]string{"checks": level}
	case resource == "contents" || resource == "git" || resource == "branches" || resource == "commits" ||
		resource == "compare" || resource == "tarball" || resource == "zipball" || resource == "readme":
		scope.Permissions = map[string]string{"contents": level}
	case resource == "pulls" || resource == "issues":
		// Hibou uses the issues API only for pull request comments.
		scope.Permissions = map[string]string{"pull_requests": level}
	case resource == "collaborators":
		// The collaborator permission lookup needs only Metadata.
		scope.Permissions = map[string]string{"metadata": "read"}
	case resource == "statuses":
		scope.Permissions = map[string]string{"statuses": level}
	case resource == "check-runs" || resource == "check-suites":
		scope.Permissions = map[string]string{"checks": level}
	}
	return scope
}

func tokenCacheKey(owner string, scope TokenScope, permissions map[string]string) string {
	names := make([]string, 0, len(permissions))
	for name, level := range permissions {
		names = append(names, name+"="+level)
	}
	sort.Strings(names)
	return strings.ToLower(strings.TrimSpace(owner)) + "|" + scope.Repo + "|" + strings.Join(names, ",")
}

// scopedInstallationToken returns a token for the owner's installation,
// limited to scope, minting one when the cached token is absent or near
// expiry.
func (g *GitHub) scopedInstallationToken(ctx context.Context, owner string, scope TokenScope) (string, error) {
	account := strings.ToLower(strings.TrimSpace(owner))
	if account == "" {
		return "", errors.New("owner is required for an installation token")
	}
	if err := checkInstallationOwner(ctx, account); err != nil {
		return "", err
	}
	installation, err := g.installationForOwner(ctx, owner)
	if err != nil {
		return "", err
	}
	if requireDeclaredScopes && scope.Repo != "" && scope.Permissions == nil {
		return "", ErrUndeclaredScope
	}
	permissions, err := resolveTokenPermissions(g.tier, installation.Permissions, scope.Permissions)
	if err != nil {
		return "", err
	}
	key := tokenCacheKey(account, scope, permissions)

	g.tokenMu.Lock()
	cached, ok := g.ownerTokens[key]
	g.tokenMu.Unlock()
	if ok && time.Until(cached.expiresAt) > 2*time.Minute {
		return cached.value, nil
	}

	request := installationTokenRequest{Permissions: permissions}
	if scope.Repo != "" {
		request.Repositories = []string{scope.Repo}
	}
	token, err := g.createInstallationTokenWith(ctx, installation.ID, &request)
	if err != nil {
		return "", err
	}
	g.tokenMu.Lock()
	g.ownerTokens[key] = ownerToken{value: token.Token, expiresAt: time.Now().Add(55 * time.Minute)}
	g.tokenMu.Unlock()
	return token.Token, nil
}

// installationTokenRequest is the body of POST
// /app/installations/{id}/access_tokens: both fields narrow the token.
type installationTokenRequest struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

// installationCacheTTL bounds how long an installation's permissions are
// trusted before being read again: a permission granted or removed on
// GitHub takes effect within it.
const installationCacheTTL = 5 * time.Minute

type cachedInstallation struct {
	installation githubInstallation
	expiresAt    time.Time
}

// installationForOwner finds the App's installation on an account, from a
// short cache: listing installations on every token would double the App
// API traffic.
func (g *GitHub) installationForOwner(ctx context.Context, owner string) (githubInstallation, error) {
	account := strings.ToLower(strings.TrimSpace(owner))
	g.tokenMu.Lock()
	cached, ok := g.ownerInstallations[account]
	g.tokenMu.Unlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return cached.installation, nil
	}
	installations, err := g.listInstallations(ctx)
	if err != nil {
		return githubInstallation{}, err
	}
	for _, installation := range installations {
		if strings.EqualFold(strings.TrimSpace(installation.Account.Login), account) {
			g.tokenMu.Lock()
			if g.ownerInstallations == nil {
				g.ownerInstallations = map[string]cachedInstallation{}
			}
			g.ownerInstallations[account] = cachedInstallation{installation: installation, expiresAt: time.Now().Add(installationCacheTTL)}
			g.tokenMu.Unlock()
			return installation, nil
		}
	}
	return githubInstallation{}, fmt.Errorf("no GitHub App installation found for owner %q", owner)
}
