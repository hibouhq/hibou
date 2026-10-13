package forge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrNoInstallation means the App is not installed on the account asked
// about, so nothing can be verified with its installation token.
var ErrNoInstallation = errors.New("github app is not installed on the account")

// ErrMembershipUnsupported means the account has no member list to ask
// (a personal account rather than an organization).
var ErrMembershipUnsupported = errors.New("account has no organization membership to verify")

// OrgMembershipVerifier answers questions about one installed account,
// always with the same installation token: a positive control asked after a
// negative answer then proves that very token can see the member list, not
// merely some token minted earlier.
//
// People are named by their immutable forge user id. The current login is
// resolved from it on every call: a login recorded at sign-in may since have
// been renamed (a 404 would remove someone still in the org) or re-registered
// by someone else (who would then answer for them).
type OrgMembershipVerifier interface {
	// AccountLogin is the account's current login, from the App API.
	AccountLogin() string
	// IsMember follows IsOrgMember's contract: (false, nil) only for a 404
	// to the membership request.
	IsMember(ctx context.Context, forgeUserID string) (bool, error)
	// RepoLevel is the permission forgeUserID holds on the account's
	// repository repo, as a GitHub level (admin, maintain, push, triage,
	// pull), or "" for none.
	RepoLevel(ctx context.Context, repo, forgeUserID string) (string, error)
}

// OrgMembershipVerifiers lists the App's installations once and returns a
// verifier per installed account, keyed by the immutable account id (never
// the login, which can be renamed and re-registered by someone else). A
// listing error is returned as is: callers must not read it as "installed
// nowhere".
func (g *GitHub) OrgMembershipVerifiers(ctx context.Context) (map[string]OrgMembershipVerifier, error) {
	if !g.isAppMode() {
		return nil, errors.New("org membership verification requires GitHub App credentials")
	}
	installations, err := g.listInstallations(ctx)
	if err != nil {
		return nil, err
	}
	verifiers := make(map[string]OrgMembershipVerifier, len(installations))
	for _, installation := range installations {
		if installation.Account.ID <= 0 || installation.ID <= 0 {
			continue
		}
		verifiers[strconv.FormatInt(installation.Account.ID, 10)] = &githubOrgVerifier{
			g:              g,
			installationID: installation.ID,
			accountLogin:   strings.TrimSpace(installation.Account.Login),
			accountType:    installation.Account.Type,
			suspended:      installation.SuspendedAt != nil,
		}
	}
	return verifiers, nil
}

type githubOrgVerifier struct {
	g              *GitHub
	installationID int64
	accountLogin   string
	accountType    string
	suspended      bool

	mu        sync.Mutex
	minted    bool
	token     string
	expiresAt time.Time
	mintErr   error
}

func (v *githubOrgVerifier) AccountLogin() string { return v.accountLogin }

func (v *githubOrgVerifier) IsMember(ctx context.Context, forgeUserID string) (bool, error) {
	if strings.EqualFold(v.accountType, "User") {
		return false, ErrMembershipUnsupported
	}
	token, err := v.installationToken(ctx)
	if err != nil {
		return false, err
	}
	login, err := v.g.loginForUserID(ctx, token, forgeUserID)
	if err != nil {
		return false, err
	}
	return v.g.orgMemberStatus(ctx, token, v.accountLogin, login)
}

func (v *githubOrgVerifier) RepoLevel(ctx context.Context, repo, forgeUserID string) (string, error) {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "", errors.New("repository permission check needs a repository")
	}
	token, err := v.installationToken(ctx)
	if err != nil {
		return "", err
	}
	login, err := v.g.loginForUserID(ctx, token, forgeUserID)
	if err != nil {
		return "", err
	}
	var payload struct {
		Permission string `json:"permission"`
		RoleName   string `json:"role_name"`
		User       struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	path := "/repos/" + url.PathEscape(v.accountLogin) + "/" + url.PathEscape(repo) + "/collaborators/" + url.PathEscape(login) + "/permission"
	request, err := v.g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	if _, err := v.g.doWithStatus(request, &payload); err != nil {
		return "", err
	}
	if payload.User.ID > 0 && strconv.FormatInt(payload.User.ID, 10) != strings.TrimSpace(forgeUserID) {
		return "", fmt.Errorf("github api %s: answered for another user", request.URL.Path)
	}
	return githubLevelForRole(payload.RoleName, payload.Permission), nil
}

// githubLevelForRole maps the permission endpoint's answer onto the levels
// ListUserAccess reports (and MapForgeRole reads).
func githubLevelForRole(roleName, permission string) string {
	switch strings.ToLower(strings.TrimSpace(roleName)) {
	case "admin":
		return "admin"
	case "maintain":
		return "maintain"
	case "write":
		return "push"
	case "triage":
		return "triage"
	case "read":
		return "pull"
	}
	switch strings.ToLower(strings.TrimSpace(permission)) {
	case "admin":
		return "admin"
	case "write":
		return "push"
	case "read":
		return "pull"
	default:
		return ""
	}
}

// loginForUserID resolves an immutable GitHub user id to its current login.
// An unknown id is an error, never "not a member": the account may simply be
// unreadable to this token.
func (g *GitHub) loginForUserID(ctx context.Context, bearer, forgeUserID string) (string, error) {
	forgeUserID = strings.TrimSpace(forgeUserID)
	if _, err := strconv.ParseInt(forgeUserID, 10, 64); err != nil || forgeUserID == "" {
		return "", fmt.Errorf("not a github user id: %q", forgeUserID)
	}
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	request, err := g.newRequest(ctx, http.MethodGet, "/user/"+url.PathEscape(forgeUserID), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", githubBearerPrefix+bearer)
	if _, err := g.doWithStatus(request, &user); err != nil {
		return "", fmt.Errorf("resolve github user %s: %w", forgeUserID, err)
	}
	if strconv.FormatInt(user.ID, 10) != forgeUserID || strings.TrimSpace(user.Login) == "" {
		return "", fmt.Errorf("resolve github user %s: answered for another user", forgeUserID)
	}
	return strings.TrimSpace(user.Login), nil
}

// installationToken mints one token per verifier and never a second: every
// answer a verifier gives comes from the same credential. Once that token
// nears expiry the verifier stops answering.
func (v *githubOrgVerifier) installationToken(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if !v.minted {
		v.minted = true
		if v.suspended {
			v.mintErr = fmt.Errorf("installation %d is suspended", v.installationID)
		} else if token, err := v.g.createInstallationToken(ctx, v.installationID); err != nil {
			v.mintErr = err
		} else if token.Token == "" {
			v.mintErr = fmt.Errorf("installation %d returned an empty token", v.installationID)
		} else {
			v.token = token.Token
			v.expiresAt = token.ExpiresAt
		}
	}
	if v.mintErr != nil {
		return "", v.mintErr
	}
	if !v.expiresAt.IsZero() && time.Until(v.expiresAt) < 2*time.Minute {
		return "", fmt.Errorf("installation %d token expired", v.installationID)
	}
	return v.token, nil
}

// orgMemberStatus asks GET /orgs/{org}/members/{login} with bearer. GitHub
// answers 204 (member), 404 (not a member) or, when the requester itself
// cannot see the member list, 302 to the public-members list. The redirect is
// not followed — its 404 would mean "not a public member" — and is an error.
func (g *GitHub) orgMemberStatus(ctx context.Context, bearer, org, login string) (bool, error) {
	if strings.TrimSpace(bearer) == "" {
		return false, errors.New("org membership check needs a token")
	}
	request, err := g.newRequest(ctx, http.MethodGet, "/orgs/"+url.PathEscape(org)+"/members/"+url.PathEscape(login), nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", githubBearerPrefix+bearer)
	response, err := g.noRedirectClient().Do(request)
	if err != nil {
		return false, fmt.Errorf("perform github request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	switch response.StatusCode {
	case http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	case http.StatusFound:
		return false, fmt.Errorf("github api %s: redirected to public members; the token cannot see %q's member list", request.URL.Path, org)
	default:
		return false, fmt.Errorf("github api %s: unexpected status %s", request.URL.Path, response.Status)
	}
}

// noRedirectClient is the configured client with redirects returned to the
// caller instead of followed.
func (g *GitHub) noRedirectClient() *http.Client {
	base := g.httpClient
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client
}

// IsAccountAdmin reports whether the forge user with immutable id userID
// administers the installed account with immutable id accountID, asked with
// that installation's token: a personal account is administered by itself
// only; an organization by an active member whose role is admin. It
// corroborates binding a legacy org to an account id: the login alone could
// belong to whoever re-registered it.
func (g *GitHub) IsAccountAdmin(ctx context.Context, accountID, userID string) (bool, error) {
	accountID, userID = strings.TrimSpace(accountID), strings.TrimSpace(userID)
	if accountID == "" || userID == "" {
		return false, errors.New("account admin check needs an account id and a user id")
	}
	verifiers, err := g.OrgMembershipVerifiers(ctx)
	if err != nil {
		return false, err
	}
	verifier, ok := verifiers[accountID].(*githubOrgVerifier)
	if !ok {
		return false, ErrNoInstallation
	}
	if strings.EqualFold(verifier.accountType, "User") {
		return accountID == userID, nil
	}
	token, err := verifier.installationToken(ctx)
	if err != nil {
		return false, err
	}

	// The membership API is keyed by login; resolve it from the id so a
	// renamed user is still found, then check the id again on the answer.
	login, err := g.loginForUserID(ctx, token, userID)
	if err != nil {
		return false, err
	}

	var membership struct {
		State string `json:"state"`
		Role  string `json:"role"`
		User  struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	path := "/orgs/" + url.PathEscape(verifier.accountLogin) + "/memberships/" + url.PathEscape(login)
	request, err := g.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Authorization", githubBearerPrefix+token)
	status, err := g.doWithStatus(request, &membership)
	if status == http.StatusNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return strings.EqualFold(membership.State, "active") &&
		strings.EqualFold(membership.Role, "admin") &&
		strconv.FormatInt(membership.User.ID, 10) == userID, nil
}
