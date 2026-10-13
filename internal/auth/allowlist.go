package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/hibouhq/hibou/internal/forge"
	"github.com/hibouhq/hibou/internal/store"
)

// The sign-in allowlist also governs requests made with an existing session
// or a user's API key: an account signed up before the allowlist existed, or
// one that left every allowed org, must not keep working through a token.
//
// AllowedUsers entries are either a forge login ("octocat") or an immutable
// "provider:id" ("github:583231"). Logins are renamable — a renamed account's
// old login can be registered by someone else — so the id form is the one to
// use; a login entry is matched against the login seen at the user's last
// sign-in. AllowedOrgs membership is re-asked of the forge (App installation
// token) once allowlistRecheck has passed since it was last confirmed.
const (
	// allowlistRecheck is how long an org-membership confirmation stands.
	allowlistRecheck = 24 * time.Hour
	// allowlistGrace keeps a user in while the forge cannot answer (API
	// errors, account not installed): a sign-in within the grace period is
	// still trusted, after that the user must sign in again.
	allowlistGrace = 7 * 24 * time.Hour
	// allowedCacheTTL bounds how stale a per-process verdict can be.
	allowedCacheTTL = 5 * time.Minute
)

type allowedVerdict struct {
	allowed bool
	until   time.Time
}

type allowlistCache struct {
	mu        sync.Mutex
	verdicts  map[uuid.UUID]allowedVerdict
	installed map[string]installedAccounts
}

type installedAccounts struct {
	logins map[string]bool
	until  time.Time
}

// Restricted reports whether a sign-in allowlist is configured.
func (m *Manager) Restricted() bool {
	return m != nil && (len(m.cfg.AllowedUsers) > 0 || len(m.cfg.AllowedOrgs) > 0)
}

// UserAllowed reports whether the sign-in allowlist still admits user. Always
// true without an allowlist. Cheap on the hot path: a per-process verdict
// cache, and forge calls at most once per allowlistRecheck per user.
func (m *Manager) UserAllowed(ctx context.Context, user *store.User) bool {
	if !m.Restricted() {
		return true
	}
	if user == nil {
		return false
	}
	now := time.Now()
	m.allow.mu.Lock()
	if verdict, ok := m.allow.verdicts[user.ID]; ok && now.Before(verdict.until) {
		m.allow.mu.Unlock()
		return verdict.allowed
	}
	m.allow.mu.Unlock()

	allowed := m.evaluateAllowlist(ctx, user, now)
	m.allow.mu.Lock()
	if m.allow.verdicts == nil {
		m.allow.verdicts = map[uuid.UUID]allowedVerdict{}
	}
	m.allow.verdicts[user.ID] = allowedVerdict{allowed: allowed, until: now.Add(allowedCacheTTL)}
	m.allow.mu.Unlock()
	return allowed
}

// forgetAllowed drops a cached verdict (sign-in just re-evaluated the user).
func (m *Manager) forgetAllowed(userID uuid.UUID) {
	m.allow.mu.Lock()
	delete(m.allow.verdicts, userID)
	m.allow.mu.Unlock()
}

func (m *Manager) evaluateAllowlist(ctx context.Context, user *store.User, now time.Time) bool {
	if allowedUserEntry(m.cfg.AllowedUsers, user.Provider, user.ProviderID, user.ForgeLogin) {
		return true
	}
	if len(m.cfg.AllowedOrgs) == 0 {
		return false
	}
	last := user.SignInAllowedAt
	if last != nil && now.Sub(*last) < allowlistRecheck {
		return true
	}
	withinGrace := last != nil && now.Sub(*last) < allowlistGrace

	provider := m.cfg.Providers[user.Provider]
	checker, ok := provider.(orgMembershipChecker)
	login := strings.TrimSpace(user.ForgeLogin)
	if !ok || login == "" {
		return withinGrace
	}
	definitive := true
	for _, org := range m.cfg.AllowedOrgs {
		// Without an installation on org the forge would answer with the
		// user's (absent) token: "not a member" would mean nothing.
		if !m.accountInstalled(ctx, user.Provider, provider, org) {
			definitive = false
			continue
		}
		member, err := checker.IsOrgMember(ctx, nil, login, org)
		if err != nil {
			definitive = false
			m.cfg.Log.Warn().Err(err).Str("org", org).Str("user_id", user.ID.String()).Msg("sign-in allowlist: org membership re-check failed")
			continue
		}
		if member {
			m.recordAllowed(ctx, user, &now)
			return true
		}
	}
	if definitive {
		// Every allowed org answered "not a member": the forge's (false, nil)
		// is a 404 to the installation token's request. A token that could
		// not be minted, a 302 or any other status is an error above and
		// keeps the grace window instead.
		m.recordAllowed(ctx, user, nil)
		return false
	}
	return withinGrace
}

func (m *Manager) recordAllowed(ctx context.Context, user *store.User, at *time.Time) {
	if m.queries == nil {
		return
	}
	if err := m.queries.SetUserSignInAllowedAt(ctx, user.ID, at); err != nil {
		m.cfg.Log.Warn().Err(err).Str("user_id", user.ID.String()).Msg("sign-in allowlist: failed to record the membership check")
	}
}

// accountInstalled reports whether the forge's App is installed on account,
// cached per provider for allowlistRecheck.
func (m *Manager) accountInstalled(ctx context.Context, providerID string, provider forge.Provider, account string) bool {
	if provider == nil {
		return false
	}
	now := time.Now()
	m.allow.mu.Lock()
	cached, ok := m.allow.installed[providerID]
	m.allow.mu.Unlock()
	if !ok || now.After(cached.until) {
		installations, err := provider.Installations(ctx)
		if err != nil {
			m.cfg.Log.Warn().Err(err).Str("provider", providerID).Msg("sign-in allowlist: failed to list installations")
			return false
		}
		cached = installedAccounts{logins: map[string]bool{}, until: now.Add(allowlistRecheck)}
		for _, installation := range installations {
			cached.logins[strings.ToLower(strings.TrimSpace(installation.AccountName))] = true
		}
		m.allow.mu.Lock()
		if m.allow.installed == nil {
			m.allow.installed = map[string]installedAccounts{}
		}
		m.allow.installed[providerID] = cached
		m.allow.mu.Unlock()
	}
	return cached.logins[strings.ToLower(strings.TrimSpace(account))]
}

// allowedUserEntry matches the AllowedUsers list: "provider:id" against the
// immutable account id, anything else against the login.
func allowedUserEntry(entries []string, provider, providerUserID, login string) bool {
	identity := strings.ToLower(strings.TrimSpace(provider)) + ":" + strings.ToLower(strings.TrimSpace(providerUserID))
	login = strings.TrimSpace(login)
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, ":") {
			if strings.TrimSpace(providerUserID) != "" && strings.EqualFold(entry, identity) {
				return true
			}
			continue
		}
		if login != "" && strings.EqualFold(entry, login) {
			return true
		}
	}
	return false
}

// accountLogin asks the forge for the token user's login; empty when the
// forge cannot name it.
func accountLogin(ctx context.Context, provider forge.Provider, token *oauth2.Token) (string, bool, error) {
	loginer, ok := provider.(accountLoginer)
	if !ok {
		return "", false, nil
	}
	login, err := loginer.AccountLogin(ctx, token)
	return strings.TrimSpace(login), true, err
}
