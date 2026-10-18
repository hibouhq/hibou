package forge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func findingCodes(findings []ConfinementFinding, repository string) map[string]ConfinementSeverity {
	out := map[string]ConfinementSeverity{}
	for _, finding := range findings {
		if finding.Repository == repository {
			out[finding.Code] = finding.Severity
		}
	}
	return out
}

// githubConfinementServer fakes the App API: one installation, three
// repositories with different rules.
//   - acme/open: no ruleset at all.
//   - acme/confined: hibou-confine on other branches, a pull request rule on
//     main, nothing on hibou/*; the App cannot bypass.
//   - acme/bypass: same rules, but the App is on hibou-confine's bypass list,
//     and a ruleset also covers hibou/*.
func githubConfinementServer(t *testing.T, contents string) *httptest.Server {
	t.Helper()
	rules := map[string]string{
		"/repos/acme/open/rules/branches/" + confinementProbeOutside:     `[]`,
		"/repos/acme/open/rules/branches/main":                           `[]`,
		"/repos/acme/open/rules/branches/" + confinementProbeInside:      `[]`,
		"/repos/acme/confined/rules/branches/" + confinementProbeOutside: `[{"type":"creation","ruleset_id":1},{"type":"update","ruleset_id":1}]`,
		"/repos/acme/confined/rules/branches/main":                       `[{"type":"update","ruleset_id":1},{"type":"pull_request","ruleset_id":2}]`,
		"/repos/acme/confined/rules/branches/" + confinementProbeInside:  `[]`,
		"/repos/acme/bypass/rules/branches/" + confinementProbeOutside:   `[{"type":"creation","ruleset_id":3}]`,
		"/repos/acme/bypass/rules/branches/main":                         `[{"type":"pull_request","ruleset_id":2}]`,
		"/repos/acme/bypass/rules/branches/" + confinementProbeInside:    `[{"type":"update","ruleset_id":4}]`,
	}
	rulesets := map[string]string{
		"/repos/acme/confined/rulesets/1": `{"name":"hibou-confine","current_user_can_bypass":"never"}`,
		"/repos/acme/confined/rulesets/2": `{"name":"main-pr","current_user_can_bypass":"never"}`,
		"/repos/acme/bypass/rulesets/2":   `{"name":"main-pr","current_user_can_bypass":"never"}`,
		"/repos/acme/bypass/rulesets/3":   `{"name":"hibou-confine","current_user_can_bypass":"always"}`,
		"/repos/acme/bypass/rulesets/4":   `{"name":"everything","current_user_can_bypass":"never"}`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.ReplaceAll(r.URL.EscapedPath(), "%2F", "/")
		switch {
		case path == "/app/installations":
			_, _ = w.Write([]byte(`[{"id":7,"account":{"id":42,"login":"acme"},"permissions":{"contents":"` + contents + `","metadata":"read"}}]`))
		case path == "/app/installations/7/access_tokens":
			_, _ = w.Write([]byte(`{"token":"meta","expires_at":"2099-01-01T00:00:00Z"}`))
		case path == "/installation/repositories":
			_, _ = w.Write([]byte(`{"repositories":[
				{"name":"open","full_name":"acme/open","default_branch":"main","owner":{"login":"acme"}},
				{"name":"confined","full_name":"acme/confined","default_branch":"main","owner":{"login":"acme"}},
				{"name":"bypass","full_name":"acme/bypass","default_branch":"main","owner":{"login":"acme"}},
				{"name":"old","full_name":"acme/old","default_branch":"main","archived":true,"owner":{"login":"acme"}}]}`))
		case rules[path] != "":
			_, _ = w.Write([]byte(rules[path]))
		case rulesets[path] != "":
			if r.URL.Query().Get("includes_parents") != "true" {
				t.Errorf("ruleset read without includes_parents: %s", r.URL)
			}
			_, _ = w.Write([]byte(rulesets[path]))
		case path == "/repos/acme/open/branches/main":
			_, _ = w.Write([]byte(`{"name":"main","protected":false}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGitHubCheckConfinement(t *testing.T) {
	t.Parallel()

	server := githubConfinementServer(t, "write")
	g := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierPropose))
	findings, err := g.CheckConfinement(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	open := findingCodes(findings, "acme/open")
	if open[ConfinementCodeUnrestricted] != ConfinementError || open[ConfinementCodeDefaultBranch] != ConfinementError {
		t.Errorf("acme/open = %v, want unrestricted and default branch errors", open)
	}
	confined := findingCodes(findings, "acme/confined")
	if len(confined) != 1 || confined[ConfinementCodeNoWrite] != ConfinementOK {
		t.Errorf("acme/confined = %v, want only the confined OK", confined)
	}
	bypass := findingCodes(findings, "acme/bypass")
	if bypass[ConfinementCodeBypass] != ConfinementError || bypass[ConfinementCodeNamespaceBlocked] != ConfinementWarning {
		t.Errorf("acme/bypass = %v, want a bypass error and a blocked-namespace warning", bypass)
	}
	if _, ok := bypass[ConfinementCodeNoWrite]; ok {
		t.Errorf("acme/bypass reported confined: %v", bypass)
	}
	if len(findingCodes(findings, "acme/old")) != 0 {
		t.Error("an archived repository was checked")
	}
}

// An App with Administration: write can delete its rulesets: an account
// error, and no repository reported as confined.
func TestGitHubCheckConfinementAdministration(t *testing.T) {
	t.Parallel()

	server := githubConfinementServer(t, `write","administration":"write`)
	g := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierPropose))
	findings, err := g.CheckConfinement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if account := findingCodes(findings, "acme"); account[ConfinementCodeAdmin] != ConfinementError {
		t.Errorf("account findings = %v, want identity_is_admin", account)
	}
	if confined := findingCodes(findings, "acme/confined"); len(confined) != 0 {
		t.Errorf("acme/confined = %v, want no confined result", confined)
	}
}

// Without Contents: write the App writes no code: one OK finding, and no
// repository is read.
func TestGitHubCheckConfinementReadOnlyInstallation(t *testing.T) {
	t.Parallel()

	server := githubConfinementServer(t, "read")
	g := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)), WithTier(TierReport))
	findings, err := g.CheckConfinement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Code != ConfinementCodeNoWrite || findings[0].Severity != ConfinementOK {
		t.Fatalf("findings = %+v, want one no-write OK", findings)
	}
}

func TestGitHubCheckConfinementWithoutApp(t *testing.T) {
	t.Parallel()

	findings, err := NewGitHub("client", "secret", "webhook").CheckConfinement(context.Background())
	if err != nil || len(findings) != 1 || findings[0].Code != ConfinementCodeNoServerToken {
		t.Fatalf("findings = %+v, %v; want no_server_token", findings, err)
	}
}

func TestForgejoPushVerdict(t *testing.T) {
	t.Parallel()

	rules := []forgejoBranchProtection{
		{RuleName: "hibou/**", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsers: []string{"Hibou-Bot"}},
		{RuleName: "release/*", EnablePush: true, EnablePushWhitelist: true, PushWhitelistTeams: []string{"release"}},
		{RuleName: "main", EnablePush: false},
		{RuleName: "*", EnablePush: true, EnablePushWhitelist: true, PushWhitelistUsers: []string{"maintainer"}},
	}
	cases := []struct {
		branch string
		want   pushVerdict
	}{
		{"hibou/fix/a", pushAllowed},
		{"release/1.0", pushUnknown},
		{"main", pushBlocked},
		{"feature", pushBlocked},
		{"feature/x", pushAllowed}, // "*" does not cross "/"
	}
	for _, tc := range cases {
		if got := forgejoPushVerdict(rules, "hibou-bot", tc.branch); got != tc.want {
			t.Errorf("%s = %v, want %v", tc.branch, got, tc.want)
		}
	}
	// An exact name wins over an earlier pattern.
	exact := []forgejoBranchProtection{{RuleName: "**", EnablePush: false}, {RuleName: "main", EnablePush: true}}
	if got := forgejoPushVerdict(exact, "hibou-bot", "main"); got != pushAllowed {
		t.Errorf("exact rule after a pattern = %v, want allowed", got)
	}
	if got := forgejoPushVerdict(nil, "hibou-bot", "any"); got != pushAllowed {
		t.Errorf("no rules = %v, want allowed", got)
	}
}

// forgejoConfinementServer fakes Forgejo: the token's user pushes to
// acme/open (no protection) and acme/confined (a "*" rule for maintainers,
// hibou/** allowed for the bot); acme/scoped has a repository-specific token
// that cannot read protections; acme/docs is read-only.
func forgejoConfinementServer(t *testing.T) *httptest.Server {
	t.Helper()
	responses := map[string]string{
		"/api/v1/user": `{"login":"hibou-bot"}`,
		"/api/v1/user/repos": `[
			{"name":"open","full_name":"acme/open","default_branch":"main","owner":{"login":"acme"},"permissions":{"push":true}},
			{"name":"confined","full_name":"acme/confined","default_branch":"main","owner":{"login":"acme"},"permissions":{"push":true}},
			{"name":"star","full_name":"acme/star","default_branch":"main","owner":{"login":"acme"},"permissions":{"push":true}},
			{"name":"scoped","full_name":"acme/scoped","default_branch":"main","owner":{"login":"acme"},"permissions":{"push":true}},
			{"name":"docs","full_name":"acme/docs","default_branch":"main","owner":{"login":"acme"},"permissions":{"push":false}},
			{"name":"owned","full_name":"acme/owned","default_branch":"main","owner":{"login":"acme"},"permissions":{"admin":true,"push":true}}]`,
		"/api/v1/repos/acme/owned/branches":              `[{"name":"main","user_can_push":false}]`,
		"/api/v1/repos/acme/owned/branch_protections":    `[{"rule_name":"hibou/**","enable_push":true},{"rule_name":"**","enable_push":false}]`,
		"/api/v1/repos/acme/open/branches":               `[{"name":"main","user_can_push":true},{"name":"dev","user_can_push":true}]`,
		"/api/v1/repos/acme/open/branch_protections":     `[]`,
		"/api/v1/repos/acme/confined/branches":           `[{"name":"main","user_can_push":false},{"name":"dev","user_can_push":false},{"name":"hibou/fix","user_can_push":true}]`,
		"/api/v1/repos/acme/confined/branch_protections": `[{"rule_name":"hibou/**","enable_push":true,"enable_push_whitelist":true,"push_whitelist_usernames":["hibou-bot"]},{"rule_name":"**","enable_push":true,"enable_push_whitelist":true,"push_whitelist_usernames":["maintainer"]}]`,
		"/api/v1/repos/acme/star/branches":               `[{"name":"main","user_can_push":false}]`,
		"/api/v1/repos/acme/star/branch_protections":     `[{"rule_name":"*","enable_push":true,"enable_push_whitelist":true,"push_whitelist_usernames":["maintainer"]}]`,
		"/api/v1/repos/acme/scoped/branches":             `[{"name":"main","user_can_push":false}]`,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token secret" {
			t.Errorf("request without the server token: %s", r.URL)
		}
		if body, ok := responses[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		if r.URL.Path == "/api/v1/repos/acme/scoped/branch_protections" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"token does not have at least one of required scope(s)"}`))
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestForgejoCheckConfinement(t *testing.T) {
	t.Parallel()

	server := forgejoConfinementServer(t)
	findings, err := NewForgejo(server.URL, "id", "secret", "hook", "secret").CheckConfinement(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	open := findingCodes(findings, "acme/open")
	if open[ConfinementCodeUnrestricted] != ConfinementError || open[ConfinementCodeDefaultBranch] != ConfinementError {
		t.Errorf("acme/open = %v, want unrestricted and default branch errors", open)
	}
	confined := findingCodes(findings, "acme/confined")
	if len(confined) != 1 || confined[ConfinementCodeNoWrite] != ConfinementOK {
		t.Errorf("acme/confined = %v, want only the confined OK", confined)
	}
	// "*" stops at "/": feature/x branches stay open.
	if star := findingCodes(findings, "acme/star"); star[ConfinementCodeUnrestricted] != ConfinementError {
		t.Errorf("acme/star = %v, want unrestricted (a \"*\" rule leaves nested branches open)", star)
	}
	scoped := findingCodes(findings, "acme/scoped")
	if len(scoped) != 1 || scoped[ConfinementCodeUnverifiable] != ConfinementInfo {
		t.Errorf("acme/scoped = %v, want only unverifiable (protections need admin)", scoped)
	}
	// Otherwise confined, an admin token can still remove the rules.
	if owned := findingCodes(findings, "acme/owned"); owned[ConfinementCodeAdmin] != ConfinementError || owned[ConfinementCodeNoWrite] != "" {
		t.Errorf("acme/owned = %v, want identity_is_admin and no confined result", owned)
	}
	if len(findingCodes(findings, "acme/docs")) != 0 {
		t.Error("a read-only repository was checked")
	}
	if all := findingCodes(findings, ""); all[ConfinementCodeNoWrite] != ConfinementOK {
		t.Errorf("forge-level findings = %v, want the read-only count", all)
	}
}

func TestForgejoAndGitLabWithoutServerToken(t *testing.T) {
	t.Parallel()

	for name, checker := range map[string]ConfinementChecker{
		"forgejo": NewForgejo("https://git.example.com", "id", "secret", "hook", ""),
		"gitlab":  &GitLab{},
	} {
		findings, err := checker.CheckConfinement(context.Background())
		if err != nil || len(findings) != 1 || findings[0].Code != ConfinementCodeNoServerToken {
			t.Errorf("%s: findings = %+v, %v; want no_server_token", name, findings, err)
		}
	}
}
