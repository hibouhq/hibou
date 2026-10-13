package apitoken

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateHasValidChecksum(t *testing.T) {
	for i := 0; i < 100; i++ {
		token, err := Generate()
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !strings.HasPrefix(token, Prefix) {
			t.Fatalf("token %q missing prefix", token)
		}
		if len(token) != len(Prefix)+randomLen+checksumLen {
			t.Fatalf("token %q length = %d, want %d", token, len(token), len(Prefix)+randomLen+checksumLen)
		}
		if !HasValidChecksum(token) {
			t.Fatalf("HasValidChecksum(%q) = false, want true", token)
		}
	}
}

func TestHasValidChecksumRejectsTampered(t *testing.T) {
	token, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// Flip the last checksum character to a different base62 char.
	runes := []byte(token)
	last := len(runes) - 1
	if runes[last] == 'A' {
		runes[last] = 'B'
	} else {
		runes[last] = 'A'
	}
	if HasValidChecksum(string(runes)) {
		t.Fatal("HasValidChecksum accepted a tampered token")
	}

	cases := []string{"", "hibou_pat_", "nope", Prefix + "short", "wrong_prefix_" + strings.Repeat("a", randomLen+checksumLen)}
	for _, c := range cases {
		if HasValidChecksum(c) {
			t.Fatalf("HasValidChecksum(%q) = true, want false", c)
		}
	}
}

func TestLooksLike(t *testing.T) {
	if !LooksLike("  hibou_pat_whatever  ") {
		t.Fatal("LooksLike should trim and match the prefix")
	}
	if LooksLike("ghp_something") {
		t.Fatal("LooksLike should reject a non-Hibou token")
	}
}

func TestAccessLevelGrants(t *testing.T) {
	cases := []struct {
		have AccessLevel
		need AccessLevel
		want bool
	}{
		{AccessWrite, AccessWrite, true},
		{AccessWrite, AccessRead, true},
		{AccessRead, AccessRead, true},
		{AccessRead, AccessWrite, false},
		{AccessNone, AccessRead, false},
		{AccessRead, AccessNone, false},
	}
	for _, c := range cases {
		if got := c.have.Grants(c.need); got != c.want {
			t.Fatalf("%s.Grants(%s) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
}

func TestScopeAllows(t *testing.T) {
	scope, err := Parse([]byte(`{
		"owner": {"type": "org", "id": "acme"},
		"org": "acme",
		"repos": {"mode": "list", "slugs": ["api", "web"]},
		"permissions": {"vulnerabilities": "write", "coverage": "read", "triage": "none"}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !scope.Allows(CapVulnerabilities, AccessWrite, "acme", "api") {
		t.Fatal("should allow vulnerabilities:write on acme/api")
	}
	if scope.Allows(CapVulnerabilities, AccessWrite, "acme", "other") {
		t.Fatal("should deny a repo outside the allowlist")
	}
	if scope.Allows(CapVulnerabilities, AccessWrite, "different-org", "api") {
		t.Fatal("should deny a different org")
	}
	if !scope.Allows(CapCoverage, AccessRead, "acme", "web") {
		t.Fatal("should allow coverage:read")
	}
	if scope.Allows(CapCoverage, AccessWrite, "acme", "web") {
		t.Fatal("read grant must not satisfy write")
	}
	if scope.Allows(CapTriage, AccessWrite, "acme", "api") {
		t.Fatal("triage:none must deny write")
	}
	if scope.Allows(CapSecrets, AccessRead, "acme", "api") {
		t.Fatal("an unlisted capability must default to none")
	}
}

func TestScopeIsReadOnly(t *testing.T) {
	readOnly, _ := Parse([]byte(`{"org":"acme","permissions":{"coverage":"read","vulnerabilities":"read","triage":"none"}}`))
	if !readOnly.IsReadOnly() {
		t.Fatal("scope with no write should be read-only (agent token)")
	}
	writer, _ := Parse([]byte(`{"org":"acme","permissions":{"uploads":"write"}}`))
	if writer.IsReadOnly() {
		t.Fatal("scope with a write grant is not read-only")
	}
}

func TestRepoSelectorAll(t *testing.T) {
	scope, _ := Parse([]byte(`{"org":"acme","repos":{"mode":"all"},"permissions":{"coverage":"read"}}`))
	if !scope.Allows(CapCoverage, AccessRead, "acme", "any-repo") {
		t.Fatal("repos.mode=all should cover any repo")
	}
}

func TestParseRejectsUnknownScopeValues(t *testing.T) {
	for _, scope := range []string{
		`{"permissions":{"unknown":"read"}}`,
		`{"permissions":{"coverage":"admin"}}`,
		`{"repos":{"mode":"some"}}`,
		`{"owner":{"type":"service"}}`,
		`{"orgs":{"mode":"some"}}`,
		`{"org":"acme","orgs":{"mode":"memberships"}}`,
		`{"owner":{"type":"org","id":"acme"},"orgs":{"mode":"memberships"}}`,
	} {
		if _, err := Parse([]byte(scope)); err == nil {
			t.Errorf("Parse(%s) error = nil, want error", scope)
		}
	}
}

func TestScopeAllowsOrgWide(t *testing.T) {
	all, err := Parse([]byte(`{"org":"acme","repos":{"mode":"all"},"permissions":{"components":"read"}}`))
	if err != nil {
		t.Fatalf("Parse all-repos scope: %v", err)
	}
	if !all.AllowsOrgWide(CapComponents, AccessRead, "acme") {
		t.Fatal("all-repos scope should allow organization-wide read")
	}
	list, err := Parse([]byte(`{"org":"acme","repos":{"mode":"list","slugs":["api"]},"permissions":{"components":"read"}}`))
	if err != nil {
		t.Fatalf("Parse list-repos scope: %v", err)
	}
	if list.AllowsOrgWide(CapComponents, AccessRead, "acme") {
		t.Fatal("repo-list scope must not allow organization-wide read")
	}
}

func TestScopeWidens(t *testing.T) {
	base := Scope{
		Org:   "acme",
		Repos: RepoSelector{Mode: RepoList, Slugs: []string{"api"}},
		Permissions: map[Capability]AccessLevel{
			CapCoverage: AccessRead,
			CapUploads:  AccessWrite,
		},
	}

	cases := []struct {
		name string
		next Scope
		want bool
	}{
		{"identical", base, false},
		{"level raised", Scope{Repos: base.Repos, Permissions: map[Capability]AccessLevel{CapCoverage: AccessWrite}}, true},
		{"new capability", Scope{Repos: base.Repos, Permissions: map[Capability]AccessLevel{CapTriage: AccessRead}}, true},
		{"level dropped", Scope{Repos: base.Repos, Permissions: map[Capability]AccessLevel{CapUploads: AccessRead}}, false},
		{"repo added", Scope{Repos: RepoSelector{Mode: RepoList, Slugs: []string{"api", "web"}}, Permissions: base.Permissions}, true},
		{"repo removed", Scope{Repos: RepoSelector{Mode: RepoList, Slugs: []string{}}, Permissions: base.Permissions}, false},
		{"list to all", Scope{Repos: RepoSelector{Mode: RepoAll}, Permissions: base.Permissions}, true},
	}
	for _, tc := range cases {
		if got := base.Widens(tc.next); got != tc.want {
			t.Errorf("%s: Widens() = %v, want %v", tc.name, got, tc.want)
		}
	}

	all := Scope{Repos: RepoSelector{Mode: RepoAll}, Permissions: base.Permissions}
	if all.Widens(Scope{Repos: RepoSelector{Mode: RepoList, Slugs: []string{"anything"}}, Permissions: base.Permissions}) {
		t.Errorf("all → list must not widen")
	}
}

func TestMembershipWideScopeCoversEveryOrg(t *testing.T) {
	scope, err := Parse([]byte(`{
		"owner": {"type": "user", "id": "u1"},
		"orgs": {"mode": "memberships"},
		"repos": {"mode": "all"},
		"permissions": {"uploads": "write", "vulnerabilities": "read"}
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !scope.MembershipWide() {
		t.Fatal("MembershipWide() = false, want true")
	}
	for _, org := range []string{"acme", "globex", ""} {
		if !scope.Allows(CapUploads, AccessWrite, org, "api") {
			t.Errorf("should allow uploads:write in %q", org)
		}
		if !scope.AllowsOrgWide(CapVulnerabilities, AccessRead, org) {
			t.Errorf("should allow org-wide vulnerabilities:read in %q", org)
		}
	}
	if scope.Allows(CapTriage, AccessWrite, "acme", "api") {
		t.Fatal("membership-wide scope must still deny ungranted capabilities")
	}

	single, _ := Parse([]byte(`{"org":"acme","repos":{"mode":"all"},"permissions":{"uploads":"write"}}`))
	if single.MembershipWide() || single.CoversOrg("globex") {
		t.Fatal("a single-org scope must not cover another org")
	}
	if !single.Widens(scope) {
		t.Fatal("single-org → membership-wide must widen")
	}
	if scope.Widens(single) {
		t.Fatal("membership-wide → single-org must not widen")
	}
}

func TestUserCodeRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		code, err := GenerateUserCode()
		if err != nil {
			t.Fatalf("GenerateUserCode: %v", err)
		}
		normalized, ok := NormalizeUserCode(strings.ToLower(FormatUserCode(code)))
		if !ok || normalized != code {
			t.Fatalf("NormalizeUserCode(Format(%q)) = %q, %v", code, normalized, ok)
		}
		seen[code] = true
	}
	if len(seen) < 195 {
		t.Fatalf("only %d distinct codes in 200 draws", len(seen))
	}
	for _, bad := range []string{"", "BCDF-GHJ", "BCDF-GHJKL", "ABCD-EFGH", "BCDF-GHJ1", "BCDF_GHJK"} {
		if _, ok := NormalizeUserCode(bad); ok {
			t.Errorf("NormalizeUserCode(%q) accepted a malformed code", bad)
		}
	}
	if got, _ := NormalizeUserCode(" bcdf ghjk "); got != "BCDFGHJK" {
		t.Errorf("spaces and case should normalise, got %q", got)
	}
}

func TestPresetsAndMembershipScope(t *testing.T) {
	cli, ok := PresetCLI.Permissions()
	if !ok || cli[CapUploads] != AccessWrite || cli[CapTriage] != "" || cli[CapAdmin] != "" {
		t.Fatalf("cli preset = %v", cli)
	}
	readOnly, ok := PresetReadOnly.Permissions()
	if !ok {
		t.Fatal("read-only preset unknown")
	}
	ro := Scope{Permissions: readOnly}
	if !ro.IsReadOnly() {
		t.Fatal("read-only preset grants a write")
	}
	if _, ok := Preset("admin").Permissions(); ok {
		t.Fatal("unknown preset accepted")
	}

	scope, ok := MembershipScope("u1", PresetCLI)
	if !ok || !scope.MembershipWide() || scope.Repos.Mode != RepoAll || scope.Owner.Type != OwnerUser {
		t.Fatalf("MembershipScope = %+v", scope)
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil || !parsed.MembershipWide() {
		t.Fatalf("round trip: %v, %+v", err, parsed)
	}
}
