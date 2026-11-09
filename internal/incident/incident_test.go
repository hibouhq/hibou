package incident

import (
	"testing"
	"time"

	"github.com/hibouhq/hibou/internal/repoconfig"
)

var t0 = time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)

func TestCRADeadlinesFollowTheKind(t *testing.T) {
	aware := t0
	fix := t0.Add(5 * 24 * time.Hour)
	vuln := ComputeDeadlines(KindExploitedVulnerability, []string{RegimeCRA}, Anchors{Signal: t0, Aware: &aware, FixAvailable: &fix}, nil, InternalTargets{}, 0)
	want := map[string]time.Time{
		StepEarlyWarning: t0.Add(24 * time.Hour),
		StepNotification: t0.Add(72 * time.Hour),
		StepFinalReport:  fix.Add(14 * 24 * time.Hour),
	}
	if len(vuln) != 3 {
		t.Fatalf("deadlines = %+v", vuln)
	}
	for _, deadline := range vuln {
		if !deadline.DueAt.Equal(want[deadline.Step]) {
			t.Fatalf("%s due %s, want %s", deadline.Step, deadline.DueAt, want[deadline.Step])
		}
	}

	// Without a fix the vulnerability's final report is owed but not clocked.
	noFix := ComputeDeadlines(KindExploitedVulnerability, []string{RegimeCRA}, Anchors{Signal: t0, Aware: &aware}, nil, InternalTargets{}, 0)
	if len(noFix) != 3 || !noFix[2].Pending || !noFix[2].DueAt.IsZero() || noFix[2].Step != StepFinalReport {
		t.Fatalf("final report before a fix: %+v", noFix)
	}
	// Before T0 nothing is clocked or owed.
	if before := ComputeDeadlines(KindExploitedVulnerability, []string{RegimeCRA}, Anchors{Signal: t0}, nil, InternalTargets{}, 0); len(before) != 0 {
		t.Fatalf("deadlines before T0: %+v", before)
	}

	// A severe incident's final report counts one month from the notification.
	severe := ComputeDeadlines(KindSevereIncident, []string{RegimeCRA}, Anchors{Signal: t0, Aware: &aware}, nil, InternalTargets{}, 0)
	last := severe[len(severe)-1]
	if last.Step != StepFinalReport || !last.DueAt.Equal(t0.Add(72*time.Hour).AddDate(0, 1, 0)) {
		t.Fatalf("severe final report = %+v", last)
	}
}

func TestInternalTargetsAndNationalRegimes(t *testing.T) {
	aware := t0
	national := []NationalRegime{{Code: "fr", Label: "National rule", Recipient: "National authority", Steps: []NationalStepSpec{{Name: "Notification", Hours: 24}}}}
	deadlines := ComputeDeadlines(KindExploitedVulnerability, []string{RegimeCRA, "national:fr"}, Anchors{Signal: t0, Aware: &aware}, national, InternalTargets{NotificationHours: 48}, 0)
	var internal, nationalStep bool
	for _, deadline := range deadlines {
		if deadline.Regime == RegimeInternal && deadline.Step == StepNotification && deadline.DueAt.Equal(t0.Add(48*time.Hour)) && deadline.Filing == "" {
			internal = true
		}
		if deadline.Regime == "national:fr" && deadline.Filing == "national_fr_notification" {
			nationalStep = true
		}
	}
	if !internal || !nationalStep {
		t.Fatalf("deadlines = %+v", deadlines)
	}
	// The regulatory notification deadline stays next to the internal one.
	if deadlineFor(deadlines, StepNotification).Equal(t0.Add(48 * time.Hour)) {
		t.Fatal("the internal target replaced the regulatory deadline in client notices")
	}
}

func TestEffectiveRulesPrecedence(t *testing.T) {
	locked := []repoconfig.IncidentRule{{Match: "exploited:true", Regimes: []string{RegimeCRA}, Priority: "P1"}}
	org := []repoconfig.IncidentRule{{Match: "severity:critical", Due: "7d"}}

	builtin := EffectiveRules(nil, nil, false, nil)
	if len(builtin) != 3 || builtin[0].Source != SourceBuiltin {
		t.Fatalf("builtin = %+v", builtin)
	}
	withOrg := EffectiveRules(locked, org, true, nil)
	if len(withOrg) != 2 || withOrg[0].Source != SourceOrgLocked || withOrg[1].Source != SourceOrg || withOrg[1].Due != 7*24*time.Hour || withOrg[1].Priority != "P2" {
		t.Fatalf("org = %+v", withOrg)
	}
	// An explicit empty repo list turns unlocked rules off; locked stay.
	repoOff := EffectiveRules(locked, org, true, &repoconfig.IncidentsConfig{RulesSet: true})
	if len(repoOff) != 1 || !repoOff[0].Locked {
		t.Fatalf("repo off = %+v", repoOff)
	}
	if got := withOrg[1].Regimes; len(got) != 1 || got[0] != RegimeInternal {
		t.Fatalf("default regime = %v", got)
	}
}

func TestDeriveKind(t *testing.T) {
	cases := []struct {
		rule    Rule
		finding FindingFacts
		want    string
	}{
		{Rule{Match: "exploited:true"}, FindingFacts{Type: "dependency", Exploited: true}, KindExploitedVulnerability},
		{Rule{Match: "epss:>=0.5 OR exploited:true"}, FindingFacts{Type: "dependency", Exploited: true}, KindPolicyBreach},
		{Rule{Match: "-exploited:true"}, FindingFacts{Type: "dependency", Exploited: true}, KindPolicyBreach},
		{Rule{Match: "type:secret verified:true"}, FindingFacts{Type: "secret"}, KindSecretLeak},
		{Rule{Match: "type:malware"}, FindingFacts{Type: "malware"}, KindMalware},
		{Rule{Match: "severity:critical"}, FindingFacts{Type: "sast"}, KindPolicyBreach},
		{Rule{Match: "severity:critical", Kind: KindSecretLeak}, FindingFacts{Type: "sast"}, KindPolicyBreach},
		{Rule{Match: "severity:critical", Kind: KindExploitedVulnerability}, FindingFacts{Type: "dependency"}, KindExploitedVulnerability},
	}
	for _, c := range cases {
		if got := DeriveKind(c.rule, c.finding); got != c.want {
			t.Fatalf("DeriveKind(%q, %+v) = %s, want %s", c.rule.Match, c.finding, got, c.want)
		}
	}
}

func TestRefSelection(t *testing.T) {
	if !RefSelected(DefaultRefs(KindSecretLeak), RefInfo{Name: "feature/x", Type: "branch"}) {
		t.Fatal("secrets must count on every branch by default")
	}
	if RefSelected(DefaultRefs(KindPolicyBreach), RefInfo{Name: "main", Type: "branch", IsDefault: true}) {
		t.Fatal("policy breaches default to released snapshots only")
	}
	if !RefSelected([]string{"release/*"}, RefInfo{Name: "release/4.2", Type: "branch"}) {
		t.Fatal("glob did not match")
	}
	if RefSelected([]string{"release/*"}, RefInfo{Name: "release/4.2", Type: "tag"}) {
		t.Fatal("globs are over branch names only")
	}
}

func TestVersRange(t *testing.T) {
	r, err := ParseVers("vers:generic/>=4.0.0|<4.3.0|>=5.0.0|<5.1.0")
	if err != nil {
		t.Fatal(err)
	}
	for version, want := range map[string]bool{"4.0.0": true, "4.2.9": true, "4.3.0": false, "4.9.0": false, "5.0.5": true, "5.1.0": false, "3.9.0": false} {
		if got := r.Contains(version); got != want {
			t.Fatalf("Contains(%s) = %v, want %v", version, got, want)
		}
	}
	exact, _ := ParseVers("vers:generic/1.2.3|2.0.0")
	if !exact.Contains("2.0.0") || exact.Contains("1.5.0") {
		t.Fatal("equality constraints")
	}
	if _, err := ParseVers("4.0|<5"); err == nil {
		t.Fatal("accepted a range without vers: prefix")
	}
	if ReleaseLine("v4.2.1") != "4.2" || ReleaseLine("4.2.1-rc1") != "4.2" || ReleaseLine("7") != "7" {
		t.Fatal("ReleaseLine")
	}
}

func exploitedFacts() Facts {
	aware := t0
	return Facts{
		Kind: KindExploitedVulnerability, State: StateReportable, Regimes: []string{RegimeCRA},
		ComponentAdvisory: true,
		Releases: []ReleaseFact{
			{ID: "r1", Version: "4.1.0", HasSnapshot: true, CreatedAt: t0.Add(-60 * 24 * time.Hour), ClientIDs: []string{"c1"}, Matched: true, ComponentPURL: "pkg:maven/x/parser@2.3.1"},
			{ID: "r2", Version: "4.2.1", HasSnapshot: true, CreatedAt: t0.Add(-30 * 24 * time.Hour), ClientIDs: []string{"c2", "c3"}, Matched: true, ComponentPURL: "pkg:maven/x/parser@2.3.1"},
			{ID: "r3", Version: "3.2.0", HasSnapshot: false, CreatedAt: t0.Add(-400 * 24 * time.Hour), ClientIDs: []string{"c4"}},
			{ID: "r4", Version: "2.9.0", HasSnapshot: true, CreatedAt: t0.Add(-800 * 24 * time.Hour), ClientIDs: []string{"c5"}},
			{ID: "r5", Version: "1.0.0", HasSnapshot: true, CreatedAt: t0.Add(-900 * 24 * time.Hour)},
		},
		Statements: []StatementFact{
			{ID: "s-r2", Status: ScopeAffected, ReleaseID: "r2", Repo: true, CreatedAt: t0},
		},
		Deadlines:   ComputeDeadlines(KindExploitedVulnerability, []string{RegimeCRA}, Anchors{Signal: t0, Aware: &aware}, nil, InternalTargets{}, 0),
		MetFilings:  map[string]bool{"srp_early_warning": true},
		ClientNames: map[string]string{"c1": "Castor"},
	}
}

func actionsByKind(actions []ActionSpec) map[string][]ActionSpec {
	out := map[string][]ActionSpec{}
	for _, action := range actions {
		out[action.Kind] = append(out[action.Kind], action)
	}
	return out
}

func TestDeriveExploitedScopeAndActions(t *testing.T) {
	derivation := Derive(exploitedFacts())
	status := map[string]string{}
	for _, row := range derivation.Scope {
		status[row.SubjectID] = row.Status
	}
	want := map[string]string{"r1": ScopePending, "r2": ScopeAffected, "r3": ScopeUnknown, "r4": ScopeNotMatched}
	if len(status) != len(want) {
		t.Fatalf("scope = %+v", derivation.Scope)
	}
	for id, s := range want {
		if status[id] != s {
			t.Fatalf("release %s = %s, want %s", id, status[id], s)
		}
	}
	actions := actionsByKind(derivation.Actions)
	// VEX for every matched or unknown release; r2 already has one.
	if len(actions[ActionVEX]) != 3 {
		t.Fatalf("vex actions = %+v", actions[ActionVEX])
	}
	for _, action := range actions[ActionVEX] {
		if (action.SubjectID == "r2") != action.Satisfied {
			t.Fatalf("vex %s satisfied=%v", action.SubjectID, action.Satisfied)
		}
	}
	// Filings: the early warning is met, the notification is not.
	if !actions["srp_early_warning"][0].Satisfied || actions["srp_notification"][0].Satisfied {
		t.Fatalf("filings = %+v", actions)
	}
	// Clients on pending, affected or unknown releases; never on not-matched.
	notices := map[string]bool{}
	for _, action := range actions[ActionClientNotice] {
		notices[action.SubjectID] = true
		if action.DueAt == nil || !action.DueAt.Equal(t0.Add(72*time.Hour)) {
			t.Fatalf("client notice due = %v", action.DueAt)
		}
	}
	if !notices["c1"] || !notices["c2"] || !notices["c3"] || !notices["c4"] || notices["c5"] {
		t.Fatalf("client notices = %v", notices)
	}
	if len(actions[ActionFixRelease]) != 1 || actions[ActionFixRelease][0].SubjectID != "4.2" {
		t.Fatalf("fix_release = %+v", actions[ActionFixRelease])
	}
}

func TestDeriveExploitedFixAndNotice(t *testing.T) {
	facts := exploitedFacts()
	facts.Releases = append(facts.Releases, ReleaseFact{ID: "r6", Version: "4.2.3", HasSnapshot: true, CreatedAt: t0})
	facts.Deliveries = []DeliveryFact{{ClientID: "c2", Status: "sent"}, {ClientID: "c3", Status: "failed"}}
	actions := actionsByKind(Derive(facts).Actions)
	if !actions[ActionFixRelease][0].Satisfied {
		t.Fatal("a later 4.2.x without the advisory did not satisfy fix_release")
	}
	for _, action := range actions[ActionClientNotice] {
		if want := action.SubjectID == "c2"; action.Satisfied != want {
			t.Fatalf("notice %s satisfied=%v", action.SubjectID, action.Satisfied)
		}
	}
	facts.Settings.RequireAcknowledgement = true
	for _, action := range actionsByKind(Derive(facts).Actions)[ActionClientNotice] {
		if action.Satisfied {
			t.Fatal("a sent but unacknowledged notice satisfied an acknowledgement-required org")
		}
	}
}

func TestDeriveExploitedNotReportable(t *testing.T) {
	facts := exploitedFacts()
	facts.State, facts.DecisionStep = StateNotReportable, StepNotReachable
	actions := actionsByKind(Derive(facts).Actions)
	if len(actions[ActionClientNotice]) != 0 || len(actions["srp_notification"]) != 0 {
		t.Fatalf("not reportable carries filings or notices: %+v", actions)
	}
	if len(actions[ActionUpstreamNotice]) != 1 || actions[ActionUpstreamNotice][0].SubjectID != "pkg:maven/x/parser@2.3.1" || actions[ActionUpstreamNotice][0].Optional {
		t.Fatalf("upstream notice = %+v", actions[ActionUpstreamNotice])
	}
	// A public advisory: the maintainer already knows (guidance §223), so
	// nothing is owed upstream.
	facts.AdvisoryPublic = true
	if upstream := actionsByKind(Derive(facts).Actions)[ActionUpstreamNotice]; len(upstream) != 0 {
		t.Fatalf("public advisory upstream notice = %+v", upstream)
	}
	facts.AdvisoryPublic = false
	facts.ComponentAdvisory = false
	if len(actionsByKind(Derive(facts).Actions)[ActionUpstreamNotice]) != 0 {
		t.Fatal("first-party advisory got an upstream notice")
	}
}

// Exploitable here but not exploited here (ladder step 3): no filing, client
// notices offered but not owed, the fix still derived.
func TestDeriveExploitedReachableNoAttack(t *testing.T) {
	facts := exploitedFacts()
	facts.State, facts.DecisionStep = StateNotReportable, StepReachableNoAttack
	actions := actionsByKind(Derive(facts).Actions)
	if len(actions["srp_early_warning"]) != 0 {
		t.Fatalf("step 3 carries a filing: %+v", actions["srp_early_warning"])
	}
	notices := actions[ActionClientNotice]
	if len(notices) == 0 {
		t.Fatal("step 3 offers no client notice")
	}
	for _, notice := range notices {
		if !notice.Optional || notice.DueAt != nil {
			t.Fatalf("step 3 notice is owed: %+v", notice)
		}
	}
	if len(actions[ActionFixRelease]) == 0 {
		t.Fatal("step 3 derives no fix")
	}
}

func TestStepStatement(t *testing.T) {
	for _, tc := range []struct{ step, just, wantStatus, wantJust string }{
		{StepNotPresent, "", "not_affected", "component_not_present"},
		{StepNotReachable, "", "not_affected", "vulnerable_code_not_in_execute_path"},
		{StepNotReachable, "inline_mitigations_already_exist", "not_affected", "inline_mitigations_already_exist"},
		{StepNotReachable, "bogus", "not_affected", "vulnerable_code_not_in_execute_path"},
		{StepReachableNoAttack, "", "affected", ""},
		{StepAttacked, "", "affected", ""},
		{"", "", "", ""},
	} {
		status, just := StepStatement(tc.step, tc.just)
		if status != tc.wantStatus || just != tc.wantJust {
			t.Fatalf("StepStatement(%q, %q) = %q, %q", tc.step, tc.just, status, just)
		}
	}
	if !StepReportable(StepAttacked) || StepReportable(StepReachableNoAttack) {
		t.Fatal("only the attacked step is reportable")
	}
}

func TestStatementPrecedenceAndApproval(t *testing.T) {
	release := ReleaseFact{ID: "r1", Version: "4.2.1", ComponentPURL: "pkg:maven/x/parser@2.3.1"}
	statements := []StatementFact{
		{ID: "org", Status: ScopeAffected, CreatedAt: t0},
		{ID: "repo", Status: ScopeAffected, Repo: true, CreatedAt: t0},
		{ID: "component", Status: ScopeNotAffected, Repo: true, ComponentPURL: "pkg:maven/x/parser@2.3.1", CreatedAt: t0},
		{ID: "range", Status: ScopeFixed, Repo: true, VersionRange: "vers:generic/>=4.2.0|<4.3.0", CreatedAt: t0},
		{ID: "other-release", Status: ScopeFixed, Repo: true, ReleaseID: "r9", CreatedAt: t0},
	}
	if got := statementFor(statements, release); got == nil || got.ID != "range" {
		t.Fatalf("statementFor = %+v", got)
	}
	statements = append(statements, StatementFact{ID: "release", Status: ScopeAffected, Repo: true, ReleaseID: "r1", CreatedAt: t0})
	if got := statementFor(statements, release); got.ID != "release" {
		t.Fatalf("release-scoped statement lost: %s", got.ID)
	}
	if statementSatisfies(&StatementFact{Status: ScopeAffected}, Settings{RequireVEXApproval: true}) {
		t.Fatal("unapproved statement satisfied an approval-required org")
	}
	if statementSatisfies(&StatementFact{Status: ScopeUnderInvestigation, Approved: true}, Settings{}) {
		t.Fatal("under_investigation satisfied the vex action")
	}
}

func TestDeriveSecret(t *testing.T) {
	facts := Facts{Kind: KindSecretLeak, State: StateSignal, Regimes: []string{RegimeInternal},
		Refs:    []RefFact{{Name: "main", Present: false}, {Name: "feature/x", Present: false}},
		Finding: &FindingFact{ValidatorDead: true, Rotated: true}}
	actions := actionsByKind(Derive(facts).Actions)
	if !actions[ActionRevoke][0].Satisfied || !actions[ActionRemove][0].Satisfied || !actions[ActionRemove][0].Optional {
		t.Fatalf("secret actions = %+v", actions)
	}
	if actions[ActionAssessExposure][0].Satisfied {
		t.Fatal("exposure satisfied without assessment")
	}
	if len(actions[ActionNotifyOwner]) != 0 {
		t.Fatal("notify_owner without an external owner")
	}
	facts.State = StateDismissed
	if len(Derive(facts).Actions) != 0 {
		t.Fatal("a dismissed secret leak keeps actions")
	}
}

func TestDeriveMalwareShippedNeedsNotice(t *testing.T) {
	facts := Facts{Kind: KindMalware, State: StateConfirmed, Regimes: []string{RegimeInternal},
		Refs:     []RefFact{{Name: "main", Present: true}},
		Releases: []ReleaseFact{{ID: "r1", Version: "1.0.0", Matched: true, ClientIDs: []string{"c1"}}}}
	actions := actionsByKind(Derive(facts).Actions)
	if len(actions[ActionClientNotice]) != 1 || actions[ActionRemovePackage][0].Satisfied {
		t.Fatalf("malware actions = %+v", actions)
	}
}

func TestDerivePolicyBreach(t *testing.T) {
	due := 7 * 24 * time.Hour
	facts := Facts{Kind: KindPolicyBreach, State: StateSignal, Regimes: []string{RegimeInternal},
		Refs:      []RefFact{{Name: "v4.2.1", Present: true}},
		Finding:   &FindingFact{Status: "detected", Accepted: true},
		Deadlines: ComputeDeadlines(KindPolicyBreach, []string{RegimeInternal}, Anchors{Signal: t0}, nil, InternalTargets{}, due)}
	actions := Derive(facts).Actions
	if len(actions) != 1 || !actions[0].Satisfied || actions[0].DueAt == nil || !actions[0].DueAt.Equal(t0.Add(due)) {
		t.Fatalf("policy actions = %+v", actions)
	}
}

func TestReadyToClose(t *testing.T) {
	done := []ActionStatus{{State: "done"}, {State: "waived"}, {State: "pending", Optional: true}, {State: "pending", Obsolete: true}}
	if !ReadyToClose(StateReportable, []string{RegimeCRA}, done) {
		t.Fatal("all required actions done but not closable")
	}
	if ReadyToClose(StateSignal, []string{RegimeCRA}, done) {
		t.Fatal("an undecided CRA incident closed")
	}
	if !ReadyToClose(StateSignal, []string{RegimeInternal}, done) {
		t.Fatal("an internal incident with every action done did not close")
	}
	if ReadyToClose(StateSignal, []string{RegimeInternal}, nil) {
		t.Fatal("a fresh signal with no actions closed itself")
	}
	if !ReadyToClose(StateDismissed, []string{RegimeInternal}, nil) {
		t.Fatal("a dismissed incident with nothing left did not close")
	}
	if ReadyToClose(StateReportable, []string{RegimeCRA}, append(done, ActionStatus{State: "pending"})) {
		t.Fatal("closed with a pending action")
	}
}
