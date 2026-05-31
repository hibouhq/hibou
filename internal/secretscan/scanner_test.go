package secretscan

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/audit"
	"github.com/hibouhq/lehibou/internal/events"
	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type scannerStoreStub struct {
	ingestStoreStub
	auditLogs []dbgen.CreateAuditLogParams
}

func (s *scannerStoreStub) CreateAuditLog(_ context.Context, arg dbgen.CreateAuditLogParams) (dbgen.AuditLog, error) {
	s.auditLogs = append(s.auditLogs, arg)
	return dbgen.AuditLog{}, nil
}

type busStub struct {
	events []events.Event
}

func (b *busStub) Publish(_ context.Context, evt events.Event) {
	b.events = append(b.events, evt)
}

type providerStub struct {
	name         string
	capabilities ProviderCapabilities
	repoFindings []SecretFinding
	diffFindings []SecretFinding
	repoErr      error
	diffErr      error
}

func (p *providerStub) Name() string                       { return p.name }
func (p *providerStub) Capabilities() ProviderCapabilities { return p.capabilities }
func (p *providerStub) ScanRepo(context.Context, ScanRepoOptions) ([]SecretFinding, error) {
	if p.repoErr != nil {
		return nil, p.repoErr
	}
	return append([]SecretFinding(nil), p.repoFindings...), nil
}
func (p *providerStub) ScanDiff(context.Context, ScanDiffOptions) ([]SecretFinding, error) {
	if p.diffErr != nil {
		return nil, p.diffErr
	}
	return append([]SecretFinding(nil), p.diffFindings...), nil
}

func TestRunFullScanPersistsFindings(t *testing.T) {
	storeStub := &scannerStoreStub{}
	bus := &busStub{}
	provider := &providerStub{
		name:         "gitleaks",
		capabilities: ProviderCapabilities{FullScan: true},
		repoFindings: []SecretFinding{{
			Tool:        "gitleaks",
			RuleID:      "aws-access-key",
			Severity:    "critical",
			FilePath:    "app.env",
			StartLine:   4,
			SecretType:  "aws-access-key",
			SecretHash:  HashSecret("AKIA123"),
			Fingerprint: ComputeFingerprint("app.env", 4, HashSecret("AKIA123")),
			Metadata:    map[string]any{"source": "repo"},
		}},
	}

	scanner := NewScanner([]SecretScanProvider{provider}, storeStub, bus, zerolog.Nop(), "")
	created, err := scanner.RunFullScan(context.Background(), uuid.New(), uuid.New(), "https://github.com/acme/repo.git", "main", "")
	if err != nil {
		t.Fatalf("RunFullScan returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if storeStub.created != 1 {
		t.Fatalf("store created = %d, want 1", storeStub.created)
	}
	if len(bus.events) == 0 {
		t.Fatal("expected events to be published")
	}
	if len(storeStub.auditLogs) != 1 {
		t.Fatalf("len(auditLogs) = %d, want 1", len(storeStub.auditLogs))
	}
	if storeStub.auditLogs[0].Action != audit.ActionSecretDiscovered {
		t.Fatalf("audit action = %q, want %q", storeStub.auditLogs[0].Action, audit.ActionSecretDiscovered)
	}
	if storeStub.auditLogs[0].ActorType != audit.ActorSystem {
		t.Fatalf("audit actor_type = %q, want %q", storeStub.auditLogs[0].ActorType, audit.ActorSystem)
	}
}

func TestRunIncrementalScanPersistsFindings(t *testing.T) {
	storeStub := &scannerStoreStub{}
	provider := &providerStub{
		name:         "gitleaks",
		capabilities: ProviderCapabilities{FullScan: true, IncrementalScan: true},
		diffFindings: []SecretFinding{{
			Tool:        "gitleaks",
			RuleID:      "slack-token",
			Severity:    "high",
			FilePath:    "config.yml",
			StartLine:   4,
			SecretType:  "slack-token",
			SecretHash:  HashSecret("xoxb-123"),
			Fingerprint: ComputeFingerprint("config.yml", 4, HashSecret("xoxb-123")),
			Metadata:    map[string]any{},
		}},
	}

	scanner := NewScanner([]SecretScanProvider{provider}, storeStub, &busStub{}, zerolog.Nop(), "")
	created, err := scanner.RunIncrementalScan(context.Background(), uuid.New(), uuid.New(), "https://github.com/acme/repo.git", "main", "abc", "def", "")
	if err != nil {
		t.Fatalf("RunIncrementalScan returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
	if storeStub.created != 1 {
		t.Fatalf("store created = %d, want 1", storeStub.created)
	}
	if len(storeStub.auditLogs) != 1 {
		t.Fatalf("len(auditLogs) = %d, want 1", len(storeStub.auditLogs))
	}
	if storeStub.auditLogs[0].Action != audit.ActionSecretDiscovered {
		t.Fatalf("audit action = %q, want %q", storeStub.auditLogs[0].Action, audit.ActionSecretDiscovered)
	}
	if storeStub.auditLogs[0].ActorType != audit.ActorSystem {
		t.Fatalf("audit actor_type = %q, want %q", storeStub.auditLogs[0].ActorType, audit.ActorSystem)
	}
}

func TestCheckPushDoesNotPersist(t *testing.T) {
	storeStub := &scannerStoreStub{}
	provider := &providerStub{
		name:         "gitleaks",
		capabilities: ProviderCapabilities{IncrementalScan: true},
		diffFindings: []SecretFinding{{
			Tool:        "gitleaks",
			RuleID:      "github-pat",
			Severity:    "critical",
			FilePath:    ".env",
			StartLine:   4,
			SecretType:  "github-pat",
			SecretHash:  HashSecret("ghp_123"),
			Fingerprint: ComputeFingerprint(".env", 4, HashSecret("ghp_123")),
			Metadata:    map[string]any{},
		}},
	}

	scanner := NewScanner([]SecretScanProvider{provider}, storeStub, &busStub{}, zerolog.Nop(), "")
	findings, err := scanner.CheckPush(context.Background(), "https://github.com/acme/repo.git", "main", "abc", "def", "")
	if err != nil {
		t.Fatalf("CheckPush returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if storeStub.created != 0 {
		t.Fatalf("store created = %d, want 0", storeStub.created)
	}
}

func TestCheckPushNilScanner(t *testing.T) {
	var scanner *Scanner
	_, err := scanner.CheckPush(context.Background(), "https://github.com/acme/repo.git", "main", "abc", "def", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRunFullScanPublishesFailureOnProviderError(t *testing.T) {
	storeStub := &scannerStoreStub{}
	bus := &busStub{}
	provider := &providerStub{
		name:         "gitleaks",
		capabilities: ProviderCapabilities{FullScan: true},
		repoErr:      errors.New("boom"),
	}

	scanner := NewScanner([]SecretScanProvider{provider}, storeStub, bus, zerolog.Nop(), "")
	_, err := scanner.RunFullScan(context.Background(), uuid.New(), uuid.New(), "https://github.com/acme/repo.git", "main", "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(bus.events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(bus.events))
	}
	if bus.events[0].Type != events.SecretScanFailed {
		t.Fatalf("event type = %q, want %q", bus.events[0].Type, events.SecretScanFailed)
	}
}

func TestRunIncrementalScanFallsBackToFullScanProvider(t *testing.T) {
	storeStub := &scannerStoreStub{}
	provider := &providerStub{
		name:         "github",
		capabilities: ProviderCapabilities{FullScan: true},
		repoFindings: []SecretFinding{{
			Tool:        "github",
			RuleID:      "github-pat",
			Severity:    "critical",
			FilePath:    ".env",
			StartLine:   2,
			SecretType:  "github-pat",
			SecretHash:  HashSecret("ghp_123"),
			Fingerprint: ComputeFingerprint(".env", 2, HashSecret("ghp_123")),
			Metadata:    map[string]any{},
		}},
	}

	scanner := NewScanner([]SecretScanProvider{provider}, storeStub, &busStub{}, zerolog.Nop(), "")
	created, err := scanner.RunIncrementalScan(context.Background(), uuid.New(), uuid.New(), "https://github.com/acme/repo.git", "main", "abc", "def", "")
	if err != nil {
		t.Fatalf("RunIncrementalScan returned error: %v", err)
	}
	if created != 1 {
		t.Fatalf("created = %d, want 1", created)
	}
}

func TestAppendUniqueSecretFindingsDeduplicatesByFingerprint(t *testing.T) {
	first := SecretFinding{Tool: "gitleaks", RuleID: "rule", FilePath: "a", StartLine: 1, SecretHash: HashSecret("x")}
	first.Fingerprint = ComputeFingerprint(first.FilePath, first.StartLine, first.SecretHash)
	second := first
	second.Metadata = map[string]any{"source": "duplicate"}

	findings := make([]SecretFinding, 0)
	appendUniqueSecretFindings(&findings, map[string]struct{}{}, []SecretFinding{first, second})
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
}

func TestMultiProviderSameSecretKeepsBoth(t *testing.T) {
	secretHash := HashSecret("shared-secret")
	fingerprint := ComputeFingerprint("app.env", 4, secretHash)

	findings := make([]SecretFinding, 0)
	appendUniqueSecretFindings(&findings, map[string]struct{}{}, []SecretFinding{
		{Tool: "gitleaks", RuleID: "aws-access-key", FilePath: "app.env", StartLine: 4, SecretHash: secretHash, Fingerprint: fingerprint},
		{Tool: "github", RuleID: "aws-access-key", FilePath: "app.env", StartLine: 4, SecretHash: secretHash, Fingerprint: fingerprint},
	})

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
}

func TestAppendUniqueSecretFindingsLineZeroKeepsDistinctSecrets(t *testing.T) {
	firstHash := HashSecret("first-secret")
	secondHash := HashSecret("second-secret")

	findings := make([]SecretFinding, 0)
	appendUniqueSecretFindings(&findings, map[string]struct{}{}, []SecretFinding{
		{Tool: "gitleaks", RuleID: "rule-a", FilePath: "app.env", SecretHash: firstHash, Fingerprint: ComputeFingerprint("app.env", 0, firstHash)},
		{Tool: "gitleaks", RuleID: "rule-b", FilePath: "app.env", SecretHash: secondHash, Fingerprint: ComputeFingerprint("app.env", 0, secondHash)},
	})

	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
}

func TestFingerprintComputationStable(t *testing.T) {
	got := ComputeFingerprint("app.env", 4, HashSecret("AKIA123"))
	want := ComputeFingerprint("app.env", 4, HashSecret("different"))
	if got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	_, _ = json.Marshal(got)
}

func TestFingerprintComputationFallsBackToSecretHashWhenLineMissing(t *testing.T) {
	first := ComputeFingerprint("app.env", 0, HashSecret("AKIA123"))
	second := ComputeFingerprint("app.env", 0, HashSecret("DIFFERENT"))
	if first == second {
		t.Fatalf("fingerprint collision for line zero fallback: %q", first)
	}
	if first != ComputeFingerprint("app.env", 0, HashSecret("AKIA123")) {
		t.Fatalf("fingerprint fallback not stable")
	}
}
