package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGitleaksReport(t *testing.T) {
	content := []byte(`[
		{
			"RuleID": "aws-access-key-id",
			"Description": "AWS Access Key ID",
			"File": "config/prod.env",
			"StartLine": 3,
			"EndLine": 3,
			"Commit": "abc123def456",
			"Author": "dev",
			"Email": "dev@example.com",
			"Match": "AKIAIOSFODNN7EXAMPLE",
			"Secret": "AKIAIOSFODNN7EXAMPLE",
			"Tags": ["critical", "aws"],
			"Entropy": 3.5
		}
	]`)

	findings, err := ParseGitleaksReport(content)
	if err != nil {
		t.Fatalf("ParseGitleaksReport returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	finding := findings[0]
	if finding.Tool != "gitleaks" {
		t.Fatalf("Tool = %q, want %q", finding.Tool, "gitleaks")
	}
	if finding.RuleID != "aws-access-key-id" {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, "aws-access-key-id")
	}
	if finding.Description != "AWS Access Key ID" {
		t.Fatalf("Description = %q, want %q", finding.Description, "AWS Access Key ID")
	}
	if finding.Severity != "critical" {
		t.Fatalf("Severity = %q, want %q", finding.Severity, "critical")
	}
	if finding.FilePath != "config/prod.env" {
		t.Fatalf("FilePath = %q, want %q", finding.FilePath, "config/prod.env")
	}
	if finding.StartLine != 3 || finding.EndLine != 3 {
		t.Fatalf("lines = %d-%d, want 3-3", finding.StartLine, finding.EndLine)
	}
	if finding.SecretType != "critical" {
		t.Fatalf("SecretType = %q, want %q", finding.SecretType, "critical")
	}
	if finding.SecretHash != HashSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("SecretHash = %q, want hash of match", finding.SecretHash)
	}
	if finding.CommitSHA != "abc123def456" {
		t.Fatalf("CommitSHA = %q, want %q", finding.CommitSHA, "abc123def456")
	}
	if finding.AuthorEmail != "dev@example.com" {
		t.Fatalf("AuthorEmail = %q, want %q", finding.AuthorEmail, "dev@example.com")
	}
	if finding.Verified {
		t.Fatal("Verified = true, want false")
	}
	if finding.Fingerprint != ComputeFingerprint("config/prod.env", 3, HashSecret("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("Fingerprint = %q, want computed fingerprint", finding.Fingerprint)
	}
	if got := finding.Metadata["RuleID"]; got != "aws-access-key-id" {
		t.Fatalf("Metadata[RuleID] = %v, want %q", got, "aws-access-key-id")
	}
	// ADR-010: metadata is persisted verbatim, so the raw secret must not
	// survive parsing in any field.
	for _, key := range []string{"Match", "Secret"} {
		if value, ok := finding.Metadata[key]; ok {
			t.Fatalf("Metadata[%s] = %v — raw secret material persisted", key, value)
		}
	}
}

func TestParseGitleaksReportEmpty(t *testing.T) {
	findings, err := ParseGitleaksReport([]byte(`[]`))
	if err != nil {
		t.Fatalf("ParseGitleaksReport returned error: %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}

func TestParseGitleaksReportInvalidJSON(t *testing.T) {
	findings, err := ParseGitleaksReport([]byte(`{`))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}

func TestParseGitleaksReportSkipsEmptyMatch(t *testing.T) {
	content := []byte(`[
		{
			"RuleID": "aws-access-key-id",
			"File": "config/prod.env",
			"StartLine": 3,
			"EndLine": 3,
			"Match": "",
			"Secret": ""
		}
	]`)

	findings, err := ParseGitleaksReport(content)
	if err != nil {
		t.Fatalf("ParseGitleaksReport returned error: %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}

func TestParseTruffleHogReportJSONArray(t *testing.T) {
	content := []byte(`[
		{
			"DetectorName": "AWS",
			"DetectorType": "AWS",
			"Raw": "AKIAIOSFODNN7EXAMPLE",
			"Verified": true,
			"StartLine": 10,
			"EndLine": 10,
			"SourceMetadata": {
				"Data": {
					"git": {
						"file": "secrets.yaml",
						"commit": "abc123",
						"email": "dev@example.com",
						"line": 10,
						"start_line": 10,
						"end_line": 10
					},
					"filesystem": {
						"file": "",
						"line": 0,
						"start_line": 0,
						"end_line": 0
					}
				}
			}
		}
	]`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	finding := findings[0]
	if finding.Tool != "trufflehog" {
		t.Fatalf("Tool = %q, want %q", finding.Tool, "trufflehog")
	}
	if finding.RuleID != "AWS" {
		t.Fatalf("RuleID = %q, want %q", finding.RuleID, "AWS")
	}
	if finding.Description != "AWS" {
		t.Fatalf("Description = %q, want %q", finding.Description, "AWS")
	}
	if finding.Severity != "critical" {
		t.Fatalf("Severity = %q, want %q", finding.Severity, "critical")
	}
	if finding.FilePath != "secrets.yaml" {
		t.Fatalf("FilePath = %q, want %q", finding.FilePath, "secrets.yaml")
	}
	if finding.StartLine != 10 || finding.EndLine != 10 {
		t.Fatalf("lines = %d-%d, want 10-10", finding.StartLine, finding.EndLine)
	}
	if finding.SecretType != "AWS" {
		t.Fatalf("SecretType = %q, want %q", finding.SecretType, "AWS")
	}
	if finding.SecretHash != HashSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("SecretHash = %q, want hash of raw", finding.SecretHash)
	}
	if finding.CommitSHA != "abc123" {
		t.Fatalf("CommitSHA = %q, want %q", finding.CommitSHA, "abc123")
	}
	if finding.AuthorEmail != "dev@example.com" {
		t.Fatalf("AuthorEmail = %q, want %q", finding.AuthorEmail, "dev@example.com")
	}
	if !finding.Verified {
		t.Fatal("Verified = false, want true")
	}
	if finding.Fingerprint != ComputeFingerprint("secrets.yaml", 10, HashSecret("AKIAIOSFODNN7EXAMPLE")) {
		t.Fatalf("Fingerprint = %q, want computed fingerprint", finding.Fingerprint)
	}
}

func TestParseTruffleHogReportJSONL(t *testing.T) {
	content := []byte("{" +
		`"DetectorName":"Slack","Raw":"xoxb-fake-token","Verified":false,"StartLine":5,"EndLine":5,"SourceMetadata":{"Data":{"git":{"file":"app.js","commit":"def456","email":"","line":5,"start_line":5,"end_line":5},"filesystem":{"file":"","line":0,"start_line":0,"end_line":0}}}}` +
		"\n" +
		`{"DetectorName":"GitHub","DetectorType":"PAT","Raw":"ghp_fake","Verified":false,"StartLine":12,"EndLine":12,"SourceMetadata":{"Data":{"git":{"file":"worker.js","commit":"ghi789","email":"ops@example.com","line":12,"start_line":12,"end_line":12},"filesystem":{"file":"","line":0,"start_line":0,"end_line":0}}}}`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	if findings[0].RuleID != "Slack" {
		t.Fatalf("first RuleID = %q, want %q", findings[0].RuleID, "Slack")
	}
	if findings[0].Severity != "high" {
		t.Fatalf("first Severity = %q, want %q", findings[0].Severity, "high")
	}
	if findings[0].FilePath != "app.js" {
		t.Fatalf("first FilePath = %q, want %q", findings[0].FilePath, "app.js")
	}
	if findings[1].RuleID != "GitHub" {
		t.Fatalf("second RuleID = %q, want %q", findings[1].RuleID, "GitHub")
	}
	if findings[1].CommitSHA != "ghi789" {
		t.Fatalf("second CommitSHA = %q, want %q", findings[1].CommitSHA, "ghi789")
	}
	if findings[1].AuthorEmail != "ops@example.com" {
		t.Fatalf("second AuthorEmail = %q, want %q", findings[1].AuthorEmail, "ops@example.com")
	}
}

func TestParseTruffleHogReportEmpty(t *testing.T) {
	findings, err := ParseTruffleHogReport([]byte(" \n\t "))
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}

func TestParseTruffleHogReportSkipsEmptyRaw(t *testing.T) {
	content := []byte(`[
		{
			"DetectorName": "AWS",
			"Raw": "",
			"Verified": false,
			"StartLine": 10,
			"EndLine": 10
		}
	]`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("len(findings) = %d, want 0", len(findings))
	}
}

func TestParseTruffleHogReportVerified(t *testing.T) {
	content := []byte(`[
		{
			"DetectorName": "AWS",
			"Raw": "AKIAIOSFODNN7EXAMPLE",
			"Verified": true,
			"StartLine": 8,
			"EndLine": 8
		}
	]`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("Severity = %q, want %q", findings[0].Severity, "critical")
	}
}

func TestParseTruffleHogReportLineFromSourceMeta(t *testing.T) {
	content := []byte(`[
		{
			"DetectorName": "Slack",
			"Raw": "xoxb-fake-token",
			"Verified": false,
			"StartLine": 0,
			"EndLine": 0,
			"SourceMetadata": {
				"Data": {
					"git": {
						"file": "app.js",
						"commit": "def456",
						"email": "dev@example.com",
						"line": 5,
						"start_line": 5,
						"end_line": 5
					},
					"filesystem": {
						"file": "",
						"line": 0,
						"start_line": 0,
						"end_line": 0
					}
				}
			}
		}
	]`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	if findings[0].StartLine != 5 || findings[0].EndLine != 5 {
		t.Fatalf("lines = %d-%d, want 5-5", findings[0].StartLine, findings[0].EndLine)
	}
}

func TestNormalizeSeverityAllValues(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "critical", want: "critical"},
		{in: "CRITICAL", want: "critical"},
		{in: "high", want: "high"},
		{in: "HIGH", want: "high"},
		{in: "medium", want: "medium"},
		{in: "moderate", want: "medium"},
		{in: "low", want: "low"},
		{in: "  Low  ", want: "low"},
		{in: "unknown", want: "high"},
		{in: "", want: "high"},
	}

	for _, tc := range cases {
		if got := NormalizeSeverity(tc.in); got != tc.want {
			t.Fatalf("NormalizeSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSeverityFromTags(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want string
	}{
		{name: "no tags", tags: nil, want: "high"},
		{name: "critical tag", tags: []string{"aws", "critical"}, want: "critical"},
		{name: "unrelated tags", tags: []string{"aws", "internal"}, want: "high"},
	}

	for _, tc := range cases {
		if got := severityFromTags(tc.tags); got != tc.want {
			t.Fatalf("%s: severityFromTags(%v) = %q, want %q", tc.name, tc.tags, got, tc.want)
		}
	}
}

// S3: secret_hash is keyed — a bare SHA-256 of a leaked value can be
// brute-forced offline from the stored hash.
func TestHashSecretIsKeyedNotPlainSHA256(t *testing.T) {
	plain := sha256.Sum256([]byte("AKIAIOSFODNN7EXAMPLE"))
	if HashSecret("AKIAIOSFODNN7EXAMPLE") == hex.EncodeToString(plain[:]) {
		t.Fatal("HashSecret is an unsalted SHA-256")
	}
	first, again := HashSecret("a"), HashSecret("a")
	if first != again || first == HashSecret("b") {
		t.Fatal("HashSecret must be deterministic and value-dependent")
	}
	if derivePepper("one") == nil || hex.EncodeToString(derivePepper("one")) == hex.EncodeToString(derivePepper("two")) {
		t.Fatal("the pepper must depend on its source secret")
	}
}

// S3: only allowlisted report fields reach finding metadata; anything
// unknown (SecretParts, ExtraData, a future field) is dropped.
func TestParsersKeepOnlyAllowlistedMetadata(t *testing.T) {
	gitleaks, err := ParseGitleaksReport([]byte(`[{"RuleID":"generic","File":"a.env","StartLine":1,"Secret":"s3cr3t-value","Match":"K=s3cr3t-value","Line":"K=s3cr3t-value","Message":"commit msg s3cr3t-value","NewField":"s3cr3t-value","Tags":["high"],"Commit":"abc"}]`))
	if err != nil || len(gitleaks) != 1 {
		t.Fatalf("gitleaks = %v, %v", gitleaks, err)
	}
	trufflehog, err := ParseTruffleHogReport([]byte(`{"DetectorName":"AWS","Raw":"s3cr3t-value","Redacted":"AKIA****","ExtraData":{"account":"s3cr3t-value"},"StructuredData":{"SecretParts":{"key":"s3cr3t-value"}},"SecretParts":{"key":"s3cr3t-value"},"SourceMetadata":{"Data":{"git":{"file":"a.env","line":1}}}}`))
	if err != nil || len(trufflehog) != 1 {
		t.Fatalf("trufflehog = %v, %v", trufflehog, err)
	}
	for _, finding := range []SecretFinding{gitleaks[0], trufflehog[0]} {
		encoded, _ := json.Marshal(finding.Metadata)
		if strings.Contains(string(encoded), "s3cr3t-value") {
			t.Fatalf("%s metadata keeps secret material: %s", finding.Tool, encoded)
		}
		for key := range finding.Metadata {
			if !safeMetadataKeys[key] {
				t.Fatalf("%s metadata keeps non-allowlisted key %q", finding.Tool, key)
			}
		}
	}
	if gitleaks[0].Metadata["Commit"] != "abc" || trufflehog[0].Metadata["DetectorName"] != "AWS" {
		t.Fatal("allowlisted fields were dropped")
	}
}

// A dedicated HIBOU_SECRET_HASH_KEY decouples secret_hash from the session
// secret: rotating the session secret then leaves hashes unchanged.
func TestHashSecretPrefersDedicatedKey(t *testing.T) {
	t.Cleanup(func() {
		pepperMu.Lock()
		hashKey, hashKeySet, sessionSecret, sessionSecretSet, pepperValue = "", false, "", false, nil
		pepperMu.Unlock()
	})
	SetHashKey("")
	SetHashPepperSource("session-one")
	sessionOne := HashSecret("AKIAIOSFODNN7EXAMPLE")
	SetHashPepperSource("session-two")
	if HashSecret("AKIAIOSFODNN7EXAMPLE") == sessionOne {
		t.Fatal("without a dedicated key the session secret must key the hash")
	}

	SetHashKey("dedicated-key")
	withKey := HashSecret("AKIAIOSFODNN7EXAMPLE")
	SetHashPepperSource("session-three")
	if HashSecret("AKIAIOSFODNN7EXAMPLE") != withKey {
		t.Fatal("rotating the session secret changed the hash despite a dedicated key")
	}
	if withKey == sessionOne {
		t.Fatal("dedicated key ignored")
	}
	// Setting the dedicated key to the current session secret keeps hashes.
	SetHashKey("session-one")
	if HashSecret("AKIAIOSFODNN7EXAMPLE") != sessionOne {
		t.Fatal("a dedicated key equal to the old session secret must keep the old hashes")
	}

	// Without SetHashKey, the environment variable is read.
	pepperMu.Lock()
	hashKey, hashKeySet, pepperValue = "", false, nil
	pepperMu.Unlock()
	t.Setenv(SecretHashKeyEnv, "dedicated-key")
	if HashSecret("AKIAIOSFODNN7EXAMPLE") != withKey {
		t.Fatal(SecretHashKeyEnv + " not used as the pepper source")
	}
}
