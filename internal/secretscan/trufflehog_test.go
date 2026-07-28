package secretscan

import "testing"

// ADR-010: metadata is persisted verbatim into the finding, so the raw secret
// (Raw/RawV2) must never survive parsing.
func TestParseTruffleHogReportStripsRawSecretFromMetadata(t *testing.T) {
	content := []byte(`{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","RawV2":"AKIAIOSFODNN7EXAMPLE:extra","Redacted":"AKIA****","Verified":true,"SourceMetadata":{"Data":{"git":{"file":"config/prod.env","commit":"abc123","email":"dev@example.com","line":3,"start_line":3,"end_line":3}}}}`)

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}

	finding := findings[0]
	if finding.SecretHash != HashSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("SecretHash must be the hash of the bare secret")
	}
	for _, key := range []string{"Raw", "RawV2"} {
		if value, ok := finding.Metadata[key]; ok {
			t.Fatalf("Metadata[%s] = %v — raw secret material persisted", key, value)
		}
	}
	// The tool's own redaction is safe to keep for display.
	if finding.Metadata["Redacted"] != "AKIA****" {
		t.Fatalf("Metadata[Redacted] = %v, want the redacted preview kept", finding.Metadata["Redacted"])
	}
}

// Real trufflehog stdout can interleave banner/log lines with JSONL findings.
func TestParseTruffleHogReportSkipsNonJSONNoise(t *testing.T) {
	content := []byte("TruffleHog. Unearth your secrets.\n" +
		`{"DetectorName":"Slack","Raw":"xoxb-fake","Verified":false,"SourceMetadata":{"Data":{"git":{"file":"app.js","line":5,"start_line":5}}}}` +
		"\nscan finished\n")

	findings, err := ParseTruffleHogReport(content)
	if err != nil {
		t.Fatalf("ParseTruffleHogReport returned error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "Slack" {
		t.Fatalf("findings = %+v, want the single Slack finding", findings)
	}
}

// Cross-tool dedup depends on gitleaks and trufflehog hashing identical bytes
// for the same leak: gitleaks now prefers the bare Secret over Match, and
// trufflehog hashes Raw.
func TestGitleaksAndTruffleHogAgreeOnSecretHash(t *testing.T) {
	gitleaksFindings, err := ParseGitleaksReport([]byte(`[{"RuleID":"aws-access-key-id","Description":"AWS","File":"config/prod.env","StartLine":3,"EndLine":3,"Match":"AWS_KEY=AKIAIOSFODNN7EXAMPLE","Secret":"AKIAIOSFODNN7EXAMPLE","Tags":["critical"]}]`))
	if err != nil {
		t.Fatalf("ParseGitleaksReport: %v", err)
	}
	trufflehogFindings, err := ParseTruffleHogReport([]byte(`{"DetectorName":"AWS","Raw":"AKIAIOSFODNN7EXAMPLE","Verified":false,"SourceMetadata":{"Data":{"git":{"file":"config/prod.env","line":3,"start_line":3}}}}`))
	if err != nil {
		t.Fatalf("ParseTruffleHogReport: %v", err)
	}
	if len(gitleaksFindings) != 1 || len(trufflehogFindings) != 1 {
		t.Fatalf("findings = %d/%d, want 1/1", len(gitleaksFindings), len(trufflehogFindings))
	}
	if gitleaksFindings[0].SecretHash != trufflehogFindings[0].SecretHash {
		t.Fatal("tools hash different bytes for the same leak; cross-tool dedup broken")
	}
	if gitleaksFindings[0].Fingerprint != trufflehogFindings[0].Fingerprint {
		t.Fatal("same file/line/secret must produce the same fingerprint across tools")
	}
}
