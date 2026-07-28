package secretscan

import "testing"

func TestParseBetterleaksReport(t *testing.T) {
	content := []byte(`[
		{
			"RuleID": "aws-access-key-id",
			"Description": "AWS Access Key ID",
			"File": "config/prod.env",
			"StartLine": 3,
			"EndLine": 3,
			"Commit": "abc123def456",
			"Email": "dev@example.com",
			"Match": "AWS_KEY=AKIAIOSFODNN7EXAMPLE",
			"Secret": "AKIAIOSFODNN7EXAMPLE",
			"MatchContext": "line above\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nline below",
			"CaptureGroups": {"key": "AKIAIOSFODNN7EXAMPLE"},
			"RequiredSets": [{"components": [{"RuleID": "aws-secret", "Secret": "wJalrXUtnFEMI"}]}],
			"Tags": ["critical", "aws"],
			"ValidationStatus": "valid",
			"ValidationReason": "authenticated as arn:aws:iam::123:user/dev"
		},
		{
			"RuleID": "slack-webhook",
			"Description": "Slack webhook",
			"File": "scripts/deploy.sh",
			"StartLine": 12,
			"EndLine": 12,
			"Secret": "https://hooks.slack.com/services/T000/B000/XXXX",
			"Tags": ["high"],
			"ValidationStatus": "revoked"
		},
		{
			"RuleID": "generic-api-key",
			"File": "app/settings.py",
			"StartLine": 7,
			"EndLine": 7,
			"Secret": "sk-plainfinding",
			"Tags": ["medium"]
		}
	]`)

	findings, err := ParseBetterleaksReport(content)
	if err != nil {
		t.Fatalf("ParseBetterleaksReport returned error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3", len(findings))
	}

	valid := findings[0]
	if valid.Tool != "betterleaks" || valid.RuleID != "aws-access-key-id" {
		t.Fatalf("attribution = %s/%s", valid.Tool, valid.RuleID)
	}
	// A "valid" verdict means the credential authenticated live: critical.
	if !valid.Verified || valid.Severity != "critical" {
		t.Fatalf("verified/severity = %v/%s, want true/critical", valid.Verified, valid.Severity)
	}
	// Same bare secret as the gitleaks/trufflehog fixtures — cross-tool dedup
	// depends on identical hash + fingerprint.
	if valid.SecretHash != HashSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("SecretHash differs from the bare-secret hash the other tools produce")
	}
	if valid.Fingerprint != ComputeFingerprint("config/prod.env", 3, valid.SecretHash) {
		t.Fatal("Fingerprint not computed from file/line/hash")
	}
	if valid.CommitSHA != "abc123def456" || valid.AuthorEmail != "dev@example.com" {
		t.Fatalf("git attribution = %s/%s", valid.CommitSHA, valid.AuthorEmail)
	}

	// A confirmed-dead credential is hygiene, not an incident.
	revoked := findings[1]
	if revoked.Verified || revoked.Severity != "low" {
		t.Fatalf("revoked severity = %s (verified=%v), want low/false", revoked.Severity, revoked.Verified)
	}

	// No validation verdict: severity falls back to the rule's tags.
	plain := findings[2]
	if plain.Severity != "medium" {
		t.Fatalf("unvalidated severity = %s, want medium from tags", plain.Severity)
	}

	// ADR-010: nothing carrying raw secret material may survive into metadata.
	for index, finding := range findings {
		for _, key := range []string{"Match", "Secret", "MatchContext", "CaptureGroups", "Fragment", "RequiredSets"} {
			if value, ok := finding.Metadata[key]; ok {
				t.Fatalf("findings[%d].Metadata[%s] = %v — raw secret material persisted", index, key, value)
			}
		}
	}
	// The validation verdict itself is safe and useful — it must survive.
	if findings[0].Metadata["ValidationStatus"] != "valid" {
		t.Fatal("ValidationStatus stripped from metadata; the verdict should be kept")
	}
}

func TestParseBetterleaksReportEmpty(t *testing.T) {
	for _, content := range []string{"", " \n\t ", "[]"} {
		findings, err := ParseBetterleaksReport([]byte(content))
		if err != nil {
			t.Fatalf("ParseBetterleaksReport(%q) returned error: %v", content, err)
		}
		if findings != nil {
			t.Fatalf("findings = %#v, want nil", findings)
		}
	}
}

func TestParseBetterleaksReportSkipsEmptySecret(t *testing.T) {
	findings, err := ParseBetterleaksReport([]byte(`[{"RuleID":"x","File":"a.txt","StartLine":1,"Secret":"","Match":""}]`))
	if err != nil {
		t.Fatalf("ParseBetterleaksReport returned error: %v", err)
	}
	if findings != nil {
		t.Fatalf("findings = %#v, want nil", findings)
	}
}
