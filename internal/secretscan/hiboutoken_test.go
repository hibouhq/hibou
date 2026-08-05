package secretscan

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/apitoken"
)

func TestHibouTokenProviderFindsRealTokens(t *testing.T) {
	t.Parallel()

	token, err := apitoken.Generate()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	// Same shape, broken checksum: flip the final character.
	tampered := token[:len(token)-1] + map[bool]string{true: "B", false: "A"}[token[len(token)-1] == 'A']

	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("config.env", "export HIBOU_TOKEN="+token+"\n")
	write("notes.txt", "maybe a token: "+tampered+"\nno tokens here\n")
	write("clean.go", "package main\n")

	provider := NewHibouTokenProvider(zerolog.New(io.Discard))
	findings, err := provider.ScanFilesystem(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanFilesystem: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2 (real + tampered)", len(findings))
	}

	byFile := make(map[string]SecretFinding, len(findings))
	for _, finding := range findings {
		byFile[filepath.Base(finding.FilePath)] = finding
	}

	real, ok := byFile["config.env"]
	if !ok {
		t.Fatal("the real token was not found")
	}
	if !real.Verified {
		t.Fatal("a checksum-valid token must be reported Verified")
	}
	if real.SecretType != "hibou_pat" || real.Severity != "critical" || real.StartLine != 1 {
		t.Fatalf("unexpected finding: %+v", real)
	}
	if real.SecretHash == "" || real.Fingerprint == "" {
		t.Fatal("finding must carry a secret hash and fingerprint for dedup")
	}

	suspect, ok := byFile["notes.txt"]
	if !ok {
		t.Fatal("the tampered token was not found")
	}
	if suspect.Verified {
		t.Fatal("a checksum-invalid match must not be reported Verified")
	}
}

func TestHibouTokenProviderSkipsRepoAndDiffScans(t *testing.T) {
	t.Parallel()

	provider := NewHibouTokenProvider(zerolog.New(io.Discard))
	capabilities := provider.Capabilities()
	if capabilities.FullScan || capabilities.IncrementalScan {
		t.Fatal("provider must not claim repo/diff scan capabilities; the scanner loop would call it and fail")
	}
}
