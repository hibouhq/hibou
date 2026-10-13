package secretscan

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// fakeGit installs a "git" on PATH that records its argv and environment and
// fails, so clone hardening can be checked without network or a real repo.
func fakeGit(t *testing.T) (argsFile, envFile string) {
	t.Helper()
	binDir := t.TempDir()
	argsFile = filepath.Join(binDir, "args")
	envFile = filepath.Join(binDir, "env")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argsFile + "\nenv > " + envFile + "\necho 'fatal: could not read from https://x-access-token:ghp_abcdefghijklmnopqrstuvwxyz0123@github.com/acme/repo' >&2\nexit 128\n"
	if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return argsFile, envFile
}

func TestCloneKeepsTokenOutOfArgvAndSecretsOutOfEnv(t *testing.T) {
	argsFile, envFile := fakeGit(t)
	t.Setenv("HIBOU_DATABASE_URL", "postgres://hibou:dbpass@db/hibou")
	t.Setenv("HIBOU_GITHUB_APP_PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----")
	token := "ghs_installationtoken1234567890"

	_, _, err := cloneRepositoryOptions(context.Background(), t.TempDir(), "https://user:old@github.com/acme/repo.git", "main", token, 0, false)
	if err == nil {
		t.Fatal("expected fake git to fail the clone")
	}
	if strings.Contains(err.Error(), "ghp_abcdefghijklmnopqrstuvwxyz0123") || strings.Contains(err.Error(), token) {
		t.Fatalf("expected token to be scrubbed from error, got %v", err)
	}

	args, _ := os.ReadFile(argsFile)
	if strings.Contains(string(args), token) || strings.Contains(string(args), "user:old") {
		t.Fatalf("expected no credentials in argv, got %q", args)
	}
	if !strings.Contains(string(args), "--\nhttps://github.com/acme/repo.git\n") {
		t.Fatalf("expected '--' before the credential-free clone URL, got %q", args)
	}

	env, _ := os.ReadFile(envFile)
	envText := string(env)
	for _, forbidden := range []string{"HIBOU_DATABASE_URL", "HIBOU_GITHUB_APP_PRIVATE_KEY"} {
		if strings.Contains(envText, forbidden) {
			t.Fatalf("expected %s not to reach git, env:\n%s", forbidden, envText)
		}
	}
	wantHeader := "GIT_CONFIG_VALUE_0=Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	for _, want := range []string{"GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_KEY_0=http.https://github.com/.extraHeader", wantHeader} {
		if !strings.Contains(envText, want+"\n") {
			t.Fatalf("expected %q in git env:\n%s", want, envText)
		}
	}
	for _, line := range strings.Split(envText, "\n") {
		if home, ok := strings.CutPrefix(line, "HOME="); ok && filepath.Base(home) != scanHomeDirName {
			t.Fatalf("expected private scanner HOME, got %q", home)
		}
	}
}

func TestScannerEnvIsAllowlisted(t *testing.T) {
	t.Setenv("HIBOU_SESSION_SECRET", "s3cret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws")
	env := strings.Join(scannerEnv("/scratch/home"), "\n") + "\n"
	for _, forbidden := range []string{"HIBOU_SESSION_SECRET", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(env, forbidden) {
			t.Fatalf("expected %s to be dropped, got:\n%s", forbidden, env)
		}
	}
	for _, want := range []string{"HOME=/scratch/home\n", "GIT_TERMINAL_PROMPT=0\n", "PATH="} {
		if !strings.Contains(env, want) {
			t.Fatalf("expected %q in env:\n%s", want, env)
		}
	}
	if strings.Contains(env, "GIT_CONFIG_COUNT") {
		t.Fatal("expected no git auth config without a token")
	}
}

func TestGitAuthEnvRequiresHTTPURL(t *testing.T) {
	if _, err := gitAuthEnv("git@github.com:acme/repo.git", "tok"); err == nil {
		t.Fatal("expected scp-style URL to be refused for token auth")
	}
	if _, err := gitAuthEnv("ext::sh -c touch% /tmp/pwned", "tok"); err == nil {
		t.Fatal("expected ext:: URL to be refused for token auth")
	}
	if env, err := gitAuthEnv("https://github.com/acme/repo.git", ""); err != nil || env != nil {
		t.Fatalf("expected no auth env without token, got %v, %v", env, err)
	}
}

func TestScrubSecrets(t *testing.T) {
	in := "fatal: https://x-access-token:ghs_abc123secretvalue@github.com/a/b\nAuthorization: Basic eC1hY2Nlc3M=\ntoken ghp_abcdefghijklmnopqrstuvwxyz and mysecrettoken"
	out := scrubSecrets(in, "mysecrettoken")
	for _, leaked := range []string{"ghs_abc123secretvalue", "eC1hY2Nlc3M=", "ghp_abcdefghijklmnopqrstuvwxyz", "mysecrettoken"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("expected %q to be scrubbed, got %q", leaked, out)
		}
	}
}

func TestValidateCommitRange(t *testing.T) {
	good := strings.Repeat("a", 40)
	if err := validateCommitRange(good, strings.Repeat("0", 64)); err != nil {
		t.Fatalf("expected full SHAs to pass, got %v", err)
	}
	if err := validateCommitRange("", good); err != nil {
		t.Fatalf("expected empty base to pass, got %v", err)
	}
	for _, bad := range []string{"--all", "HEAD", "abc123", good + " --output=/tmp/x", strings.ToUpper(good), good[:39] + "g"} {
		if err := validateCommitRange(bad, good); err == nil {
			t.Errorf("expected base %q to be rejected", bad)
		}
		if err := validateCommitRange(good, bad); err == nil {
			t.Errorf("expected head %q to be rejected", bad)
		}
	}
}

func TestScanDiffRejectsInvalidRangeBeforeCloning(t *testing.T) {
	argsFile, _ := fakeGit(t)
	opts := ScanDiffOptions{CloneURL: "https://github.com/acme/repo.git", FromCommit: "--output=/tmp/pwn", ToCommit: strings.Repeat("b", 40), TempDir: t.TempDir()}
	providers := []SecretScanProvider{
		&GitleaksProvider{bin: "gitleaks"},
		&BetterleaksProvider{bin: "betterleaks"},
		&TruffleHogProvider{bin: "trufflehog"},
	}
	for _, provider := range providers {
		if _, err := provider.ScanDiff(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "invalid diff base commit") {
			t.Fatalf("%s: expected invalid range error, got %v", provider.Name(), err)
		}
	}
	if _, err := os.Stat(argsFile); !os.IsNotExist(err) {
		t.Fatal("expected no git invocation for an invalid range")
	}
}

func TestLoadFirstLocationPinsAPIHost(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte("[]"))
	}))
	defer other.Close()

	provider := NewGitHubProvider(other.Client(), "https://api.github.com", zerolog.Nop())
	if _, _, _, err := provider.loadFirstLocation(context.Background(), other.URL+"/locations", "secret-token"); err == nil {
		t.Fatal("expected off-host locations_url to be refused")
	}
	if hits != 0 {
		t.Fatal("expected no request (and no bearer token) to reach the foreign host")
	}
	for _, candidate := range []string{"https://api.github.com.evil.example/x", "http://api.github.com/x", "https://user@api.github.com/x"} {
		if sameOrigin(candidate, "https://api.github.com") {
			t.Errorf("expected %q not to match the API origin", candidate)
		}
	}
	if !sameOrigin("https://API.github.com/repos/a/b/secret-scanning/alerts/1/locations", "https://api.github.com") {
		t.Error("expected same-origin locations_url to match")
	}
}

// The forge token goes only to https clone URLs; plain http is allowed for a
// development instance (local forge) only.
func TestGitAuthEnvRefusesPlainHTTPOutsideDevelopment(t *testing.T) {
	t.Cleanup(func() {
		devMu.Lock()
		devSet, devOn = false, false
		devMu.Unlock()
	})
	SetDevelopment(false)
	if env, err := gitAuthEnv("http://forge.internal/acme/repo.git", "tok"); err == nil || env != nil {
		t.Fatalf("http clone URL got the token outside development: %v, %v", env, err)
	}
	if _, err := gitAuthEnv("HTTP://forge.internal/acme/repo.git", "tok"); err == nil {
		t.Fatal("upper-case HTTP scheme got the token outside development")
	}
	if env, err := gitAuthEnv("https://forge.internal/acme/repo.git", "tok"); err != nil || len(env) == 0 {
		t.Fatalf("https clone URL refused: %v, %v", env, err)
	}
	SetDevelopment(true)
	if env, err := gitAuthEnv("http://localhost:3000/acme/repo.git", "tok"); err != nil || len(env) == 0 {
		t.Fatalf("development http clone URL refused: %v, %v", env, err)
	}

	devMu.Lock()
	devSet = false
	devMu.Unlock()
	t.Setenv("HIBOU_DEVELOPMENT", "false")
	if _, err := gitAuthEnv("http://forge.internal/acme/repo.git", "tok"); err == nil {
		t.Fatal("env HIBOU_DEVELOPMENT=false allowed http")
	}
	t.Setenv("HIBOU_DEVELOPMENT", "true")
	if _, err := gitAuthEnv("http://forge.internal/acme/repo.git", "tok"); err != nil {
		t.Fatalf("env HIBOU_DEVELOPMENT=true refused http: %v", err)
	}
}
