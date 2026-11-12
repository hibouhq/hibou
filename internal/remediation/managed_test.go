package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManagedArtifactFailsClosed(t *testing.T) {
	patch := []byte("verified patch")
	sum := sha256.Sum256(patch)
	data := []byte("new")
	after := sha256.Sum256(data)
	request := ManagedInput{BaseSHA: strings.Repeat("a", 40), Units: []Unit{{ID: ".", WritableFiles: []string{"package-lock.json"}}}}
	valid := func() *Artifact {
		return &Artifact{
			BaseSHA: request.BaseSHA, SHA256: hex.EncodeToString(sum[:]), Patch: slices.Clone(patch),
			Changes: []Change{{Path: "package-lock.json", Before: strings.Repeat("b", 64), After: hex.EncodeToString(after[:])}},
			Units:   []UnitResult{{ID: "."}}, Verification: []Verification{{true, true, true}},
		}
	}
	if err := ValidateManagedArtifact(request, valid()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Artifact){
		"failed relock":            func(a *Artifact) { a.Verification[0].DependencyFilesConsistent = false },
		"unresolved selected":      func(a *Artifact) { a.Verification[0].SelectedVulnsAddressed = false },
		"introduced vulnerability": func(a *Artifact) { a.Verification[0].NoIntroducedVulns = false },
		"stale base":               func(a *Artifact) { a.BaseSHA = strings.Repeat("c", 40) },
		"corrupted patch":          func(a *Artifact) { a.Patch[0] = 'x' },
		"unselected file":          func(a *Artifact) { a.Changes[0].Path = "README.md" },
		"missing verification":     func(a *Artifact) { a.Verification = nil },
	} {
		t.Run(name, func(t *testing.T) {
			a := valid()
			mutate(a)
			if ValidateManagedArtifact(request, a) == nil {
				t.Fatal("unverified artifact accepted")
			}
		})
	}
	if err := ValidateManagedFiles(valid(), map[string][]byte{"package-lock.json": data}); err != nil {
		t.Fatal(err)
	}
	if ValidateManagedFiles(valid(), map[string][]byte{"package-lock.json": []byte("tampered")}) == nil {
		t.Fatal("publication bytes not verified")
	}
}

func TestManagedBrokerMatchingAndPrivateNamespace(t *testing.T) {
	root := t.TempDir()
	socket := filepath.Join(root, "broker.sock")
	match := func(_ context.Context, ids []string) ([]AdvisoryMatch, error) {
		var result []AdvisoryMatch
		for _, id := range ids {
			private := strings.Contains(id, "private")
			result = append(result, AdvisoryMatch{Purl: id, Supported: true, PrivateNamespace: &private, Decision: "allow"})
		}
		return result, nil
	}
	broker, err := StartJobBroker(context.Background(), socket, match)
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	info, err := os.Stat(socket)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unsafe socket: %v %v", info, err)
	}
	result, err := JobMatchClient(socket)(context.Background(), []string{"pkg:npm/test@1.0.0"})
	if err != nil || len(result) != 1 || result[0].PrivateNamespace == nil {
		t.Fatalf("identity response: %v %v", result, err)
	}
	if _, err := JobMatchClient(socket)(context.Background(), []string{"https://example.com"}); err == nil {
		t.Fatal("non-identity accepted")
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://registry.npmjs.org/@private/package", nil)
	response, err := JobRegistryClient(socket).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("private namespace forwarded: %d", response.StatusCode)
	}
	for _, raw := range []string{"https://evil.example/package", "http://registry.npmjs.org/package", "https://registry.npmjs.org:443/package"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, nil)
		resp, err := JobRegistryClient(socket).Do(req)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err == nil {
			t.Fatalf("unapproved origin forwarded: %s", raw)
		}
	}
}

func TestManagedBrokerEvidenceFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "broker.sock")
	broker, err := StartJobBroker(context.Background(), socket, func(context.Context, []string) ([]AdvisoryMatch, error) { return nil, errors.New("database down") })
	if err != nil {
		t.Fatal(err)
	}

	defer broker.Close()
	if _, err := JobMatchClient(socket)(context.Background(), []string{"pkg:npm/test@1.0.0"}); !errors.Is(err, ErrAdvisoryEvidence) {
		t.Fatalf("matching failure not propagated: %v", err)
	}
}
