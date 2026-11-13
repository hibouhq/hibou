package remediation

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"deps.dev/util/resolve"
)

func TestProxyRejectsPrivateNamespaceBeforeUpstream(t *testing.T) {
	var calls atomic.Int32
	match := func(_ context.Context, purls []string) ([]AdvisoryMatch, error) {
		calls.Add(1)
		private := true
		return []AdvisoryMatch{{Purl: purls[0], Supported: true, PrivateNamespace: &private}}, nil
	}
	proxy, err := startNPMProxy(t.Context(), match)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.close() }()
	resp, err := http.Get(proxy.URL + "@private%2fdependency")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || calls.Load() != 1 {
		t.Fatalf("private namespace was not blocked: %d (%d lookups)", resp.StatusCode, calls.Load())
	}
	if err := proxy.close(); err == nil {
		t.Fatal("proxy failure was not retained")
	}
}

func TestProxyRequiresJobNonce(t *testing.T) {
	var calls atomic.Int32
	proxy, err := startNPMProxy(t.Context(), func(context.Context, []string) ([]AdvisoryMatch, error) {
		calls.Add(1)
		return nil, errors.New("must not be called")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.close() }()
	u, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/wrong-nonce/package"
	resp, err := http.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || calls.Load() != 0 {
		t.Fatal("unauthenticated proxy request was processed")
	}
}

func TestMetadataCannotRedirectNativeFetches(t *testing.T) {
	for _, input := range []string{
		`{"dist":{"tarball":"https://unapproved.example/package.tgz"}}`,
		`{"dependencies":{"private":"git+ssh://unapproved.example/repo"}}`,
		`{"versions":{"1.0.0":{"optionalDependencies":{"local":"file:../local"}}}}`,
	} {
		if _, err := checkedNPMMetadata([]byte(input)); err == nil {
			t.Fatalf("unsafe registry metadata accepted: %s", input)
		}
	}
	data, err := checkedNPMMetadata([]byte(`{"dist":{"tarball":"http://registry.npmjs.org/public/-/public-1.tgz"}}`))
	if err != nil || !strings.Contains(string(data), "https://registry.npmjs.org/") {
		t.Fatalf("canonical transport upgrade failed: %s %v", data, err)
	}
}

func TestEphemeralRegistryLocationsNeverEnterArtifact(t *testing.T) {
	root := t.TempDir()
	prefix := "http://127.0.0.1:1234/private-job-nonce/"
	_, lock := npmFixture(t, "1.0.1", "~1.0.1")
	lock = strings.ReplaceAll(lock, "https://registry.npmjs.org/", prefix)
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := canonicalizeProxyLocations(root, testUnit(), prefix, ""); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if err != nil || strings.Contains(string(data), "private-job-nonce") || strings.Contains(string(data), "127.0.0.1") {
		t.Fatalf("ephemeral registry leaked into output: %s %v", data, err)
	}
}

type namespaceCountingClient struct {
	resolve.Client
	calls *atomic.Int32
}

func (c namespaceCountingClient) Versions(context.Context, resolve.PackageKey) ([]resolve.Version, error) {
	c.calls.Add(1)
	return nil, nil
}

func TestMetadataResolverChecksNamespaceBeforeRegistry(t *testing.T) {
	var calls atomic.Int32
	private := true
	client := &namespaceGuardResolver{
		Client: namespaceCountingClient{calls: &calls},
		match: func(_ context.Context, purls []string) ([]AdvisoryMatch, error) {
			return []AdvisoryMatch{{Purl: purls[0], Supported: true, PrivateNamespace: &private}}, nil
		}, checked: map[string]bool{},
	}
	if _, err := client.Versions(t.Context(), resolve.PackageKey{System: resolve.NPM, Name: "@private/dependency"}); err == nil || calls.Load() != 0 {
		t.Fatal("private package reached the registry")
	}
}

func TestProxyRejectsUnexpectedMethods(t *testing.T) {
	proxy, err := startNPMProxy(t.Context(), npmMatchFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = proxy.close() }()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, proxy.URL+"package", strings.NewReader("no"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("unexpected method accepted")
	}
}
