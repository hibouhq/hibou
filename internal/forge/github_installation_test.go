package forge

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testAppKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// Audit §3.4: provisioning re-reads installations from the App API; the
// lookup must surface the immutable account id, suspension, and a distinct
// not-found error.
func TestGetInstallationAccount(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/7":
			_, _ = w.Write([]byte(`{"id":7,"account":{"id":42,"login":"Acme","type":"Organization"}}`))
		case "/app/installations/8":
			_, _ = w.Write([]byte(`{"id":8,"account":{"id":43,"login":"paused","type":"User"},"suspended_at":"2026-01-01T00:00:00Z"}`))
		case "/app/installations":
			_, _ = w.Write([]byte(`[{"id":7,"account":{"id":42,"login":"Acme"}}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	g := NewGitHub("client", "secret", "webhook", WithAPIURL(server.URL), WithAppCredentials(1, testAppKeyPEM(t)))
	ctx := context.Background()

	account, err := g.GetInstallationAccount(ctx, 7)
	if err != nil {
		t.Fatalf("GetInstallationAccount(7): %v", err)
	}
	if account.AccountID != "42" || account.AccountLogin != "Acme" || account.Suspended {
		t.Fatalf("account = %+v", account)
	}
	if account, err := g.GetInstallationAccount(ctx, 8); err != nil || !account.Suspended {
		t.Fatalf("GetInstallationAccount(8) = %+v, %v; want suspended", account, err)
	}
	if _, err := g.GetInstallationAccount(ctx, 9); !errors.Is(err, ErrInstallationNotFound) {
		t.Fatalf("GetInstallationAccount(9) error = %v, want ErrInstallationNotFound", err)
	}

	ids, err := g.InstallationAccountIDs(ctx)
	if err != nil || ids["acme"] != "42" {
		t.Fatalf("InstallationAccountIDs() = %v, %v", ids, err)
	}
}
