package repoconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
)

// Audit §3.1: onboarding writes a branch and opens a PR with an installation
// token minted by owner, so it refuses owners outside the org's account.
func TestCreateOnboardingPRForOrgRefusesForeignOwner(t *testing.T) {
	t.Parallel()

	svc := NewOnboardingService(nil, zerolog.Nop())
	org := &store.Organization{Slug: "acme", ForgeAccountLogin: "acme"}

	if _, err := svc.CreateOnboardingPRForOrg(context.Background(), org, "github", "hibouhq", "hibou", "main"); !errors.Is(err, ErrForeignRepository) {
		t.Fatalf("foreign owner error = %v, want ErrForeignRepository", err)
	}
	// Own owner passes the guard and reaches the (unconfigured) provider.
	if _, err := svc.CreateOnboardingPRForOrg(context.Background(), org, "github", "acme", "api", "main"); err == nil || errors.Is(err, ErrForeignRepository) {
		t.Fatalf("own owner error = %v, want provider-not-configured", err)
	}
}
