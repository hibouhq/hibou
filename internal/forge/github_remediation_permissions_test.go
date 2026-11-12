package forge

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGitHubManagedPublicationChecksFullPermissionsBeforeWrites(t *testing.T) {
	for _, permission := range []map[string]string{
		{"contents": "read", "pull_requests": "write"},
		{"contents": "write", "pull_requests": "read"},
	} {
		g := NewGitHub("client", "secret", "", WithTier(TierPropose))
		g.appID = 1
		g.ownerInstallations = map[string]cachedInstallation{"acme": {installation: githubInstallation{Permissions: permission}, expiresAt: time.Now().Add(time.Hour)}}
		_, err := g.PublishRemediation(context.Background(), "acme", "app", AtomicRemediationRequest{Branch: "hibou/fix-main-test"})
		if !errors.Is(err, ErrInstallationLacksPermission) {
			t.Fatalf("insufficient installation was not rejected before any API operation: %v", err)
		}
	}
	for _, tier := range []Tier{TierUnset, TierRead, TierReport} {
		g := NewGitHub("client", "secret", "", WithTier(tier))
		g.appID = 1
		if err := g.CheckRemediationPublication(context.Background(), "acme", "app"); err == nil {
			t.Fatalf("tier %s advertised publication", tier)
		}
	}
}
