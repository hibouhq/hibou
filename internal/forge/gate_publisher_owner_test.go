package forge

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ownerGuardedGateStore reports every owner as foreign to the repo's org.
type ownerGuardedGateStore struct {
	*gatePublisherStore
	checked []string
}

func (s *ownerGuardedGateStore) ForgeOwnerBoundToOrg(_ context.Context, _ uuid.UUID, owner string) (bool, error) {
	s.checked = append(s.checked, owner)
	return owner == "acme", nil
}

// Audit §3.1: check runs and statuses go out with an installation token minted
// by owner, so a repository row naming another account's repo is never
// published to.
func TestLoadGateRepositoryRefusesForeignOwner(t *testing.T) {
	t.Parallel()

	st := &ownerGuardedGateStore{gatePublisherStore: newGatePublisherStore()}
	own := dbgen.Repository{ID: uuid.New(), OrgID: uuid.New(), Provider: "github", ProviderID: "acme/api"}
	foreign := dbgen.Repository{ID: uuid.New(), OrgID: own.OrgID, Provider: "github", ProviderID: "hibouhq/hibou"}
	st.repos[own.ID] = own
	st.repos[foreign.ID] = foreign
	publisher := NewGatePublisher(map[string]Provider{"github": &mockForgeProvider{}}, nil, nil, st, nil, nil, "", zerolog.New(io.Discard))

	if _, _, _, _, ok := publisher.loadGateRepository(context.Background(), dbgen.Ref{RepoID: own.ID}); !ok {
		t.Fatal("own repository must load")
	}
	if _, _, _, _, ok := publisher.loadGateRepository(context.Background(), dbgen.Ref{RepoID: foreign.ID}); ok {
		t.Fatal("foreign repository must not load")
	}
	if len(st.checked) != 2 {
		t.Fatalf("owner checks = %v", st.checked)
	}
}

// The context guard refuses minting another account's token before any API
// call, and before the token cache is consulted.
func TestCachedInstallationTokenHonoursBoundOwner(t *testing.T) {
	t.Parallel()

	g := &GitHub{ownerTokens: map[string]ownerToken{}}
	g.ownerTokens["hibouhq"] = ownerToken{value: "cached-victim-token"}
	ctx := WithInstallationOwner(context.Background(), "acme")

	if _, err := g.scopedInstallationToken(ctx, "hibouhq", TokenScope{}); err == nil {
		t.Fatal("expected owner mismatch error")
	}
	if err := checkInstallationOwner(ctx, "ACME"); err != nil {
		t.Fatalf("bound owner refused: %v", err)
	}
	if err := checkInstallationOwner(context.Background(), "anyone"); err != nil {
		t.Fatalf("unbound context refused: %v", err)
	}
}
