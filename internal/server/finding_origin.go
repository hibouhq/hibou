package server

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// findingOrigin is the provenance stamped on a finding at creation (ADR-020).
// It is derived from the authenticated principal and never from the request
// body, so a caller cannot pass itself off as a scanner, as another user, or as
// a different token.
type findingOrigin struct {
	Origin    dbgen.FindingOrigin
	APIKeyID  uuid.NullUUID
	TokenName string
	OwnerType string
	OwnerID   uuid.NullUUID
	CreatedBy uuid.NullUUID
}

// resolveFindingOrigin classifies the caller. A bearer token is an agent —
// including a legacy unscoped one, since "acting through a token" is what the
// distinction is about, not whether the token happens to carry a scope. Anything
// else authenticated is a human. Ingested tool reports never come through here;
// they default to scanner in the store.
func resolveFindingOrigin(ctx context.Context, user *store.User) findingOrigin {
	origin := findingOrigin{Origin: dbgen.FindingOriginHuman}
	if user != nil {
		origin.CreatedBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}

	tokenAuth := auth.TokenAuthFromContext(ctx)
	if tokenAuth == nil {
		return origin
	}

	origin.Origin = dbgen.FindingOriginAgent
	origin.APIKeyID = uuid.NullUUID{UUID: tokenAuth.KeyID, Valid: true}
	origin.TokenName = tokenAuth.Name
	origin.OwnerType = tokenAuth.OwnerType
	if tokenAuth.OwnerID != uuid.Nil {
		origin.OwnerID = uuid.NullUUID{UUID: tokenAuth.OwnerID, Valid: true}
	}
	return origin
}
