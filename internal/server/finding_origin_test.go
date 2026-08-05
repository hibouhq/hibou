package server

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/auth"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

func TestResolveFindingOriginHuman(t *testing.T) {
	t.Parallel()

	user := &store.User{ID: uuid.New()}
	origin := resolveFindingOrigin(context.Background(), user)

	if origin.Origin != dbgen.FindingOriginHuman {
		t.Fatalf("origin = %q, want %q", origin.Origin, dbgen.FindingOriginHuman)
	}
	if !origin.CreatedBy.Valid || origin.CreatedBy.UUID != user.ID {
		t.Fatalf("created_by = %+v, want %s", origin.CreatedBy, user.ID)
	}
	if origin.APIKeyID.Valid || origin.TokenName != "" || origin.OwnerType != "" {
		t.Fatalf("session origin carried token provenance: %+v", origin)
	}
}

func TestResolveFindingOriginAgent(t *testing.T) {
	t.Parallel()

	user := &store.User{ID: uuid.New()}
	keyID := uuid.New()
	ownerID := uuid.New()

	for _, tc := range []struct {
		name   string
		scoped bool
	}{
		{"scoped token", true},
		{"legacy unscoped token", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := auth.WithTokenAuth(context.Background(), &auth.TokenAuth{
				KeyID:     keyID,
				Name:      "release-bot",
				OwnerType: "org",
				OwnerID:   ownerID,
				Scoped:    tc.scoped,
			})
			origin := resolveFindingOrigin(ctx, user)

			if origin.Origin != dbgen.FindingOriginAgent {
				t.Fatalf("origin = %q, want %q", origin.Origin, dbgen.FindingOriginAgent)
			}
			if !origin.APIKeyID.Valid || origin.APIKeyID.UUID != keyID {
				t.Fatalf("api key = %+v, want %s", origin.APIKeyID, keyID)
			}
			if origin.TokenName != "release-bot" {
				t.Fatalf("token name = %q, want %q", origin.TokenName, "release-bot")
			}
			if origin.OwnerType != "org" || !origin.OwnerID.Valid || origin.OwnerID.UUID != ownerID {
				t.Fatalf("owner = %q/%+v, want org/%s", origin.OwnerType, origin.OwnerID, ownerID)
			}
			// The accountable human behind the token is still recorded.
			if !origin.CreatedBy.Valid || origin.CreatedBy.UUID != user.ID {
				t.Fatalf("created_by = %+v, want %s", origin.CreatedBy, user.ID)
			}
		})
	}
}

func TestManualFindingFingerprintIsStableAndDistinct(t *testing.T) {
	t.Parallel()

	base := manualFindingFingerprint("manual/sqli", "internal/db/user.go", 42, "SQL injection")
	if base != manualFindingFingerprint("manual/sqli", "internal/db/user.go", 42, "SQL injection") {
		t.Fatal("fingerprint is not stable for identical input")
	}

	for _, other := range []string{
		manualFindingFingerprint("manual/xss", "internal/db/user.go", 42, "SQL injection"),
		manualFindingFingerprint("manual/sqli", "internal/db/other.go", 42, "SQL injection"),
		manualFindingFingerprint("manual/sqli", "internal/db/user.go", 43, "SQL injection"),
		manualFindingFingerprint("manual/sqli", "internal/db/user.go", 42, "XSS"),
	} {
		if other == base {
			t.Fatal("fingerprint collided across distinct findings")
		}
	}
}

func TestManualFindingSeverity(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"critical", "HIGH", " medium ", "low", "info", "informational"} {
		if _, err := manualFindingSeverity(valid); err != nil {
			t.Fatalf("severity %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "blocker", "none"} {
		if _, err := manualFindingSeverity(invalid); err == nil {
			t.Fatalf("severity %q accepted, want rejection", invalid)
		}
	}
}
