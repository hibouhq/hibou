package forge

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPollingTokensUseImmutableIdentity(t *testing.T) {
	g, fake := newTokenTestGitHub(t, reportInstallation, TierRead)
	ctx := WithRepositoryIdentity(context.Background(), "42", "314")
	token, err := g.scopedInstallationToken(ctx, "acme", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "read"}})
	if err != nil || token == "" {
		t.Fatalf("identity-scoped token=%q %v", token, err)
	}
	if len(fake.requests) != 1 || len(fake.requests[0].Repositories) != 0 || !reflect.DeepEqual(fake.requests[0].RepositoryIDs, []int64{314}) {
		t.Fatalf("token request was not confined by immutable repository ID: %+v", fake.requests)
	}
	_, err = g.scopedInstallationToken(WithRepositoryIdentity(context.Background(), "999", "314"), "acme", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "read"}})
	if err == nil {
		t.Fatal("cached owner installation bypassed immutable account check")
	}
	if len(fake.requests) != 1 {
		t.Fatal("account mismatch minted a token")
	}
	_, err = g.scopedInstallationToken(WithRepositoryIdentity(context.Background(), "42", "bad"), "acme", TokenScope{Repo: "app", Permissions: map[string]string{"contents": "read"}})
	if err == nil || errors.Is(err, ErrTierForbids) {
		t.Fatalf("invalid repository identity=%v", err)
	}
}
