package repoinventory

import (
	"context"
	"io"
	"testing"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/forge"
)

func TestInventoryPersistsObservedAccountIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		inst *forge.Installation
		repo forge.Repository
		want string
	}{
		{
			name: "slim installation repository",
			inst: &forge.Installation{ID: 10, AccountName: "acme", AccountID: "100"},
			repo: forge.Repository{Owner: "acme", Name: "app", FullName: "acme/app", ProviderRepoID: "42"},
			want: "100",
		},
		{
			name: "repository event",
			repo: forge.Repository{Owner: "acme", OwnerID: "100", Name: "app", FullName: "acme/app", ProviderRepoID: "42"},
			want: "100",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := newFakeStore()
			service := NewService(storage, nil, zerolog.New(io.Discard))
			result, err := service.upsertRepositoryCore(context.Background(), "github", tc.inst, tc.repo, false)
			if err != nil {
				t.Fatal(err)
			}
			if result.Repository.AccountID != tc.want {
				t.Fatalf("persisted account identity=%q want=%q", result.Repository.AccountID, tc.want)
			}
		})
	}
}
