package store

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hibouhq/hibou/internal/apitoken"
)

func TestAPIKeyScope(t *testing.T) {
	expected := apitoken.Scope{
		Owner: apitoken.Owner{
			Type: apitoken.OwnerUser,
			ID:   "user-1",
		},
		Org: "org-1",
		Repos: apitoken.RepoSelector{
			Mode: apitoken.RepoAll,
		},
		Permissions: map[apitoken.Capability]apitoken.AccessLevel{
			apitoken.CapCoverage: apitoken.AccessRead,
		},
	}

	tests := []struct {
		name   string
		scopes json.RawMessage
		want   apitoken.Scope
	}{
		{name: "empty"},
		{name: "null", scopes: json.RawMessage("null")},
		{
			name:   "valid scope",
			scopes: json.RawMessage(`{"owner":{"type":"user","id":"user-1"},"org":"org-1","repos":{"mode":"all"},"permissions":{"coverage":"read"}}`),
			want:   expected,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := (&APIKey{Scopes: test.scopes}).Scope()
			if err != nil {
				t.Fatalf("Scope() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Scope() = %#v, want %#v", got, test.want)
			}
		})
	}
}
