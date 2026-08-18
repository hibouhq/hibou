package server

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
)

func TestBuildAuditLogFilterOrgOnly(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	where, args := buildAuditLogFilter(orgID, "", "", "")

	if where != "org_id = $1" {
		t.Fatalf("where = %q", where)
	}
	if !reflect.DeepEqual(args, []any{orgID}) {
		t.Fatalf("args = %+v", args)
	}
}

func TestBuildAuditLogFilterAllPredicates(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	repoID := uuid.New().String()
	where, args := buildAuditLogFilter(orgID, "vuln.suppress", "vuln_match", repoID)

	want := "org_id = $1 AND action = $2 AND resource_type = $3 AND ((resource_type = 'repository' AND resource_id = $4) OR context->>'repo_id' = $4)"
	if where != want {
		t.Fatalf("where = %q, want %q", where, want)
	}
	if !reflect.DeepEqual(args, []any{orgID, "vuln.suppress", "vuln_match", repoID}) {
		t.Fatalf("args = %+v", args)
	}
}

// The repo predicate must match rows where the repository is the resource AND
// rows that only carry the repo in their context — with one bound arg reused.
func TestBuildAuditLogFilterRepoOnly(t *testing.T) {
	t.Parallel()

	orgID := uuid.New()
	repoID := uuid.New().String()
	where, args := buildAuditLogFilter(orgID, "", "", repoID)

	want := "org_id = $1 AND ((resource_type = 'repository' AND resource_id = $2) OR context->>'repo_id' = $2)"
	if where != want {
		t.Fatalf("where = %q, want %q", where, want)
	}
	if !reflect.DeepEqual(args, []any{orgID, repoID}) {
		t.Fatalf("args = %+v", args)
	}
}
