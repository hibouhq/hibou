package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

func (q *Queries) CaptureForgeRepositoryBinding(ctx context.Context, repoID uuid.UUID) error {
	_, err := q.execer().ExecContext(ctx, `INSERT INTO forge_repository_bindings(repo_id,provider,account_id,repository_id)
	SELECT r.id,r.provider,o.forge_account_id,f.provider_repo_id
	FROM repositories r JOIN organizations o ON o.id=r.org_id
	JOIN forge_repositories f ON f.provider=r.provider AND lower(f.provider_key)=lower(r.provider_id)
	WHERE r.id=$1 AND o.forge_account_id<>'' AND COALESCE(f.provider_repo_id,'')<>''
	AND lower(f.account_login)=lower(o.forge_account_login)
	AND (f.account_id='' OR f.account_id=o.forge_account_id)
	AND f.removed_at IS NULL
	ON CONFLICT(repo_id) DO NOTHING`, repoID)
	return err
}

// Names are routing metadata, not authority. Both current identities must
// match the enrollment captured before namespace reuse can alter inventory.
type ForgeRepositoryTarget struct{ Owner, Name, AccountID, RepositoryID string }

func (q *Queries) HasForgeRepositoryBinding(ctx context.Context, repoID uuid.UUID) (bool, error) {
	var exists bool
	err := q.rawDB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forge_repository_bindings WHERE repo_id=$1)`, repoID).Scan(&exists)
	return exists, err
}

func (q *Queries) VerifiedForgeRepositoryTarget(ctx context.Context, repoID uuid.UUID) (*ForgeRepositoryTarget, error) {
	target := &ForgeRepositoryTarget{}
	err := q.rawDB().QueryRowContext(ctx, `SELECT f.owner,f.name,b.account_id,b.repository_id FROM repositories r
	JOIN organizations o ON o.id=r.org_id
	JOIN forge_repository_bindings b ON b.repo_id=r.id AND b.provider=r.provider
	JOIN forge_repositories f ON f.provider=r.provider AND lower(f.provider_key)=lower(r.provider_id)
	WHERE r.id=$1 AND b.account_id=o.forge_account_id
	AND f.account_id=b.account_id AND f.provider_repo_id=b.repository_id
	AND lower(f.account_login)=lower(o.forge_account_login)
	AND f.removed_at IS NULL AND NOT f.archived`, repoID).Scan(&target.Owner, &target.Name, &target.AccountID, &target.RepositoryID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("forge repository identity unavailable or differs from enrollment; metadata retained, polling refused")
	}
	return target, err
}

func (q *Queries) ForgeObservedIdentityMatches(ctx context.Context, repoID uuid.UUID, accountID, repositoryID string) (bool, error) {
	var matches bool
	err := q.rawDB().QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM forge_repository_bindings b
	JOIN repositories r ON r.id=b.repo_id JOIN organizations o ON o.id=r.org_id
	WHERE b.repo_id=$1 AND b.account_id=$2 AND b.repository_id=$3 AND o.forge_account_id=b.account_id)`,
		repoID, accountID, repositoryID).Scan(&matches)
	return matches, err
}
