package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ComparePatchCacheEntry is a cached forge comparison: which new-side lines each
// changed file touched. Keyed by two immutable commit SHAs, so it never expires.
type ComparePatchCacheEntry struct {
	Truncated bool                     `json:"truncated"`
	Files     []ComparePatchCachedFile `json:"files"`
}

type ComparePatchCachedFile struct {
	Path       string `json:"path"`
	OldPath    string `json:"old_path,omitempty"`
	Status     string `json:"status,omitempty"`
	AddedLines []int  `json:"added_lines,omitempty"`
	// Hunks is the raw unified-diff text. It must be cached: the annotated PR
	// diff renders from it, so serving a cache hit without hunks would silently
	// empty every diff view.
	Hunks string `json:"hunks,omitempty"`
}

// GetComparePatchCache returns nil (no error) on a miss.
func (q *Queries) GetComparePatchCache(ctx context.Context, repoID uuid.UUID, baseSHA, headSHA string) (*ComparePatchCacheEntry, error) {
	row, err := q.db.GetComparePatchCache(ctx, dbgen.GetComparePatchCacheParams{
		RepoID:  repoID,
		BaseSha: baseSHA,
		HeadSha: headSHA,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var files []ComparePatchCachedFile
	if err := json.Unmarshal(row.Payload, &files); err != nil {
		// A corrupt row must behave like a miss, not break the page: the caller
		// re-fetches from the forge and overwrites it.
		return nil, nil
	}
	return &ComparePatchCacheEntry{Truncated: row.Truncated, Files: files}, nil
}

func (q *Queries) UpsertComparePatchCache(ctx context.Context, repoID uuid.UUID, baseSHA, headSHA string, entry ComparePatchCacheEntry) error {
	payload, err := json.Marshal(entry.Files)
	if err != nil {
		return fmt.Errorf("marshal compare patch cache: %w", err)
	}
	_, err = q.db.UpsertComparePatchCache(ctx, dbgen.UpsertComparePatchCacheParams{
		RepoID:    repoID,
		BaseSha:   baseSHA,
		HeadSha:   headSHA,
		Truncated: entry.Truncated,
		Payload:   payload,
	})
	return err
}

// DeleteComparePatchCacheForCommit drops every cached comparison involving the
// commit, called when its snapshot is purged.
func (q *Queries) DeleteComparePatchCacheForCommit(ctx context.Context, repoID uuid.UUID, commitSHA string) error {
	return q.db.DeleteComparePatchCacheForCommit(ctx, dbgen.DeleteComparePatchCacheForCommitParams{
		RepoID:  repoID,
		BaseSha: commitSHA,
	})
}
