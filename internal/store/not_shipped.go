package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// NotShippedEntry is one not-shipped list entry (ADR-045 §6).
type NotShippedEntry struct {
	ID        uuid.UUID  `json:"id"`
	OrgID     uuid.UUID  `json:"org_id"`
	RepoID    *uuid.UUID `json:"repo_id,omitempty"`
	Pattern   string     `json:"pattern"`
	Reason    string     `json:"reason"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

type UpsertNotShippedEntryParams struct {
	OrgID     uuid.UUID
	RepoID    *uuid.UUID
	Pattern   string
	Reason    string
	CreatedBy *uuid.UUID
}

func (q *Queries) UpsertNotShippedEntry(ctx context.Context, params UpsertNotShippedEntryParams) (*NotShippedEntry, error) {
	row, err := q.db.UpsertNotShippedEntry(ctx, dbgen.UpsertNotShippedEntryParams{
		OrgID:     params.OrgID,
		RepoID:    nullUUIDFromPtr(params.RepoID),
		Pattern:   params.Pattern,
		Reason:    params.Reason,
		CreatedBy: nullUUIDFromPtr(params.CreatedBy),
	})
	if err != nil {
		return nil, err
	}
	return notShippedEntryFromRow(row), nil
}

func (q *Queries) DeleteNotShippedEntry(ctx context.Context, orgID, id uuid.UUID) (bool, error) {
	rows, err := q.db.DeleteNotShippedEntry(ctx, dbgen.DeleteNotShippedEntryParams{ID: id, OrgID: orgID})
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}

func (q *Queries) GetNotShippedEntry(ctx context.Context, orgID, id uuid.UUID) (*NotShippedEntry, error) {
	row, err := q.db.GetNotShippedEntry(ctx, dbgen.GetNotShippedEntryParams{ID: id, OrgID: orgID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return notShippedEntryFromRow(row), nil
}

// ListNotShippedEntries returns the org-wide entries and, when repoID is
// set, the repository's own.
func (q *Queries) ListNotShippedEntries(ctx context.Context, orgID uuid.UUID, repoID *uuid.UUID) ([]NotShippedEntry, error) {
	rows, err := q.db.ListNotShippedEntries(ctx, dbgen.ListNotShippedEntriesParams{OrgID: orgID, RepoID: nullUUIDFromPtr(repoID)})
	if err != nil {
		return nil, err
	}
	out := make([]NotShippedEntry, 0, len(rows))
	for _, row := range rows {
		out = append(out, *notShippedEntryFromRow(row))
	}
	return out, nil
}

func notShippedEntryFromRow(row dbgen.NotShippedEntry) *NotShippedEntry {
	entry := &NotShippedEntry{ID: row.ID, OrgID: row.OrgID, Pattern: row.Pattern, Reason: row.Reason, CreatedAt: row.CreatedAt}
	if row.RepoID.Valid {
		id := row.RepoID.UUID
		entry.RepoID = &id
	}
	if row.CreatedBy.Valid {
		id := row.CreatedBy.UUID
		entry.CreatedBy = &id
	}
	return entry
}
