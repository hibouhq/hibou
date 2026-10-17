package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Scan reuse (ADR-045, Database section): advisory matching runs once per
// distinct inventory set. A snapshot whose set another snapshot already
// scanned, with the same providers, after the last advisory change,
// copies that scan's matches instead of matching again.

// ReusableScan names a complete scan whose matches apply to a snapshot.
type ReusableScan struct {
	ScanID     uuid.UUID
	SnapshotID uuid.UUID
}

// CopiedVulnerability is one match written by CopyMatchedVulnerabilities.
type CopiedVulnerability struct {
	ID               uuid.UUID
	Type             string
	Identifier       string
	Severity         string
	ComponentName    string
	ComponentVersion string
}

// FindReusableScan returns the newest scan of the same inventory set the
// snapshot can reuse, nil when there is none.
func (q *Queries) FindReusableScan(ctx context.Context, snapshotID uuid.UUID, providers []string, notBefore time.Time) (*ReusableScan, error) {
	if providers == nil {
		providers = []string{}
	}
	row, err := q.db.FindReusableScan(ctx, dbgen.FindReusableScanParams{SnapshotID: snapshotID, Providers: providers, NotBefore: notBefore})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ReusableScan{ScanID: row.ScanID, SnapshotID: row.SnapshotID}, nil
}

// CopyMatchedVulnerabilities writes the prior snapshot's dependency and
// malware matches for the snapshot and returns them.
func (q *Queries) CopyMatchedVulnerabilities(ctx context.Context, fromSnapshotID, toSnapshotID uuid.UUID) ([]CopiedVulnerability, error) {
	rows, err := q.db.CopyMatchedVulnerabilities(ctx, dbgen.CopyMatchedVulnerabilitiesParams{ToSnapshotID: toSnapshotID, FromSnapshotID: fromSnapshotID})
	if err != nil {
		return nil, err
	}
	out := make([]CopiedVulnerability, 0, len(rows))
	for _, row := range rows {
		out = append(out, CopiedVulnerability{
			ID: row.FindingID, Type: row.Type, Identifier: strings.TrimSpace(row.PrimaryIdentifierValue), Severity: strings.ToLower(string(row.Severity)),
			ComponentName: strings.TrimSpace(row.ComponentName.String), ComponentVersion: strings.TrimSpace(row.ComponentVersion.String),
		})
	}
	return out, nil
}

// MarkScanReused records which scan's matches a scan copied.
func (q *Queries) MarkScanReused(ctx context.Context, scanID, fromScanID uuid.UUID) error {
	return q.db.MarkScanReused(ctx, dbgen.MarkScanReusedParams{FromScanID: uuid.NullUUID{UUID: fromScanID, Valid: true}, ID: scanID})
}
