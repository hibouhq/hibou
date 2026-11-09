package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// ErrVEXStatementNotCurrent is returned when a revision or withdrawal targets
// a statement something else already superseded.
var ErrVEXStatementNotCurrent = errors.New("vex statement is no longer current")

// RecordVEXStatement makes arg the current statement of its scope (ADR-053
// §4a). The scope's current row, if any, is stamped superseded and linked from
// the new row in the same transaction; its content is never edited.
func (q *Queries) RecordVEXStatement(ctx context.Context, arg dbgen.CreateVEXStatementParams) (dbgen.VexStatement, error) {
	var recorded dbgen.VexStatement
	err := q.inTx(ctx, func(tx *Queries) error {
		current, err := tx.db.GetCurrentVEXStatementForScope(ctx, dbgen.GetCurrentVEXStatementForScopeParams{
			OrgID:         arg.OrgID,
			AdvisoryID:    arg.AdvisoryID,
			RepoID:        arg.RepoID,
			ComponentPurl: arg.ComponentPurl,
			ReleaseID:     arg.ReleaseID,
			VersionRange:  arg.VersionRange,
		})
		switch {
		case err == nil:
			if _, err := tx.db.MarkVEXStatementSuperseded(ctx, dbgen.MarkVEXStatementSupersededParams{ID: current.ID, OrgID: arg.OrgID}); err != nil {
				return fmt.Errorf("supersede vex statement: %w", err)
			}
			arg.Supersedes = uuid.NullUUID{UUID: current.ID, Valid: true}
		case errors.Is(err, sql.ErrNoRows):
			arg.Supersedes = uuid.NullUUID{}
		default:
			return fmt.Errorf("load current vex statement: %w", err)
		}
		if len(arg.Evidence) == 0 {
			arg.Evidence = json.RawMessage(`{}`)
		}
		recorded, err = tx.db.CreateVEXStatement(ctx, arg)
		return err
	})
	return recorded, err
}

// WithdrawVEXStatement ends a statement without a successor: a withdrawn row
// carrying the same scope becomes current, and readers skip it.
func (q *Queries) WithdrawVEXStatement(ctx context.Context, orgID, statementID uuid.UUID, actor uuid.NullUUID) (dbgen.VexStatement, error) {
	statement, err := q.db.GetVEXStatementByID(ctx, statementID)
	if err != nil {
		return dbgen.VexStatement{}, err
	}
	if statement.OrgID != orgID {
		return dbgen.VexStatement{}, sql.ErrNoRows
	}
	if statement.SupersededAt.Valid {
		return dbgen.VexStatement{}, ErrVEXStatementNotCurrent
	}
	if statement.Withdrawn {
		return statement, nil
	}
	params := VEXParamsFromStatement(statement)
	params.Withdrawn = true
	params.CreatedBy = actor
	params.ApprovedBy = uuid.NullUUID{}
	params.ApprovedAt = sql.NullTime{}
	return q.RecordVEXStatement(ctx, params)
}

// ListVEXStatementHistory returns the chain a statement belongs to, oldest
// first.
func (q *Queries) ListVEXStatementHistory(ctx context.Context, orgID, statementID uuid.UUID) ([]dbgen.VexStatement, error) {
	rows, err := q.db.ListVEXStatementHistory(ctx, dbgen.ListVEXStatementHistoryParams{ID: statementID, OrgID: orgID})
	if err != nil {
		return nil, err
	}
	out := make([]dbgen.VexStatement, 0, len(rows))
	for _, row := range rows {
		out = append(out, dbgen.VexStatement(row))
	}
	return out, nil
}

// ListVEXStatementsForAdvisoryRepo lists every current statement about an
// advisory that applies to a repository, whatever its product axis.
func (q *Queries) ListVEXStatementsForAdvisoryRepo(ctx context.Context, orgID, advisoryID, repoID uuid.UUID) ([]dbgen.VexStatement, error) {
	return q.db.ListVEXStatementsForAdvisoryRepo(ctx, dbgen.ListVEXStatementsForAdvisoryRepoParams{
		OrgID: orgID, AdvisoryID: advisoryID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true},
	})
}

// ApproveVEXStatement records a second person's approval as a revision: the
// approved row supersedes the unapproved one, so the history shows both.
func (q *Queries) ApproveVEXStatement(ctx context.Context, orgID, statementID, approver uuid.UUID) (dbgen.VexStatement, error) {
	statement, err := q.db.GetVEXStatementByID(ctx, statementID)
	if err != nil {
		return dbgen.VexStatement{}, err
	}
	if statement.OrgID != orgID {
		return dbgen.VexStatement{}, sql.ErrNoRows
	}
	if statement.SupersededAt.Valid || statement.Withdrawn {
		return dbgen.VexStatement{}, ErrVEXStatementNotCurrent
	}
	if statement.ApprovedBy.Valid {
		return statement, nil
	}
	params := VEXParamsFromStatement(statement)
	params.ApprovedBy = uuid.NullUUID{UUID: approver, Valid: true}
	params.ApprovedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	return q.RecordVEXStatement(ctx, params)
}

func (q *Queries) ListUnapprovedVEXStatementsByOrg(ctx context.Context, orgID uuid.UUID, limit int32) ([]dbgen.VexStatement, error) {
	return q.db.ListUnapprovedVEXStatementsByOrg(ctx, dbgen.ListUnapprovedVEXStatementsByOrgParams{OrgID: orgID, Limit: limit})
}

// VEXParamsFromStatement copies a stored statement into insert parameters,
// for a revision that changes some fields and keeps the rest.
func VEXParamsFromStatement(statement dbgen.VexStatement) dbgen.CreateVEXStatementParams {
	return dbgen.CreateVEXStatementParams{
		OrgID:             statement.OrgID,
		AdvisoryID:        statement.AdvisoryID,
		RepoID:            statement.RepoID,
		ComponentPurl:     statement.ComponentPurl,
		ReleaseID:         statement.ReleaseID,
		VersionRange:      statement.VersionRange,
		Status:            statement.Status,
		Justification:     statement.Justification,
		ImpactStatement:   statement.ImpactStatement,
		ActionStatement:   statement.ActionStatement,
		Source:            statement.Source,
		SourceDocumentUrl: statement.SourceDocumentUrl,
		Supplier:          statement.Supplier,
		Evidence:          statement.Evidence,
		Withdrawn:         statement.Withdrawn,
		ApprovedBy:        statement.ApprovedBy,
		ApprovedAt:        statement.ApprovedAt,
		CreatedBy:         statement.CreatedBy,
		ExpiresAt:         statement.ExpiresAt,
	}
}

func (q *Queries) CreateFirstPartyAdvisory(ctx context.Context, arg dbgen.CreateFirstPartyAdvisoryParams) (dbgen.FirstPartyAdvisory, error) {
	return q.db.CreateFirstPartyAdvisory(ctx, arg)
}

func (q *Queries) ListFirstPartyAdvisoriesByRepo(ctx context.Context, repoID uuid.UUID) ([]dbgen.ListFirstPartyAdvisoriesByRepoRow, error) {
	return q.db.ListFirstPartyAdvisoriesByRepo(ctx, repoID)
}

func (q *Queries) GetFirstPartyAdvisory(ctx context.Context, repoID, advisoryID uuid.UUID) (dbgen.FirstPartyAdvisory, error) {
	return q.db.GetFirstPartyAdvisory(ctx, dbgen.GetFirstPartyAdvisoryParams{RepoID: repoID, AdvisoryID: advisoryID})
}

// inTx runs fn in the caller's transaction when there is one, else in a new
// one committed on success.
func (q *Queries) inTx(ctx context.Context, fn func(tx *Queries) error) error {
	if q.tx != nil {
		return fn(q)
	}
	tx, err := q.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit()
}

// Incidents exposes the generated incident queries (ADR-053) as they are:
// their parameter and row types are the API, and a transaction-bound Queries
// yields transaction-bound incident queries. Wrapping each of them one by one
// would add a layer that converts nothing.
func (q *Queries) Incidents() *dbgen.Queries {
	return q.db
}
