package rbac

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

// Adapter implements Casbin persistence using the existing casbin_rules table.
type Adapter struct {
	db *sql.DB
}

// NewAdapter creates a new Casbin adapter.
func NewAdapter(db *sql.DB) *Adapter {
	return &Adapter{db: db}
}

func (a *Adapter) LoadPolicy(model model.Model) error {
	rows, err := a.db.QueryContext(
		context.Background(),
		`SELECT ptype, v0, v1, v2, v3, v4, v5 FROM casbin_rules`,
	)
	if err != nil {
		return fmt.Errorf("querying casbin rules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ptype string
		var values [6]sql.NullString
		if err := rows.Scan(&ptype, &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]); err != nil {
			return fmt.Errorf("scanning casbin rule: %w", err)
		}

		tokens := []string{ptype}
		for _, value := range values {
			if value.Valid && value.String != "" {
				tokens = append(tokens, value.String)
			}
		}

		//nolint:errcheck // persist.LoadPolicyLine only returns error for invalid CSV, which cannot happen with our formatted input
		persist.LoadPolicyLine(strings.Join(tokens, ", "), model)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating casbin rules: %w", err)
	}

	return nil
}

func (a *Adapter) SavePolicy(model model.Model) error {
	tx, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("beginning casbin policy save: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.ExecContext(context.Background(), `DELETE FROM casbin_rules`); err != nil {
		return fmt.Errorf("clearing casbin rules: %w", err)
	}

	savePolicyType := func(ptype string, rules [][]string) error {
		for _, rule := range rules {
			if err := a.insertRule(tx, ptype, rule); err != nil {
				return err
			}
		}
		return nil
	}

	for ptype, assertion := range model["p"] {
		if err := savePolicyType(ptype, assertion.Policy); err != nil {
			return err
		}
	}
	for ptype, assertion := range model["g"] {
		if err := savePolicyType(ptype, assertion.Policy); err != nil {
			return err
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing casbin policy save: %w", err)
	}

	return nil
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	if err := a.insertRule(a.db, ptype, rule); err != nil {
		return fmt.Errorf("adding casbin policy: %w", err)
	}

	return nil
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	query := `DELETE FROM casbin_rules WHERE ptype = $1`
	args := []any{ptype}

	for index, value := range rule {
		//nolint:gosec,perfsprint // G202: query parameters are positional ($1, $2...), not interpolated values.
		query += fmt.Sprintf(` AND v%d = $%d`, index, index+2)
		args = append(args, value)
	}

	if _, err := a.db.ExecContext(context.Background(), query, args...); err != nil {
		return fmt.Errorf("removing casbin policy: %w", err)
	}

	return nil
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	query := `DELETE FROM casbin_rules WHERE ptype = $1`
	args := []any{ptype}
	placeholder := 2

	for index, value := range fieldValues {
		if value == "" {
			continue
		}

		//nolint:gosec,perfsprint // G202: query parameters are positional ($1, $2...), not interpolated values.
		query += fmt.Sprintf(` AND v%d = $%d`, fieldIndex+index, placeholder)
		args = append(args, value)
		placeholder++
	}

	if _, err := a.db.ExecContext(context.Background(), query, args...); err != nil {
		return fmt.Errorf("removing filtered casbin policy: %w", err)
	}

	return nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (a *Adapter) insertRule(exec execer, ptype string, rule []string) error {
	values := make([]any, 7)
	values[0] = ptype
	for index := 1; index < len(values); index++ {
		values[index] = ""
	}
	for index, value := range rule {
		if index >= len(values)-1 {
			break
		}
		values[index+1] = value
	}

	if _, err := exec.ExecContext(
		context.Background(),
		`INSERT INTO casbin_rules (ptype, v0, v1, v2, v3, v4, v5) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		values...,
	); err != nil {
		return fmt.Errorf("inserting casbin rule: %w", err)
	}

	return nil
}
