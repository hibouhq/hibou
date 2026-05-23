package store

import (
	"database/sql"

	"github.com/hibouhq/lehibou/internal/store/dbgen"
)

type Queries struct {
	db    *dbgen.Queries
	sqlDB *sql.DB
}

func NewQueries(db *sql.DB) *Queries {
	return &Queries{db: dbgen.New(db), sqlDB: db}
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{db: q.db.WithTx(tx), sqlDB: q.sqlDB}
}
