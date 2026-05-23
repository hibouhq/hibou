package store

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

func stringPtrFromNull(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}

	result := value.String
	return &result
}

func nullStringFromPtr(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}

	return sql.NullString{String: *value, Valid: true}
}

func int32PtrFromNull(value sql.NullInt32) *int32 {
	if !value.Valid {
		return nil
	}

	result := value.Int32
	return &result
}

func nullInt32FromPtr(value *int32) sql.NullInt32 {
	if value == nil {
		return sql.NullInt32{}
	}

	return sql.NullInt32{Int32: *value, Valid: true}
}

func timePtrFromNull(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}

	result := value.Time
	return &result
}

func nullTimeFromPtr(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{}
	}

	return sql.NullTime{Time: *value, Valid: true}
}

func uuidPtrFromNull(value uuid.NullUUID) *uuid.UUID {
	if !value.Valid {
		return nil
	}

	result := value.UUID
	return &result
}

func nullUUIDFromPtr(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}

	return uuid.NullUUID{UUID: *value, Valid: true}
}
