package store

import "github.com/hibouhq/lehibou/internal/store/dbgen"

type SeverityLevel = dbgen.SeverityLevel

const (
	SeverityLevelCritical = dbgen.SeverityLevelCritical
	SeverityLevelHigh     = dbgen.SeverityLevelHigh
	SeverityLevelMedium   = dbgen.SeverityLevelMedium
	SeverityLevelLow      = dbgen.SeverityLevelLow
	SeverityLevelInfo     = dbgen.SeverityLevelInfo
)
