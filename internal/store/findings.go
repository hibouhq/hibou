package store

import "github.com/hibouhq/hibou/internal/store/dbgen"

type SeverityLevel = dbgen.SeverityLevel

const (
	SeverityLevelCritical = dbgen.SeverityLevelCritical
	SeverityLevelHigh     = dbgen.SeverityLevelHigh
	SeverityLevelMedium   = dbgen.SeverityLevelMedium
	SeverityLevelUnknown  = dbgen.SeverityLevelUnknown
	SeverityLevelLow      = dbgen.SeverityLevelLow
	SeverityLevelInfo     = dbgen.SeverityLevelInfo
)

type VulnerabilityType = dbgen.VulnerabilityType

const VulnerabilityTypeManual = dbgen.VulnerabilityTypeManual

type VulnerabilityStatus = dbgen.VulnerabilityStatus

const VulnerabilityStatusDetected = dbgen.VulnerabilityStatusDetected

// FindingOrigin records which kind of principal produced a finding (ADR-020).
type FindingOrigin = dbgen.FindingOrigin

const (
	FindingOriginScanner = dbgen.FindingOriginScanner
	FindingOriginHuman   = dbgen.FindingOriginHuman
	FindingOriginAgent   = dbgen.FindingOriginAgent
)
