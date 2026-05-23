package retention

import "time"

// Policy defines snapshot retention rules for an organization.
type Policy struct {
	HotRetention     time.Duration
	ArchiveRetention time.Duration
	AutoPurge        bool
}

func DefaultPolicy() Policy {
	return Policy{
		HotRetention:     90 * 24 * time.Hour,
		ArchiveRetention: 7 * 365 * 24 * time.Hour,
		AutoPurge:        false,
	}
}
