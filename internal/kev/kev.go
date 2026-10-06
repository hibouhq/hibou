// Package kev mirrors "known exploited vulnerabilities" catalogs: CISA KEV
// and the ENISA EUVD exploited set, the same pair Dependency-Track mirrors out
// of the box. An entry means the publisher has evidence of active exploitation
// in the wild — a stronger and rarer fact than any CVSS score, which is why
// ADR-031/032 treat it as an `actively_exploited` signal and the gate blocks
// on it unconditionally.
//
// Each catalog is a Source; the sync loop stores every source side by side and
// membership is a union — listed anywhere is listed.
package kev

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Source is one exploited-vulnerabilities catalog.
type Source interface {
	// Name keys the source's rows in storage and its entry in sync health.
	// Stable across releases: it scopes which rows a sync pass may delete.
	Name() string
	Fetch(ctx context.Context) (Catalog, error)
	// WithdrawalGrace is how long an entry absent from a fetch may stay stored
	// before it is deleted. Zero means absence IS withdrawal — right for a
	// source fetched as one atomic document. A source walked through unstable
	// pagination returns a positive grace, because a record shifting between
	// pages mid-walk can be skipped once without having been withdrawn.
	WithdrawalGrace() time.Duration
}

// cveIDPattern is the shape an entry's key must have. Catalogs have carried
// formatting slips before; an entry whose key is not a CVE id cannot ever be
// matched against an advisory, so it is skipped and counted rather than stored.
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Entry is one catalog row, normalized: CVEID uppercase, dates parsed, source
// quirks resolved by each Source.
type Entry struct {
	CVEID             string
	VendorProject     string
	Product           string
	VulnerabilityName string
	// DateAdded is when the publisher listed the entry as exploited (CISA's
	// dateAdded; EUVD's exploitedSince, falling back to publication date).
	DateAdded time.Time
	// DueDate and KnownRansomwareCampaignUse stay zero for sources that do
	// not publish them (today everyone but CISA).
	DueDate                    time.Time
	KnownRansomwareCampaignUse bool
}

// Catalog is a fetched, validated catalog.
type Catalog struct {
	// Version and Released are publisher metadata when the source has any
	// (CISA does; the EUVD exploited set does not).
	Version  string
	Released string
	Entries  []Entry
	// Skipped counts upstream entries dropped for not carrying a usable CVE id.
	Skipped int
}

func parseDate(layout, value string) time.Time {
	parsed, err := time.Parse(layout, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}
	}
	return parsed
}
