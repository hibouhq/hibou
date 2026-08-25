// Package cvefeed decodes CVE Records (CVE Record Format 5.x) from the CVE
// Program's own feed into the projection hibou stores.
//
// It exists because the advisories that matter most to us carry no package
// coordinates anywhere upstream: the CNA publishes a product name ("Apache
// Tomcat") and exact version ranges, and nothing maps that to
// org.apache.tomcat:tomcat-catalina. That mapping is authored by a person
// (ADR-028); this package's job is everything around it that is mechanical —
// version ranges, product keys, severity and state.
//
// Two rules shape the whole package, and both fail closed:
//
//   - A bound is never invented. `lessThanOrEqual` is an inclusive last-affected
//     version and is stored as such; only `lessThan` yields a fixed version.
//     Turning the former into the latter would name a release we have not
//     verified exists, and every consumer downstream would inherit it.
//   - A version entry with no upper bound is dropped, never widened. An
//     unbounded range matches every future release forever, which is a
//     false-positive generator we have watched other tools ship.
//
// Records are decoded, not mirrored: raw JSON is 3.14 GB across the corpus and
// holds records up to 23.4 MB, while this projection is ~0.33 KB (index) or
// ~0.88 KB (with prose) per record.
package cvefeed

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MaxRecordBytes caps a single record. The published corpus contains a 23.4 MB
// record; nothing legitimate in our path is close, so an oversized record is
// rejected rather than allowed to size every buffer that touches it.
const MaxRecordBytes = 2 << 20

// Record states, from cveMetadata.state. REJECTED is deliberately decoded
// rather than skipped: a record moving to REJECTED means the vulnerability was
// withdrawn upstream, and findings derived from it must be retired.
const (
	StatePublished = "PUBLISHED"
	StateRejected  = "REJECTED"
)

var errTooLarge = errors.New("cve record exceeds size cap")

// Projection is the stored form of one CVE record.
//
// Description and References are the "prose tier" — populated by Decode and
// dropped by the caller when only the index tier is kept.
type Projection struct {
	ID          string
	State       string
	Assigner    string
	Published   time.Time
	Updated     time.Time
	Severity    Severity
	CWEs        []string
	Affected    []AffectedProduct
	Description string
	References  []string
}

// Withdrawn reports whether upstream has retracted this record.
func (p Projection) Withdrawn() bool { return p.State == StateRejected }

// AffectedProduct is one CNA affected[] entry, flattened.
//
// VendorKey and ProductKey are the normalized match keys; Vendor and Product
// keep the CNA's own spelling for display. A subscription matches on
// ProductKey, with VendorKey as an optional narrowing — never the reverse, and
// never on the assigner, which names the CNA rather than the vendor.
type AffectedProduct struct {
	Vendor     string
	Product    string
	VendorKey  string
	ProductKey string
	Ranges     []VersionRange
}

// VersionRange is an affected interval. Exactly one upper bound is set:
// LastAffected is inclusive, Fixed is exclusive. Both empty means the entry
// was dropped before reaching here.
type VersionRange struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Severity is the best CVSS the record carries, from any container.
type Severity struct {
	Score  float64
	Vector string
	Label  string
	Source string // provider shortName the score came from
}

// Scored reports whether a real CVSS score was found.
func (s Severity) Scored() bool { return s.Vector != "" }

// Decode parses one CVE record into its projection.
func Decode(data []byte) (Projection, error) {
	if len(data) > MaxRecordBytes {
		return Projection{}, fmt.Errorf("%w: %d bytes", errTooLarge, len(data))
	}
	var raw record
	if err := json.Unmarshal(data, &raw); err != nil {
		return Projection{}, fmt.Errorf("decode cve record: %w", err)
	}
	id := strings.TrimSpace(raw.Metadata.ID)
	if id == "" {
		return Projection{}, errors.New("cve record has no cveId")
	}

	projection := Projection{
		ID:          id,
		State:       strings.ToUpper(strings.TrimSpace(raw.Metadata.State)),
		Assigner:    strings.TrimSpace(raw.Metadata.Assigner),
		Published:   parseTime(raw.Metadata.Published),
		Updated:     parseTime(raw.Metadata.Updated),
		Severity:    bestSeverity(raw),
		CWEs:        collectCWEs(raw),
		Affected:    collectAffected(raw.Containers.CNA.Affected),
		Description: englishDescription(raw.Containers.CNA.Descriptions),
		References:  collectReferences(raw),
	}
	return projection, nil
}

func collectAffected(entries []affected) []AffectedProduct {
	out := make([]AffectedProduct, 0, len(entries))
	for _, entry := range entries {
		vendor := strings.TrimSpace(entry.Vendor)
		product := strings.TrimSpace(entry.Product)
		if IsPlaceholder(product) {
			// Without a product there is nothing a subscription can match on;
			// a vendor alone would join every product that vendor ships.
			continue
		}
		ranges := collectRanges(entry.Versions)
		if len(ranges) == 0 {
			continue
		}
		if IsPlaceholder(vendor) {
			vendor = ""
		}
		out = append(out, AffectedProduct{
			Vendor:     vendor,
			Product:    product,
			VendorKey:  ProductKey(vendor),
			ProductKey: ProductKey(product),
			Ranges:     ranges,
		})
	}
	return out
}

func collectRanges(versions []versionEntry) []VersionRange {
	out := make([]VersionRange, 0, len(versions))
	for _, version := range versions {
		if !strings.EqualFold(strings.TrimSpace(version.Status), "affected") {
			continue
		}
		introduced := strings.TrimSpace(version.Version)
		if introduced == "" {
			continue
		}
		switch {
		case strings.TrimSpace(version.LessThanOrEqual) != "":
			// Inclusive upper bound. Kept as last-affected: the CNA stated the
			// last version that IS affected, not the version that fixes it.
			out = append(out, VersionRange{
				Introduced:   introduced,
				LastAffected: strings.TrimSpace(version.LessThanOrEqual),
			})
		case strings.TrimSpace(version.LessThan) != "":
			// Exclusive upper bound is exactly a fixed version.
			out = append(out, VersionRange{
				Introduced: introduced,
				Fixed:      strings.TrimSpace(version.LessThan),
			})
		case isWildcardVersion(introduced):
			// "*" or "0" with no upper bound is the genuinely open statement —
			// every release, forever. Dropped rather than widened.
			continue
		default:
			// A bare version with no bound names one exact affected release.
			// This is the most common shape in the corpus by a wide margin
			// (65% of affected entries), so treating it as unbounded — or
			// discarding it — would lose most of the feed's usable data.
			out = append(out, VersionRange{
				Introduced:   introduced,
				LastAffected: introduced,
			})
		}
	}
	return out
}

// isWildcardVersion reports whether a version string is a stand-in for "any",
// which several CNAs use with defaultStatus to mean "the whole product".
func isWildcardVersion(value string) bool {
	switch strings.TrimSpace(value) {
	case "*", "0", "-", "all", "All":
		return true
	}
	return false
}

func englishDescription(entries []description) string {
	for _, entry := range entries {
		if entry.Lang == "" || strings.HasPrefix(strings.ToLower(entry.Lang), "en") {
			if value := strings.TrimSpace(entry.Value); value != "" {
				return value
			}
		}
	}
	return ""
}

func collectCWEs(raw record) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(problems []problemType) {
		for _, problem := range problems {
			for _, entry := range problem.Descriptions {
				id := strings.TrimSpace(entry.CWEID)
				if id == "" {
					continue
				}
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}
				out = append(out, id)
			}
		}
	}
	add(raw.Containers.CNA.ProblemTypes)
	for _, adp := range raw.Containers.ADP {
		add(adp.ProblemTypes)
	}
	return out
}

func collectReferences(raw record) []string {
	seen := map[string]struct{}{}
	out := []string{}
	add := func(refs []reference) {
		for _, ref := range refs {
			url := strings.TrimSpace(ref.URL)
			if url == "" {
				continue
			}
			if _, ok := seen[url]; ok {
				continue
			}
			seen[url] = struct{}{}
			out = append(out, url)
		}
	}
	add(raw.Containers.CNA.References)
	for _, adp := range raw.Containers.ADP {
		add(adp.References)
	}
	return out
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
