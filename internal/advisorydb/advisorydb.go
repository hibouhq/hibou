// Package advisorydb is the offline advisory database of ADR-046 (rollout
// step 6): an export of the organisation's advisory view that `hibou deps
// scan --advisory-db` matches against without a server, the way the
// offline mode of ADR-035 runs scanners from an imported bundle.
//
// The file is newline-delimited JSON: a header line, then one record per
// advisory with its affected ranges, ratings, aliases, exploited-catalog
// flag and EPSS score. Matching uses the same version comparison as the
// server (internal/versioncmp) and the same rating choice
// (advisory.FindingRating), so a local match agrees with the stateless
// endpoint for the same data. What the file cannot carry is the
// repository's triage: VEX statements, not-shipped lists and package
// signals need the server.
package advisorydb

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/distro"
	"github.com/hibouhq/hibou/internal/sbom"
	"github.com/hibouhq/hibou/internal/versioncmp"
)

const (
	// Format names the file in its header.
	Format = "hibou-advisory-db"
	// Version is the record layout; a reader refuses a newer one.
	Version = 1
	// StaleAfter is the age past which the CLI warns (ADR-035: rule and
	// database staleness is shown, never hidden).
	StaleAfter = 7 * 24 * time.Hour
	// maxLineBytes bounds one record.
	maxLineBytes = 16 << 20
)

// Header is the first line.
type Header struct {
	Format     string    `json:"format"`
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	Server     string    `json:"server,omitempty"`
	Org        string    `json:"org,omitempty"`
	// Ecosystems lists what the export covers; empty means every one.
	Ecosystems []string `json:"ecosystems,omitempty"`
}

// Record is one advisory.
type Record struct {
	ID          string     `json:"id"`
	CanonicalID string     `json:"canonical_id"`
	Aliases     []string   `json:"aliases,omitempty"`
	Title       string     `json:"title,omitempty"`
	IsMalware   bool       `json:"is_malware,omitempty"`
	MalwareType string     `json:"malware_type,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	Withdrawn   bool       `json:"withdrawn,omitempty"`
	KEV         bool       `json:"kev,omitempty"`
	EPSS        *float64   `json:"epss,omitempty"`
	Ratings     []Rating   `json:"ratings,omitempty"`
	Ranges      []Range    `json:"ranges"`
}

// Rating is one rater's statement, as advisory.Rating serialises.
type Rating struct {
	Rater    string   `json:"rater"`
	Provider string   `json:"provider,omitempty"`
	Version  string   `json:"version,omitempty"`
	Vector   string   `json:"vector,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Label    string   `json:"label,omitempty"`
}

// Range is one affected range.
type Range struct {
	Ecosystem    string `json:"ecosystem"`
	Package      string `json:"package"`
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	// Release scopes a distribution range (ADR-038); empty for language
	// ecosystems.
	Release string `json:"release,omitempty"`
}

// Writer streams a database.
type Writer struct {
	w       *bufio.Writer
	records int
}

// NewWriter writes the header and returns a writer for the records.
func NewWriter(w io.Writer, header Header) (*Writer, error) {
	header.Format, header.Version = Format, Version
	if header.ExportedAt.IsZero() {
		header.ExportedAt = time.Now().UTC()
	}
	out := &Writer{w: bufio.NewWriterSize(w, 256<<10)}
	if err := out.line(header); err != nil {
		return nil, err
	}
	return out, nil
}

// Write appends one record.
func (w *Writer) Write(record Record) error {
	if err := w.line(record); err != nil {
		return err
	}
	w.records++
	return nil
}

// Records is how many were written.
func (w *Writer) Records() int { return w.records }

// Flush completes the file.
func (w *Writer) Flush() error { return w.w.Flush() }

func (w *Writer) line(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := w.w.Write(encoded); err != nil {
		return err
	}
	return w.w.WriteByte('\n')
}

// DB is a loaded database, indexed by ecosystem and package.
type DB struct {
	Header    Header
	byPackage map[string][]*Record
	records   int
}

// Load reads a database file.
func Load(path string) (*DB, error) {
	f, err := os.Open(path) // #nosec G304 -- a file the user named
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Read(f)
}

// Read reads a database.
func Read(r io.Reader) (*DB, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), maxLineBytes)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, err
		}
		return nil, errors.New("empty advisory database")
	}
	db := &DB{byPackage: map[string][]*Record{}}
	if err := json.Unmarshal(scanner.Bytes(), &db.Header); err != nil {
		return nil, fmt.Errorf("advisory database header: %w", err)
	}
	if db.Header.Format != Format {
		return nil, fmt.Errorf("not a hibou advisory database (format %q)", db.Header.Format)
	}
	if db.Header.Version > Version {
		return nil, fmt.Errorf("advisory database version %d is newer than this hibou understands (%d): upgrade the CLI", db.Header.Version, Version)
	}
	line := 1
	for scanner.Scan() {
		line++
		if len(strings.TrimSpace(string(scanner.Bytes()))) == 0 {
			continue
		}
		record := &Record{}
		if err := json.Unmarshal(scanner.Bytes(), record); err != nil {
			return nil, fmt.Errorf("advisory database line %d: %w", line, err)
		}
		db.records++
		seen := map[string]bool{}
		for _, affected := range record.Ranges {
			key := packageKey(affected.Ecosystem, affected.Package)
			if seen[key] {
				continue
			}
			seen[key] = true
			db.byPackage[key] = append(db.byPackage[key], record)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return db, nil
}

// Advisories is the record count.
func (db *DB) Advisories() int { return db.records }

// Age is how old the export is.
func (db *DB) Age(now time.Time) time.Duration { return now.Sub(db.Header.ExportedAt) }

// Stale says the export is older than StaleAfter.
func (db *DB) Stale(now time.Time) bool { return db.Age(now) > StaleAfter }

// Match is what one purl matched, in the shape of the stateless endpoint.
type Match struct {
	Purl       string
	Ecosystem  string
	Name       string
	Version    string
	Supported  bool
	Advisories []MatchedAdvisory
}

// MatchedAdvisory is one advisory a version falls in.
type MatchedAdvisory struct {
	ID            string
	CanonicalID   string
	Title         string
	Severity      string
	CVSS          *float64
	RatedBy       string
	IsMalware     bool
	MalwareType   string
	FixedVersions []string
	PublishedAt   *time.Time
	KEV           bool
	EPSS          *float64
}

// Match matches one purl.
func (db *DB) Match(purl string) Match {
	purl = strings.TrimSpace(purl)
	match := Match{
		Purl:      purl,
		Ecosystem: sbom.EcosystemFromPURL(purl),
		Name:      sbom.PackageNameFromPURL(purl),
		Version:   sbom.VersionFromPURL(purl),
	}
	if match.Ecosystem == "" || match.Name == "" || match.Version == "" {
		return match
	}
	if _, ok := versioncmp.Get(match.Ecosystem); !ok {
		return match
	}
	match.Supported = true
	for _, record := range db.byPackage[packageKey(match.Ecosystem, match.Name)] {
		if record.Withdrawn {
			continue
		}
		affected := false
		var fixed []string
		for _, affectedRange := range record.Ranges {
			if !strings.EqualFold(affectedRange.Ecosystem, match.Ecosystem) || !strings.EqualFold(affectedRange.Package, match.Name) {
				continue
			}
			if f := strings.TrimSpace(affectedRange.Fixed); f != "" {
				fixed = append(fixed, f)
			}
			if affected {
				continue
			}
			if !distroRangeApplies(match, affectedRange) {
				continue
			}
			inRange, err := versioncmp.InRange(match.Ecosystem, match.Version, affectedRange.Introduced, affectedRange.Fixed, affectedRange.LastAffected)
			if err == nil && inRange {
				affected = true
			}
		}
		if !affected {
			continue
		}
		choice := advisory.FindingRating(toRatings(record.Ratings), record.IsMalware, match.Ecosystem, purl)
		matched := MatchedAdvisory{
			ID:            record.ID,
			CanonicalID:   record.CanonicalID,
			Title:         firstNonEmpty(strings.TrimSpace(record.Title), record.CanonicalID),
			Severity:      string(choice.Severity),
			IsMalware:     record.IsMalware,
			MalwareType:   record.MalwareType,
			FixedVersions: uniqueSorted(fixed),
			PublishedAt:   record.PublishedAt,
			KEV:           record.KEV,
			EPSS:          record.EPSS,
		}
		if choice.Rating != nil {
			matched.CVSS = choice.Rating.Score
			matched.RatedBy = choice.Rating.Rater
		}
		match.Advisories = append(match.Advisories, matched)
	}
	sort.Slice(match.Advisories, func(i, j int) bool { return match.Advisories[i].CanonicalID < match.Advisories[j].CanonicalID })
	return match
}

// distroRangeApplies mirrors the scanner: a distribution range only
// applies to the release it was scoped to, and an unscoped one never does.
func distroRangeApplies(match Match, affectedRange Range) bool {
	if !distro.IsDistroEcosystem(match.Ecosystem) {
		return true
	}
	if affectedRange.Release == "" {
		return false
	}
	_, release := distro.FromPurl(match.Purl)
	return distro.ReleaseKey(match.Ecosystem, release) == affectedRange.Release
}

// FromRatings converts the server's ratings to the file's shape.
func FromRatings(ratings []advisory.Rating) []Rating {
	out := make([]Rating, 0, len(ratings))
	for _, rating := range ratings {
		entry := Rating{Rater: rating.Rater, Provider: rating.Provider, Vector: rating.Vector, Score: rating.Score}
		if rating.Version != nil {
			entry.Version = string(*rating.Version)
		}
		if rating.Label != nil {
			entry.Label = string(*rating.Label)
		}
		out = append(out, entry)
	}
	return out
}

func toRatings(ratings []Rating) []advisory.Rating {
	out := make([]advisory.Rating, 0, len(ratings))
	for _, rating := range ratings {
		entry := advisory.Rating{Rater: rating.Rater, Provider: rating.Provider, Vector: rating.Vector, Score: rating.Score}
		if rating.Version != "" {
			version := advisory.CVSSVersion(rating.Version)
			entry.Version = &version
		}
		if rating.Label != "" {
			label := advisory.Severity(rating.Label)
			entry.Label = &label
		}
		out = append(out, entry)
	}
	return out
}

func packageKey(ecosystem, name string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "/" + strings.ToLower(strings.TrimSpace(name))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
