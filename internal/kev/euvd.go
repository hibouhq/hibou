package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/version"
)

// DefaultEUVDBaseURL is the ENISA EU Vulnerability Database API. No token, no
// custom headers; operators point kev.euvd.url at a mirror of the same API.
const DefaultEUVDBaseURL = "https://euvdservices.enisa.europa.eu/api"

// euvdPageSize is the API's maximum page size.
const euvdPageSize = 100

// euvdMaxPages bounds the pagination walk (100 × 100 = 10,000 entries, ~7×
// today's exploited set). A server that keeps promising more pages than that
// is broken or hostile, and an unbounded walk is how a sync never returns.
const euvdMaxPages = 100

// euvdDateLayout is how the EUVD API prints dates: "Apr 15, 2025, 8:30:58 PM".
const euvdDateLayout = "Jan 2, 2006, 3:04:05 PM"

// EUVD fetches the exploited subset of the ENISA EU Vulnerability Database —
// the catalog the CRA's coordinated disclosure regime builds on. There is no
// bulk document like CISA's: the exploited set is walked through the paginated
// search API (`/search?exploited=true`).
type EUVD struct {
	baseURL    string
	httpClient *http.Client
	log        zerolog.Logger
}

func NewEUVD(baseURL string, log zerolog.Logger) *EUVD {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultEUVDBaseURL
	}
	return &EUVD{
		baseURL: strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		log: log.With().Str("component", "kev.euvd").Logger(),
	}
}

func (e *EUVD) Name() string { return "euvd" }

// euvdWithdrawalGrace keeps an entry one missed pass past its disappearance.
// The search API pages by position with no stable sort, so a record shifting
// between pages mid-walk can be skipped once; un-listing an exploited CVE over
// a pagination artifact is the worse error, and a real withdrawal still lands
// within a day.
const euvdWithdrawalGrace = 24 * time.Hour

func (e *EUVD) WithdrawalGrace() time.Duration { return euvdWithdrawalGrace }

// Wire shapes, as the EUVD search API serves them. aliases and references are
// newline-separated strings; enisaIdProduct/enisaIdVendor nest the name one
// level down (and have shifted shape before, hence euvdName's tolerance).
type euvdSearchPage struct {
	Items []euvdItem `json:"items"`
	Total int        `json:"total"`
}

type euvdItem struct {
	ID            string `json:"id"`
	Description   string `json:"description"`
	DatePublished string `json:"datePublished"`
	// ExploitedSince is when the record was listed as exploited — the exact
	// counterpart of CISA's dateAdded. Served by the live API (verified
	// 2026-10) though absent from the community API docs.
	ExploitedSince string        `json:"exploitedSince"`
	Aliases        string        `json:"aliases"`
	Products       []euvdProduct `json:"enisaIdProduct"`
	Vendors        []euvdVendor  `json:"enisaIdVendor"`
}

type euvdProduct struct {
	Product euvdName `json:"product"`
}

type euvdVendor struct {
	Vendor euvdName `json:"vendor"`
}

// euvdName decodes either a bare string or {"name": "..."} — the API has
// served both spellings.
type euvdName struct {
	Name string
}

func (n *euvdName) UnmarshalJSON(data []byte) error {
	var plain string
	if err := json.Unmarshal(data, &plain); err == nil {
		n.Name = plain
		return nil
	}
	var nested struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &nested); err != nil {
		// A name we cannot read costs display text, never the entry.
		n.Name = ""
		return nil //nolint:nilerr // tolerated by design, see comment above
	}
	n.Name = nested.Name
	return nil
}

// Fetch walks the exploited set. Same refuse-empty stance as CISA: the caller
// replaces this source's stored rows with the result.
func (e *EUVD) Fetch(ctx context.Context) (Catalog, error) {
	catalog := Catalog{}
	seen := map[string]struct{}{}
	walked := 0
	// The last total the API advertised; -1 until a page carried items. The
	// walk is verified against it below: a partial result must never be
	// reported as a catalog, because the caller DELETES whatever it is missing.
	total := -1

	for page := 0; page < euvdMaxPages; page++ {
		result, err := e.fetchPage(ctx, page)
		if err != nil {
			return Catalog{}, err
		}
		if len(result.Items) == 0 {
			break
		}
		walked += len(result.Items)
		total = result.Total
		for _, item := range result.Items {
			entry, ok := normalizeEUVDItem(item)
			if !ok {
				catalog.Skipped++
				continue
			}
			// The same CVE can back several EUVD records; first one wins, and
			// a duplicate is not "skipped" — the CVE is stored.
			if _, dup := seen[entry.CVEID]; dup {
				continue
			}
			seen[entry.CVEID] = struct{}{}
			catalog.Entries = append(catalog.Entries, entry)
		}
		// page/size is the only pagination the API offers; stop once the
		// walked count covers the advertised total. Counted from the items
		// actually received, not page × requested size — a server that caps
		// the page size smaller than asked must not truncate the walk.
		if walked >= result.Total {
			break
		}
	}

	// Completeness, verified, not assumed. An early exit — the page cap, a
	// response that stopped carrying items, a mirror that dropped the total
	// field — must be an error, never a smaller catalog: success here means
	// "delete everything I did not return".
	if walked == 0 {
		return Catalog{}, errors.New("kev/euvd: exploited set came back empty; refusing to replace stored entries")
	}
	if total <= 0 {
		return Catalog{}, fmt.Errorf("kev/euvd: response advertised no total alongside %d items; cannot verify the walk is complete", walked)
	}
	if walked < total {
		return Catalog{}, fmt.Errorf("kev/euvd: incomplete walk: %d of %d advertised entries (page cap %d)", walked, total, euvdMaxPages)
	}
	if len(catalog.Entries) == 0 {
		return Catalog{}, fmt.Errorf("kev/euvd: exploited set contains no usable entries (%d skipped)", catalog.Skipped)
	}
	return catalog, nil
}

func (e *EUVD) fetchPage(ctx context.Context, page int) (euvdSearchPage, error) {
	query := url.Values{
		"exploited": {"true"},
		"size":      {strconv.Itoa(euvdPageSize)},
		"page":      {strconv.Itoa(page)},
	}
	// e.baseURL is operator-configured, same trust stance as the OSV base URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL+"/search?"+query.Encode(), nil)
	if err != nil {
		return euvdSearchPage{}, fmt.Errorf("kev/euvd: create request: %w", err)
	}
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return euvdSearchPage{}, fmt.Errorf("kev/euvd: fetch page %d: %w", page, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return euvdSearchPage{}, fmt.Errorf("kev/euvd: page %d returned status %d", page, resp.StatusCode)
	}
	var result euvdSearchPage
	limitedBody := io.LimitReader(resp.Body, maxCatalogBytes)
	if err := json.NewDecoder(limitedBody).Decode(&result); err != nil {
		return euvdSearchPage{}, fmt.Errorf("kev/euvd: decode page %d: %w", page, err)
	}
	return result, nil
}

// normalizeEUVDItem maps one record to an Entry. The storage key is the CVE
// alias: an exploited EUVD record without one cannot match an advisory today
// (advisories carry CVE/GHSA aliases, not EUVD ids), so it is skipped and
// counted — revisit if EUVD ids ever show up as advisory aliases.
func normalizeEUVDItem(item euvdItem) (Entry, bool) {
	cveID := ""
	for _, alias := range strings.Split(item.Aliases, "\n") {
		candidate := strings.ToUpper(strings.TrimSpace(alias))
		if cveIDPattern.MatchString(candidate) {
			cveID = candidate
			break
		}
	}
	if cveID == "" {
		return Entry{}, false
	}
	entry := Entry{
		CVEID: cveID,
		// The EUVD id is the name the publisher gave the record; the detail
		// view shows it so a reader can find the record on euvd.enisa.europa.eu.
		VulnerabilityName: strings.TrimSpace(item.ID),
		// exploitedSince is when the record was listed as exploited — CISA's
		// dateAdded equivalent; publication date is the fallback for records
		// that predate the field.
		DateAdded: euvdDate(item.ExploitedSince),
	}
	if entry.DateAdded.IsZero() {
		entry.DateAdded = euvdDate(item.DatePublished)
	}
	if len(item.Vendors) > 0 {
		entry.VendorProject = strings.TrimSpace(item.Vendors[0].Vendor.Name)
	}
	if len(item.Products) > 0 {
		entry.Product = strings.TrimSpace(item.Products[0].Product.Name)
	}
	return entry, true
}

// euvdDate parses the API's localized date strings. A narrow no-break space
// before AM/PM would otherwise break the parse.
func euvdDate(value string) time.Time {
	return parseDate(euvdDateLayout, strings.ReplaceAll(value, " ", " "))
}
