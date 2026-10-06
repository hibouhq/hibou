package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/version"
)

// DefaultCISACatalogURL is CISA's published JSON feed. Operators with no
// outbound internet point kev.cisa.url at a mirror serving the same document.
const DefaultCISACatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxCatalogBytes caps a catalog response read. The CISA catalog is ~3 MB
// today; the cap leaves an order of magnitude of growth before it needs
// revisiting.
const maxCatalogBytes = 50 << 20

// CISA fetches the CISA Known Exploited Vulnerabilities catalog: one JSON
// document (~1,400 entries) that CISA updates a few times a week.
type CISA struct {
	url        string
	httpClient *http.Client
	log        zerolog.Logger
}

func NewCISA(url string, log zerolog.Logger) *CISA {
	if strings.TrimSpace(url) == "" {
		url = DefaultCISACatalogURL
	}
	return &CISA{
		url: url,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		log: log.With().Str("component", "kev.cisa").Logger(),
	}
}

func (c *CISA) Name() string { return "cisa" }

// WithdrawalGrace is zero: the catalog is one atomic JSON document, so an
// entry absent from a successful fetch has genuinely been withdrawn.
func (c *CISA) WithdrawalGrace() time.Duration { return 0 }

// Wire shapes, exactly as CISA publishes them. Dates are "2006-01-02" strings
// and knownRansomwareCampaignUse is the string "Known" or "Unknown".
type cisaWireCatalog struct {
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []cisaWireEntry `json:"vulnerabilities"`
}

type cisaWireEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// Fetch downloads and validates the catalog.
//
// An empty result is an error, never a catalog: the caller replaces the stored
// rows with what this returns, and a truncated or misrouted response must not
// silently un-list every known-exploited vulnerability.
func (c *CISA) Fetch(ctx context.Context) (Catalog, error) {
	// c.url is operator-configured, same trust stance as the OSV base URL.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return Catalog{}, fmt.Errorf("kev/cisa: create request: %w", err)
	}
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Catalog{}, fmt.Errorf("kev/cisa: fetch catalog: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Catalog{}, fmt.Errorf("kev/cisa: catalog returned status %d", resp.StatusCode)
	}

	var wire cisaWireCatalog
	limitedBody := io.LimitReader(resp.Body, maxCatalogBytes)
	if err := json.NewDecoder(limitedBody).Decode(&wire); err != nil {
		return Catalog{}, fmt.Errorf("kev/cisa: decode catalog: %w", err)
	}
	return normalizeCISA(wire)
}

func normalizeCISA(wire cisaWireCatalog) (Catalog, error) {
	catalog := Catalog{
		Version:  wire.CatalogVersion,
		Released: wire.DateReleased,
		Entries:  make([]Entry, 0, len(wire.Vulnerabilities)),
	}
	for _, entry := range wire.Vulnerabilities {
		cveID := strings.ToUpper(strings.TrimSpace(entry.CVEID))
		if !cveIDPattern.MatchString(cveID) {
			catalog.Skipped++
			continue
		}
		catalog.Entries = append(catalog.Entries, Entry{
			CVEID:             cveID,
			VendorProject:     strings.TrimSpace(entry.VendorProject),
			Product:           strings.TrimSpace(entry.Product),
			VulnerabilityName: strings.TrimSpace(entry.VulnerabilityName),
			// A date that fails to parse stays zero rather than failing the
			// whole catalog; the id is the load-bearing field.
			DateAdded:                  parseDate("2006-01-02", entry.DateAdded),
			DueDate:                    parseDate("2006-01-02", entry.DueDate),
			KnownRansomwareCampaignUse: strings.EqualFold(strings.TrimSpace(entry.KnownRansomwareCampaignUse), "known"),
		})
	}
	if len(catalog.Entries) == 0 {
		return Catalog{}, fmt.Errorf("kev/cisa: catalog contains no usable entries (%d skipped)", catalog.Skipped)
	}
	return catalog, nil
}
