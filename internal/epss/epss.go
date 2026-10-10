// Package epss reads FIRST's daily EPSS file (ADR-038 §4).
//
// The file is a gzipped CSV of ~300k rows. Its first line names the model
// and the score date, "#model_version:v2025.03.14,score_date:2026-10-09T...",
// followed by the header "cve,epss,percentile". A score from one model is not
// comparable with another's, so the model travels with the data.
package epss

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hibouhq/hibou/internal/version"
)

// DefaultURL is FIRST's published daily file.
const DefaultURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// MinRows is the smallest file accepted: the real one carries ~300k CVEs, so
// a much shorter file is truncated or wrong, and replacing the mirror with it
// would wipe scores for no reason.
const MinRows = 100_000

// Score is one CVE's probability of exploitation in the next 30 days, and its
// percentile among all scored CVEs.
type Score struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// Catalog is one day's file.
type Catalog struct {
	ModelVersion string
	ScoreDate    time.Time
	Scores       []Score
}

// Fetch downloads and parses the file at url (DefaultURL when empty).
func Fetch(ctx context.Context, client *http.Client, url string) (Catalog, error) {
	if strings.TrimSpace(url) == "" {
		url = DefaultURL
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Catalog{}, fmt.Errorf("epss: build request: %w", err)
	}
	req.Header.Set("User-Agent", "hibou/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return Catalog{}, fmt.Errorf("epss: download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Catalog{}, fmt.Errorf("epss: download returned status %d", resp.StatusCode)
	}
	// 64 MiB compressed is twenty times today's file.
	return Parse(io.LimitReader(resp.Body, 64<<20), true)
}

// Parse reads the file, gzipped or not.
func Parse(r io.Reader, gzipped bool) (Catalog, error) {
	if gzipped {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return Catalog{}, fmt.Errorf("epss: open gzip: %w", err)
		}
		defer zr.Close()
		r = zr
	}
	buffered := bufio.NewReader(r)
	first, err := buffered.ReadString('\n')
	if err != nil {
		return Catalog{}, fmt.Errorf("epss: read model line: %w", err)
	}
	catalog, err := parseModelLine(first)
	if err != nil {
		return Catalog{}, err
	}

	reader := csv.NewReader(buffered)
	reader.FieldsPerRecord = 3
	reader.ReuseRecord = true
	header, err := reader.Read()
	if err != nil || header[0] != "cve" || header[1] != "epss" || header[2] != "percentile" {
		return Catalog{}, errors.New("epss: unexpected header, want cve,epss,percentile")
	}
	catalog.Scores = make([]Score, 0, 320_000)
	for {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Catalog{}, fmt.Errorf("epss: read row %d: %w", len(catalog.Scores)+1, err)
		}
		score, errScore := strconv.ParseFloat(record[1], 64)
		percentile, errPercentile := strconv.ParseFloat(record[2], 64)
		cveID := strings.ToUpper(strings.TrimSpace(record[0]))
		if errScore != nil || errPercentile != nil || !strings.HasPrefix(cveID, "CVE-") ||
			score < 0 || score > 1 || percentile < 0 || percentile > 1 {
			return Catalog{}, fmt.Errorf("epss: malformed row %q", strings.Join(record, ","))
		}
		catalog.Scores = append(catalog.Scores, Score{CVEID: cveID, Score: score, Percentile: percentile})
	}
	return catalog, nil
}

// parseModelLine reads "#model_version:v2025.03.14,score_date:2026-10-09T12:00:22Z".
func parseModelLine(line string) (Catalog, error) {
	line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
	catalog := Catalog{}
	for _, part := range strings.Split(line, ",") {
		key, value, _ := strings.Cut(part, ":")
		switch strings.TrimSpace(key) {
		case "model_version":
			catalog.ModelVersion = strings.TrimSpace(value)
		case "score_date":
			value = strings.TrimSpace(value)
			parsed, err := time.Parse(time.RFC3339, value)
			if err != nil {
				parsed, err = time.Parse("2006-01-02", value)
			}
			if err != nil {
				return Catalog{}, fmt.Errorf("epss: bad score_date %q", value)
			}
			catalog.ScoreDate = parsed.UTC()
		}
	}
	if catalog.ModelVersion == "" || catalog.ScoreDate.IsZero() {
		return Catalog{}, fmt.Errorf("epss: first line %q names no model_version and score_date", line)
	}
	return catalog, nil
}
