package provider

import (
	"context"
	"encoding/json"
	"time"

	"github.com/hibouhq/hibou/internal/advisory"
)

type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
	// Distro is the purl "distro" qualifier for OS packages ("alpine-3.18.4",
	// "debian-12"). Empty for language ecosystems. Providers that match distro
	// advisories need it to stay release-accurate.
	Distro string
}

type AdvisoryResult struct {
	ProviderName   string
	ProviderID     string
	Aliases        []string
	Title          string
	Description    string
	Ratings        []advisory.Rating
	CWEIDs         []string
	IsMalware      bool
	MalwareType    *string
	AffectedRanges []advisory.AffectedRange
	PublishedAt    *time.Time
	WithdrawnAt    *time.Time
	RawData        json.RawMessage
}

func (r AdvisoryResult) ToIngestResult() advisory.IngestResult {
	return advisory.IngestResult{
		ProviderID:     r.ProviderID,
		Aliases:        append([]string(nil), r.Aliases...),
		Title:          r.Title,
		Description:    r.Description,
		Ratings:        append([]advisory.Rating(nil), r.Ratings...),
		CWEIDs:         append([]string(nil), r.CWEIDs...),
		IsMalware:      r.IsMalware,
		MalwareType:    r.MalwareType,
		AffectedRanges: append([]advisory.AffectedRange(nil), r.AffectedRanges...),
		PublishedAt:    r.PublishedAt,
		WithdrawnAt:    r.WithdrawnAt,
		RawData:        r.RawData,
	}
}

type AdvisoryProvider interface {
	Name() string
	SupportedEcosystems() []string
	QueryPackages(ctx context.Context, queries []PackageQuery) ([]AdvisoryResult, error)
	BatchSize() int
}
