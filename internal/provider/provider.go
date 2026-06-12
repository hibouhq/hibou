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
}

type AdvisoryResult struct {
	ProviderName   string
	ProviderID     string
	Aliases        []string
	Title          string
	Description    string
	Severity       *advisory.Severity
	CVSSScore      *float64
	CVSSVersion    *advisory.CVSSVersion
	CVSSVector     string
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
		Severity:       r.Severity,
		CVSSScore:      r.CVSSScore,
		CVSSVersion:    r.CVSSVersion,
		CVSSVector:     r.CVSSVector,
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
