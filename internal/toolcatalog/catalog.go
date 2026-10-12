package toolcatalog

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	CategoryAdvisoryProvider = "advisory_provider"
	CategorySAST             = "sast"
	CategorySecretScanning   = "secret_scanning"
	CategorySBOMGenerator    = "sbom_generator"
	CategoryVEXSource        = "vex_source"
	CategoryCoverage         = "coverage"

	StatusHealthy   = "healthy"
	StatusDegraded  = "degraded"
	StatusUnhealthy = "unhealthy"
	StatusInactive  = "inactive"
)

const (
	recentWindow   = 24 * time.Hour
	inactiveWindow = 30 * 24 * time.Hour
)

type ToolEntry struct {
	Name          string    `json:"name"`
	Category      string    `json:"category"`
	Status        string    `json:"status"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	DataPoints    int64     `json:"data_points"`
	RepoCount     int64     `json:"repo_count"`
	// LastOutcome is the outcome of the producer's latest run (completed,
	// partial, failed); Warning explains a partial or failed one (ADR-034).
	LastOutcome string `json:"last_outcome,omitempty"`
	Warning     string `json:"warning,omitempty"`
	// ResolutionPolicy / PolicyThreshold: how this producer's absent
	// findings are resolved (ADR-034 §5); set for producers with runs.
	ResolutionPolicy string `json:"resolution_policy,omitempty"`
	PolicyThreshold  int    `json:"policy_threshold,omitempty"`
}

type Catalog struct {
	OrgName     string      `json:"org_name"`
	GeneratedAt time.Time   `json:"generated_at"`
	Tools       []ToolEntry `json:"tools"`
}

type Service struct {
	store Store
	now   func() time.Time
}

type Store interface {
	ListAdvisoryProviderStats(ctx context.Context, orgID uuid.UUID) ([]AdvisoryProviderStat, error)
	ListFindingToolStats(ctx context.Context, orgID uuid.UUID) ([]FindingToolStat, error)
	ListProducerRunToolStats(ctx context.Context, orgID uuid.UUID) ([]ProducerRunStat, error)
	ListVEXSourceStats(ctx context.Context, orgID uuid.UUID) ([]VEXSourceStat, error)
	ListComponentEcosystemStats(ctx context.Context, orgID uuid.UUID) ([]ComponentEcosystemStat, error)
	ListCoverageSnapshotStats(ctx context.Context, orgID uuid.UUID) ([]CoverageSnapshotStat, error)
}

type AdvisoryProviderStat struct {
	Provider        string
	LastCompletedAt time.Time
	TotalAdvisories int64
	RepoCount       int64
	LastErrorAt     time.Time
	LastError       string
}

type FindingToolStat struct {
	Tool         string
	LastSeenAt   time.Time
	FindingCount int64
	RepoCount    int64
}

// ProducerRunStat summarizes a producer's recorded runs (ADR-034 §2).
type ProducerRunStat struct {
	Producer      string
	LastRunAt     time.Time
	LastSuccessAt time.Time
	LastErrorAt   time.Time
	LastError     string
	LastOutcome   string
	RunCount      int64
	RepoCount     int64
}

type VEXSourceStat struct {
	Source         string
	LastSeenAt     time.Time
	StatementCount int64
	RepoCount      int64
}

type ComponentEcosystemStat struct {
	Ecosystem      string
	ComponentCount int64
	RepoCount      int64
	LastSeenAt     time.Time
}

type CoverageSnapshotStat struct {
	Format        string
	LastSeenAt    time.Time
	SnapshotCount int64
	RepoCount     int64
}

func NewService(store Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Catalog(ctx context.Context, orgID uuid.UUID, orgName string) (Catalog, error) {
	generatedAt := s.now()
	tools := make([]ToolEntry, 0)

	providerStats, err := s.store.ListAdvisoryProviderStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	for _, stat := range providerStats {
		tools = append(tools, advisoryEntry(stat, generatedAt))
	}

	// Producers with recorded runs carry real health; tools only known from
	// their findings (uploads before run recording) keep the activity view.
	runStats, err := s.store.ListProducerRunToolStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	withRuns := make(map[string]struct{}, len(runStats))
	for _, stat := range runStats {
		entry := producerEntry(stat, generatedAt)
		withRuns[entry.Name] = struct{}{}
		tools = append(tools, entry)
	}
	findingStats, err := s.store.ListFindingToolStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	for _, stat := range findingStats {
		if _, ok := withRuns[normalizeName(stat.Tool)]; ok {
			continue
		}
		tools = append(tools, activityEntry(strings.TrimSpace(stat.Tool), CategorySAST, stat.LastSeenAt, stat.LastSeenAt, time.Time{}, "", stat.FindingCount, stat.RepoCount, generatedAt))
	}

	vexStats, err := s.store.ListVEXSourceStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	for _, stat := range vexStats {
		tools = append(tools, activityEntry(strings.TrimSpace(stat.Source), CategoryVEXSource, stat.LastSeenAt, stat.LastSeenAt, time.Time{}, "", stat.StatementCount, stat.RepoCount, generatedAt))
	}

	ecosystemStats, err := s.store.ListComponentEcosystemStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	for _, stat := range ecosystemStats {
		tools = append(tools, activityEntry(normalizeName(stat.Ecosystem), CategorySBOMGenerator, stat.LastSeenAt, stat.LastSeenAt, time.Time{}, "", stat.ComponentCount, stat.RepoCount, generatedAt))
	}

	coverageStats, err := s.store.ListCoverageSnapshotStats(ctx, orgID)
	if err != nil {
		return Catalog{}, err
	}
	for _, stat := range coverageStats {
		tools = append(tools, activityEntry(normalizeName(stat.Format), CategoryCoverage, stat.LastSeenAt, stat.LastSeenAt, time.Time{}, "", stat.SnapshotCount, stat.RepoCount, generatedAt))
	}

	sort.Slice(tools, func(i, j int) bool {
		if tools[i].Category == tools[j].Category {
			return tools[i].Name < tools[j].Name
		}
		return tools[i].Category < tools[j].Category
	})

	return Catalog{OrgName: orgName, GeneratedAt: generatedAt, Tools: tools}, nil
}

func advisoryEntry(stat AdvisoryProviderStat, now time.Time) ToolEntry {
	name := normalizeName(stat.Provider)
	lastError := strings.TrimSpace(stat.LastError)
	status := StatusHealthy
	switch {
	case stat.LastCompletedAt.IsZero() && stat.LastErrorAt.IsZero():
		status = StatusInactive
	case !stat.LastErrorAt.IsZero() && (stat.LastCompletedAt.IsZero() || !stat.LastCompletedAt.After(stat.LastErrorAt)):
		status = StatusUnhealthy
	case !stat.LastErrorAt.IsZero() && stat.LastErrorAt.After(now.Add(-recentWindow)):
		status = StatusDegraded
	case stat.LastCompletedAt.Before(now.Add(-inactiveWindow)):
		status = StatusInactive
	}

	return ToolEntry{
		Name:          name,
		Category:      CategoryAdvisoryProvider,
		Status:        status,
		LastSeenAt:    stat.LastCompletedAt,
		LastSuccessAt: stat.LastCompletedAt,
		LastErrorAt:   stat.LastErrorAt,
		LastError:     lastError,
		DataPoints:    stat.TotalAdvisories,
		RepoCount:     stat.RepoCount,
	}
}

// producerEntry rates a producer by its latest run: failed is unhealthy,
// partial degraded (some files or paths went unanalysed), and no run in the
// inactive window inactive.
func producerEntry(stat ProducerRunStat, now time.Time) ToolEntry {
	name := normalizeName(stat.Producer)
	category := CategorySAST
	if strings.HasPrefix(name, "secret-scanning") {
		category = CategorySecretScanning
	}
	entry := ToolEntry{
		Name:          name,
		Category:      category,
		Status:        StatusHealthy,
		LastSeenAt:    stat.LastRunAt,
		LastSuccessAt: stat.LastSuccessAt,
		LastErrorAt:   stat.LastErrorAt,
		LastError:     strings.TrimSpace(stat.LastError),
		DataPoints:    stat.RunCount,
		RepoCount:     stat.RepoCount,
		LastOutcome:   stat.LastOutcome,
	}
	switch {
	case stat.LastRunAt.IsZero() || stat.LastRunAt.Before(now.Add(-inactiveWindow)):
		entry.Status = StatusInactive
	case stat.LastOutcome == "failed":
		entry.Status = StatusUnhealthy
		entry.Warning = "Latest run failed: its findings were not re-checked."
	case stat.LastOutcome == "partial":
		entry.Status = StatusDegraded
		entry.Warning = "Latest run was partial: findings outside what it analysed were not re-checked."
	}
	return entry
}

func activityEntry(name, category string, lastSeenAt, lastSuccessAt, lastErrorAt time.Time, lastError string, dataPoints, repoCount int64, now time.Time) ToolEntry {
	name = normalizeName(name)
	status := StatusHealthy
	if name == "" {
		name = "unknown"
	}
	if lastSeenAt.IsZero() {
		status = StatusInactive
	} else if lastSeenAt.Before(now.Add(-inactiveWindow)) {
		status = StatusInactive
	}

	return ToolEntry{
		Name:          name,
		Category:      category,
		Status:        status,
		LastSeenAt:    lastSeenAt,
		LastSuccessAt: lastSuccessAt,
		LastErrorAt:   lastErrorAt,
		LastError:     strings.TrimSpace(lastError),
		DataPoints:    dataPoints,
		RepoCount:     repoCount,
	}
}

func normalizeName(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "unknown"
	}
	return strings.ToLower(trimmed)
}
