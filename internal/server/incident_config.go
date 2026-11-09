package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// persistedRepoConfig is the slice of .hibou.yaml incidents need between
// forge reads (ADR-053 §1): sweeps run after catalogue and advisory refreshes
// for every repository, and must not call the forge once per repository.
type persistedRepoConfig struct {
	Product   *repoconfig.ProductConfig   `json:"product,omitempty"`
	Incidents *repoconfig.IncidentsConfig `json:"incidents,omitempty"`
}

// persistRepoIncidentConfig records the product and incidents sections each
// time the file is read. Best-effort: a failure leaves the previous copy.
func (s *Server) persistRepoIncidentConfig(ctx context.Context, repoID uuid.UUID, cfg *repoconfig.RepoConfig) {
	if s == nil || s.queries == nil || cfg == nil {
		return
	}
	payload, err := json.Marshal(persistedRepoConfig{Product: cfg.Product, Incidents: cfg.Incidents})
	if err != nil {
		return
	}
	if err := s.queries.Incidents().UpsertRepoIncidentConfig(ctx, dbgen.UpsertRepoIncidentConfigParams{RepoID: repoID, Config: payload}); err != nil {
		s.log.Warn().Err(err).Str("repo_id", repoID.String()).Msg("persist repo incident config")
	}
}

func (s *Server) loadPersistedRepoConfig(ctx context.Context, repoID uuid.UUID) persistedRepoConfig {
	var out persistedRepoConfig
	row, err := s.queries.Incidents().GetRepoIncidentConfig(ctx, repoID)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(row.Config, &out)
	return out
}

// productIdentity is the product a repository ships, for VEX and advisories:
// the configured purl, else pkg:generic/<org>/<repo>.
type productIdentity struct {
	PURL string
	Name string
	CPE  string
}

func (s *Server) repoProduct(ctx context.Context, org *store.Organization, repo *store.Repository) productIdentity {
	cfg := s.loadPersistedRepoConfig(ctx, repo.ID)
	out := productIdentity{PURL: "pkg:generic/" + org.Slug + "/" + repo.Slug, Name: repo.Name}
	if cfg.Product != nil {
		if purl := strings.TrimSpace(cfg.Product.PURL); purl != "" {
			out.PURL = purl
		}
		if name := strings.TrimSpace(cfg.Product.Name); name != "" {
			out.Name = name
		}
		out.CPE = strings.TrimSpace(cfg.Product.CPE)
	}
	if out.Name == "" {
		out.Name = repo.Slug
	}
	return out
}

// cpeForVersion fills a product CPE's version field for one release.
func cpeForVersion(cpe, version string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 || version == "" {
		return cpe
	}
	if parts[5] == "*" || parts[5] == "-" || parts[5] == "" {
		parts[5] = strings.ReplaceAll(version, ":", `\:`)
	}
	return strings.Join(parts, ":")
}

// incidentSettings are an organisation's incident settings with defaults.
type incidentSettings struct {
	Row             dbgen.IncidentSetting
	Locked          []repoconfig.IncidentRule
	Defaults        []repoconfig.IncidentRule
	DefaultsSet     bool
	National        []incident.NationalRegime
	InternalTargets incident.InternalTargets
}

func (s *Server) loadIncidentSettings(ctx context.Context, orgID uuid.UUID) (incidentSettings, error) {
	out := incidentSettings{Row: dbgen.IncidentSetting{OrgID: orgID, DueSoonLeadMinutes: 360}}
	row, err := s.queries.Incidents().GetIncidentSettings(ctx, orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.Row = row
	_ = json.Unmarshal(row.LockedRules, &out.Locked)
	if len(row.DefaultRules) > 0 && string(row.DefaultRules) != "null" {
		out.DefaultsSet = json.Unmarshal(row.DefaultRules, &out.Defaults) == nil
	}
	_ = json.Unmarshal(row.NationalRegimes, &out.National)
	_ = json.Unmarshal(row.InternalTargets, &out.InternalTargets)
	return out, nil
}

// effectiveIncidentRules resolves the rules a repository runs (ADR-053 §1).
func (s *Server) effectiveIncidentRules(ctx context.Context, orgID, repoID uuid.UUID) ([]incident.Rule, error) {
	settings, err := s.loadIncidentSettings(ctx, orgID)
	if err != nil {
		return nil, err
	}
	cfg := s.loadPersistedRepoConfig(ctx, repoID)
	return incident.EffectiveRules(settings.Locked, settings.Defaults, settings.DefaultsSet, cfg.Incidents), nil
}
