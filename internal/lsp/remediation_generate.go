package lsp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/remediation"
)

type remediationPrepareParams struct {
	Root         string   `json:"root"`
	ConsentLocal bool     `json:"consent_local"`
	Manifests    []string `json:"manifests,omitempty"`
	Vulns        []string `json:"vulns,omitempty"`
	UpgradeLevel string   `json:"upgrade_level,omitempty"`
}

type remediationPrepared struct {
	ID             string             `json:"id"`
	Root           string             `json:"root"`
	BaseSHA        string             `json:"base_sha"`
	Branch         string             `json:"branch"`
	ManagerVersion string             `json:"manager_version"`
	ManagerPath    string             `json:"manager_path"`
	RuntimeVersion string             `json:"runtime_version"`
	Units          []remediation.Unit `json:"units"`
	Unavailable    []string           `json:"unavailable"`
	ExpiresAt      time.Time          `json:"expires_at"`
}

type localRemediationDraft struct {
	prepared           remediationPrepared
	backend            remediation.NPMBackend
	artifact           *remediation.Artifact
	generated          bool
	generatedUnits     []string
	generationDigest   string
	generatedSelection remediationGenerateParams
}

type localToolInspector func(context.Context) (remediation.Tool, error)
type localBackendFactory func(remediation.Tool, remediation.MatchPackages) remediation.NPMBackend

func (s *Server) remediationWorkspace(root string) (*workspace, error) {
	if root == "" {
		return nil, errors.New("choose a repository root explicitly")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	for _, ws := range s.allWorkspaces() {
		if filepath.Clean(ws.root) == root {
			return ws, nil
		}
	}
	return nil, errors.New("repository is not registered in this language-server session")
}

func (s *Server) remediationPrepare(ctx context.Context, p remediationPrepareParams) (*remediationPrepared, error) {
	if !p.ConsentLocal {
		return nil, errors.New("local execution requires workspace trust and explicit user consent")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	s.remediationMu.Lock()
	defer s.remediationMu.Unlock()
	ws, err := s.remediationWorkspace(p.Root)
	if err != nil {
		return nil, err
	}
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	if client.token == "" {
		return nil, errors.New("sign in before preparing dependency fixes")
	}
	branch := ws.git.branch(ctx)
	repo, err := ws.resolveRepo(ctx, client, branch)
	if err != nil {
		return nil, err
	}
	sha, err := ws.git.head(ctx)
	if err != nil {
		return nil, err
	}
	inspect := s.remediationToolInspector
	if inspect == nil {
		inspect = remediation.InspectLocalNPM
	}
	tool, err := inspect(ctx)
	if err != nil {
		return nil, err
	}
	match := func(ctx context.Context, purls []string) ([]remediation.AdvisoryMatch, error) {
		current, err := s.api()
		if err != nil {
			return nil, err
		}
		var results []remediation.AdvisoryMatch
		for start := 0; start < len(purls); start += 500 {
			end := min(start+500, len(purls))
			var response struct {
				Matches []remediation.AdvisoryMatch `json:"matches"`
			}
			endpoint := "/orgs/" + url.PathEscape(repo.Provider) + "/" + url.PathEscape(repo.Org) + "/advisories/match"
			body := map[string]any{"purls": purls[start:end], "repo": repo.Repo, "include_ranges": true}
			if err := current.do(ctx, http.MethodPost, endpoint, nil, body, &response, nil); err != nil {
				return nil, err
			}
			results = append(results, response.Matches...)
		}
		return results, nil
	}
	backend := remediation.NPMBackend{Tool: tool, Match: match}
	if s.remediationBackendFactory != nil {
		backend = s.remediationBackendFactory(tool, match)
	}
	manifests := p.Manifests
	if len(manifests) == 0 {
		manifests, err = remediation.DiscoverNPMManifests(ctx, ws.root, sha)
		if err != nil {
			return nil, err
		}
	}
	if len(manifests) > remediation.MaxUnits {
		return nil, errors.New("too many selected dependency modules")
	}
	prepared := remediationPrepared{
		ID: uuid.NewString(), Root: ws.root, BaseSHA: sha, Branch: branch, ManagerVersion: tool.VersionOutput,
		ManagerPath: tool.Path, RuntimeVersion: tool.RuntimeVersionOutput, ExpiresAt: time.Now().Add(15 * time.Minute),
		Units: []remediation.Unit{}, Unavailable: []string{},
	}
	for _, manifest := range manifests {
		unit, err := backend.Prepare(ctx, ws.root, sha, manifest, p.Vulns, p.UpgradeLevel)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, remediation.ErrAdvisoryEvidence) {
				return nil, err
			}
			prepared.Unavailable = append(prepared.Unavailable, fmt.Sprintf("%s: %s", manifest, err))
			continue
		}
		prepared.Units = append(prepared.Units, unit)
	}
	if s.remediationDrafts == nil {
		s.remediationDrafts = map[string]*localRemediationDraft{}
	}
	for id, draft := range s.remediationDrafts {
		if time.Now().After(draft.prepared.ExpiresAt) {
			delete(s.remediationDrafts, id)
		}
	}
	if len(prepared.Units) > 0 && len(s.remediationDrafts) >= 4 {
		return nil, errors.New("four local remediation drafts are already open; restart the language server or wait for expiry")
	}
	if len(prepared.Units) > 0 {
		s.remediationDrafts[prepared.ID] = &localRemediationDraft{prepared: prepared, backend: backend}
	}
	return &prepared, nil
}

type remediationGenerateParams struct {
	Root           string                                 `json:"root"`
	ID             string                                 `json:"id"`
	UnitIDs        []string                               `json:"unit_ids"`
	VersionTargets map[string][]remediation.VersionTarget `json:"version_targets,omitempty"`
	UpgradeLevel   string                                 `json:"upgrade_level,omitempty"`
	AllowMajor     bool                                   `json:"allow_major,omitempty"`
}

func (s *Server) remediationGenerate(ctx context.Context, p remediationGenerateParams) (*remediation.Artifact, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	s.remediationMu.Lock()
	defer s.remediationMu.Unlock()
	ws, err := s.remediationWorkspace(p.Root)
	if err != nil {
		return nil, err
	}
	draft := s.remediationDrafts[p.ID]
	if draft == nil || draft.prepared.Root != ws.root || time.Now().After(draft.prepared.ExpiresAt) {
		return nil, errors.New("local remediation draft is missing or expired; prepare again")
	}
	normalized := p
	normalized.UnitIDs = slices.Clone(p.UnitIDs)
	slices.Sort(normalized.UnitIDs)
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if draft.generated {
		requested := slices.Clone(p.UnitIDs)
		slices.Sort(requested)
		if !slices.Equal(requested, draft.generatedUnits) {
			return nil, errors.New("generation selection is immutable; prepare a new draft")
		}
		if draft.generationDigest != digest {
			return nil, errors.New("version choices are immutable after generation; prepare a new draft")
		}
		if draft.artifact != nil {
			return draft.artifact, nil
		}
		return nil, errors.New("this generation failed; prepare a new draft rather than retrying changed inputs")
	}
	sha, err := ws.git.head(ctx)
	if err != nil {
		return nil, err
	}
	if sha != draft.prepared.BaseSHA {
		return nil, errors.New("HEAD changed; prepare a new draft")
	}
	if len(p.UnitIDs) == 0 {
		return nil, errors.New("select at least one prepared dependency module")
	}
	if p.UpgradeLevel == "major" && !p.AllowMajor {
		return nil, errors.New("major upgrades require explicit consent")
	}
	for id := range p.VersionTargets {
		if !slices.Contains(p.UnitIDs, id) {
			return nil, errors.New("version choices reference an unselected module")
		}
	}
	var units []remediation.Unit
	for _, unit := range draft.prepared.Units {
		if slices.Contains(p.UnitIDs, unit.ID) {
			unit.VersionTargets = slices.Clone(p.VersionTargets[unit.ID])
			if p.UpgradeLevel != "" {
				unit.UpgradeLevel = p.UpgradeLevel
			}
			if len(unit.VersionTargets) > 200 {
				return nil, errors.New("too many exact version choices")
			}
			units = append(units, unit)
		}
	}
	if len(units) != len(p.UnitIDs) {
		return nil, errors.New("unknown or duplicate resolution unit selection")
	}
	draft.generated = true
	if err := json.Unmarshal(encoded, &draft.generatedSelection); err != nil {
		return nil, err
	}
	draft.generationDigest = digest
	draft.generatedUnits = slices.Clone(p.UnitIDs)
	slices.Sort(draft.generatedUnits)
	artifact, err := (remediation.Engine{Backend: draft.backend}).Generate(ctx, remediation.Request{Repository: ws.root, BaseSHA: sha, Units: units})
	if err != nil {
		return nil, err
	}
	draft.artifact = artifact
	return artifact, nil
}
