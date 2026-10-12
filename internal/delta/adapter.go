package delta

import (
	"context"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/license"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type StoreAdapter struct {
	queries *store.Queries
}

func NewStoreAdapter(queries *store.Queries) *StoreAdapter {
	return &StoreAdapter{queries: queries}
}

// The gate reaches these two through optional interface assertions on the store,
// so a missing method degrades to "no license gating" instead of a compile
// error. That is exactly how the license gate silently never ran: the adapter
// simply did not forward ListComponentsBySnapshot. These assertions make the
// omission a build failure.
// GateStore is pinned too, and it is not optional hygiene: commit 6a8efc6 added
// GetOrganizationByID to the interface without forwarding it here, the
// `store.(GateStore)` assertion in NewService silently went nil, and EVERY gate
// evaluation in production — the PR compare and the forge check publisher —
// failed with "gate store is not configured" from that release on.
var (
	_ GateStore           = (*StoreAdapter)(nil)
	_ componentLister     = (*StoreAdapter)(nil)
	_ acceptanceLister    = (*StoreAdapter)(nil)
	_ licensePolicyReader = (*StoreAdapter)(nil)
	_ kevLister           = (*StoreAdapter)(nil)
	_ cweLister           = (*StoreAdapter)(nil)
	_ coverageStore       = (*StoreAdapter)(nil)
)

func (a *StoreAdapter) SnapshotProducerRuns(ctx context.Context, snapshotID uuid.UUID) ([]store.ProducerRun, error) {
	return a.queries.SnapshotProducerRuns(ctx, snapshotID)
}

func (a *StoreAdapter) SnapshotCoverageKnown(ctx context.Context, snapshotID uuid.UUID) (bool, error) {
	return a.queries.SnapshotCoverageKnown(ctx, snapshotID)
}

func (a *StoreAdapter) ListFindingCWEs(ctx context.Context, vulnerabilityIDs []uuid.UUID) (map[uuid.UUID][]store.FindingCWE, error) {
	return a.queries.ListFindingCWEs(ctx, vulnerabilityIDs)
}

func (a *StoreAdapter) ListComponentsBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]dbgen.Component, error) {
	return a.queries.ListComponentsBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) ListActiveFindingAcceptancesByRepo(ctx context.Context, repoID uuid.UUID) ([]store.FindingAcceptance, error) {
	return a.queries.ListActiveFindingAcceptancesByRepo(ctx, repoID)
}

func (a *StoreAdapter) GetOrgLicensePolicy(ctx context.Context, orgID uuid.UUID) (*license.Spec, error) {
	return a.queries.GetOrgLicensePolicy(ctx, orgID)
}

func (a *StoreAdapter) GetOrganizationByID(ctx context.Context, id uuid.UUID) (*store.Organization, error) {
	return a.queries.GetOrganizationByID(ctx, id)
}

func (a *StoreAdapter) ListAllVulnerabilitiesBySnapshot(ctx context.Context, snapshotID uuid.UUID) ([]store.Vulnerability, error) {
	return a.queries.ListAllVulnerabilitiesBySnapshot(ctx, snapshotID)
}

func (a *StoreAdapter) GetAdvisoryByID(ctx context.Context, id uuid.UUID) (dbgen.Advisory, error) {
	return a.queries.GetAdvisoryByID(ctx, id)
}

func (a *StoreAdapter) GetEffectiveVEXStatus(ctx context.Context, arg dbgen.GetEffectiveVEXStatusParams) (dbgen.VexStatement, error) {
	return a.queries.GetEffectiveVEXStatus(ctx, arg)
}

func (a *StoreAdapter) GetSnapshotByID(ctx context.Context, id uuid.UUID) (*store.Snapshot, error) {
	return a.queries.GetSnapshotByID(ctx, id)
}

func (a *StoreAdapter) GetRefByID(ctx context.Context, id uuid.UUID) (*store.Ref, error) {
	return a.queries.GetRefByID(ctx, id)
}

func (a *StoreAdapter) GetRepositoryByID(ctx context.Context, id uuid.UUID) (*store.Repository, error) {
	return a.queries.GetRepositoryByID(ctx, id)
}

func (a *StoreAdapter) GetComponentByID(ctx context.Context, id uuid.UUID) (dbgen.Component, error) {
	return a.queries.GetComponentByID(ctx, id)
}

func (a *StoreAdapter) FilterKEVAdvisoryIDs(ctx context.Context, advisoryIDs []uuid.UUID) ([]uuid.UUID, error) {
	return a.queries.FilterKEVAdvisoryIDs(ctx, advisoryIDs)
}

func (a *StoreAdapter) FilterKEVIdentifiers(ctx context.Context, identifiers []string) ([]string, error) {
	return a.queries.FilterKEVIdentifiers(ctx, identifiers)
}

func (a *StoreAdapter) ListQualityGatesByRepo(ctx context.Context, repoID uuid.UUID) ([]dbgen.QualityGate, error) {
	return a.queries.ListQualityGatesByRepo(ctx, uuid.NullUUID{UUID: repoID, Valid: repoID != uuid.Nil})
}

func (a *StoreAdapter) ListOrgWideQualityGates(ctx context.Context, orgID uuid.UUID) ([]dbgen.QualityGate, error) {
	return a.queries.ListOrgWideQualityGates(ctx, orgID)
}
