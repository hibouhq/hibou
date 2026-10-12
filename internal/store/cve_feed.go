package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/cvefeed"
	"github.com/hibouhq/hibou/internal/cwe"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// SaveCVERecord writes one decoded record and replaces its affected products.
//
// Replace rather than merge: a CNA revision can remove an affected product as
// well as add one, and merging would leave a withdrawn product matching for
// ever. The whole write is one transaction so a record is never visible with
// half its products.
func (q *Queries) SaveCVERecord(ctx context.Context, db *sql.DB, record cvefeed.Projection) error {
	return q.SaveCVERecords(ctx, db, []cvefeed.Projection{record})
}

// MatchSubscriptions finds the watched products an incoming record concerns.
//
// Watches are instance-wide, so there is no org to narrow by: the feed worker
// has no org context, and a mapping decided here is a fact about the world
// rather than about one organization.
func (q *Queries) MatchSubscriptions(ctx context.Context, productKeys, vendorKeys []string) ([]dbgen.CveSubscription, error) {
	if len(productKeys) == 0 {
		return []dbgen.CveSubscription{}, nil
	}
	if vendorKeys == nil {
		vendorKeys = []string{}
	}
	return q.db.MatchSubscriptionsForProductKeys(ctx, dbgen.MatchSubscriptionsForProductKeysParams{
		Column1: productKeys,
		Column2: vendorKeys,
	})
}

// PreviewSubscription answers "which advisories would this have caught?" before
// a subscription exists.
//
// This is the mitigation for the one failure mode nothing else catches: a
// subscription under the wrong product name produces silence, and silence is
// indistinguishable from safety. Running it against the local corpus turns that
// into a visibly short list while the operator is still deciding.
func (q *Queries) PreviewSubscription(ctx context.Context, productKeys []string, limit int32) ([]dbgen.PreviewSubscriptionMatchesRow, int64, error) {
	if len(productKeys) == 0 {
		return []dbgen.PreviewSubscriptionMatchesRow{}, 0, nil
	}
	rows, err := q.db.PreviewSubscriptionMatches(ctx, dbgen.PreviewSubscriptionMatchesParams{
		Column1: productKeys,
		Limit:   limit,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("preview subscription: %w", err)
	}
	total, err := q.db.CountSubscriptionMatches(ctx, productKeys)
	if err != nil {
		return nil, 0, fmt.Errorf("count subscription matches: %w", err)
	}
	return rows, total, nil
}

// QueueTriageItem records that a subscription matched a record. Idempotent: the
// same record arriving twice must not queue the same decision twice.
// BackfillSubscriptionMatches lists the stored, published records a new watch's
// keys already cover, newest first, capped. See the query for why this exists.
func (q *Queries) BackfillSubscriptionMatches(ctx context.Context, productKeys, vendorKeys []string, maxItems int32) ([]string, error) {
	if vendorKeys == nil {
		vendorKeys = []string{}
	}
	rows, err := q.db.BackfillSubscriptionMatches(ctx, dbgen.BackfillSubscriptionMatchesParams{
		ProductKeys: productKeys,
		VendorKeys:  vendorKeys,
		MaxItems:    maxItems,
	})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.CveID)
	}
	return ids, nil
}

func (q *Queries) QueueTriageItem(ctx context.Context, subscriptionID uuid.UUID, cveID string) error {
	return q.db.UpsertTriageItem(ctx, dbgen.UpsertTriageItemParams{
		SubscriptionID: subscriptionID,
		CveID:          cveID,
	})
}

// RecordAdvisoryEvent appends one timeline entry.
//
// occurredAt is when the thing happened — upstream's clock for an upstream
// change — while observed_at is stamped by the database. Reporting our clock as
// the event time would hide the gap between publication and detection, which is
// the number most worth seeing.
func (q *Queries) RecordAdvisoryEvent(ctx context.Context, event AdvisoryEvent) error {
	// detail is NOT NULL, and a nil RawMessage binds as SQL NULL rather than
	// taking the column default — every detail-less event ("published") was
	// rejected and the activity stream silently lost it.
	detail := event.Detail
	if len(detail) == 0 {
		detail = json.RawMessage(`{}`)
	}
	return q.db.InsertAdvisoryEvent(ctx, dbgen.InsertAdvisoryEventParams{
		AdvisoryID: toNullUUID(event.AdvisoryID),
		CveID:      event.CVEID,
		Kind:       string(event.Kind),
		OccurredAt: event.OccurredAt,
		ActorID:    toNullUUID(event.ActorID),
		Detail:     detail,
	})
}

func nullTime(value time.Time) sql.NullTime {
	if value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value, Valid: true}
}

func toNullUUID(value *uuid.UUID) uuid.NullUUID {
	if value == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: *value, Valid: true}
}

// ListCVESubscriptions lists every watched product on the instance.
func (q *Queries) ListCVESubscriptions(ctx context.Context) ([]dbgen.ListCVESubscriptionsRow, error) {
	return q.db.ListCVESubscriptions(ctx)
}

// CreateCVESubscription starts watching a product.
func (q *Queries) CreateCVESubscription(ctx context.Context, params dbgen.CreateCVESubscriptionParams) (dbgen.CveSubscription, error) {
	return q.db.CreateCVESubscription(ctx, params)
}

// DeleteCVESubscription stops watching a product. Triage items cascade; the
// advisory data already authored does not, because it remains true.
func (q *Queries) DeleteCVESubscription(ctx context.Context, id uuid.UUID) error {
	return q.db.DeleteCVESubscription(ctx, id)
}

// GetCVERecord returns the stored projection for one CVE.
func (q *Queries) GetCVERecord(ctx context.Context, cveID string) (dbgen.CveRecord, error) {
	return q.db.GetCVERecord(ctx, cveID)
}

// TouchSubscriptionMatched stamps a subscription as having caught something.
//
// This is the column that makes silence legible: a watched product with no
// last-matched date is either safe or watched under a name its vendor never
// files under, and nothing else on the row tells those apart.
func (q *Queries) TouchSubscriptionMatched(ctx context.Context, subscriptionID uuid.UUID) error {
	return q.db.TouchSubscriptionMatched(ctx, subscriptionID)
}

// ListPendingTriage returns the queue, oldest first.
func (q *Queries) ListPendingTriage(ctx context.Context, limit int32) ([]dbgen.ListPendingTriageItemsRow, error) {
	return q.db.ListPendingTriageItems(ctx, limit)
}

// GetTriageItem loads one queue item with its record and subscription.
func (q *Queries) GetTriageItem(ctx context.Context, id uuid.UUID) (dbgen.GetTriageItemRow, error) {
	return q.db.GetTriageItem(ctx, id)
}

// ListCVEAffected returns a record's affected products and ranges.
func (q *Queries) ListCVEAffected(ctx context.Context, cveID string) ([]dbgen.CveAffectedProduct, error) {
	return q.db.ListCVEAffectedProducts(ctx, cveID)
}

// ListTriageCandidates ranks inventory components that might ship a product,
// across the whole instance — the decision applies there, so the evidence
// should too.
func (q *Queries) ListTriageCandidates(ctx context.Context, pattern string, limit int32) ([]dbgen.ListTriageCandidateComponentsRow, error) {
	return q.db.ListTriageCandidateComponents(ctx, dbgen.ListTriageCandidateComponentsParams{
		LikeEscape: []byte(pattern), Limit: limit,
	})
}

// ListTriageCandidatesForOrg is ListTriageCandidates limited to one org's
// repositories.
func (q *Queries) ListTriageCandidatesForOrg(ctx context.Context, orgID uuid.UUID, pattern string, limit int32) ([]dbgen.ListTriageCandidateComponentsForOrgRow, error) {
	return q.db.ListTriageCandidateComponentsForOrg(ctx, dbgen.ListTriageCandidateComponentsForOrgParams{
		Pattern: []byte(pattern), OrgID: orgID, RowLimit: limit,
	})
}

// DecideTriageItem records the outcome and stamps the record revision it was
// decided against, so a later CNA revision re-opens it instead of leaving a
// stale mapping standing.
func (q *Queries) DecideTriageItem(ctx context.Context, id uuid.UUID, state string, actorID uuid.UUID) error {
	return q.db.RecordTriageDecision(ctx, dbgen.RecordTriageDecisionParams{
		ID:        id,
		State:     state,
		DecidedBy: uuid.NullUUID{UUID: actorID, Valid: true},
	})
}

// GetActiveMapping returns the current mapping for a subscription, if any.
func (q *Queries) GetActiveMapping(ctx context.Context, subscriptionID uuid.UUID) (dbgen.ProductPackageMapping, error) {
	return q.db.GetActiveMappingForSubscription(ctx, subscriptionID)
}

// CreateMapping stores the durable product-to-packages decision.
func (q *Queries) CreateMapping(ctx context.Context, params dbgen.CreateProductPackageMappingParams) (dbgen.ProductPackageMapping, error) {
	return q.db.CreateProductPackageMapping(ctx, params)
}

// GetCVESubscription loads one watched product, for ownership checks.
func (q *Queries) GetCVESubscription(ctx context.Context, id uuid.UUID) (dbgen.CveSubscription, error) {
	return q.db.GetCVESubscription(ctx, id)
}

// ListRecentAdvisoryEvents returns the activity stream, newest first.
func (q *Queries) ListRecentAdvisoryEvents(ctx context.Context, limit int32) ([]dbgen.AdvisoryEvent, error) {
	return q.db.ListRecentAdvisoryEvents(ctx, limit)
}

// ListTriageItemsNeedingReview returns decisions whose record moved upstream.
func (q *Queries) ListTriageItemsNeedingReview(ctx context.Context) ([]dbgen.ListTriageItemsNeedingReviewRow, error) {
	return q.db.ListTriageItemsNeedingReview(ctx)
}

// ListMappedCVEsForDivergenceCheck returns CVEs we authored coordinates for,
// with the packages chosen, so they can be compared against what upstream now
// publishes (ADR-028 §10).
func (q *Queries) ListMappedCVEsForDivergenceCheck(ctx context.Context, limit int32) ([]dbgen.ListMappedCVEsForDivergenceCheckRow, error) {
	return q.db.ListMappedCVEsForDivergenceCheck(ctx, limit)
}

// ListWithdrawnMappedCVEs returns mapped records upstream has since retracted.
func (q *Queries) ListWithdrawnMappedCVEs(ctx context.Context) ([]string, error) {
	return q.db.ListWithdrawnMappedCVEs(ctx)
}

// ReopenTriageItem puts a decided item back in the queue.
func (q *Queries) ReopenTriageItem(ctx context.Context, id uuid.UUID) error {
	return q.db.ReopenTriageItem(ctx, id)
}

// SaveCVERecords writes a batch of records in one transaction.
//
// SaveCVERecord's per-record transaction is right for a sweep, which handles a
// dozen records at a time and wants each to stand or fall alone. It is the
// wrong shape for importing the published corpus: 380,000 transactions turned a
// one-off import into a half-hour wait, which is long enough that an operator
// reasonably assumes it has hung.
//
// The batch is all-or-nothing. That is safe because the import is idempotent —
// a failed batch is simply re-imported — and it keeps the failure unit small
// enough to retry cheaply.
//
// Measured gain is about 1.5x, not the order of magnitude batching usually
// buys: the remaining cost is per-record round trips (an upsert, a delete and
// ~2.6 inserts each, so roughly 1.7 million statements for the full corpus)
// rather than transaction setup. Multi-row inserts or COPY would move the
// needle again if a ~20 minute import ever becomes a problem.
func (q *Queries) SaveCVERecords(ctx context.Context, db *sql.DB, records []cvefeed.Projection) error {
	if len(records) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin cve batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	queries := q.WithTx(tx)

	for _, record := range records {
		if err := queries.saveCVERecordTx(ctx, record); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit cve batch: %w", err)
	}
	return nil
}

// saveCVERecordTx writes one record inside an existing transaction.
func (q *Queries) saveCVERecordTx(ctx context.Context, record cvefeed.Projection) error {
	var score sql.NullString
	if record.Severity.Scored() {
		score = sql.NullString{String: strconv.FormatFloat(record.Severity.Score, 'f', 2, 64), Valid: true}
	}
	if err := q.db.UpsertCVERecord(ctx, dbgen.UpsertCVERecordParams{
		CveID:           record.ID,
		State:           record.State,
		Assigner:        record.Assigner,
		PublishedAt:     nullTime(record.Published),
		RecordUpdatedAt: nullTime(record.Updated),
		CvssScore:       score,
		CvssVector:      record.Severity.Vector,
		Severity:        record.Severity.Label,
		CvssSource:      record.Severity.Source,
		Summary:         record.Description,
		ReferenceUrls:   record.References,
	}); err != nil {
		return fmt.Errorf("upsert cve record %s: %w", record.ID, err)
	}
	if err := q.db.SyncCVERecordCWEs(ctx, dbgen.SyncCVERecordCWEsParams{CveID: record.ID, CweIds: toInt32s(cwe.ParseAll(record.CWEs))}); err != nil {
		return fmt.Errorf("store cwes for %s: %w", record.ID, err)
	}
	if err := q.db.DeleteCVEAffectedProducts(ctx, record.ID); err != nil {
		return fmt.Errorf("clear affected products for %s: %w", record.ID, err)
	}
	for _, product := range record.Affected {
		for _, versionRange := range product.Ranges {
			if err := q.db.InsertCVEAffectedProduct(ctx, dbgen.InsertCVEAffectedProductParams{
				CveID:        record.ID,
				Vendor:       product.Vendor,
				Product:      product.Product,
				VendorKey:    product.VendorKey,
				ProductKey:   product.ProductKey,
				Introduced:   versionRange.Introduced,
				Fixed:        versionRange.Fixed,
				LastAffected: versionRange.LastAffected,
			}); err != nil {
				return fmt.Errorf("insert affected product for %s: %w", record.ID, err)
			}
		}
	}
	return nil
}

// ListWatchCandidates returns components nothing covers, most-used first.
func (q *Queries) ListWatchCandidates(ctx context.Context, limit int32) ([]dbgen.ListWatchCandidatesRow, error) {
	return q.db.ListWatchCandidates(ctx, limit)
}

// GetAutoApplyMapping returns a subscription's mapping only if it is opted in
// to automatic application.
func (q *Queries) GetAutoApplyMapping(ctx context.Context, subscriptionID uuid.UUID) (dbgen.ProductPackageMapping, error) {
	return q.db.GetAutoApplyMapping(ctx, subscriptionID)
}

// SetMappingAutoApply turns automatic application on or off for one product.
func (q *Queries) SetMappingAutoApply(ctx context.Context, id uuid.UUID, autoApply bool) error {
	return q.db.SetMappingAutoApply(ctx, dbgen.SetMappingAutoApplyParams{ID: id, AutoApply: autoApply})
}

// ListAdvisoryEventsForCVE returns one advisory's history, newest first.
func (q *Queries) ListAdvisoryEventsForCVE(ctx context.Context, cveID string, limit int32) ([]dbgen.AdvisoryEvent, error) {
	return q.db.ListAdvisoryEventsForCVE(ctx, dbgen.ListAdvisoryEventsForCVEParams{CveID: cveID, Limit: limit})
}

func (q *Queries) ListKEVAdvisoryEventsForCVEs(ctx context.Context, cveIDs []string, limit int32) ([]dbgen.AdvisoryEvent, error) {
	if len(cveIDs) == 0 {
		return []dbgen.AdvisoryEvent{}, nil
	}
	return q.db.ListKEVAdvisoryEventsForCVEs(ctx, dbgen.ListKEVAdvisoryEventsForCVEsParams{CveIds: cveIDs, EventLimit: limit})
}

// GrantLocalRole records an operator-granted role, clearing any suspension.
func (q *Queries) GrantLocalRole(ctx context.Context, userID uuid.UUID, role string, orgID *uuid.UUID, grantedBy uuid.UUID) error {
	return q.db.UpsertLocalRoleGrant(ctx, dbgen.UpsertLocalRoleGrantParams{
		UserID:    userID,
		Role:      role,
		OrgID:     toNullUUID(orgID),
		GrantedBy: uuid.NullUUID{UUID: grantedBy, Valid: true},
	})
}

// RevokeLocalRole removes the record of a grant.
func (q *Queries) RevokeLocalRole(ctx context.Context, userID uuid.UUID, role string, orgID *uuid.UUID) error {
	return q.db.DeleteLocalRoleGrant(ctx, dbgen.DeleteLocalRoleGrantParams{
		UserID: userID, Role: role, OrgID: toNullUUID(orgID),
	})
}

// RevokeLocalRolesForOrg drops every grant a user held in one org.
//
// Used when membership ends rather than when a role changes: leaving an
// organization is not ambiguous the way a downgrade is, and a grant must not
// outlive the membership that justified it.
func (q *Queries) RevokeLocalRolesForOrg(ctx context.Context, userID, orgID uuid.UUID) error {
	return q.db.DeleteLocalRoleGrantsForOrg(ctx, dbgen.DeleteLocalRoleGrantsForOrgParams{
		UserID: userID, OrgID: uuid.NullUUID{UUID: orgID, Valid: true},
	})
}

// SuspendLocalRoles suspends a user's grants in one org and returns them.
func (q *Queries) SuspendLocalRoles(ctx context.Context, userID, orgID uuid.UUID, reason string) ([]LocalRoleGrant, error) {
	rows, err := q.db.SuspendLocalRoleGrants(ctx, dbgen.SuspendLocalRoleGrantsParams{
		UserID:          userID,
		OrgID:           uuid.NullUUID{UUID: orgID, Valid: true},
		SuspendedReason: reason,
	})
	if err != nil {
		return nil, err
	}
	grants := make([]LocalRoleGrant, 0, len(rows))
	for _, row := range rows {
		grants = append(grants, toLocalRoleGrant(row))
	}
	return grants, nil
}

// ListLocalRoleGrantsForUser returns a user's grants, suspended ones included.
func (q *Queries) ListLocalRoleGrantsForUser(ctx context.Context, userID uuid.UUID) ([]dbgen.LocalRoleGrant, error) {
	return q.db.ListLocalRoleGrantsForUser(ctx, userID)
}

// ListActiveLocalRoleGrants returns every active grant on the instance.
func (q *Queries) ListActiveLocalRoleGrants(ctx context.Context) ([]dbgen.ListActiveLocalRoleGrantsRow, error) {
	return q.db.ListActiveLocalRoleGrants(ctx)
}

// LocalRoleGrant is an operator-granted role, with its suspension state.
type LocalRoleGrant struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Role      string
	OrgID     *uuid.UUID
	Reason    string
	Suspended bool
}

func toLocalRoleGrant(row dbgen.LocalRoleGrant) LocalRoleGrant {
	grant := LocalRoleGrant{
		ID:        row.ID,
		UserID:    row.UserID,
		Role:      row.Role,
		Reason:    row.SuspendedReason,
		Suspended: row.SuspendedAt.Valid,
	}
	if row.OrgID.Valid {
		orgID := row.OrgID.UUID
		grant.OrgID = &orgID
	}
	return grant
}

// ListInstanceMembers returns every membership across every org and forge.
func (q *Queries) ListInstanceMembers(ctx context.Context) ([]dbgen.ListInstanceMembersRow, error) {
	return q.db.ListInstanceMembers(ctx)
}
