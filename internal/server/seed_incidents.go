package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/kev"
	"github.com/hibouhq/hibou/internal/notify"
	"github.com/hibouhq/hibou/internal/repoconfig"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// seedKEVSource names the demo's known-exploited catalogue, apart from the
// real feeds so a feed refresh does not remove it.
const seedKEVSource = "seed"

// SeedIncidents gives the development seed incidents in the states a person
// meets (ADR-053): a reportable exploited vulnerability with its clocks
// running, undecided signals, a secret leak, a malicious package, a manual
// security incident and closed ones. It adds the signals the base seed lacks
// (a known-exploited entry, a verified secret, product identities, client
// channels, a policy rule), then lets the incident service open and derive
// everything, so the data is what the product computes. It does nothing when
// the base seed is absent or the demo organisation already has incidents.
func SeedIncidents(ctx context.Context, cfg config.Config, db *sql.DB, log zerolog.Logger) error {
	key, err := notify.ParseEncryptionKey(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	if err := notify.SetEncryptionKey(key); err != nil {
		return fmt.Errorf("encryption key: %w", err)
	}
	s := &Server{cfg: cfg, db: db, log: log, queries: store.NewQueries(db), bus: events.New(log), lifecycleCtx: ctx}

	acme, err := s.queries.GetOrganizationByProviderAndSlug(ctx, "github", "acme")
	if err != nil || acme == nil {
		return err
	}
	var existing int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM incidents WHERE org_id = $1`, acme.ID).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		log.Info().Int("incidents", existing).Msg("seed incidents already present, skipping")
		return nil
	}
	admin, err := s.queries.GetUserByProviderID(ctx, "local", "dev-admin")
	if err != nil || admin == nil {
		return fmt.Errorf("seed dev user: %w", errors.Join(err, errors.New("missing")))
	}
	seed := incidentSeeder{s: s, actor: incidentActor{ID: uuid.NullUUID{UUID: admin.ID, Valid: true}, Type: audit.ActorUser, Display: admin.DisplayName}, adminID: admin.ID}
	if err := seed.signals(ctx, acme); err != nil {
		return fmt.Errorf("seeding incident signals: %w", err)
	}

	// The rules open what they match, in every organisation, as the hourly
	// sweep would; in slug order, so the demo's incident numbers are stable.
	rows, err := db.QueryContext(ctx, `SELECT r.id FROM repositories r JOIN organizations o ON o.id = r.org_id ORDER BY o.slug, r.slug`)
	if err != nil {
		return err
	}
	var repoIDs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		repoIDs = append(repoIDs, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, repoID := range repoIDs {
		if _, err := s.sweepIncidentRules(ctx, repoID); err != nil {
			return fmt.Errorf("sweeping %s: %w", repoID, err)
		}
	}
	if err := seed.progress(ctx, acme); err != nil {
		return fmt.Errorf("progressing seed incidents: %w", err)
	}

	var count int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM incidents`).Scan(&count)
	log.Info().Int("incidents", count).Msg("seed incidents created")
	return nil
}

type incidentSeeder struct {
	s       *Server
	actor   incidentActor
	adminID uuid.UUID
}

// signals adds what the base seed lacks for the default rules to fire.
func (seed incidentSeeder) signals(ctx context.Context, acme *store.Organization) error {
	s := seed.s
	// HTTP/2 Rapid Reset is in CISA's catalogue since 2023-10-10.
	if _, err := s.queries.ReplaceKEVSource(ctx, s.db, seedKEVSource, []kev.Entry{{
		CVEID: "CVE-2023-44487", VendorProject: "IETF", Product: "HTTP/2", VulnerabilityName: "HTTP/2 Rapid Reset Attack Vulnerability",
		DateAdded: time.Date(2023, time.October, 10, 0, 0, 0, 0, time.UTC), DueDate: time.Date(2023, time.October, 31, 0, 0, 0, 0, time.UTC),
	}}, 0); err != nil {
		return fmt.Errorf("kev: %w", err)
	}
	// The validator confirmed the dashboard's GitHub token is live.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE findings f SET verified = true
		  FROM repositories r
		 WHERE r.id = f.repo_id AND r.org_id = $1 AND r.slug = 'web-dashboard'
		   AND f.type = 'secret' AND f.primary_identifier_value = 'github-token-exposed'`, acme.ID); err != nil {
		return fmt.Errorf("verified secret: %w", err)
	}

	// Every demo organisation adds a policy line on top of the built-in
	// rules and an internal target stricter than the regulation, and makes
	// the dev user the owner so Home's "Needs you" has content.
	rules := append(incident.BuiltinRules(), repoconfig.IncidentRule{
		Match: "severity:critical AND fix:available", Refs: repoconfig.RefSelector{"released", "default"}, Priority: "P2", Due: "7d",
	})
	rulesJSON, _ := json.Marshal(rules)
	var orgIDs []uuid.UUID
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM organizations ORDER BY slug`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		orgIDs = append(orgIDs, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, orgID := range orgIDs {
		if _, err := s.queries.Incidents().UpsertIncidentSettings(ctx, dbgen.UpsertIncidentSettingsParams{
			OrgID: orgID, OwnerID: uuid.NullUUID{UUID: seed.adminID, Valid: true}, DefaultRules: rulesJSON, LockedRules: json.RawMessage(`[]`),
			InternalTargets: json.RawMessage(`{"early_warning_hours":12,"notification_hours":48}`), NationalRegimes: json.RawMessage(`[]`),
			DueSoonLeadMinutes: 360, UpdatedBy: uuid.NullUUID{UUID: seed.adminID, Valid: true},
		}); err != nil {
			return fmt.Errorf("incident settings %s: %w", orgID, err)
		}
	}

	repos, _, err := s.queries.ListRepositoriesByOrg(ctx, acme.ID, 100, 0)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		product := persistedRepoConfig{Product: &repoconfig.ProductConfig{
			Name: "Acme " + repo.Name, PURL: "pkg:generic/acme/" + repo.Slug,
			CPE: fmt.Sprintf("cpe:2.3:a:acme:%s:*:*:*:*:*:*:*:*", repo.Slug),
		}}
		raw, _ := json.Marshal(product)
		if err := s.queries.Incidents().UpsertRepoIncidentConfig(ctx, dbgen.UpsertRepoIncidentConfigParams{RepoID: repo.ID, Config: raw}); err != nil {
			return fmt.Errorf("product identity %s: %w", repo.Slug, err)
		}
	}

	// Globex receives notices by hand, Initech through the portal.
	for slug, channel := range map[string]string{"globex": channelManual, "initech": channelPortal} {
		client, err := s.queries.Incidents().GetClientBySlug(ctx, dbgen.GetClientBySlugParams{OrgID: acme.ID, Slug: slug})
		if err != nil {
			return fmt.Errorf("client %s: %w", slug, err)
		}
		contacts, _ := json.Marshal([]securityContact{{Name: "Security team", Email: "security@" + slug + ".example", Role: "PSIRT"}})
		raw, _ := json.Marshal(clientDeliveryConfig{Channel: channel}) // #nosec G117 -- no secret set; sealed by SealConfig before it is stored
		sealed, err := notify.Secrets().SealConfig(clientSealContext(client), raw)
		if err != nil {
			return err
		}
		if _, err := s.queries.Incidents().UpdateClientDelivery(ctx, dbgen.UpdateClientDeliveryParams{ID: client.ID, SecurityContacts: contacts, DeliveryConfig: sealed}); err != nil {
			return fmt.Errorf("client delivery %s: %w", slug, err)
		}
	}
	return nil
}

// progress walks the opened incidents to the states the demo shows.
func (seed incidentSeeder) progress(ctx context.Context, acme *store.Organization) error {
	s := seed.s
	db := s.queries.Incidents()

	// 1. api-gateway: Rapid Reset is reportable, aware 20 hours ago, so the
	// early warning is due within the hour of the internal target and four
	// hours of the regulatory one; the current release has its statement and
	// Globex its notice, the laggard release and Initech are still owed.
	gateway, err := seed.exploited(ctx, acme, "api-gateway", "CVE-2023-44487")
	if err != nil {
		return err
	}
	aware := time.Now().UTC().Add(-20 * time.Hour).Truncate(time.Minute)
	gateway, _, err = s.decideIncident(ctx, gateway, seed.actor, incidentDecision{
		State: incident.StateReportable, DecisionStep: incident.StepAttacked, AwareAt: &aware,
		Reason: "Globex's SOC reported a Rapid Reset flood against their gateway; our edge logs confirm it.",
	})
	if err != nil {
		return fmt.Errorf("decide api-gateway: %w", err)
	}
	scope, err := db.ListIncidentScope(ctx, gateway.ID)
	if err != nil {
		return err
	}
	advisoryID, _ := uuid.Parse(gateway.SubjectID)
	var current dbgen.IncidentScope
	for _, row := range scope {
		if row.SubjectType == "release" && (current.SubjectID == "" || row.Label > current.Label) {
			current = row
		}
	}
	if current.SubjectID != "" {
		releaseID, _ := uuid.Parse(current.SubjectID)
		if err := seed.statement(ctx, acme, gateway.RepoID.UUID, advisoryID, releaseID, createVEXStatementRequest{
			Status: "affected", ActionStatement: "Upgrade golang.org/x/net to 0.17.0; until then cap concurrent streams at the load balancer.",
		}); err != nil {
			return err
		}
	}
	gateway, err = s.reconcileIncident(ctx, gateway.ID)
	if err != nil {
		return err
	}
	globex, err := db.GetClientBySlug(ctx, dbgen.GetClientBySlugParams{OrgID: acme.ID, Slug: "globex"})
	if err != nil {
		return err
	}
	if _, err := s.deliverIncidentNotices(ctx, gateway, acme, seed.actor, deliverRequest{
		ClientIDs: []string{globex.ID.String()}, Channel: channelManual,
		Evidence: "Walked through on the Globex security call; minutes sent to their PSIRT.",
		Measures: "Cap concurrent HTTP/2 streams at the load balancer until the upgrade ships.",
	}); err != nil {
		return fmt.Errorf("deliver api-gateway: %w", err)
	}
	if _, err := s.reconcileIncident(ctx, gateway.ID); err != nil {
		return err
	}
	if err := s.addIncidentNote(ctx, gateway, seed.actor, "Edge rate limits raised as a stop-gap; upgrade PR is in review."); err != nil {
		return err
	}

	// 2. auth-service: the same CVE, undecided — the decision ladder to try.
	// 3. web-dashboard: a live GitHub token and flatmap-stream, as the rules
	// opened them. Nothing to do here.

	// 4. A security incident no scanner sees, opened by hand.
	gatewayRepo, err := s.queries.GetRepositoryBySlug(ctx, acme.ID, "api-gateway")
	if err != nil || gatewayRepo == nil {
		return fmt.Errorf("api-gateway: %w", err)
	}
	if _, _, err := s.openIncident(ctx, incidentOpenInput{
		OrgID: acme.ID, RepoID: uuid.NullUUID{UUID: gatewayRepo.ID, Valid: true}, Kind: incident.KindSevereIncident,
		Title: "api-gateway build signed outside the release pipeline", Priority: "P1", SignalSource: "internal",
		Regimes: []string{incident.RegimeCRA}, SignalAt: time.Now().UTC().Add(-3 * time.Hour), Actor: seed.actor,
	}); err != nil {
		return fmt.Errorf("open security incident: %w", err)
	}

	// 5. cloudnative/service-mesh: the HTTP/2 server is not enabled, so not
	// reportable; the not-affected statements close it.
	if err := seed.closeNotReachable(ctx, "cloudnative", "service-mesh", "CVE-2023-44487"); err != nil {
		return err
	}
	return nil
}

// exploited returns the incident the rules opened for an advisory on a repo.
func (seed incidentSeeder) exploited(ctx context.Context, org *store.Organization, repoSlug, cve string) (dbgen.Incident, error) {
	s := seed.s
	repo, err := s.queries.GetRepositoryBySlug(ctx, org.ID, repoSlug)
	if err != nil || repo == nil {
		return dbgen.Incident{}, fmt.Errorf("repository %s: %w", repoSlug, err)
	}
	advisory, err := s.resolveVEXAdvisory(ctx, cve)
	if err != nil {
		return dbgen.Incident{}, fmt.Errorf("advisory %s: %w", cve, err)
	}
	inc, err := s.queries.Incidents().FindIncidentForSubject(ctx, dbgen.FindIncidentForSubjectParams{
		OrgID: org.ID, RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true}, Kind: incident.KindExploitedVulnerability,
		SubjectType: incident.SubjectAdvisory, SubjectID: advisory.ID.String(),
	})
	if err != nil {
		return inc, fmt.Errorf("no exploited incident for %s on %s (did the sweep match?): %w", cve, repoSlug, err)
	}
	return inc, nil
}

// statement records an approved VEX statement for one release.
func (seed incidentSeeder) statement(ctx context.Context, org *store.Organization, repoID, advisoryID, releaseID uuid.UUID, input createVEXStatementRequest) error {
	params, err := buildCreateVEXParams(org.ID, repoID, seed.adminID, advisoryID, input)
	if err != nil {
		return err
	}
	params.ReleaseID = uuid.NullUUID{UUID: releaseID, Valid: true}
	params.ApprovedBy = params.CreatedBy
	params.ApprovedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
	if _, err := seed.s.queries.RecordVEXStatement(ctx, params); err != nil {
		return fmt.Errorf("vex statement: %w", err)
	}
	return nil
}

func (seed incidentSeeder) closeNotReachable(ctx context.Context, orgSlug, repoSlug, cve string) error {
	s := seed.s
	org, err := s.queries.GetOrganizationByProviderAndSlug(ctx, "github", orgSlug)
	if err != nil || org == nil {
		return fmt.Errorf("organization %s: %w", orgSlug, err)
	}
	inc, err := seed.exploited(ctx, org, repoSlug, cve)
	if err != nil {
		return err
	}
	inc, _, err = s.decideIncident(ctx, inc, seed.actor, incidentDecision{
		State: incident.StateNotReportable, DecisionStep: incident.StepNotReachable,
		Reason: "The mesh terminates HTTP/2 in Envoy; the Go HTTP/2 server is compiled in but never started.",
	})
	if err != nil {
		return fmt.Errorf("decide %s: %w", repoSlug, err)
	}
	scope, err := s.queries.Incidents().ListIncidentScope(ctx, inc.ID)
	if err != nil {
		return err
	}
	advisoryID, _ := uuid.Parse(inc.SubjectID)
	for _, row := range scope {
		if row.SubjectType != "release" {
			continue
		}
		releaseID, _ := uuid.Parse(row.SubjectID)
		if err := seed.statement(ctx, org, inc.RepoID.UUID, advisoryID, releaseID, createVEXStatementRequest{
			Status: "not_affected", Justification: "vulnerable_code_not_in_execute_path",
			ImpactStatement: "golang.org/x/net/http2 is linked but no HTTP/2 server is started; Envoy terminates HTTP/2.",
		}); err != nil {
			return err
		}
	}
	inc, err = s.reconcileIncident(ctx, inc.ID)
	if err != nil {
		return err
	}
	// The maintainer published the fix: nothing left to report upstream.
	actions, err := s.queries.Incidents().ListIncidentActions(ctx, inc.ID)
	if err != nil {
		return err
	}
	for _, action := range actions {
		if action.Kind != incident.ActionUpstreamNotice || action.Obsolete || action.State != "pending" {
			continue
		}
		if _, err := s.completeIncidentAction(ctx, inc, seed.actor, action.ID,
			"Already public upstream with a fix (golang.org/x/net 0.17.0, GHSA-qppj-fm5r-hxr3); nothing new to report.", "GHSA-qppj-fm5r-hxr3"); err != nil {
			return fmt.Errorf("upstream notice: %w", err)
		}
	}
	_, err = s.reconcileIncident(ctx, inc.ID)
	return err
}
