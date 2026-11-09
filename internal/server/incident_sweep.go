package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/events"
	"github.com/hibouhq/hibou/internal/filterquery"
	"github.com/hibouhq/hibou/internal/incident"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The rule sweep (ADR-053 §1, §2): evaluate a repository's incident rules over
// the snapshots they select and open an incident per newly matching subject.
// It runs after a snapshot is processed, after an advisory or secret scan,
// after a catalogue sync and an advisory refresh (a KEV listing can predate
// the CVE alias by a refresh cycle), and periodically as a safety net.

const incidentSweepRowLimit = 500

// sweepIncidentRules runs one repository's rules and returns how many
// incidents it opened.
func (s *Server) sweepIncidentRules(ctx context.Context, repoID uuid.UUID) (int, error) {
	repo, err := s.queries.GetRepositoryByID(ctx, repoID)
	if err != nil || repo == nil {
		return 0, err
	}
	rules, err := s.effectiveIncidentRules(ctx, repo.OrgID, repo.ID)
	if err != nil || len(rules) == 0 {
		return 0, err
	}
	db := s.queries.Incidents()
	refRows, err := db.ListLatestSnapshotsForRepoRefs(ctx, repo.ID)
	if err != nil {
		return 0, err
	}
	releases, err := db.ListReleasesWithClientsByRepo(ctx, repo.ID)
	if err != nil {
		return 0, err
	}
	infos := map[uuid.UUID]incident.RefInfo{}
	for _, row := range refRows {
		infos[row.SnapshotID] = incident.RefInfo{
			Name: row.RefName, Type: row.RefType,
			IsDefault: row.RefType == "branch" && row.RefName == repo.DefaultBranch,
		}
	}
	for _, release := range releases {
		if !release.SnapshotID.Valid {
			continue
		}
		info := infos[release.SnapshotID.UUID]
		info.Released = true
		if info.Name == "" {
			info.Name, info.Type = release.Version, "tag"
		}
		infos[release.SnapshotID.UUID] = info
	}
	if len(infos) == 0 {
		return 0, nil
	}
	snapshotIDs := make([]uuid.UUID, 0, len(infos))
	for id := range infos {
		snapshotIDs = append(snapshotIDs, id)
	}

	handled := map[string]bool{}
	opened := 0
	for _, rule := range rules {
		node, err := filterquery.Parse(rule.Match)
		if err != nil {
			continue
		}
		compiled, err := filterquery.ToSQL(node, 2)
		if err != nil {
			continue
		}
		rows, _, err := s.queries.ListVulnerabilitiesBySnapshotsDynamicWithFilters(ctx, snapshotIDs, compiled.Where, compiled.Params, "", true, "", incidentSweepRowLimit, 0)
		if err != nil {
			s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Str("match", rule.Match).Msg("incident rule query failed")
			continue
		}
		exploited := s.exploitedFindings(ctx, rows)
		for _, row := range rows {
			fingerprint := strings.TrimSpace(row.Fingerprint)
			if fingerprint == "" || handled[fingerprint] {
				continue
			}
			kind := incident.DeriveKind(rule, incident.FindingFacts{Type: row.Type, Exploited: exploited[row.ID]})
			if !incident.RefSelected(incident.RefsFor(rule, kind), infos[row.SnapshotID]) {
				continue
			}
			// First matching rule wins for a finding (§1).
			handled[fingerprint] = true
			advisoryID := ""
			if row.AdvisoryID != nil {
				advisoryID = row.AdvisoryID.String()
			}
			subjectType, subjectID := incident.SubjectFor(kind, fingerprint, advisoryID)
			if subjectType == incident.SubjectAdvisory && handled["advisory:"+subjectID] {
				continue
			}
			handled["advisory:"+subjectID] = true
			source := "trigger"
			if kind == incident.KindExploitedVulnerability {
				source = "kev"
			}
			_, created, err := s.openIncident(ctx, incidentOpenInput{
				OrgID: repo.OrgID, RepoID: uuid.NullUUID{UUID: repo.ID, Valid: true}, Kind: kind,
				SubjectType: subjectType, SubjectID: subjectID, Title: incidentTitle(kind, row, repo),
				Priority: rule.Priority, SignalSource: source, TriggerRule: rule.Match, Regimes: rule.Regimes,
				Target: rule.Due, Actor: incidentSystemActor,
				Detail: map[string]any{"finding_id": row.ID.String(), "fingerprint": fingerprint, "ref": infos[row.SnapshotID].Name, "rule_source": rule.Source},
			})
			if err != nil {
				s.log.Warn().Err(err).Str("repo_id", repo.ID.String()).Msg("open incident from rule")
				continue
			}
			if created {
				opened++
				if kind == incident.KindExploitedVulnerability && s.bus != nil {
					s.bus.Publish(context.WithoutCancel(ctx), events.Event{Type: events.ExploitationObserved, Payload: map[string]any{
						"org_id": repo.OrgID.String(), "repo_id": repo.ID.String(), "advisory_id": advisoryID,
						"title":    "Known-exploited vulnerability in a shipped version of " + repo.Name,
						"message":  fmt.Sprintf("%s is listed as exploited and matches %s.", row.PrimaryIdentifierValue, infos[row.SnapshotID].Name),
						"severity": "critical",
					}, Timestamp: time.Now().UTC()})
				}
			}
		}
	}
	return opened, nil
}

// exploitedFindings marks rows whose advisory or identifier is on a
// known-exploited catalogue.
func (s *Server) exploitedFindings(ctx context.Context, rows []store.Vulnerability) map[uuid.UUID]bool {
	out := map[uuid.UUID]bool{}
	advisoryIDs := []uuid.UUID{}
	identifiers := []string{}
	for _, row := range rows {
		if row.AdvisoryID != nil {
			advisoryIDs = append(advisoryIDs, *row.AdvisoryID)
		}
		if row.PrimaryIdentifierValue != "" {
			identifiers = append(identifiers, strings.ToUpper(row.PrimaryIdentifierValue))
		}
	}
	listedAdvisories := map[uuid.UUID]bool{}
	if ids, err := s.queries.FilterKEVAdvisoryIDs(ctx, advisoryIDs); err == nil {
		for _, id := range ids {
			listedAdvisories[id] = true
		}
	}
	listedIDs := map[string]bool{}
	if ids, err := s.queries.FilterKEVIdentifiers(ctx, identifiers); err == nil {
		for _, id := range ids {
			listedIDs[strings.ToUpper(id)] = true
		}
	}
	for _, row := range rows {
		if (row.AdvisoryID != nil && listedAdvisories[*row.AdvisoryID]) || listedIDs[strings.ToUpper(row.PrimaryIdentifierValue)] {
			out[row.ID] = true
		}
	}
	return out
}

func incidentTitle(kind string, row store.Vulnerability, repo *store.Repository) string {
	identifier := strings.TrimSpace(row.PrimaryIdentifierValue)
	switch kind {
	case incident.KindExploitedVulnerability:
		component := ""
		if row.ComponentName != nil {
			component = " (" + *row.ComponentName + ")"
		}
		return fmt.Sprintf("Exploited %s%s in %s", identifier, component, repo.Name)
	case incident.KindSecretLeak:
		secretType := identifier
		if row.SecretType != nil && *row.SecretType != "" {
			secretType = *row.SecretType
		}
		location := ""
		if row.FilePath != nil {
			location = " at " + *row.FilePath
		}
		return fmt.Sprintf("Leaked %s in %s%s", secretType, repo.Name, location)
	case incident.KindMalware:
		pkg := identifier
		if row.ComponentPurl != nil {
			pkg = *row.ComponentPurl
		}
		return fmt.Sprintf("Malicious package %s in %s", pkg, repo.Name)
	default:
		title := strings.TrimSpace(row.Title)
		if title == "" {
			title = identifier
		}
		return fmt.Sprintf("%s in %s", title, repo.Name)
	}
}

// queueIncidentSweep runs a repository's rules in the background.
func (s *Server) queueIncidentSweep(repoID uuid.UUID) {
	if s.queries == nil || s.db == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(s.backgroundContext(), 2*time.Minute)
		defer cancel()
		if _, err := s.sweepIncidentRules(ctx, repoID); err != nil {
			s.log.Warn().Err(err).Str("repo_id", repoID.String()).Msg("incident sweep failed")
		}
		s.queueIncidentReconcileForRepo(ctx, repoID)
	}()
}

func (s *Server) backgroundContext() context.Context {
	if s.lifecycleCtx != nil {
		return s.lifecycleCtx
	}
	return context.Background()
}

// sweepAllIncidentRules runs every active repository's rules once, on one
// replica.
func (s *Server) sweepAllIncidentRules(ctx context.Context) {
	_, err := store.WithLeaderLock(ctx, s.db, store.LockIncidentSweep, func(runCtx context.Context) error {
		ids, err := s.queries.Incidents().ListRepositoryIDsForIncidentSweep(runCtx)
		if err != nil {
			return err
		}
		opened := 0
		for _, id := range ids {
			if runCtx.Err() != nil {
				return runCtx.Err()
			}
			count, err := s.sweepIncidentRules(runCtx, id)
			if err != nil {
				s.log.Warn().Err(err).Str("repo_id", id.String()).Msg("incident sweep failed")
			}
			opened += count
		}
		openIDs, err := s.queries.Incidents().ListOpenIncidentIDs(runCtx)
		if err == nil {
			s.queueIncidentReconcile(openIDs...)
		}
		if opened > 0 {
			s.log.Info().Int("opened", opened).Int("repositories", len(ids)).Msg("incident sweep opened incidents")
		}
		return nil
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("incident sweep pass failed")
	}
}

// runIncidentLoop subscribes the triggers, runs the reconcile worker, the
// deadline clock every minute and a full sweep every hour.
func (s *Server) runIncidentLoop(ctx context.Context) {
	if s.bus != nil {
		repoFrom := func(payload any) (uuid.UUID, bool) {
			data, _ := payload.(map[string]any)
			switch value := data["repo_id"].(type) {
			case uuid.UUID:
				return value, true
			case string:
				id, err := uuid.Parse(value)
				return id, err == nil
			}
			return uuid.Nil, false
		}
		for _, eventType := range []events.Type{events.ScanCompleted, events.SecretScanCompleted, events.MalwareDetected} {
			s.bus.Subscribe(eventType, func(_ context.Context, event events.Event) {
				repoID, ok := repoFrom(event.Payload)
				if !ok {
					return
				}
				if event.Type == events.SecretScanCompleted {
					if data, _ := event.Payload.(map[string]any); data != nil {
						if snapshotID, ok := uuidFromAny(data["snapshot_id"]); ok {
							s.resolveDeadSecrets(s.backgroundContext(), snapshotID)
						}
					}
				}
				s.queueIncidentSweep(repoID)
			})
		}
	}
	go s.runIncidentWorker(ctx)

	clock := time.NewTicker(time.Minute)
	sweep := time.NewTicker(time.Hour)
	defer clock.Stop()
	defer sweep.Stop()
	// First sweep shortly after start: a restart must not delay signals an
	// hour.
	first := time.NewTimer(2 * time.Minute)
	defer first.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
			s.sweepAllIncidentRules(ctx)
		case <-sweep.C:
			s.sweepAllIncidentRules(ctx)
		case <-clock.C:
			s.runIncidentClock(ctx)
		}
	}
}

// runIncidentClock sends due-soon and overdue notifications once per step and
// level (ADR-053 §11).
func (s *Server) runIncidentClock(ctx context.Context) {
	_, err := store.WithLeaderLock(ctx, s.db, store.LockIncidentClock, func(runCtx context.Context) error {
		db := s.queries.Incidents()
		// The widest lead any organisation may set; per-organisation leads are
		// applied below.
		rows, err := db.ListDueIncidentDeadlines(runCtx, time.Now().UTC().Add(7*24*time.Hour))
		if err != nil {
			return err
		}
		leads := map[uuid.UUID]time.Duration{}
		now := time.Now().UTC()
		for _, row := range rows {
			lead, ok := leads[row.OrgID]
			if !ok {
				lead = 6 * time.Hour
				if settings, err := s.loadIncidentSettings(runCtx, row.OrgID); err == nil && settings.Row.DueSoonLeadMinutes > 0 {
					lead = time.Duration(settings.Row.DueSoonLeadMinutes) * time.Minute
				}
				leads[row.OrgID] = lead
			}
			level := ""
			switch {
			case now.After(row.DueAt):
				level = "overdue"
			case row.DueAt.Sub(now) <= lead && row.Notified == "":
				level = "due_soon"
			}
			if level == "" || row.Notified == level {
				continue
			}
			if err := db.MarkIncidentDeadlineNotified(runCtx, dbgen.MarkIncidentDeadlineNotifiedParams{IncidentID: row.IncidentID, Regime: row.Regime, Step: row.Step, Notified: level}); err != nil {
				continue
			}
			inc, err := db.GetIncident(runCtx, row.IncidentID)
			if err != nil {
				continue
			}
			label := strings.ReplaceAll(row.Step, "_", " ")
			eventType, title := events.IncidentDueSoon, fmt.Sprintf("Incident #%d: %s due %s", inc.Number, label, row.DueAt.Format(time.RFC3339))
			if level == "overdue" {
				eventType, title = events.IncidentOverdue, fmt.Sprintf("Incident #%d: %s overdue since %s", inc.Number, label, row.DueAt.Format(time.RFC3339))
			}
			s.appendIncidentEvent(runCtx, db, inc.ID, incidentSystemActor, "deadline."+level, map[string]any{"regime": row.Regime, "step": row.Step, "due_at": row.DueAt})
			s.publishIncidentEvent(runCtx, eventType, inc, title, fmt.Sprintf("%s (%s) for %s.", label, row.Regime, inc.Title))
		}
		return nil
	})
	if err != nil {
		s.log.Warn().Err(err).Msg("incident clock pass failed")
	}
}

func uuidFromAny(value any) (uuid.UUID, bool) {
	switch typed := value.(type) {
	case uuid.UUID:
		return typed, true
	case string:
		id, err := uuid.Parse(typed)
		return id, err == nil
	}
	return uuid.Nil, false
}

// resolveDeadSecrets resolves secret findings a validator confirmed dead
// (ADR-053 §4, amending ADR-023): a secret resolves by attestation or by a
// validator's verdict that the credential no longer works, never by absence.
func (s *Server) resolveDeadSecrets(ctx context.Context, snapshotID uuid.UUID) {
	rows, _, err := s.queries.ListVulnerabilitiesBySnapshotDynamicWithFilters(ctx, snapshotID, "v.type = 'secret'", nil, "", true, "", 1000, 0)
	if err != nil {
		return
	}
	for _, row := range rows {
		if row.Status == "resolved" || !secretValidatorDead(row.Metadata) {
			continue
		}
		comment := "credential confirmed dead by its validator"
		if _, err := s.queries.UpdateVulnerabilityStatus(ctx, row.ID, "resolved", &comment, nil); err != nil {
			s.log.Warn().Err(err).Str("finding_id", row.ID.String()).Msg("resolve validator-dead secret")
		}
	}
}
