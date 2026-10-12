package server

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/delta"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// carryTriageAcrossRekeys copies acceptances and disputes from a finding's old
// fingerprint to its new one when the same finding was re-keyed between the
// previous snapshot of the ref and this one (ADR-034, D15): the fallback key
// moving from ref to repo scope, the CLI starting to send content
// fingerprints, or a line move. Triage is keyed by fingerprint, so without
// this every accepted finding would reopen once. Copied, not moved: other
// refs may still report the old fingerprint.
//
// Best effort: a failure here leaves triage where it was (the finding reads
// as open), and never fails the snapshot.
func (s *Server) carryTriageAcrossRekeys(ctx context.Context, snapshot *store.Snapshot) {
	if s.queries == nil {
		return
	}
	log := s.log.With().Str("snapshot", snapshot.ID.String()).Logger()
	previous, err := s.queries.GetLatestCompleteSnapshotByRef(ctx, snapshot.RefID)
	if err != nil || previous == nil || previous.ID == snapshot.ID {
		if err != nil {
			log.Warn().Err(err).Msg("triage rekey: load previous snapshot")
		}
		return
	}
	older, err := s.queries.ListAllVulnerabilitiesBySnapshot(ctx, previous.ID)
	if err != nil {
		log.Warn().Err(err).Msg("triage rekey: list previous findings")
		return
	}
	newer, err := s.queries.ListAllVulnerabilitiesBySnapshot(ctx, snapshot.ID)
	if err != nil {
		log.Warn().Err(err).Msg("triage rekey: list findings")
		return
	}
	newer = reportedOnly(newer)
	pairs := delta.RekeyedPairs(older, newer)
	if len(pairs) == 0 {
		return
	}
	ref, err := s.queries.GetRefByID(ctx, snapshot.RefID)
	if err != nil || ref == nil {
		log.Warn().Err(err).Msg("triage rekey: load ref")
		return
	}
	repo, err := s.queries.GetRepositoryByID(ctx, ref.RepoID)
	if err != nil || repo == nil {
		log.Warn().Err(err).Msg("triage rekey: load repository")
		return
	}
	acceptances, err := s.queries.ListActiveFindingAcceptancesByRepo(ctx, repo.ID)
	if err != nil {
		log.Warn().Err(err).Msg("triage rekey: list acceptances")
		return
	}
	disputes, err := s.queries.ListFindingDisputesByRepo(ctx, repo.ID)
	if err != nil {
		log.Warn().Err(err).Msg("triage rekey: list disputes")
		return
	}
	acceptanceByFP := make(map[string]store.FindingAcceptance, len(acceptances))
	for _, acceptance := range acceptances {
		acceptanceByFP[acceptance.Fingerprint] = acceptance
	}
	disputeByFP := make(map[string]store.FindingDispute, len(disputes))
	for _, dispute := range disputes {
		disputeByFP[dispute.Fingerprint] = dispute
	}

	for _, pair := range pairs {
		oldFP, newFP := pair.Old.Fingerprint, pair.New.Fingerprint
		carried := make([]string, 0, 2)
		if acceptance, ok := acceptanceByFP[oldFP]; ok {
			if _, exists := acceptanceByFP[newFP]; !exists {
				if _, err := s.queries.UpsertFindingAcceptance(ctx, store.AcceptFindingInput{
					RepoID:           repo.ID,
					Fingerprint:      newFP,
					ReasonKind:       acceptance.ReasonKind,
					Reason:           acceptance.Reason,
					Labels:           acceptance.Labels,
					VEXJustification: acceptance.VEXJustification,
					AcceptedBy:       acceptance.AcceptedBy,
					ExpiresAt:        acceptance.ExpiresAt,
				}); err != nil {
					log.Warn().Err(err).Str("fingerprint", newFP).Msg("triage rekey: copy acceptance")
				} else {
					carried = append(carried, "acceptance")
				}
			}
		}
		if dispute, ok := disputeByFP[oldFP]; ok {
			if _, exists := disputeByFP[newFP]; !exists {
				if _, err := s.queries.UpsertFindingDispute(ctx, repo.ID, newFP, dispute.Reason, dispute.DisputedBy); err != nil {
					log.Warn().Err(err).Str("fingerprint", newFP).Msg("triage rekey: copy dispute")
				} else {
					carried = append(carried, "dispute")
				}
			}
		}
		if len(carried) > 0 {
			s.writeRekeyAudit(ctx, repo, snapshot.ID, oldFP, newFP, carried)
		}
	}
}

func (s *Server) writeRekeyAudit(ctx context.Context, repo *store.Repository, snapshotID uuid.UUID, oldFP, newFP string, carried []string) {
	encoded, err := json.Marshal(map[string]any{
		"repo_id":         repo.ID,
		"fingerprint":     newFP,
		"snapshot_id":     snapshotID,
		"old_fingerprint": oldFP,
		"carried":         carried,
	})
	if err != nil {
		encoded = json.RawMessage(`{}`)
	}
	if _, err := s.queries.CreateAuditLog(ctx, dbgen.CreateAuditLogParams{
		ActorType:    audit.ActorSystem,
		ActorDisplay: "finding-identity",
		Action:       audit.ActionFindingRekeyed,
		ResourceType: "finding",
		ResourceID:   newFP,
		OrgID:        uuid.NullUUID{UUID: repo.OrgID, Valid: true},
		Context:      encoded,
	}); err != nil {
		s.log.Warn().Err(err).Str("fingerprint", newFP).Msg("triage rekey audit write failed")
	}
}

// reportedOnly drops carried rows (ADR-034): a carried row keeps its old
// fingerprint, so it would hide the re-key it stands in for.
func reportedOnly(rows []store.Vulnerability) []store.Vulnerability {
	out := rows[:0:0]
	for _, row := range rows {
		if row.Presence == "" || row.Presence == store.PresenceReported {
			out = append(out, row)
		}
	}
	return out
}
