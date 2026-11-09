package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hibouhq/hibou/internal/audit"
	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// The triage decision writes the VEX statement (ADR-053 §4a, amending
// ADR-023). A finding on a component with a vulnerability identifier gets a
// statement: not affected with its justification, or affected with the
// accepted risk as action statement. Findings without an identifier (code,
// secrets) get none, and their dialog asks only for a reason.

// triageMakesStatement reports whether a decision on this finding produces a
// VEX statement.
func triageMakesStatement(finding *store.Vulnerability) bool {
	return finding != nil && componentBackedFindingType(finding.Type) && finding.AdvisoryID != nil
}

// validateTriageStatement enforces the two rules of §4a: a justification is
// required exactly when a not_affected statement is produced, and accepting
// the risk of a known-exploited vulnerability needs an expiry.
func (s *Server) validateTriageStatement(ctx context.Context, finding *store.Vulnerability, reasonKind, justification string, expiresAt *time.Time) error {
	if !triageMakesStatement(finding) {
		return nil
	}
	if reasonKind == "false_positive" && strings.TrimSpace(justification) == "" {
		return errors.New("a not-affected decision on a dependency finding names its VEX justification")
	}
	if reasonKind == "risk_accepted" && expiresAt == nil {
		if s.exploitedFindings(ctx, []store.Vulnerability{*finding})[finding.ID] {
			return errors.New("accepting the risk of a known-exploited vulnerability needs an expiry")
		}
	}
	return nil
}

// applyTriageStatement records the decision's statement and returns its id,
// or nil when the finding carries no vulnerability identifier.
func (s *Server) applyTriageStatement(ctx context.Context, orgID, repoID uuid.UUID, user *store.User, finding *store.Vulnerability, reasonKind, reason, justification string, expiresAt *time.Time) (*uuid.UUID, error) {
	if !triageMakesStatement(finding) {
		return nil, nil
	}
	createdBy := uuid.NullUUID{}
	if user != nil {
		createdBy = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	evidence := map[string]any{"source": "triage", "finding_id": finding.ID, "fingerprint": finding.Fingerprint}
	if finding.Reachability != nil && *finding.Reachability != "" {
		evidence["reachability"] = *finding.Reachability
	}
	evidenceJSON, _ := json.Marshal(evidence)
	params := dbgen.CreateVEXStatementParams{
		OrgID: orgID, AdvisoryID: *finding.AdvisoryID, RepoID: uuid.NullUUID{UUID: repoID, Valid: true},
		Source: dbgen.VexSourceManual, Evidence: evidenceJSON, CreatedBy: createdBy, ExpiresAt: nullTimePtr(expiresAt),
	}
	if finding.ComponentPurl != nil && strings.TrimSpace(*finding.ComponentPurl) != "" {
		params.ComponentPurl = sql.NullString{String: strings.TrimSpace(*finding.ComponentPurl), Valid: true}
	}
	if reasonKind == "false_positive" {
		params.Status = dbgen.VexStatusNotAffected
		parsed, err := parseVEXJustification(justification, dbgen.VexStatusNotAffected)
		if err != nil {
			return nil, err
		}
		params.Justification = parsed
		params.ImpactStatement = reason
	} else {
		params.Status = dbgen.VexStatusAffected
		action := "Risk accepted"
		if expiresAt != nil {
			action += " until " + expiresAt.UTC().Format("2006-01-02")
		}
		if reason != "" {
			action += ": " + reason
		}
		params.ActionStatement = action
	}
	s.applyVEXApprovalPolicy(ctx, orgID, &params)
	statement, err := s.queries.RecordVEXStatement(ctx, params)
	if err != nil {
		return nil, err
	}
	s.writeSystemAuditLog(ctx, triageActor(user), orgID, audit.ActionVEXCreate, statement.ID.String(), map[string]any{
		"repo_id": repoID, "status": statement.Status, "source": "triage", "fingerprint": finding.Fingerprint,
	})
	s.queueIncidentReconcileForAdvisory(ctx, orgID, statement.AdvisoryID)
	return &statement.ID, nil
}

// withdrawTriageStatement ends the statement a reopened decision had made.
func (s *Server) withdrawTriageStatement(ctx context.Context, orgID, repoID uuid.UUID, user *store.User, fingerprint string) {
	acceptance, err := s.queries.GetActiveFindingAcceptance(ctx, repoID, fingerprint)
	if err != nil || acceptance == nil || acceptance.VEXStatementID == nil {
		return
	}
	actor := uuid.NullUUID{}
	if user != nil {
		actor = uuid.NullUUID{UUID: user.ID, Valid: true}
	}
	statement, err := s.queries.GetVEXStatementByID(ctx, *acceptance.VEXStatementID)
	if err != nil || statement.SupersededAt.Valid || statement.Withdrawn {
		return
	}
	if _, err := s.queries.WithdrawVEXStatement(ctx, orgID, statement.ID, actor); err == nil {
		s.writeSystemAuditLog(ctx, triageActor(user), orgID, audit.ActionVEXRevoke, statement.ID.String(), map[string]any{"repo_id": repoID, "source": "triage reopened", "fingerprint": fingerprint})
		s.queueIncidentReconcileForAdvisory(ctx, orgID, statement.AdvisoryID)
	}
}

func triageActor(user *store.User) incidentActor {
	if user == nil {
		return incidentSystemActor
	}
	return incidentActor{ID: uuid.NullUUID{UUID: user.ID, Valid: true}, Type: audit.ActorUser, Display: actorDisplay(user)}
}
