package lsp

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (s *Server) remediationRevise(ctx context.Context, p remediationGenerateParams) (*remediationPrepared, error) {
	s.remediationMu.Lock()
	defer s.remediationMu.Unlock()
	ws, err := s.remediationWorkspace(p.Root)
	if err != nil {
		return nil, err
	}
	old := s.remediationDrafts[p.ID]
	if old == nil || old.prepared.Root != ws.root || time.Now().After(old.prepared.ExpiresAt) {
		return nil, errors.New("draft is missing or expired; prepare again")
	}
	sha, err := ws.git.head(ctx)
	if err != nil {
		return nil, err
	}
	if sha != old.prepared.BaseSHA {
		return nil, errors.New("HEAD changed; close this draft and prepare again")
	}
	prepared := old.prepared
	prepared.ID = uuid.NewString()
	prepared.ExpiresAt = time.Now().Add(15 * time.Minute)
	s.remediationDrafts[prepared.ID] = &localRemediationDraft{prepared: prepared, backend: old.backend}
	delete(s.remediationDrafts, p.ID)
	return &prepared, nil
}
