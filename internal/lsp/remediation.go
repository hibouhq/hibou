package lsp

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/hibouhq/hibou/internal/remediation"
)

type remediationApplyParams struct {
	Root     string               `json:"root"`
	Artifact remediation.Artifact `json:"artifact"`
}

func (s *Server) remediationApply(ctx context.Context, p remediationApplyParams) (*remediation.ApplyResult, error) {
	if p.Root == "" {
		return nil, &rpcError{Code: codeInvalidParams, Message: "choose the repository root explicitly"}
	}
	root, err := filepath.Abs(p.Root)
	if err != nil {
		return nil, err
	}
	s.remediationMu.Lock()
	defer s.remediationMu.Unlock()
	known := false
	for _, ws := range s.allWorkspaces() {
		if filepath.Clean(ws.root) == root {
			known = true
			break
		}
	}
	if !known {
		return nil, &rpcError{Code: codeInvalidParams, Message: "repository is not registered in this language-server session"}
	}
	s.mu.Lock()
	for _, change := range p.Artifact.Changes {
		if !filepath.IsLocal(change.Path) {
			s.mu.Unlock()
			return nil, &rpcError{Code: codeInvalidParams, Message: "artifact paths must stay inside the repository"}
		}
		file := filepath.Join(root, filepath.FromSlash(change.Path))
		for _, doc := range s.docs {
			if filepath.Clean(doc.path) != filepath.Clean(file) {
				continue
			}
			data, readErr := os.ReadFile(file)
			if readErr != nil || string(data) != doc.text {
				s.mu.Unlock()
				return nil, &rpcError{Code: codeInvalidRequest, Message: "an affected file has an unsaved editor buffer; save or resolve it before applying"}
			}
		}
	}
	s.mu.Unlock()
	out, err := remediation.Apply(ctx, root, p.Artifact)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil, &rpcError{Code: codeRequestCancelled, Message: err.Error()}
		}
		return nil, &rpcError{Code: codeInvalidRequest, Message: err.Error()}
	}
	return out, nil
}
