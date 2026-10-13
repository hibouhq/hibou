package lsp

import (
	"bytes"
	"context"
	"net/http"
	"path/filepath"
)

// maxSecretCheckBytes matches the server's limit on POST /secret-scan/check.
const maxSecretCheckBytes = 1 << 20

// secretCheckResult is the hibou/secretCheck answer (ADR-042 phase 3).
type secretCheckResult struct {
	Block    bool                 `json:"block"`
	Findings []secretCheckFinding `json:"findings"`
	Message  string               `json:"message,omitempty"`
}

type secretCheckFinding struct {
	Tool       string `json:"tool"`
	RuleID     string `json:"ruleId"`
	Severity   string `json:"severity"`
	Path       string `json:"path"`
	URI        string `json:"uri,omitempty"`
	Line       int    `json:"line"` // 0-based
	SecretType string `json:"secretType"`
	Verified   bool   `json:"verified"`
}

// secretCheck sends the staged diff of each workspace to the server's
// synchronous secret check, as `hibou secret-scan --staged` does. The server
// stores nothing: it scans the patch and answers. The check is opt-in
// (Options.SecretCheck), because it sends uncommitted content to the server;
// the client asks the user before enabling it.
func (s *Server) secretCheck(ctx context.Context, root string) (*secretCheckResult, error) {
	s.mu.Lock()
	enabled := s.opts.SecretCheck
	s.mu.Unlock()
	if !enabled {
		return nil, &rpcError{Code: codeInvalidRequest, Message: "the staged-changes secret check is disabled in the IDE settings"}
	}
	client, err := s.api()
	if err != nil {
		return nil, err
	}
	if client.token == "" {
		return nil, &rpcError{Code: codeInvalidRequest, Message: "sign in to hibou first"}
	}

	res := &secretCheckResult{Findings: []secretCheckFinding{}}
	checked := 0
	for _, ws := range s.allWorkspaces() {
		if root != "" && filepath.Clean(root) != ws.root {
			continue
		}
		// Reading the index can run core.fsmonitor; external diff drivers and
		// textconv filters are commands too. None of them may run here.
		patch, err := ws.git.run(ctx, "-c", "core.fsmonitor=false", "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--cached")
		if err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(patch)) == 0 {
			continue
		}
		if len(patch) > maxSecretCheckBytes {
			return nil, &rpcError{Code: codeInvalidRequest, Message: "the staged diff is larger than 1 MiB; run `hibou secret-scan --staged` in a terminal"}
		}
		checked++

		var out struct {
			Block    bool `json:"block"`
			Findings []struct {
				Tool       string `json:"tool"`
				RuleID     string `json:"rule_id"`
				Severity   string `json:"severity"`
				FilePath   string `json:"file_path"`
				Line       int    `json:"line"`
				SecretType string `json:"secret_type"`
				Verified   bool   `json:"verified"`
			} `json:"findings"`
		}
		if err := client.postRaw(ctx, "/secret-scan/check", "text/x-diff", patch, &out); err != nil {
			if isStatus(err, http.StatusForbidden) {
				return nil, &rpcError{Code: codeInvalidRequest, Message: "the token cannot run secret checks (needs secrets:read)"}
			}
			return nil, err
		}
		res.Block = res.Block || out.Block
		for _, f := range out.Findings {
			rel := normalizeRepoPath(f.FilePath)
			sf := secretCheckFinding{
				Tool: f.Tool, RuleID: f.RuleID, Severity: f.Severity, Path: rel,
				Line: max(f.Line-1, 0), SecretType: f.SecretType, Verified: f.Verified,
			}
			if rel != "" {
				sf.URI = pathToURI(filepath.Join(ws.root, filepath.FromSlash(rel)))
			}
			res.Findings = append(res.Findings, sf)
		}
	}
	switch {
	case checked == 0:
		res.Message = "Nothing staged to check."
	case len(res.Findings) == 0:
		res.Message = "No secrets detected in the staged changes."
	default:
		res.Message = "Secrets detected in the staged changes. Remove them before committing; rotate anything already pushed."
	}
	return res, nil
}
