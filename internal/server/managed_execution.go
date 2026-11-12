package server

import (
	"context"
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/config"
	"github.com/hibouhq/hibou/internal/remediation"
)

func (s *Server) requireManagedExecution(w http.ResponseWriter, r *http.Request) bool {
	if ready, reason := s.managedExecutionReady(r.Context()); !ready {
		api.JSONError(w, http.StatusServiceUnavailable, reason)
		return false
	}
	return true
}

func (s *Server) managedExecutionReady(ctx context.Context) (bool, string) {
	cfg, err := config.ManagedExecutionFromEnv()
	if err != nil {
		return false, err.Error()
	}
	if !cfg.Enabled {
		return false, remediation.ErrManagedExecutionUnavailable.Error()
	}
	ready, err := s.queries.RemediationControllerReady(ctx, cfg.Profile())
	if err != nil {
		s.log.Error().Err(err).Msg("check managed Kubernetes controller readiness")
		return false, "Managed Kubernetes controller readiness is unavailable."
	}
	if !ready {
		return false, "No ready Kubernetes controller for the configured remediation image, toolchain and mirror profile (ADR-056)."
	}
	return true, ""
}
