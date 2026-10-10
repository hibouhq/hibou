package server

import (
	"net/http"

	"github.com/hibouhq/hibou/internal/api"
	"github.com/hibouhq/hibou/internal/storageusage"
)

// ADR-039: the instance-admin view of the persisted storage usage sample.

type instanceStorageResponse struct {
	// Sample is null until the sampler's first pass has completed.
	Sample                   *storageusage.Sample `json:"sample"`
	Enabled                  bool                 `json:"enabled"`
	IntervalSeconds          float64              `json:"interval_seconds"`
	InventoryEnabled         bool                 `json:"inventory_enabled"`
	InventoryIntervalSeconds float64              `json:"inventory_interval_seconds"`
	ArtifactBackend          string               `json:"artifact_backend"`
	// MetricsExposure says how /metrics is reachable: "disabled",
	// "dedicated_port", "token" or "public" (application port, no token).
	MetricsExposure string `json:"metrics_exposure"`
}

// @Summary      Instance storage usage
// @Description  The latest storage usage sample (Postgres, artifact ledger, optional backend inventory) and the sampler settings. Usage only, no prices. Instance admins only.
// @Tags         instance
// @Produce      json
// @Success      200  {object}  api.Response{data=instanceStorageResponse}
// @Failure      401  {object}  api.Response
// @Failure      403  {object}  api.Response
// @Failure      500  {object}  api.Response
// @Security     BearerAuth
// @Router       /instance/storage [get]
func (s *Server) handleInstanceStorage(w http.ResponseWriter, r *http.Request) {
	if !s.requireInstanceAdmin(w, r) {
		return
	}
	sample, err := s.loadStorageUsageSample(r.Context())
	if err != nil {
		s.log.Error().Err(err).Msg("load storage usage sample failed")
		api.JSONError(w, http.StatusInternalServerError, "failed to load storage usage")
		return
	}
	cfg := s.cfg.StorageUsage
	api.JSON(w, http.StatusOK, instanceStorageResponse{
		Sample:                   sample,
		Enabled:                  cfg.Enabled,
		IntervalSeconds:          cfg.Interval.Seconds(),
		InventoryEnabled:         cfg.Inventory.Enabled,
		InventoryIntervalSeconds: cfg.Inventory.Interval.Seconds(),
		ArtifactBackend:          s.cfg.ArtifactBackend,
		MetricsExposure:          s.metricsExposure(),
	})
}

func (s *Server) metricsExposure() string {
	switch {
	case !s.cfg.Metrics.Enabled:
		return "disabled"
	case s.cfg.Metrics.Port != 0:
		return "dedicated_port"
	case s.cfg.Metrics.BearerToken != "":
		return "token"
	default:
		return "public"
	}
}
