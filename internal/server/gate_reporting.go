package server

import "context"

func (l repoConfigGateLoader) HasGateReportingConfig(ctx context.Context, providerID, owner, repo, defaultBranch string) (bool, error) {
	if l.loader == nil {
		return false, nil
	}
	cfg, err := l.loader.Load(ctx, providerID, owner, repo, defaultBranch)
	if err != nil {
		return false, err
	}
	return cfg != nil && len(cfg.QualityGates) > 0, nil
}
