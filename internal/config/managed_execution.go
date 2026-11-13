package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ManagedExecutionConfig struct {
	Enabled           bool
	Image             string
	RegistryURL       string
	RegistryCAFile    string
	RegistryTokenFile string
	NPMPath           string
	NPMVersion        string
	NodePath          string
	NodeVersion       string
	ToolPath          string
}

func ManagedExecutionFromEnv() (ManagedExecutionConfig, error) {
	var cfg ManagedExecutionConfig
	if value := os.Getenv("HIBOU_REMEDIATION_ENABLED"); value != "" {
		enabled, err := strconv.ParseBool(value)
		if err != nil {
			return cfg, errors.New("HIBOU_REMEDIATION_ENABLED must be a boolean")
		}
		cfg.Enabled = enabled
	}
	if !cfg.Enabled {
		return cfg, nil
	}
	cfg.Image = os.Getenv("HIBOU_WORKLOAD_IMAGE")
	cfg.RegistryURL = os.Getenv("HIBOU_REMEDIATION_NPM_REGISTRY")
	cfg.RegistryCAFile = os.Getenv("HIBOU_REMEDIATION_REGISTRY_CA_FILE")
	cfg.RegistryTokenFile = os.Getenv("HIBOU_REMEDIATION_REGISTRY_TOKEN_FILE")
	cfg.NPMPath = os.Getenv("HIBOU_REMEDIATION_NPM_PATH")
	cfg.NPMVersion = os.Getenv("HIBOU_REMEDIATION_NPM_VERSION")
	cfg.NodePath = os.Getenv("HIBOU_REMEDIATION_NODE_PATH")
	cfg.NodeVersion = os.Getenv("HIBOU_REMEDIATION_NODE_VERSION")
	cfg.ToolPath = os.Getenv("HIBOU_REMEDIATION_TOOL_PATH")
	imageName, imageDigest, pinned := strings.Cut(cfg.Image, "@sha256:")
	if !pinned || imageName == "" || strings.ContainsAny(imageName, "@\r\n\x00 ") ||
		len(imageDigest) != 64 || strings.ToLower(imageDigest) != imageDigest {
		return cfg, errors.New("managed execution requires a digest-pinned workload image")
	}
	if _, err := hex.DecodeString(imageDigest); err != nil {
		return cfg, errors.New("managed workload image digest is invalid")
	}
	registry, err := url.Parse(cfg.RegistryURL)
	if err != nil || registry.Scheme != "https" || registry.Host == "" || registry.User != nil ||
		registry.RawQuery != "" || registry.Fragment != "" || registry.Hostname() == "registry.npmjs.org" {
		return cfg, errors.New("managed remediation requires an explicit HTTPS internal npm mirror without credentials, query or fragment")
	}
	for _, field := range []struct{ name, value string }{
		{"NPM_PATH", cfg.NPMPath}, {"NODE_PATH", cfg.NodePath},
	} {
		if !filepath.IsAbs(field.value) || strings.ContainsAny(field.value, "\r\n\x00") {
			return cfg, fmt.Errorf("HIBOU_REMEDIATION_%s must be an approved absolute workload path", field.name)
		}
	}
	if cfg.NPMVersion == "" || cfg.NodeVersion == "" || cfg.ToolPath == "" ||
		strings.ContainsAny(cfg.NPMVersion+cfg.NodeVersion+cfg.ToolPath, "\r\n\x00") {
		return cfg, errors.New("managed execution requires exact npm/node versions and an explicit tool PATH")
	}
	for _, entry := range filepath.SplitList(cfg.ToolPath) {
		if !filepath.IsAbs(entry) {
			return cfg, errors.New("managed tool PATH entries must be absolute")
		}
	}
	return cfg, nil
}

// Profile identifies the configuration for which a live controller is ready.
// Historical host-runtime controller heartbeats cannot satisfy this contract.
func (c ManagedExecutionConfig) Profile() string {
	data := strings.Join([]string{c.Image, c.RegistryURL, c.NPMPath, c.NPMVersion, c.NodePath, c.NodeVersion, c.ToolPath}, "\x00")
	sum := sha256.Sum256([]byte(data))
	return "kubernetes-v1:" + hex.EncodeToString(sum[:])
}
