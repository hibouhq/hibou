package workload

import (
	"testing"
	"time"
)

func TestConfigFromEnvResourcesAndDeadline(t *testing.T) {
	f := setup(t)
	for k, v := range map[string]string{
		"HIBOU_WORKLOAD_NAMESPACE":            f.cfg.Namespace,
		"HIBOU_WORKLOAD_CONTROLLER_NAMESPACE": f.cfg.ControllerNamespace,
		"HIBOU_WORKLOAD_IMAGE":                f.cfg.Image,
		"HIBOU_WORKLOAD_RUNTIME_CLASS":        f.cfg.RuntimeClass,
		"HIBOU_WORKLOAD_RUNTIME_VALIDATED":    "true",
		"HIBOU_WORKLOAD_SERVICE_ACCOUNT":      f.cfg.ServiceAccount,
		"HIBOU_WORKLOAD_BROKER_URL":           f.cfg.BrokerURL,
		"HIBOU_WORKLOAD_CA":                   f.cfg.CABundle,
		"HIBOU_WORKLOAD_DEADLINE_SECONDS":     "540",
		"HIBOU_WORKLOAD_CPU_REQUEST":          "500m",
		"HIBOU_WORKLOAD_CPU_LIMIT":            "4",
		"HIBOU_WORKLOAD_MEMORY_REQUEST":       "1Gi",
		"HIBOU_WORKLOAD_MEMORY_LIMIT":         "4Gi",
		"HIBOU_WORKLOAD_STORAGE_REQUEST":      "2Gi",
		"HIBOU_WORKLOAD_STORAGE_LIMIT":        "4Gi",
		"HIBOU_WORKLOAD_IMAGE_PULL_SECRETS":   "internal-oci-auth, secondary.oci",
	} {
		t.Setenv(k, v)
	}
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Deadline != 9*time.Minute || c.Resources != (Resources{"500m", "4", "1Gi", "4Gi", "2Gi", "4Gi"}) {
		t.Fatalf("environment overrides not honored: %#v", c)
	}
	if c.MaxInputBytes != MaxBodyBytes || c.MaxOutputBytes != MaxBodyBytes {
		t.Fatal("transport bounds differ")
	}
	if len(c.ImagePullSecrets) != 2 || c.ImagePullSecrets[0] != "internal-oci-auth" || c.ImagePullSecrets[1] != "secondary.oci" {
		t.Fatal("image pull-reference environment not honored")
	}
	for _, bad := range []string{"0", "-1", "1801", "999999999999999999999", "not-an-integer"} {
		t.Setenv("HIBOU_WORKLOAD_DEADLINE_SECONDS", bad)
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatalf("invalid explicit deadline %q accepted", bad)
		}
	}
}
