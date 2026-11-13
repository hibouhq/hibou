package workload

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestApprovedExecutionImagePullSecrets(t *testing.T) {
	f := setup(t)
	names := []string{"internal-oci-auth", "secondary.oci"}
	c := f.cfg
	c.ImagePullSecrets = names
	r, err := NewRunner(c, f.client, f.broker)
	if err != nil {
		t.Fatal(err)
	}
	names[0] = "mutated"
	if r.config.ImagePullSecrets[0] != "internal-oci-auth" {
		t.Fatal("configuration retained mutable caller slice")
	}
	if err := r.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	j := r.config.job(randomID(), randomToken(), "fence")
	p := j.Spec.Template.Spec
	if !r.config.approvedPullSecrets(p) || len(p.Volumes) != 1 || p.Volumes[0].Name != "scratch" {
		t.Fatal("pull credentials must be approved references, never mounted volumes")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "secretKeyRef") || strings.Contains(string(raw), `"secret":`) {
		t.Fatal("pull credentials exposed to workload")
	}
	p.ImagePullSecrets[0].Name = "unapproved"
	if r.config.approvedPullSecrets(p) {
		t.Fatal("unapproved pull reference accepted")
	}
	for _, bad := range [][]string{{""}, {"app/oci-auth"}, {"oci", "oci"}, {"a..b"}, {"UPPER"}} {
		cfg := f.cfg
		cfg.ImagePullSecrets = bad
		if _, err := NewRunner(cfg, f.client, f.broker); err == nil {
			t.Fatalf("invalid pull references %v accepted", bad)
		}
	}
}

func TestChartExecutionImagePullSecretScope(t *testing.T) {
	values := chartValues()
	values["workload"].(map[string]any)["imagePullSecrets"] = []any{map[string]any{"name": "internal-oci-auth"}, map[string]any{"name": "secondary.oci"}}
	if b, err := lintChart(t, values); err != nil {
		t.Fatalf("private image pull configuration failed lint: %v %s", err, b)
	}
	b, err := renderChart(t, values, "1.36.0")
	if err != nil {
		t.Fatalf("%v %s", err, b)
	}
	var account, controller, jobPolicy, podPolicy bool
	for _, o := range decodeChart(t, b) {
		name := nested(o, "metadata", "name")
		if o["kind"] == "ServiceAccount" {
			refs, has := o["imagePullSecrets"].([]any)
			if name == "security-test-hibou-remediation" {
				account = true
				if nested(o, "metadata", "namespace") != "security-test-hibou-workloads" || !has || len(refs) != 2 || refs[0].(map[string]any)["name"] != "internal-oci-auth" || refs[1].(map[string]any)["name"] != "secondary.oci" {
					t.Fatal("pull reference not scoped to execution ServiceAccount")
				}
			} else if has && len(refs) > 0 {
				t.Fatal("execution pull secrets reused in API/controller namespace")
			}
		}
		if o["kind"] == "Deployment" && name == "security-test-hibou-workload-controller" {
			controller = true
			c := nested(o, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)
			var env bool
			for _, item := range c["env"].([]any) {
				e := item.(map[string]any)
				if e["name"] == "HIBOU_WORKLOAD_IMAGE_PULL_SECRETS" {
					env = true
					if e["value"] != "internal-oci-auth,secondary.oci" {
						t.Fatal("controller pull-reference environment differs")
					}
				}
			}
			if !env {
				t.Fatal("controller lacks approved pull-reference configuration")
			}
			for _, item := range nested(o, "spec", "template", "spec", "volumes").([]any) {
				v := item.(map[string]any)
				if nested(v, "secret", "secretName") == "internal-oci-auth" || nested(v, "secret", "secretName") == "secondary.oci" {
					t.Fatal("controller must not mount execution pull secrets")
				}
			}
		}
		if o["kind"] == "ValidatingAdmissionPolicy" {
			raw, _ := json.Marshal(o)
			for _, constraint := range []string{"size(variables.p.imagePullSecrets) == 2", "variables.p.imagePullSecrets[0].name == ", "internal-oci-auth", "variables.p.imagePullSecrets[1].name == ", "secondary.oci"} {
				if !strings.Contains(string(raw), constraint) {
					t.Fatal("exact image pull-reference admission allowlist missing")
				}
			}
			if strings.HasSuffix(name.(string), "-job") {
				jobPolicy = true
			} else if strings.HasSuffix(name.(string), "-pod") {
				podPolicy = true
			}
		}
	}
	if !account || !controller || !jobPolicy || !podPolicy {
		t.Fatal("incomplete private OCI pull support")
	}
}
