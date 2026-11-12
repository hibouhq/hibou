package workload

import "testing"

func TestChartPublicProfileParityAndEnablement(t *testing.T) {
	for _, flags := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		values := chartValues()
		values["workload"].(map[string]any)["enabled"] = flags[0]
		managed := values["managedRemediation"].(map[string]any)
		managed["enabled"] = flags[1]
		managed["maintenanceBranchAllowlist"] = []string{"release/*"}
		b, err := renderChart(t, values, "1.36.0")
		if err != nil {
			t.Fatalf("%v %s", err, b)
		}
		objects := decodeChart(t, b)
		var data map[string]any
		for _, o := range objects {
			if o["kind"] == "ConfigMap" && nested(o, "metadata", "name") == "security-test-hibou" {
				data = o["data"].(map[string]any)
			}
		}
		if data == nil {
			t.Fatal("API ConfigMap absent")
		}
		want := "false"
		if flags[0] && flags[1] {
			want = "true"
		}
		if data["HIBOU_REMEDIATION_ENABLED"] != want {
			t.Fatal("enablement requires both flags")
		}
		if data["HIBOU_REMEDIATION_MAINTENANCE_BRANCH_ALLOWLIST"] != "release/*" {
			t.Fatal("existing maintenance allowlist changed")
		}
		for _, secret := range []string{"HIBOU_REMEDIATION_REGISTRY_CA_FILE", "HIBOU_REMEDIATION_REGISTRY_TOKEN_FILE", "HIBOU_WORKLOAD_TLS_KEY_FILE", "HIBOU_WORKLOAD_NAMESPACE"} {
			if _, ok := data[secret]; ok {
				t.Fatalf("API received controller-only configuration %s", secret)
			}
		}
		keys := []string{"HIBOU_REMEDIATION_ENABLED", "HIBOU_WORKLOAD_IMAGE", "HIBOU_REMEDIATION_NPM_REGISTRY", "HIBOU_REMEDIATION_NPM_PATH", "HIBOU_REMEDIATION_NPM_VERSION", "HIBOU_REMEDIATION_NODE_PATH", "HIBOU_REMEDIATION_NODE_VERSION", "HIBOU_REMEDIATION_TOOL_PATH"}
		for _, key := range keys {
			if _, ok := data[key]; !ok {
				t.Fatalf("missing public profile field %s", key)
			}
		}
		var controller bool
		for _, o := range objects {
			if o["kind"] != "Deployment" || nested(o, "metadata", "name") != "security-test-hibou-workload-controller" {
				continue
			}
			controller = true
			c := nested(o, "spec", "template", "spec", "containers").([]any)[0].(map[string]any)
			env := map[string]any{}
			for _, item := range c["env"].([]any) {
				e := item.(map[string]any)
				env[e["name"].(string)] = e["value"]
			}
			for _, key := range keys {
				if env[key] != data[key] {
					t.Fatalf("API/controller profile differs for %s", key)
				}
			}
		}
		if controller != (flags[0] && flags[1]) {
			t.Fatal("controller enablement differs")
		}
	}
}
