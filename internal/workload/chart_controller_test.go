package workload

import "testing"

func TestChartControllerTLSAndDestinationPolicies(t *testing.T) {
	for _, database := range []string{"postgresql", "cnpg"} {
		t.Run(database, func(t *testing.T) {
			values := chartValues()
			if database == "cnpg" {
				values["postgresql"] = map[string]any{"enabled": false}
				values["cnpg"] = map[string]any{"cluster": map[string]any{"enabled": true, "networkPolicy": map[string]any{"enabled": true, "operatorFrom": []any{map[string]any{"podSelector": map[string]any{"matchLabels": map[string]any{"app.kubernetes.io/name": "cloudnative-pg"}}}}}}}
			}
			b, err := renderChart(t, values, "1.36.0")
			if err != nil {
				t.Fatalf("%v %s", err, b)
			}
			var db, artifacts, deployment bool
			for _, o := range decodeChart(t, b) {
				name := nested(o, "metadata", "name")
				if o["kind"] == "HorizontalPodAutoscaler" && nested(o, "spec", "scaleTargetRef", "name") == "security-test-hibou-workload-controller" {
					t.Fatal("in-memory broker controller must not be autoscaled")
				}
				if o["kind"] == "Deployment" && name == "security-test-hibou-workload-controller" {
					deployment = true
					strategy := nested(o, "spec", "strategy").(map[string]any)
					if nested(o, "spec", "replicas") != 1 || len(strategy) != 1 || strategy["type"] != "Recreate" {
						t.Fatal("in-memory broker requires exactly one controller and Recreate without rolling overlap")
					}
					pod := nested(o, "spec", "template", "spec").(map[string]any)
					if nested(pod, "securityContext", "runAsUser") != 65532 || nested(pod, "securityContext", "runAsGroup") != 65532 || nested(pod, "securityContext", "runAsNonRoot") != true {
						t.Fatal("controller identity overridden")
					}
					c := pod["containers"].([]any)[0].(map[string]any)
					if nested(c, "securityContext", "allowPrivilegeEscalation") != false || nested(c, "securityContext", "readOnlyRootFilesystem") != true {
						t.Fatal("controller privilege expansion")
					}
					for _, probe := range []string{"startupProbe", "readinessProbe"} {
						if nested(c, probe, "httpGet", "scheme") != "HTTPS" || nested(c, probe, "httpGet", "path") != "/readyz" || nested(c, probe, "httpGet", "port") != "broker" {
							t.Fatal("controller probe does not use broker TLS readiness")
						}
					}
					var tls bool
					for _, v := range pod["volumes"].([]any) {
						volume := v.(map[string]any)
						if volume["name"] == "tls" {
							tls = true
							if nested(volume, "secret", "secretName") != "operator-broker-tls" {
								t.Fatal("controller TLS Secret mismatch")
							}
						}
					}
					if !tls {
						t.Fatal("controller TLS Secret missing")
					}
				}
				if o["kind"] != "NetworkPolicy" || (name != "security-test-hibou-workload-controller-database" && name != "security-test-hibou-workload-controller-artifacts") {
					continue
				}
				if nested(o, "metadata", "namespace") != "application" {
					t.Fatal("destination ingress policy in wrong namespace")
				}
				rule := nested(o, "spec", "ingress").([]any)[0].(map[string]any)
				peers := rule["from"].([]any)
				if len(peers) != 1 {
					t.Fatal("broad controller destination ingress")
				}
				peer := peers[0].(map[string]any)
				labels := nested(peer, "podSelector", "matchLabels").(map[string]any)
				if len(peer) != 1 || len(labels) != 3 || labels["app.kubernetes.io/component"] != "workload-controller" || labels["app.kubernetes.io/instance"] != "security-test" || labels["app.kubernetes.io/name"] != "hibou" {
					t.Fatal("destination ingress not narrowly controller-scoped")
				}
				if name == "security-test-hibou-workload-controller-database" {
					db = true
					if database == "cnpg" {
						if nested(o, "spec", "podSelector", "matchLabels", "cnpg.io/cluster") != "security-test-hibou-pg" {
							t.Fatal("CNPG destination mismatch")
						}
					} else if nested(o, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") != "postgresql" {
						t.Fatal("database destination mismatch")
					}
				} else {
					artifacts = true
					if nested(o, "spec", "podSelector", "matchLabels", "app.kubernetes.io/component") != "seaweedfs" {
						t.Fatal("artifact destination mismatch")
					}
				}
			}
			if !deployment || !db || !artifacts {
				t.Fatal("controller TLS or required destination ingress absent")
			}
		})
	}
}
