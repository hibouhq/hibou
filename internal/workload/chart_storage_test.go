package workload

import "testing"

func TestChartArtifactStorageAndSecretMounts(t *testing.T) {
	for _, mode := range []string{"local", "rwo", "rwx", "s3", "shadow"} {
		t.Run(mode, func(t *testing.T) {
			values := chartValues()
			values["seaweedfs"] = map[string]any{"enabled": false}
			artifact := map[string]any{"backend": "filesystem"}
			if mode == "rwo" || mode == "rwx" || mode == "shadow" {
				access := "ReadWriteOnce"
				if mode == "rwx" || mode == "shadow" {
					access = "ReadWriteMany"
				}
				artifact["filesystem"] = map[string]any{"persistence": map[string]any{"enabled": true, "accessMode": access}}
			}
			if mode == "shadow" {
				artifact["path"] = "/etc/hibou"
			}
			if mode == "s3" {
				artifact = map[string]any{"backend": "s3", "s3": map[string]any{"endpoint": "https://s3.internal", "bucket": "private", "existingSecret": "shared-artifact-creds"}}
			}
			values["artifact"] = artifact
			registry := values["managedRemediation"].(map[string]any)["registry"].(map[string]any)
			registry["existingSecret"] = "mirror-auth"
			registry["tokenEnabled"] = true
			registry["caEnabled"] = true
			registry["tokenKey"] = "npm-token"
			registry["caKey"] = "mirror-ca"
			b, err := renderChart(t, values, "1.36.0")
			if mode == "local" || mode == "rwo" || mode == "shadow" {
				if err == nil {
					t.Fatal("unshared artifact store accepted")
				}
				return
			}
			if err != nil {
				t.Fatalf("%v: %s", err, b)
			}
			var controller bool
			for _, o := range decodeChart(t, b) {
				if o["kind"] != "Deployment" {
					continue
				}
				name := nested(o, "metadata", "name").(string)
				if name != "security-test-hibou" && name != "security-test-hibou-workload-controller" {
					continue
				}
				pod := nested(o, "spec", "template", "spec").(map[string]any)
				c := pod["containers"].([]any)[0].(map[string]any)
				if mode == "s3" {
					var creds int
					for _, item := range c["env"].([]any) {
						env := item.(map[string]any)
						if env["name"] == "HIBOU_ARTIFACT_S3_ACCESS_KEY_ID" || env["name"] == "HIBOU_ARTIFACT_S3_SECRET_ACCESS_KEY" {
							if nested(env, "valueFrom", "secretKeyRef", "name") != "shared-artifact-creds" {
								t.Fatal("artifact credentials differ between API/controller")
							}
							creds++
						}
					}
					if creds != 2 {
						t.Fatal("artifact credentials absent")
					}
				}
				var registryMount, pvc bool
				for _, item := range pod["volumes"].([]any) {
					v := item.(map[string]any)
					if v["name"] == "registry" {
						registryMount = true
						if nested(v, "secret", "secretName") != "mirror-auth" {
							t.Fatal("wrong registry Secret")
						}
						items := nested(v, "secret", "items").([]any)
						if len(items) != 2 || items[0].(map[string]any)["key"] != "npm-token" || items[1].(map[string]any)["key"] != "mirror-ca" {
							t.Fatal("wrong registry Secret keys")
						}
					}
					if v["name"] == "artifact-filesystem" {
						pvc = true
						if nested(v, "persistentVolumeClaim", "claimName") != "security-test-hibou-artifact-filesystem" {
							t.Fatal("artifact PVC differs")
						}
					}
				}
				if mode == "rwx" && !pvc {
					t.Fatal("shared artifact PVC not mounted")
				}
				if name == "security-test-hibou-workload-controller" {
					controller = true
					if !registryMount {
						t.Fatal("controller registry mount absent")
					}
				} else if registryMount {
					t.Fatal("API received registry credentials")
				}
			}
			if !controller {
				t.Fatal("controller not rendered")
			}
		})
	}
}
