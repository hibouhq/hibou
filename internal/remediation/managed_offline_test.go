package remediation

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"testing"
)

func TestManagedNPMUsesOnlyInternalMirrorWithRealNativeTools(t *testing.T) {
	for _, binary := range []string{"node", "npm"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("preinstalled %s is unavailable: %v", binary, err)
		}
	}
	tool, err := InspectLocalNPM(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	archives := map[string][]byte{}
	integrities := map[string]string{}
	for _, version := range []string{"1.0.0", "1.0.1"} {
		var data bytes.Buffer
		zip := gzip.NewWriter(&data)
		writer := tar.NewWriter(zip)
		for name, contents := range map[string]string{
			"package/package.json": `{"name":"fixture-dependency","version":"` + version + `"}`,
			"package/index.js":     "module.exports = true;\n",
		} {
			if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(contents))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(contents)); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := zip.Close(); err != nil {
			t.Fatal(err)
		}
		archives[version] = data.Bytes()
		sum := sha512.Sum512(data.Bytes())
		integrities[version] = "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
	}
	var origin string
	_, mirrorConfig := mirrorFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/-/") {
			for version, data := range archives {
				if strings.HasSuffix(r.URL.Path, "/fixture-"+version+".tgz") {
					_, _ = w.Write(data)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		versions := map[string]any{}
		for version := range archives {
			versions[version] = map[string]any{
				"name": "fixture-dependency", "version": version,
				"dist": map[string]string{
					"tarball":   origin + "/fixture-dependency/-/fixture-" + version + ".tgz",
					"integrity": integrities[version],
				},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "fixture-dependency", "dist-tags": map[string]string{"latest": "1.0.1"}, "versions": versions,
		})
	}))
	origin = mirrorConfig.URL
	client, err := NewNPMMirrorClient(mirrorConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	tool.RegistryOrigin = origin
	manifest, lock := npmFixture(t, "1.0.0", "1.0.0")
	lock = strings.ReplaceAll(lock, "https://registry.npmjs.org/fixture-dependency/-/fixture.tgz", origin+"/fixture-dependency/-/fixture-1.0.0.tgz")
	lock = strings.ReplaceAll(lock, "sha512-"+base64.StdEncoding.EncodeToString(make([]byte, 64)), integrities["1.0.0"])
	repo, sha := repository(t, map[string]string{"package.json": manifest, "package-lock.json": lock})
	backend := NPMBackend{Tool: tool, Match: npmMatchFixture, RegistryClient: client}
	unit, err := backend.Prepare(t.Context(), repo, sha, "package.json", nil, "patch")
	if err != nil {
		t.Fatal(err)
	}
	unit.VersionTargets = []VersionTarget{{Name: "fixture-dependency", Mode: "exact", Version: "1.0.1"}}
	artifact, err := (Engine{Backend: backend}).Generate(t.Context(), Request{Repository: repo, BaseSHA: sha, Units: []Unit{unit}})
	if err != nil {
		t.Fatal(err)
	}
	files, err := managedArtifactFiles(t.Context(), repo, t.TempDir(), *artifact)
	if err != nil {
		t.Fatal(err)
	}
	result := &ManagedResult{Artifact: artifact, Files: files}
	if err := VerifyManagedCandidate(t.Context(), repo, ManagedInput{BaseSHA: sha, Units: []Unit{unit}}, result, backend, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(files["package-lock.json"]), origin+"/") || strings.Contains(string(artifact.Patch), "127.0.0.1:1234") {
		t.Fatal("mirror profile was not preserved in the generated lockfile")
	}
}
