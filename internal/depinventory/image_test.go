package depinventory

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const testDpkgStatus = `Package: libc6
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 12000
Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>
Architecture: amd64
Source: glibc
Version: 2.36-9+deb12u4
Description: GNU C Library: Shared libraries

`

const testOSRelease = "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"

// testImage builds a two-layer image: a base layer with a dpkg database,
// an empty CMD entry that ends the base image, then an application layer
// with an installed npm package and a jar without metadata.
func testImage(t *testing.T) v1.Image {
	t.Helper()
	base, err := crane.Layer(map[string][]byte{
		"var/lib/dpkg/status": []byte(testDpkgStatus),
		"etc/os-release":      []byte(testOSRelease),
	})
	if err != nil {
		t.Fatal(err)
	}
	app, err := crane.Layer(map[string][]byte{
		"app/node_modules/left-pad/package.json": []byte(`{"name":"left-pad","version":"1.3.0"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.Append(empty.Image,
		mutate.Addendum{Layer: base, History: v1.History{CreatedBy: "/bin/sh -c #(nop) ADD file:rootfs.tar.xz in / "}},
		mutate.Addendum{History: v1.History{CreatedBy: "/bin/sh -c #(nop)  CMD [\"bash\"]", EmptyLayer: true}},
		mutate.Addendum{Layer: app, History: v1.History{CreatedBy: "COPY app /app # buildkit"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.Config(img, v1.Config{Labels: map[string]string{
		"org.opencontainers.image.revision":  "0123456789abcdef0123456789abcdef01234567",
		"org.opencontainers.image.version":   "1.2.3",
		"org.opencontainers.image.base.name": "docker.io/library/debian:12-slim",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func testRegistry(t *testing.T) (string, name.Repository) {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(server.Close)
	host := strings.TrimPrefix(server.URL, "http://")
	repo, err := name.NewRepository(host + "/acme/app")
	if err != nil {
		t.Fatal(err)
	}
	return host, repo
}

func cycloneDXDoc(purls ...string) []byte {
	components := make([]map[string]any, 0, len(purls))
	for _, p := range purls {
		parts := strings.Split(strings.TrimPrefix(p, "pkg:"), "@")
		components = append(components, map[string]any{"type": "library", "name": parts[0][strings.LastIndex(parts[0], "/")+1:], "version": parts[1], "purl": p})
	}
	doc, _ := json.Marshal(map[string]any{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components})
	return doc
}

func spdxDoc(purl, nameOf, version string) []byte {
	doc, _ := json.Marshal(map[string]any{
		"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "app",
		"packages": []map[string]any{{
			"name": nameOf, "SPDXID": "SPDXRef-pkg", "versionInfo": version,
			"externalRefs": []map[string]string{{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}},
		}},
	})
	return doc
}

func statementJSON(predicateType string, predicate []byte, subjectSHA256 string) []byte {
	statement, _ := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject":       []map[string]any{{"name": "acme/app", "digest": map[string]string{"sha256": subjectSHA256}}},
		"predicate":     json.RawMessage(predicate),
	})
	return statement
}

func TestScanImageLayersAndAttachedSBOMs(t *testing.T) {
	host, repo := testRegistry(t)
	img := testImage(t)
	tag := repo.Tag("1.2.3")
	if err := remote.Write(tag, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}

	// 1. An OCI referrer with a CycloneDX layer (oras attach / cosign in
	// OCI 1.1 mode) declaring a package the filesystem scan cannot see.
	sbomLayers, err := mutate.AppendLayers(empty.Image, static.NewLayer(cycloneDXDoc("pkg:maven/org.example/shaded@3.1.0", "pkg:npm/left-pad@1.3.0"), mediaTypeCycloneDX))
	if err != nil {
		t.Fatal(err)
	}
	sbomImg := mutate.MediaType(mutate.ConfigMediaType(sbomLayers, mediaTypeCycloneDX), types.OCIManifestSchema1)
	if err := remote.Write(repo.Tag("sbom-blobs"), sbomImg); err != nil {
		t.Fatal(err)
	}
	size, _ := img.Size()
	mediaType, _ := img.MediaType()
	subject := v1.Descriptor{Digest: digest, Size: size, MediaType: mediaType}
	if err := remote.Put(repo.Tag("sbom-referrer"), mutate.Subject(sbomImg, subject)); err != nil {
		t.Fatal(err)
	}

	// 2. The cosign .att tag with a DSSE envelope around an SPDX statement.
	statement := statementJSON("https://spdx.dev/Document", spdxDoc("pkg:pypi/requests@2.31.0", "requests", "2.31.0"), digest.Hex)
	envelope, _ := json.Marshal(map[string]any{
		"payloadType": mediaTypeInToto,
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"keyid": "", "sig": base64.StdEncoding.EncodeToString([]byte("not-checked-here"))}},
	})
	attLayer := static.NewLayer(envelope, mediaTypeDSSE)
	attImg, err := mutate.Append(empty.Image, mutate.Addendum{Layer: attLayer, Annotations: map[string]string{"predicateType": "https://spdx.dev/Document"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(repo.Tag("sha256-"+digest.Hex+".att"), attImg); err != nil {
		t.Fatal(err)
	}

	warnings := []string{}
	out, err := ScanImage(context.Background(), host+"/acme/app:1.2.3", ScanOptions{Warn: func(m string) { warnings = append(warnings, m) }})
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if out.Digest != digest.String() {
		t.Errorf("digest %s, want %s", out.Digest, digest)
	}
	if out.BaseImage != "docker.io/library/debian:12-slim" {
		t.Errorf("base image %q", out.BaseImage)
	}
	byName := map[string]Component{}
	for _, c := range out.Inventory.Components {
		byName[c.Name] = c
	}
	libc, ok := byName["libc6"]
	if !ok {
		t.Fatalf("libc6 not found in %+v", byName)
	}
	if libc.Layer == nil || libc.Layer.Index != 0 || !libc.Layer.BaseImage {
		t.Errorf("libc6 layer %+v, want index 0 in the base image", libc.Layer)
	}
	leftPad, ok := byName["left-pad"]
	if !ok {
		t.Fatalf("left-pad not found in %+v", byName)
	}
	if leftPad.Layer == nil || leftPad.Layer.Index != 2 || leftPad.Layer.BaseImage {
		t.Errorf("left-pad layer %+v, want index 2 outside the base image", leftPad.Layer)
	}
	if leftPad.Layer != nil && !strings.Contains(leftPad.Layer.Command, "COPY app") {
		t.Errorf("left-pad layer command %q", leftPad.Layer.Command)
	}
	if len(out.Layers) != 3 || !out.Layers[0].BaseImage || !out.Layers[1].BaseImage || !out.Layers[1].Empty || out.Layers[2].BaseImage {
		t.Errorf("layer summaries %+v", out.Layers)
	}
	if out.Layers[0].Components != 1 || out.Layers[2].Components != 1 {
		t.Errorf("components per layer %+v", out.Layers)
	}

	// Attached SBOMs: the referrer (unsigned CycloneDX) and the cosign
	// attestation (signed SPDX).
	if len(out.AttachedSBOMs) != 2 {
		t.Fatalf("attached SBOMs %+v, warnings %v", out.AttachedSBOMs, warnings)
	}
	sources := map[string]AttachedSBOM{}
	for _, a := range out.AttachedSBOMs {
		sources[a.Source] = a
	}
	referrer := sources["referrers"]
	if referrer.Format != "cyclonedx" || referrer.Signed || referrer.Components != 2 || referrer.Added != 1 {
		t.Errorf("referrer %+v", referrer)
	}
	cosignAtt := sources["cosign"]
	if cosignAtt.Format != "spdx" || !cosignAtt.Signed || cosignAtt.PredicateType != "https://spdx.dev/Document" || cosignAtt.Added != 1 {
		t.Errorf("cosign attestation %+v", cosignAtt)
	}
	shaded, ok := byName["org.example:shaded"]
	if !ok || shaded.Extractor != "sbom" || !strings.Contains(shaded.Path, "!sbom/referrers/") {
		t.Errorf("shaded component from the attached SBOM: %+v", shaded)
	}
	if _, ok := byName["requests"]; !ok {
		t.Errorf("requests from the attestation missing")
	}
	// left-pad came from the filesystem scan: the SBOM did not add it.
	if leftPad.Extractor == "sbom" {
		t.Errorf("left-pad should come from the filesystem scan, got %s", leftPad.Extractor)
	}
	if len(out.Inventory.Targets) != 3 || out.Inventory.Targets[0].Kind != KindImage || out.Inventory.Targets[0].Metadata["version"] != "1.2.3" || out.Inventory.Targets[0].Metadata["base_image"] == "" {
		t.Errorf("targets %+v", out.Inventory.Targets)
	}
	for _, target := range out.Inventory.Targets[1:] {
		if target.Kind != KindSBOM || target.Metadata["attached_sbom"] == "" {
			t.Errorf("attached target %+v", target)
		}
	}

	// The CycloneDX output carries the layer properties, so the server
	// keeps them as labels.
	document, err := ToCycloneDX(&Inventory{Components: out.Inventory.Components, Modules: RebuildModules(out.Inventory.Components)}, "app", "test", testTime())
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	for _, want := range []string{`"name": "hibou:layer",`, `"value": "0"`, `"name": "hibou:base_image",`, `"value": "true"`, `"value": "false"`, `"name": "hibou:layer_digest",`} {
		if !strings.Contains(text, want) {
			t.Errorf("CycloneDX lacks %s", want)
		}
	}
}

func TestScanImageBuildKitAttestation(t *testing.T) {
	host, repo := testRegistry(t)
	img := testImage(t)
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	statement := statementJSON("https://spdx.dev/Document", spdxDoc("pkg:golang/golang.org/x/net@v0.17.0", "golang.org/x/net", "v0.17.0"), digest.Hex)
	attImg, err := mutate.Append(empty.Image, mutate.Addendum{Layer: static.NewLayer(statement, mediaTypeInToto), Annotations: map[string]string{"in-toto.io/predicate-type": "https://spdx.dev/Document"}})
	if err != nil {
		t.Fatal(err)
	}
	attImg = mutate.MediaType(attImg, types.OCIManifestSchema1)
	attDigest, err := attImg.Digest()
	if err != nil {
		t.Fatal(err)
	}
	attSize, _ := attImg.Size()
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: attImg, Descriptor: v1.Descriptor{
			Digest: attDigest, Size: attSize, MediaType: types.OCIManifestSchema1,
			Platform:    &v1.Platform{OS: "unknown", Architecture: "unknown"},
			Annotations: map[string]string{buildkitReferenceType: buildkitAttestation, buildkitReferenceDigest: digest.String()},
		}},
	)
	if err := remote.WriteIndex(repo.Tag("multi"), index); err != nil {
		t.Fatal(err)
	}
	out, err := ScanImage(context.Background(), host+"/acme/app:multi", ScanOptions{})
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if len(out.AttachedSBOMs) != 1 || out.AttachedSBOMs[0].Source != "buildkit" || out.AttachedSBOMs[0].Format != "spdx" || out.AttachedSBOMs[0].Signed {
		t.Fatalf("attached %+v", out.AttachedSBOMs)
	}
	found := false
	for _, c := range out.Inventory.Components {
		if c.Name == "golang.org/x/net" && c.Version == "v0.17.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("x/net from the BuildKit attestation missing: %+v", out.Inventory.Components)
	}
	// Skipping attached SBOMs leaves the filesystem scan alone.
	out, err = ScanImage(context.Background(), host+"/acme/app:multi", ScanOptions{SkipAttachedSBOMs: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.AttachedSBOMs) != 0 || len(out.Inventory.Targets) != 1 {
		t.Errorf("skip: attached %+v targets %+v", out.AttachedSBOMs, out.Inventory.Targets)
	}
}
