package scancatalog

import (
	"errors"
	"strings"
	"testing"
)

func TestEmbeddedCatalogIsValid(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	opengrep, ok := catalog.Scanner("opengrep")
	if !ok || opengrep.Prerelease || opengrep.EngineVersion != "1.30.1" {
		t.Fatalf("opengrep = %+v", opengrep)
	}
	// The released build has no cross-file taint (Phase 5 POC): the catalog
	// must not advertise it.
	for _, capability := range opengrep.Capabilities {
		if capability.Capability == "cross-file-taint" {
			t.Fatal("opengrep 1.30.1 must not advertise cross-file-taint")
		}
	}
	interfile, ok := catalog.Scanner("opengrep-interfile")
	if !ok || !interfile.Prerelease || interfile.SupportStatus != StatusPreview {
		t.Fatalf("interfile entry = %+v", interfile)
	}
	// Both write the same SARIF driver name: a version string cannot tell
	// them apart, the digest does.
	if got := catalog.ScannerForProducer("opengrep oss"); len(got) != 2 {
		t.Fatalf("producers sharing a driver name = %d", len(got))
	}
	ruleset, ok := catalog.Ruleset("opengrep-rules")
	if !ok || ruleset.Selectable() {
		t.Fatalf("ruleset under license review must not be selectable: %+v", ruleset)
	}
	binary, ok := opengrep.BinaryFor("linux", "amd64", "")
	if !ok || binary.Libc != "glibc" {
		t.Fatalf("linux/amd64 binary = %+v", binary)
	}
	if musl, ok := opengrep.BinaryFor("linux", "amd64", "musl"); !ok || musl.Libc != "musl" {
		t.Fatalf("musl binary = %+v", musl)
	}
}

func TestCatalogValidationRejects(t *testing.T) {
	base := `{"schema_version":1,"revision":"r","rulesets":[],"scanners":[{"id":"x","name":"X","engine":"x","engine_version":"1","adapter_version":"1","license":"MIT","support_status":"supported","producer_names":["x"],
	  "distributions":[{"kind":"binary","os":"linux","arch":"amd64","asset":"x","url":"%URL%","sha256":"%SHA%"}],
	  "rulesets":[],"capabilities":[{"language":"go","capability":"source-patterns","evidence":"%EVIDENCE%"}],
	  "applicability":{},"stages":{"requires":[],"produces":[]},"diff_support":"none","resources":{"cpu":1,"memory_mb":1,"timeout_seconds":1},"exit_codes":{},"command":{"args":[%ARGS%]},"sarif":{"fingerprint":"","paths":"","code_flows":""}}]}`
	good := map[string]string{"%URL%": "https://example.test/x", "%SHA%": strings.Repeat("a", 64), "%EVIDENCE%": "declared", "%ARGS%": `"scan"`}
	render := func(overrides map[string]string) []byte {
		doc := base
		for key, value := range good {
			if override, ok := overrides[key]; ok {
				value = override
			}
			doc = strings.ReplaceAll(doc, key, value)
		}
		return []byte(doc)
	}
	if _, err := Parse(render(nil)); err != nil {
		t.Fatalf("good catalog rejected: %v", err)
	}
	for name, overrides := range map[string]map[string]string{
		"plain http":       {"%URL%": "http://example.test/x"},
		"missing sha256":   {"%SHA%": ""},
		"no evidence":      {"%EVIDENCE%": "trust me"},
		"shell in command": {"%ARGS%": `"scan; rm -rf /"`},
	} {
		if _, err := Parse(render(overrides)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveLocations(t *testing.T) {
	catalog, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	opengrep, _ := catalog.Scanner("opengrep")
	binary, _ := opengrep.BinaryFor("linux", "amd64", "")
	spotbugs, _ := catalog.Scanner("spotbugs-findsecbugs")
	maven := &spotbugs.Distributions[0]

	upstream, err := DistributionConfig{}.Resolve(opengrep, binary)
	if err != nil || upstream.Source != "upstream" || upstream.URL != binary.URL || upstream.SHA256 != binary.SHA256 {
		t.Fatalf("upstream = %+v, %v", upstream, err)
	}
	mirrored, _ := DistributionConfig{MirrorBaseURL: "https://mirror.example.test/scanners/"}.Resolve(opengrep, binary)
	if mirrored.URL != "https://mirror.example.test/scanners/opengrep/1.30.1/opengrep_manylinux_x86" || mirrored.SHA256 != binary.SHA256 {
		t.Fatalf("mirror = %+v", mirrored)
	}
	approved, _ := DistributionConfig{Locations: map[string]string{"opengrep": "https://bin.example.test/og"}, MirrorBaseURL: "https://mirror.example.test"}.Resolve(opengrep, binary)
	if approved.Source != "approved-location" || approved.URL != "https://bin.example.test/og/1.30.1/opengrep_manylinux_x86" {
		t.Fatalf("approved location must win over the mirror: %+v", approved)
	}
	if _, err := (DistributionConfig{Mode: ModeMirror, MavenMirrorURL: "https://maven.example.test"}).Resolve(opengrep, binary); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mirror mode must not fall back upstream: %v", err)
	}
	mavenMirrored, _ := DistributionConfig{Mode: ModeMirror, MavenMirrorURL: "https://maven.example.test/repo"}.Resolve(spotbugs, maven)
	if mavenMirrored.URL != "https://maven.example.test/repo/com/github/spotbugs/spotbugs-maven-plugin/4.9.3.0/spotbugs-maven-plugin-4.9.3.0.jar" {
		t.Fatalf("maven mirror = %+v", mavenMirrored)
	}
	offline, _ := DistributionConfig{Mode: ModeOffline, BundleDir: "/srv/hibou-bundle"}.Resolve(spotbugs, maven)
	if offline.Source != "bundle" || offline.URL != "file:///srv/hibou-bundle/spotbugs-findsecbugs/4.9.3/com/github/spotbugs/spotbugs-maven-plugin/4.9.3.0/spotbugs-maven-plugin-4.9.3.0.jar" {
		t.Fatalf("offline = %+v", offline)
	}
}

func TestDistributionConfigValidate(t *testing.T) {
	catalog, _ := Load()
	for name, cfg := range map[string]DistributionConfig{
		"unknown mode":        {Mode: "sideload"},
		"offline sans bundle": {Mode: ModeOffline},
		"relative bundle":     {Mode: ModeOffline, BundleDir: "bundle"},
		"http mirror":         {MirrorBaseURL: "http://mirror.example.test"},
		"credentials in url":  {MirrorBaseURL: "https://user:pass@mirror.example.test"},
		"unapproved host":     {MirrorBaseURL: "https://evil.example.test", ApprovedHosts: []string{"mirror.example.test"}},
		"unknown scanner":     {Locations: map[string]string{"nope": "https://x.example.test"}},
		"mirror sans mirror":  {Mode: ModeMirror},
	} {
		if err := cfg.Validate(catalog); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (DistributionConfig{Mode: ModeMirror, MirrorBaseURL: "https://mirror.example.test", ApprovedHosts: []string{"mirror.example.test"}}).Validate(catalog); err != nil {
		t.Fatalf("valid mirror config rejected: %v", err)
	}
}
