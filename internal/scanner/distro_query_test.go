package scanner

import (
	"testing"

	"github.com/hibouhq/hibou/internal/distro"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

// Real purl shapes from `trivy image --format cyclonedx` (see the sample-repo
// fixture images). Alpine omits the family in the distro qualifier, Debian and
// RHEL include it — every case must normalize to "family-version".
func TestBuildPackageQueriesNormalizesDistro(t *testing.T) {
	components := []dbgen.Component{
		{Purl: "pkg:apk/alpine/busybox@1.29.3-r10?arch=x86_64&distro=3.9.6", Name: "busybox", Version: "1.29.3-r10", Ecosystem: "apk"},
		{Purl: "pkg:deb/debian/openssl@1.1.1n-0+deb10u6?arch=amd64&distro=debian-10.13", Name: "openssl", Version: "1.1.1n-0+deb10u6", Ecosystem: "deb"},
		{Purl: "pkg:rpm/redhat/openssl-libs@1:3.0.7-27.el9?arch=x86_64&distro=redhat-8.5", Name: "openssl-libs", Version: "1:3.0.7-27.el9", Ecosystem: "rpm"},
		{Purl: "pkg:npm/lodash@4.17.11", Name: "lodash", Version: "4.17.11", Ecosystem: "npm"},
	}
	byName := map[string]string{}
	for _, q := range buildPackageQueries(components) {
		byName[q.Name] = q.Distro
	}

	want := map[string]string{
		"busybox":      "alpine-3.9.6",
		"openssl":      "debian-10.13",
		"openssl-libs": "redhat-8.5",
		"lodash":       "",
	}
	for name, distroQualifier := range want {
		if byName[name] != distroQualifier {
			t.Errorf("%s distro = %q, want %q", name, byName[name], distroQualifier)
		}
	}

	// The alpine qualifier must resolve to a release-qualified OSV ecosystem;
	// this is the path that was silently skipped before the namespace fix.
	if eco, ok := distro.OSVEcosystemFor("apk", byName["busybox"]); !ok || eco != "Alpine:v3.9" {
		t.Fatalf("alpine OSV ecosystem = %q %v, want Alpine:v3.9", eco, ok)
	}
}
