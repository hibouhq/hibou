package distro

import "testing"

func TestFromPurl(t *testing.T) {
	cases := []struct {
		purl, family, release string
	}{
		{"pkg:apk/alpine/busybox@1.36.1-r5?arch=x86_64&distro=alpine-3.18.4", "alpine", "3.18.4"},
		{"pkg:apk/alpine/busybox@1.36.1-r5?distro=3.18.4", "", "3.18.4"},
		{"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12", "debian", "12"},
		{"pkg:rpm/redhat/openssl-libs@3.0.7?distro=redhat-9.4", "redhat", "9.4"},
		{"pkg:rpm/rocky/bash@5.1.8?distro=rocky-9.3", "rocky", "9.3"},
		{"pkg:npm/lodash@4.17.11", "", ""},
	}
	for _, c := range cases {
		family, release := FromPurl(c.purl)
		if family != c.family || release != c.release {
			t.Errorf("FromPurl(%q) = (%q, %q), want (%q, %q)", c.purl, family, release, c.family, c.release)
		}
	}
}

func TestReleaseKey(t *testing.T) {
	cases := []struct{ eco, version, want string }{
		{"apk", "3.18.4", "3.18"},
		{"apk", "v3.18", "3.18"},
		{"deb", "12", "12"},
		{"deb", "11.7", "11"},
		{"rpm", "9.4", "9"},
		{"apk", "", ""},
	}
	for _, c := range cases {
		if got := ReleaseKey(c.eco, c.version); got != c.want {
			t.Errorf("ReleaseKey(%q, %q) = %q, want %q", c.eco, c.version, got, c.want)
		}
	}
}

func TestParseOSVEcosystem(t *testing.T) {
	cases := []struct {
		in, eco, release string
		ok               bool
	}{
		{"Alpine:v3.18", "apk", "3.18", true},
		{"Debian:12", "deb", "12", true},
		// Bare distro ecosystems and Red Hat stream qualifiers cannot be
		// release-matched safely — both must be rejected, not guessed at.
		{"Alpine", "", "", false},
		{"Debian", "", "", false},
		{"Red Hat:rhel_aus:8.2::appstream", "", "", false},
		{"Rocky Linux:8", "", "", false},
		{"npm", "", "", false},
	}
	for _, c := range cases {
		eco, release, ok := ParseOSVEcosystem(c.in)
		if eco != c.eco || release != c.release || ok != c.ok {
			t.Errorf("ParseOSVEcosystem(%q) = (%q, %q, %v), want (%q, %q, %v)", c.in, eco, release, ok, c.eco, c.release, c.ok)
		}
	}
}

func TestOSVEcosystemFor(t *testing.T) {
	if eco, ok := OSVEcosystemFor("apk", "alpine-3.18.4"); !ok || eco != "Alpine:v3.18" {
		t.Fatalf("apk = %q %v", eco, ok)
	}
	if eco, ok := OSVEcosystemFor("deb", "debian-12"); !ok || eco != "Debian:12" {
		t.Fatalf("deb = %q %v", eco, ok)
	}
	if _, ok := OSVEcosystemFor("apk", ""); ok {
		t.Fatal("unknown release must not build an OSV ecosystem")
	}
	if _, ok := OSVEcosystemFor("rpm", "redhat-9.4"); ok {
		t.Fatal("rpm must not query OSV")
	}
}
