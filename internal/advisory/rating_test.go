package advisory

import "testing"

func label(s Severity) *Severity { return &s }

func score(v float64) *float64 { return &v }

// The ratings Trivy reports for CVE-2024-13176 (OpenSSL timing side-channel)
// on RHEL 9: Red Hat labels it Low while its own CVSS is 4.7 (medium), and
// several other vendors say medium. The NVD rating is illustrative, added
// to exercise the headline rule.
func cve202413176(t *testing.T) []Rating {
	t.Helper()
	return []Rating{
		mustRating(t, "redhat", "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N", label(SeverityLow)),
		mustRating(t, "julia", "CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L", label(SeverityMedium)),
		mustRating(t, "ubuntu", "", label(SeverityLow)),
		mustRating(t, "alma", "", label(SeverityMedium)),
		mustRating(t, "nvd", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", nil),
	}
}

func TestRatingSeverityPrefersLabel(t *testing.T) {
	ratings := cve202413176(t)
	if got, _ := ratings[0].Severity(); got != SeverityLow {
		t.Fatalf("Red Hat 4.7 labelled Low: got %s", got)
	}
	if *ratings[0].Score != 4.7 {
		t.Fatalf("score computed from vector: %v", *ratings[0].Score)
	}
}

func TestHeadlinePrefersNVD(t *testing.T) {
	choice := Headline(cve202413176(t))
	if choice.RatedBy() != "nvd" || choice.Severity != SeverityMedium || *choice.Rating.Score != 5.9 {
		t.Fatalf("headline: %+v", choice)
	}
}

func TestHeadlineWithoutNVDTakesStrongest(t *testing.T) {
	ratings := []Rating{
		mustRating(t, "ghsa", "", label(SeverityHigh)),
		mustRating(t, "cisa-adp", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil),
	}
	if choice := Headline(ratings); choice.RatedBy() != "cisa-adp" || choice.Severity != SeverityCritical {
		t.Fatalf("strongest: %+v", choice)
	}
}

func TestHeadlineUnrated(t *testing.T) {
	if choice := Headline(nil); choice.Severity != SeverityUnknown || choice.Rating != nil {
		t.Fatalf("unrated: %+v", choice)
	}
}

func TestForFindingPrefersDistro(t *testing.T) {
	ratings := cve202413176(t)
	cases := []struct {
		name, ecosystem, purl, rater string
		severity                     Severity
	}{
		{"rhel", "rpm", "pkg:rpm/redhat/openssl@3.0.7-6.el9_2?distro=redhat-9.2", "redhat", SeverityLow},
		{"alma has its own", "rpm", "pkg:rpm/alma/openssl@3.0.7?distro=alma-9.2", "alma", SeverityMedium},
		{"rocky falls back to redhat", "rpm", "pkg:rpm/rocky/openssl@3.0.7?distro=rocky-9.2", "redhat", SeverityLow},
		{"ubuntu label only", "deb", "pkg:deb/ubuntu/openssl@3.0.2?distro=ubuntu-22.04", "ubuntu", SeverityLow},
		{"alpine has none", "apk", "pkg:apk/alpine/openssl@3.1.4?distro=alpine-3.18.4", "nvd", SeverityMedium},
		{"language package", "npm", "pkg:npm/openssl@1.0.0", "nvd", SeverityMedium},
	}
	for _, tc := range cases {
		choice := ForFinding(ratings, tc.ecosystem, tc.purl)
		if choice.RatedBy() != tc.rater || choice.Severity != tc.severity {
			t.Errorf("%s: got %s/%s, want %s/%s", tc.name, choice.RatedBy(), choice.Severity, tc.rater, tc.severity)
		}
	}
}

func TestPreferredVersionPerRater(t *testing.T) {
	v4, _ := NewRating("ghsa", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", score(9.3), nil)
	v31 := mustRating(t, "ghsa", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", nil)
	choice := Headline([]Rating{v4, v31})
	if *choice.Rating.Version != CVSSVersionV31 {
		t.Fatalf("v3.1 preferred over v4.0: %+v", choice.Rating)
	}
	if !Disagree([]Rating{v4, v31, mustRating(t, "nvd", "", label(SeverityLow))}) {
		t.Fatal("high vs low disagree")
	}
	if Disagree([]Rating{v31, mustRating(t, "nvd", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", nil)}) {
		t.Fatal("same band agrees")
	}
}

func TestParseLabelVendorWords(t *testing.T) {
	for raw, want := range map[string]Severity{"Important": SeverityHigh, "moderate": SeverityMedium, "unimportant": SeverityLow, "negligible": SeverityLow} {
		if got := ParseLabel(raw); got == nil || *got != want {
			t.Errorf("%s: %v", raw, got)
		}
	}
	if ParseLabel("UNKNOWN") != nil || ParseLabel("") != nil {
		t.Fatal("unknown words are not evidence")
	}
}

func TestNewRatingRejectsBadVectorsButKeepsScores(t *testing.T) {
	rating, ok := NewRating("trivy-vendor", "not-a-vector", score(6.5), nil)
	if !ok || rating.Vector != "" || *rating.Score != 6.5 {
		t.Fatalf("supplied score kept, vector dropped: %+v", rating)
	}
	if _, ok := NewRating("x", "", nil, nil); ok {
		t.Fatal("no signal")
	}
}

func TestHeadlineTieGoesToTheCVERecord(t *testing.T) {
	vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
	cna := mustRating(t, "cisa-adp", vector, nil)
	cna.Provider = CVEProvider
	ratings := []Rating{mustRating(t, "bitnami", vector, nil), cna, mustRating(t, "ghsa", vector, nil)}
	if choice := Headline(ratings); choice.RatedBy() != "cisa-adp" {
		t.Fatalf("tie: %+v", choice)
	}
	if choice := Headline(ratings[:1:1]); choice.RatedBy() != "bitnami" {
		t.Fatalf("alone: %+v", choice)
	}
	if choice := Headline([]Rating{ratings[0], ratings[2]}); choice.RatedBy() != "ghsa" {
		t.Fatalf("ghsa over a redistributor: %+v", choice)
	}
}
