package cvss

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// Expected scores are the ones NVD publishes for these vectors.
func TestBaseScores(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		// Log4Shell as OSV serves it: a temporal metric rides along.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", 8.1},
		{"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", 8.6},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0},
		{"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0},
		{"AV:N/AC:M/Au:N/C:N/I:P/A:N", 4.3},
		{"AV:L/AC:L/Au:N/C:P/I:N/A:N", 2.1},
		{"(AV:N/AC:L/Au:N/C:N/I:N/A:P)", 5.0},
		{"CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0},
	}
	for _, tc := range cases {
		_, score, err := Score(tc.vector)
		if err != nil {
			t.Fatalf("%s: %v", tc.vector, err)
		}
		if score == nil || *score != tc.want {
			t.Errorf("%s: score %v, want %v", tc.vector, score, tc.want)
		}
	}
}

// Every golden vector was scored by FIRST's own v4.0 calculator
// (cvss_score.js run unmodified); the port must agree on all of them,
// threat, environmental and supplemental metrics included.
func TestV4MatchesFIRSTReference(t *testing.T) {
	raw, err := os.ReadFile("testdata/v4-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden [][2]any
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if len(golden) < 1000 {
		t.Fatalf("golden set too small: %d", len(golden))
	}
	for _, entry := range golden {
		vector, want := entry[0].(string), entry[1].(float64)
		_, score, err := Score(vector)
		if err != nil {
			t.Fatalf("%s: %v", vector, err)
		}
		if score == nil || *score != want {
			t.Errorf("%s: got %v, want %v", vector, score, want)
		}
	}
}

func TestV4KnownScores(t *testing.T) {
	for vector, want := range map[string]float64{
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N":      9.3,
		"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/CR:H": 0,
	} {
		vector, score, err := Score(vector)
		if err != nil || score == nil || *score != want {
			t.Errorf("%s: %v %v, want %v", vector.String(), score, err, want)
		}
	}
	if _, _, err := Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:Z"); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid optional v4 value accepted")
	}
}

func TestRejectsMalformedVectors(t *testing.T) {
	for _, raw := range []string{
		"",
		"7.5",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",          // missing A
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",      // bad value
		"CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // repeated
		"CVSS:5.0/AV:N",
		"CVSS:3.1/AV:N/AC",
	} {
		if _, _, err := Score(raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: want ErrInvalid, got %v", raw, err)
		}
	}
}

func TestStringRoundTrips(t *testing.T) {
	for _, raw := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
		"AV:N/AC:L/Au:N/C:P/I:P/A:P",
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		vector, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if vector.String() != raw {
			t.Errorf("%s rendered as %s", raw, vector.String())
		}
	}
}

func TestBandAndPreference(t *testing.T) {
	if Band(9.0) != "critical" || Band(6.9) != "medium" || Band(0.1) != "low" || Band(0) != "none" {
		t.Fatal("bands")
	}
	if Preference(V31) <= Preference(V40) || Preference(V40) <= Preference(V2) {
		t.Fatal("v3 > v4 > v2")
	}
}
