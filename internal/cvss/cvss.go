// Package cvss parses CVSS vectors and computes base scores (ADR-038 §1).
//
// Providers hand hibou vectors far more often than numbers: the OSV schema
// defines severity[].score as a vector string, and the CVE feed and Trivy
// carry vectors per rater. Every provider scores them here, so one vector
// always gets one score.
//
// v2, v3.0 and v3.1 base scores follow the published equations. v4.0 is
// scored with FIRST's MacroVector algorithm (v4.go), threat, environmental
// and supplemental metrics included, matching the reference calculator.
package cvss

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// Version is a CVSS specification version, spelled as the cvss_version
// database enum spells it.
type Version string

const (
	V2  Version = "v2"
	V30 Version = "v3.0"
	V31 Version = "v3.1"
	V40 Version = "v4.0"
)

// Vector is a parsed, validated CVSS vector.
type Vector struct {
	Version Version
	// Metrics holds every metric of the vector, base and optional, by its
	// abbreviation (AV, AC, ...).
	Metrics map[string]string
	// Order keeps the metrics in vector order, for String.
	Order []string
}

// ErrInvalid wraps every parse failure.
var ErrInvalid = errors.New("invalid cvss vector")

var baseMetrics = map[Version]map[string][]string{
	V2: {
		"AV": {"L", "A", "N"},
		"AC": {"H", "M", "L"},
		"Au": {"M", "S", "N"},
		"C":  {"N", "P", "C"},
		"I":  {"N", "P", "C"},
		"A":  {"N", "P", "C"},
	},
	V30: v3Base,
	V31: v3Base,
	V40: {
		"AV": {"N", "A", "L", "P"},
		"AC": {"L", "H"},
		"AT": {"N", "P"},
		"PR": {"N", "L", "H"},
		"UI": {"N", "P", "A"},
		"VC": {"H", "L", "N"},
		"VI": {"H", "L", "N"},
		"VA": {"H", "L", "N"},
		"SC": {"H", "L", "N"},
		"SI": {"H", "L", "N"},
		"SA": {"H", "L", "N"},
	},
}

// v4AllMetrics is every v4.0 metric and its values (the specification's
// table; base metrics are also in baseMetrics).
var v4AllMetrics = map[string][]string{
	"AV": {"N", "A", "L", "P"}, "AC": {"L", "H"}, "AT": {"N", "P"}, "PR": {"N", "L", "H"}, "UI": {"N", "P", "A"},
	"VC": {"H", "L", "N"}, "VI": {"H", "L", "N"}, "VA": {"H", "L", "N"},
	"SC": {"H", "L", "N"}, "SI": {"H", "L", "N"}, "SA": {"H", "L", "N"},
	"E":  {"X", "A", "P", "U"},
	"CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
	"MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MAT": {"X", "N", "P"},
	"MPR": {"X", "N", "L", "H"}, "MUI": {"X", "N", "P", "A"},
	"MVC": {"X", "H", "L", "N"}, "MVI": {"X", "H", "L", "N"}, "MVA": {"X", "H", "L", "N"},
	"MSC": {"X", "H", "L", "N"}, "MSI": {"X", "S", "H", "L", "N"}, "MSA": {"X", "S", "H", "L", "N"},
	"S": {"X", "N", "P"}, "AU": {"X", "N", "Y"}, "R": {"X", "A", "U", "I"}, "V": {"X", "D", "C"},
	"RE": {"X", "L", "M", "H"}, "U": {"X", "Clear", "Green", "Amber", "Red"},
}

var v3Base = map[string][]string{
	"AV": {"N", "A", "L", "P"},
	"AC": {"L", "H"},
	"PR": {"N", "L", "H"},
	"UI": {"N", "R"},
	"S":  {"U", "C"},
	"C":  {"H", "L", "N"},
	"I":  {"H", "L", "N"},
	"A":  {"H", "L", "N"},
}

// Parse validates a vector. The v3 and v4 forms carry their version prefix
// ("CVSS:3.1/..."); a v2 vector has none, and may come wrapped in
// parentheses or with NVD's "CVSS:2.0/" prefix. Base metrics are required
// and checked; temporal, threat, environmental and supplemental metrics are
// kept as given and do not affect the base score.
func Parse(raw string) (Vector, error) {
	text := strings.TrimSpace(raw)
	text = strings.TrimSuffix(strings.TrimPrefix(text, "("), ")")
	if text == "" {
		return Vector{}, fmt.Errorf("%w: empty", ErrInvalid)
	}

	version := V2
	parts := strings.Split(text, "/")
	if prefix, ok := strings.CutPrefix(parts[0], "CVSS:"); ok {
		switch prefix {
		case "2.0":
			version = V2
		case "3.0":
			version = V30
		case "3.1":
			version = V31
		case "4.0":
			version = V40
		default:
			return Vector{}, fmt.Errorf("%w: unsupported version %q", ErrInvalid, prefix)
		}
		parts = parts[1:]
	}

	vector := Vector{Version: version, Metrics: make(map[string]string, len(parts))}
	for _, part := range parts {
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "" || value == "" {
			return Vector{}, fmt.Errorf("%w: malformed metric %q", ErrInvalid, part)
		}
		if _, dup := vector.Metrics[key]; dup {
			return Vector{}, fmt.Errorf("%w: metric %s repeated", ErrInvalid, key)
		}
		vector.Metrics[key] = value
		vector.Order = append(vector.Order, key)
	}
	if version == V40 {
		for key, value := range vector.Metrics {
			allowed, known := v4AllMetrics[key]
			if !known {
				return Vector{}, fmt.Errorf("%w: unknown v4.0 metric %s", ErrInvalid, key)
			}
			if !contains(allowed, value) {
				return Vector{}, fmt.Errorf("%w: %s:%s", ErrInvalid, key, value)
			}
		}
	}
	for key, allowed := range baseMetrics[version] {
		value, ok := vector.Metrics[key]
		if !ok {
			return Vector{}, fmt.Errorf("%w: missing base metric %s", ErrInvalid, key)
		}
		if !contains(allowed, value) {
			return Vector{}, fmt.Errorf("%w: %s:%s", ErrInvalid, key, value)
		}
	}
	return vector, nil
}

// String renders the vector in its canonical form, version prefix included
// for v3 and v4.
func (v Vector) String() string {
	parts := make([]string, 0, len(v.Order)+1)
	switch v.Version {
	case V30:
		parts = append(parts, "CVSS:3.0")
	case V31:
		parts = append(parts, "CVSS:3.1")
	case V40:
		parts = append(parts, "CVSS:4.0")
	}
	for _, key := range v.Order {
		parts = append(parts, key+":"+v.Metrics[key])
	}
	return strings.Join(parts, "/")
}

// BaseScore computes the vector's score: the base score for v2 and v3, and
// for v4.0 the CVSS-B/BT/BE/BTE score its metrics define (v4.0 folds threat
// and environmental metrics into the one number).
func (v Vector) BaseScore() (score float64, ok bool) {
	switch v.Version {
	case V2:
		return v2Score(v.Metrics), true
	case V30:
		return v3Score(v.Metrics, roundUp30), true
	case V31:
		return v3Score(v.Metrics, roundUp31), true
	case V40:
		return v4Score(v.Metrics), true
	default:
		return 0, false
	}
}

// Score parses a vector and computes its score in one step.
func Score(raw string) (Vector, *float64, error) {
	vector, err := Parse(raw)
	if err != nil {
		return Vector{}, nil, err
	}
	score, ok := vector.BaseScore()
	if !ok {
		return vector, nil, nil
	}
	return vector, &score, nil
}

func v3Score(m map[string]string, roundUp func(float64) float64) float64 {
	changed := m["S"] == "C"
	iss := 1 - (1-v3CIA[m["C"]])*(1-v3CIA[m["I"]])*(1-v3CIA[m["A"]])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	pr := v3PRUnchanged[m["PR"]]
	if changed {
		pr = v3PRChanged[m["PR"]]
	}
	exploitability := 8.22 * v3AV[m["AV"]] * v3AC[m["AC"]] * pr * v3UI[m["UI"]]
	if impact <= 0 {
		return 0
	}
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10))
	}
	return roundUp(math.Min(impact+exploitability, 10))
}

var (
	v3AV          = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	v3AC          = map[string]float64{"L": 0.77, "H": 0.44}
	v3PRUnchanged = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	v3PRChanged   = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	v3UI          = map[string]float64{"N": 0.85, "R": 0.62}
	v3CIA         = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
)

// roundUp31 is CVSS v3.1's Roundup (specification Appendix A): it rounds up
// to one decimal while avoiding floating-point artefacts such as 4.000001.
func roundUp31(value float64) float64 {
	scaled := int64(math.Round(value * 100000))
	if scaled%10000 == 0 {
		return float64(scaled) / 100000
	}
	return float64(scaled/10000+1) / 10
}

// roundUp30 is CVSS v3.0's plain round-up to one decimal.
func roundUp30(value float64) float64 {
	return math.Ceil(value*10) / 10
}

func v2Score(m map[string]string) float64 {
	impact := 10.41 * (1 - (1-v2CIA[m["C"]])*(1-v2CIA[m["I"]])*(1-v2CIA[m["A"]]))
	exploitability := 20 * v2AV[m["AV"]] * v2AC[m["AC"]] * v2Au[m["Au"]]
	if impact == 0 {
		return 0
	}
	score := (0.6*impact + 0.4*exploitability - 1.5) * 1.176
	return math.Round(score*10) / 10
}

var (
	v2AV  = map[string]float64{"L": 0.395, "A": 0.646, "N": 1.0}
	v2AC  = map[string]float64{"H": 0.35, "M": 0.61, "L": 0.71}
	v2Au  = map[string]float64{"M": 0.45, "S": 0.56, "N": 0.704}
	v2CIA = map[string]float64{"N": 0, "P": 0.275, "C": 0.660}
)

// Band is the qualitative severity of a score (v3/v4 table; v2 scores use the
// same bands in hibou, as NVD displays them).
func Band(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// Preference orders versions when one rater publishes several: v3.1, v3.0,
// v4.0, then v2 (ADR-038 §2). Higher is preferred.
func Preference(version Version) int {
	switch version {
	case V31:
		return 4
	case V30:
		return 3
	case V40:
		return 2
	case V2:
		return 1
	default:
		return 0
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
