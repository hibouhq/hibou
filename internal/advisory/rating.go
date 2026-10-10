package advisory

import (
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/cvss"
	"github.com/hibouhq/hibou/internal/distro"
)

// RatingsVersion names the provider mappings that build ratings. Bump it when
// a mapping changes: the startup backfill rebuilds every source below it from
// its stored raw_data (ADR-038 §8).
//
// 2: v4.0 vectors are scored (FIRST's algorithm, internal/cvss).
const RatingsVersion = 2

// Rating is one rater's statement about an advisory: a CVSS vector and score
// for one CVSS version, its own severity word, or both (ADR-038 §2). A source
// publishes several, and all of them are kept.
type Rating struct {
	// Rater is who made the statement: nvd, ghsa, redhat, debian, a CNA's
	// short name... normalized by NormalizeRater.
	Rater   string
	Version *CVSSVersion
	Vector  string
	Score   *float64
	// Label is the rater's own severity word. It wins over the band of its
	// score: a vendor rates impact separately from CVSS.
	Label *Severity
	// Provider is the advisory source the rating came from; set on read.
	Provider string
}

// NewRating builds a rating from what a provider received. The score is
// computed from the vector whenever there is one (internal/cvss, every
// version), so one vector always means one score; supplied is used only when
// there is no usable vector. An unparseable vector is dropped.
func NewRating(rater, vector string, supplied *float64, label *Severity) (Rating, bool) {
	rating := Rating{Rater: NormalizeRater(rater), Label: label}
	if vector = strings.TrimSpace(vector); vector != "" {
		if parsed, score, err := cvss.Score(vector); err == nil {
			version := CVSSVersion(parsed.Version)
			rating.Version = &version
			rating.Vector = parsed.String()
			rating.Score = score
		}
	}
	if rating.Score == nil && supplied != nil && *supplied > 0 && *supplied <= 10 {
		value := *supplied
		rating.Score = &value
	}
	if rating.Rater == "" || (rating.Score == nil && rating.Label == nil && rating.Vector == "") {
		return Rating{}, false
	}
	return rating, true
}

// Severity is the rating's verdict: its label, else the band of its score.
func (r Rating) Severity() (Severity, bool) {
	if r.Label != nil {
		return *r.Label, true
	}
	if r.Score != nil {
		return NormalizeSeverity(*r.Score), true
	}
	return "", false
}

// NormalizeRater folds the spellings providers use for one rater.
func NormalizeRater(name string) string {
	rater := strings.ToLower(strings.TrimSpace(name))
	switch rater {
	case "oracle-oval":
		return "oracle"
	case "redhat-oval":
		return "redhat"
	case "suse-cvrf":
		return "suse"
	case "github_m", "github", "github-reviewed":
		return "ghsa"
	}
	return rater
}

// distroRaters lists, per purl namespace of an OS package, the raters whose
// rating applies to it, in order. A distro rates the flaw as it affects the
// build it ships (ADR-038 §2); RHEL rebuilds fall back to Red Hat when they
// publish no rating of their own. Alpine publishes no severities.
var distroRaters = map[string][]string{
	"redhat":        {"redhat"},
	"rhel":          {"redhat"},
	"centos":        {"redhat"},
	"rocky":         {"rocky", "redhat"},
	"alma":          {"alma", "redhat"},
	"almalinux":     {"alma", "redhat"},
	"oracle":        {"oracle"},
	"ol":            {"oracle"},
	"fedora":        {"fedora"},
	"debian":        {"debian"},
	"ubuntu":        {"ubuntu"},
	"amazon":        {"amazon"},
	"amzn":          {"amazon"},
	"azurelinux":    {"azure", "cbl-mariner"},
	"cbl-mariner":   {"cbl-mariner", "azure"},
	"mariner":       {"cbl-mariner", "azure"},
	"photon":        {"photon"},
	"suse":          {"suse"},
	"sles":          {"suse"},
	"opensuse":      {"suse"},
	"opensuse-leap": {"suse"},
}

// Choice is the rating a finding or an advisory uses, and the severity it
// yields. Rating is nil when nothing rates it (SeverityUnknown).
type Choice struct {
	Severity Severity
	Rating   *Rating
}

// RatedBy is the rater of the chosen rating, empty when none.
func (c Choice) RatedBy() string {
	if c.Rating == nil {
		return ""
	}
	return c.Rating.Rater
}

// Headline picks the advisory-level rating: NVD first when it rates, else the
// strongest rater (ADR-038 §2, rule 2).
func Headline(ratings []Rating) Choice {
	summaries := summarize(ratings)
	if nvd, ok := summaries["nvd"]; ok {
		return choiceOf(nvd)
	}
	var best *Rating
	for _, rater := range sortedRaters(summaries) {
		candidate := summaries[rater]
		if best == nil || stronger(candidate, *best) {
			copied := candidate
			best = &copied
		}
	}
	if best == nil {
		return Choice{Severity: SeverityUnknown}
	}
	return choiceOf(*best)
}

// ForFinding picks the rating a dependency finding uses: for an OS package,
// its distro's own rating when the distro published one; otherwise the
// headline (ADR-038 §2, rules 1 and 2).
func ForFinding(ratings []Rating, ecosystem, purl string) Choice {
	if distro.IsDistroEcosystem(ecosystem) {
		family, _ := distro.FromPurl(purl)
		summaries := summarize(ratings)
		for _, rater := range distroRaters[family] {
			if rating, ok := summaries[rater]; ok {
				return choiceOf(rating)
			}
		}
	}
	return Headline(ratings)
}

// Disagree reports whether raters fall in different severity bands, the
// condition the list marks (ADR-038 §7).
func Disagree(ratings []Rating) bool {
	var first Severity
	for _, rating := range summarize(ratings) {
		severity, _ := rating.Severity()
		if first == "" {
			first = severity
			continue
		}
		if severity != first {
			return true
		}
	}
	return false
}

// summarize reduces ratings to one per rater: its preferred scored version
// (v3.1, v3.0, v4.0, v2) carrying the rater's label, or its label alone.
// Raters with no signal are left out.
func summarize(ratings []Rating) map[string]Rating {
	out := make(map[string]Rating)
	labels := make(map[string]*Severity)
	for _, rating := range ratings {
		if rating.Label != nil {
			labels[rating.Rater] = rating.Label
		}
		if _, ok := rating.Severity(); !ok {
			continue
		}
		current, seen := out[rating.Rater]
		if !seen || preferVersion(rating, current) {
			out[rating.Rater] = rating
		}
	}
	for rater, label := range labels {
		rating, ok := out[rater]
		if !ok {
			rating = Rating{Rater: rater}
		}
		rating.Label = label
		out[rater] = rating
	}
	return out
}

// preferVersion: a scored rating beats an unscored one, then the version
// order of cvss.Preference.
func preferVersion(candidate, current Rating) bool {
	if (candidate.Score != nil) != (current.Score != nil) {
		return candidate.Score != nil
	}
	return versionPreference(candidate.Version) > versionPreference(current.Version)
}

func versionPreference(version *CVSSVersion) int {
	if version == nil {
		return 0
	}
	return cvss.Preference(cvss.Version(*version))
}

// stronger orders raters by severity, then score, then having a vector, then
// standing: among equals, the CVE record's authority (a CNA or CISA-ADP) and
// then GitHub's review beat a downstream redistributor that copied the score.
func stronger(candidate, current Rating) bool {
	candidateSeverity, _ := candidate.Severity()
	currentSeverity, _ := current.Severity()
	if cmp := compareSeverityRank(candidateSeverity, currentSeverity); cmp != 0 {
		return cmp > 0
	}
	if cmp := compareOptionalScore(candidate.Score, current.Score); cmp != 0 {
		return cmp > 0
	}
	if (candidate.Vector != "") != (current.Vector != "") {
		return candidate.Vector != ""
	}
	return standing(candidate) > standing(current)
}

func standing(rating Rating) int {
	switch {
	case rating.Provider == CVEProvider:
		return 2
	case rating.Rater == "ghsa":
		return 1
	}
	return 0
}

func choiceOf(rating Rating) Choice {
	severity, ok := rating.Severity()
	if !ok {
		return Choice{Severity: SeverityUnknown}
	}
	copied := rating
	return Choice{Severity: severity, Rating: &copied}
}

func sortedRaters(summaries map[string]Rating) []string {
	raters := make([]string, 0, len(summaries))
	for rater := range summaries {
		raters = append(raters, rater)
	}
	sort.Strings(raters)
	return raters
}
