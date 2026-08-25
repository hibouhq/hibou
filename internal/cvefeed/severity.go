package cvefeed

import "strings"

// bestSeverity picks the strongest severity statement the record carries, from
// any container.
//
// This is deliberately not "CNA first, enrichment second". On CVE-2026-59084
// the CNA (apache) supplied only a textual `other` metric reading "low", while
// CISA-ADP supplied CVSS:3.1 with a base score of 9.1 — CRITICAL. Preferring
// the CNA there would understate a critical flaw by four severity bands.
//
// So the order is by the quality of the statement, not the standing of its
// author: a structured vector beats free text, and a newer CVSS version beats
// an older one. Across a 6,063-record sample the CNA scored 41% of records and
// CISA-ADP a further 47%, so between them nearly every record arrives scored,
// at no extra request — both containers ship inside the record we already
// fetched.
func bestSeverity(raw record) Severity {
	best := Severity{}
	bestRank := 0

	consider := func(source string, metrics []metric) {
		for _, m := range metrics {
			for rank, candidate := range []*cvss{m.CVSSv4, m.CVSSv31, m.CVSSv30} {
				if candidate == nil || strings.TrimSpace(candidate.VectorString) == "" {
					continue
				}
				// Ranks: v4 = 4, v3.1 = 3, v3.0 = 2, textual = 1.
				score := 4 - rank
				if score <= bestRank {
					continue
				}
				bestRank = score
				best = Severity{
					Score:  candidate.BaseScore,
					Vector: strings.TrimSpace(candidate.VectorString),
					Label:  normalizeLabel(candidate.BaseSeverity),
					Source: source,
				}
			}
			if m.Other != nil && bestRank < 1 {
				if text := strings.TrimSpace(m.Other.Content.Text); text != "" {
					bestRank = 1
					best = Severity{Label: normalizeLabel(text), Source: source}
				}
			}
		}
	}

	consider(strings.TrimSpace(raw.Containers.CNA.ProviderMetadata.ShortName), raw.Containers.CNA.Metrics)
	for _, adp := range raw.Containers.ADP {
		consider(strings.TrimSpace(adp.ProviderMetadata.ShortName), adp.Metrics)
	}
	return best
}

// normalizeLabel folds severity words to hibou's own severity vocabulary.
// Anything unrecognized becomes empty rather than a guess — an unknown word is
// not evidence of low risk.
func normalizeLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "none", "info", "informational":
		return "info"
	}
	return ""
}
