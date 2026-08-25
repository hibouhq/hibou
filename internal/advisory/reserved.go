package advisory

import (
	"regexp"
	"strings"
)

// Hibou's own advisory identifier namespace, reserved but not yet issued.
//
// `HSA-YYYY-NNNN` and `HSAT-YYYY-NNNN` are set aside for advisories with no
// upstream identity to attach to — ours to mint centrally, and an instance's to
// mint locally, respectively. Nothing mints either today, and the machinery that
// would (curation, distribution channel, publication) is deliberately unbuilt.
//
// Reserving it early is worth the few lines because the risk runs the other
// way. Identifiers arrive from providers and from records published by third
// parties; if one of them can put `HSA-2026-0001` into an alias list, it joins
// whatever advisory it likes to a name we intend to make authoritative later —
// and the collision would be discovered only after we started issuing them,
// with the poisoned rows already indistinguishable from real ones.
//
// So the namespace is closed to everyone from the start: no ingest path accepts
// an `HSA-*` alias from a provider, and when minting eventually exists it will
// be the only writer.
// Two namespaces, because two different parties would mint them:
//
//	HSA-YYYY-NNNN   hibou's own, minted centrally and shipped to every instance
//	HSAT-YYYY-NNNN  an instance's own, minted locally for a flaw it triaged
//	                that has no upstream identity to attach to
//
// Keeping them apart matters at the moment of minting. An instance issuing an
// identifier under our prefix would collide with a real one the day we start
// issuing them, and the two are not interchangeable to a reader either: one
// carries our review, the other carries the instance's.
const (
	ReservedPrefix      = "HSA-"
	ReservedLocalPrefix = "HSAT-"
)

var reservedIdentifierPattern = regexp.MustCompile(`(?i)^HSAT?-\d{4}-\d+$`)

// IsReservedIdentifier reports whether an identifier belongs to either hibou
// namespace. It matches the shape rather than only the prefix, so an unrelated
// vendor id that merely starts with those letters is not mistakenly claimed.
func IsReservedIdentifier(identifier string) bool {
	return reservedIdentifierPattern.MatchString(strings.TrimSpace(identifier))
}

// rejectReservedAliases drops identifiers in hibou's namespace from data that
// arrived from a provider.
//
// Silent removal rather than a hard error: an advisory carrying a stray alias is
// still worth ingesting, and failing the whole batch would let one bad record
// block a feed. What must not happen is the alias being stored.
func rejectReservedAliases(aliases []string) []string {
	kept := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		if IsReservedIdentifier(alias) {
			continue
		}
		kept = append(kept, alias)
	}
	return kept
}
