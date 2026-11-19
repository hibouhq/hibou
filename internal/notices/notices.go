// Package notices generates a third-party notices document from a dependency
// inventory and the licence files the packages themselves ship (ADR-051).
//
// The document is a pure function of its inputs: the shipped components, the
// licence evidence found for each, and the overrides. It carries no
// timestamp, Hibou build version or count of skipped components. The pinned
// detector version is recorded because it can change the evidence conclusion.
package notices

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/hibouhq/hibou/internal/license"
)

// FormatVersion identifies the layout of the rendered document. Bump it when
// the rendering changes so `--check` explains a diff caused by an upgrade.
const FormatVersion = 1

// Component is one shipped component, as the inventory describes it.
type Component struct {
	Purl      string
	Name      string
	Version   string
	Ecosystem string
	// Module is the directory of the manifest that declared the component,
	// relative to Root ("." at the root).
	Module string
}

// Source says where a component's licence evidence came from, strongest
// first (ADR-051 §3).
const (
	SourceOverride = "override"
	SourcePackage  = "package files"
	SourceDeclared = "declared only"
	SourceNone     = "none"
)

// File is one licence file found in a package, verbatim.
type File struct {
	// Path is relative to the package (or inside its archive).
	Path string
	Text string
	// License is the classifier's SPDX identifier, "" when it found none.
	License    string
	Confidence float64
}

// Evidence is what a package ships about its own licence.
type Evidence struct {
	// Found is false when the package is not in any local cache.
	Found bool
	// Location is the directory or archive the files were read from.
	Location string
	// Declared is the identifier or expression in the package's metadata
	// (package.json "license", Cargo.toml "license", METADATA
	// License-Expression), "" when there is none or it is free text.
	Declared string
	Files    []File
	// Issues are incomplete or unreadable local evidence, never silently skipped.
	Issues []string
	// Notice is the content of the package's NOTICE file (Apache-2.0 §4(d)).
	Notice string
}

// Gap kinds (ADR-051 §5).
const (
	GapNotFound      = "not-found"
	GapNoLicenseFile = "no-licence-file"
	GapNoCopyright   = "no-copyright"
	GapUnknown       = "unknown-licence"
	GapDisagreement  = "disagreement"
	GapEvidence      = "incomplete-evidence"
)

// Gap is one thing the generator could not establish, with how to fix it.
type Gap struct {
	Kind    string
	Message string
	Fix     string
}

// Entry is one component in the document.
type Entry struct {
	Component
	// License is the concluded expression; Chosen is the alternative used
	// when License is an OR expression, and equals License otherwise.
	License string
	Chosen  string
	// ChoiceReason says who picked Chosen: "override" or "least demanding".
	ChoiceReason string
	Copyrights   []string
	// TextIDs are the digests of the licence texts that apply, in order.
	TextIDs []string
	Notice  string
	Source  string
	// OverrideReason is the reason recorded with the override that applied.
	OverrideReason string
	Gaps           []Gap
}

// Text is one distinct licence text, printed once.
type Text struct {
	ID      string // first 12 hex digits of the sha256 of the normalized text
	License string
	Body    string
	UsedBy  []string // "name version", sorted
}

// Obligation is a duty beyond attribution that a person must act on.
type Obligation struct {
	License    string
	Duty       string
	Components []string
}

// Included is a hand-maintained file appended verbatim (vendored or ported
// code no inventory lists).
type Included struct {
	Path string
	Body string
}

// Document is the generated notices document.
type Document struct {
	Entries     []Entry
	Texts       []Text
	Obligations []Obligation
	Included    []Included
	Detector    string
}

// GapCount is the number of components with at least one gap.
func (d *Document) GapCount() int {
	n := 0
	for i := range d.Entries {
		if len(d.Entries[i].Gaps) > 0 {
			n++
		}
	}
	return n
}

// Licenses returns the distinct chosen licence expressions, sorted.
func (d *Document) Licenses() []string {
	seen := map[string]bool{}
	for i := range d.Entries {
		seen[d.Entries[i].Chosen] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Classifier identifies the licence of a text.
type Classifier interface {
	// Classify returns the SPDX identifier of the best match and its
	// confidence in [0,1], or "" when nothing matches.
	Classify(text []byte) (id string, confidence float64)
	// Version is recorded so a document can be reproduced.
	Version() string
}

// Collector finds the licence evidence of a component in a local source.
type Collector interface {
	// Handles reports whether the collector knows the component's ecosystem.
	Handles(c Component) bool
	Collect(c Component) Evidence
}

// Override corrects or completes the evidence of a package (ADR-051 §5).
type Override struct {
	// Purl names the package, with a version ("pkg:npm/left-pad@1.3.0") or
	// without one for every version.
	Purl      string
	License   string
	Copyright string
	// Choose picks one alternative of an OR expression.
	Choose string
	Reason string
}

// Options are the inputs of Generate besides the components.
type Options struct {
	Collectors []Collector
	Classifier Classifier
	Overrides  []Override
	Included   []Included
}

// Generate builds the document for the shipped components. Components are
// deduplicated by purl; the result is sorted and deterministic.
func Generate(components []Component, opts Options) *Document {
	byPurl := map[string]Component{}
	for _, c := range components {
		if c.Purl == "" {
			continue
		}
		if existing, ok := byPurl[c.Purl]; !ok || c.Module < existing.Module {
			byPurl[c.Purl] = c
		}
	}
	doc := &Document{Included: opts.Included}
	if opts.Classifier != nil {
		doc.Detector = opts.Classifier.Version()
	}
	texts := map[string]*Text{}
	duties := map[string]*Obligation{}

	purls := make([]string, 0, len(byPurl))
	for purl := range byPurl {
		purls = append(purls, purl)
	}
	sort.Strings(purls)
	for _, purl := range purls {
		c := byPurl[purl]
		entry, files := buildEntry(c, opts)
		label := strings.TrimSpace(c.Name + " " + c.Version)
		for _, f := range files {
			id := textID(f.Text)
			text, ok := texts[id]
			if !ok {
				text = &Text{ID: id, License: f.License, Body: normalizeText(f.Text)}
				texts[id] = text
			}
			text.UsedBy = append(text.UsedBy, label)
			entry.TextIDs = append(entry.TextIDs, id)
		}
		entry.TextIDs = uniqueSorted(entry.TextIDs)
		obligationIDs := expressionIDs(entry.Chosen)
		for _, gap := range entry.Gaps {
			if gap.Kind == GapDisagreement {
				for _, file := range files {
					obligationIDs = append(obligationIDs, expressionIDs(file.License)...)
				}
				break
			}
		}
		for _, id := range uniqueSorted(obligationIDs) {
			duty := dutyFor(id)
			if duty == "" {
				continue
			}
			key := id + "\x00" + duty
			if duties[key] == nil {
				duties[key] = &Obligation{License: id, Duty: duty}
			}
			duties[key].Components = append(duties[key].Components, label)
		}
		doc.Entries = append(doc.Entries, entry)
	}

	sort.Slice(doc.Entries, func(i, j int) bool { return entryLess(doc.Entries[i], doc.Entries[j]) })
	for _, text := range texts {
		text.UsedBy = uniqueSorted(text.UsedBy)
		doc.Texts = append(doc.Texts, *text)
	}
	sort.Slice(doc.Texts, func(i, j int) bool {
		if doc.Texts[i].License != doc.Texts[j].License {
			return doc.Texts[i].License < doc.Texts[j].License
		}
		return doc.Texts[i].ID < doc.Texts[j].ID
	})
	for _, duty := range duties {
		duty.Components = uniqueSorted(duty.Components)
		doc.Obligations = append(doc.Obligations, *duty)
	}
	sort.Slice(doc.Obligations, func(i, j int) bool {
		if doc.Obligations[i].License != doc.Obligations[j].License {
			return doc.Obligations[i].License < doc.Obligations[j].License
		}
		return doc.Obligations[i].Duty < doc.Obligations[j].Duty
	})
	return doc
}

func entryLess(a, b Entry) bool {
	an, bn := strings.ToLower(a.Name), strings.ToLower(b.Name)
	if an != bn {
		return an < bn
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	return a.Purl < b.Purl
}

// buildEntry concludes one component: evidence, override, licence choice,
// copyright lines and gaps. It returns the licence files that apply.
func buildEntry(c Component, opts Options) (Entry, []File) {
	entry := Entry{Component: c, Source: SourceNone}
	var evidence Evidence
	if c.Module != "" {
		for _, segment := range strings.Split(strings.ReplaceAll(c.Module, "\\", "/"), "/") {
			if segment == ".." || strings.HasPrefix(c.Module, "/") || strings.Contains(c.Module, ":") {
				evidence.Issues = append(evidence.Issues, "component module is outside the inventory root")
				entry.License, entry.Chosen = "NOASSERTION", "NOASSERTION"
				entry.Gaps = gapsFor(entry, evidence, "", nil, false)
				return entry, nil
			}
		}
	}
	for _, collector := range opts.Collectors {
		if !collector.Handles(c) {
			continue
		}
		evidence = collector.Collect(c)
		if evidence.Found {
			break
		}
	}
	for i := range evidence.Files {
		if opts.Classifier != nil {
			evidence.Files[i].License, evidence.Files[i].Confidence = opts.Classifier.Classify([]byte(evidence.Files[i].Text))
		}
	}
	override, overridden := matchOverride(opts.Overrides, c.Purl)

	detected := []string{}
	for _, f := range evidence.Files {
		if f.License != "" {
			detected = append(detected, f.License)
		}
	}
	detected = uniqueSorted(detected)
	declared := strings.TrimSpace(evidence.Declared)

	switch {
	case overridden && override.License != "":
		entry.License = override.License
	case declared != "":
		entry.License = declared
	case len(detected) > 0:
		entry.License = strings.Join(detected, " AND ")
	default:
		entry.License = "NOASSERTION"
	}
	entry.Notice = normalizeText(evidence.Notice)
	if len(evidence.Files) > 0 {
		entry.Source = SourcePackage
	} else if declared != "" {
		entry.Source = SourceDeclared
	}

	entry.Chosen, entry.ChoiceReason = chooseAlternative(entry.License, override.Choose)
	// Metadata may be wrong. Keep every observed licence/copyright text,
	// including bundled third-party notices, even when choosing an OR branch.
	files := evidence.Files
	for _, f := range files {
		entry.Copyrights = append(entry.Copyrights, CopyrightLines(f.Text)...)
	}
	entry.Copyrights = append(entry.Copyrights, CopyrightLines(evidence.Notice)...)
	if overridden {
		entry.Source = SourceOverride
		entry.OverrideReason = override.Reason
		if override.Copyright != "" {
			entry.Copyrights = append(entry.Copyrights, strings.TrimSpace(override.Copyright))
		}
	}
	entry.Copyrights = uniqueStable(entry.Copyrights)

	entry.Gaps = gapsFor(entry, evidence, declared, detected, overridden && override.License != "")
	if _, err := license.Alternatives(entry.License); err != nil {
		entry.Gaps = append(entry.Gaps, Gap{GapUnknown, "invalid licence expression", "correct the package metadata or record a valid notices.overrides licence expression"})
	}
	if override.Choose != "" && !strings.EqualFold(strings.TrimSpace(override.Choose), entry.Chosen) {
		entry.Gaps = append(entry.Gaps, Gap{GapDisagreement, "requested licence choice is not an available alternative", "correct notices.overrides[].choose"})
	}
	return entry, files
}

func gapsFor(entry Entry, evidence Evidence, declared string, detected []string, overridden bool) []Gap {
	var gaps []Gap
	for _, issue := range evidence.Issues {
		gaps = append(gaps, Gap{GapEvidence, issue, "repair or install the package's complete licence evidence"})
	}
	overrideFix := "add a notices.overrides entry in .hibou.yaml with the licence, the copyright line and a reason"
	switch {
	case !evidence.Found:
		gaps = append(gaps, Gap{GapNotFound,
			"package not found in the local package caches",
			"install the exact package version before generating notices; an identifier override cannot supply its text"})
	case len(evidence.Files) == 0:
		message := "no licence file in the package"
		if declared != "" {
			message += "; declared " + declared
		}
		gaps = append(gaps, Gap{GapNoLicenseFile, message, "supply the package's original licence file or ask upstream to ship it; metadata overrides do not replace licence text"})
	}
	if entry.License == "NOASSERTION" {
		gaps = append(gaps, Gap{GapUnknown, "licence unknown", overrideFix})
	}
	for _, id := range expressionIDs(entry.Chosen) {
		found := false
		for _, actual := range detected {
			for _, detectedID := range expressionIDs(actual) {
				found = found || strings.EqualFold(id, detectedID)
			}
		}
		if id != "NOASSERTION" && !found && len(evidence.Files) > 0 {
			gaps = append(gaps, Gap{GapUnknown, "no identified licence text for " + id, "supply the package's actual licence file; an identifier override does not supply its text"})
		}
	}
	if declared != "" && len(detected) > 0 && !overridden {
		declaredIDs := map[string]bool{}
		for _, id := range expressionIDs(declared) {
			declaredIDs[id] = true
		}
		var extra []string
		for _, detectedExpression := range detected {
			for _, id := range expressionIDs(detectedExpression) {
				if !declaredIDs[id] {
					extra = append(extra, id)
				}
			}
		}
		if len(extra) > 0 {
			gaps = append(gaps, Gap{GapDisagreement,
				"declared " + declared + ", licence file is " + strings.Join(extra, ", "),
				"check which is right and record it in a notices.overrides entry"})
		}
	}
	if len(entry.Copyrights) == 0 && needsCopyrightLine(entry.Chosen) && entry.License != "NOASSERTION" &&
		(evidence.Found || overridden) && (len(evidence.Files) > 0 || overridden) {
		gaps = append(gaps, Gap{GapNoCopyright,
			"licence text has no copyright line",
			"add a notices.overrides entry with the copyright line"})
	}
	return gaps
}

// matchOverride returns the override for a purl: one naming the exact
// version wins over one naming every version.
func matchOverride(overrides []Override, purl string) (Override, bool) {
	base := PurlBase(purl)
	var any *Override
	for i := range overrides {
		pattern := strings.TrimSpace(overrides[i].Purl)
		switch {
		case pattern == purl || pattern == stripQualifiers(purl):
			return overrides[i], true
		case pattern == base && any == nil:
			any = &overrides[i]
		}
	}
	if any != nil {
		return *any, true
	}
	return Override{}, false
}

// PurlBase strips the version, qualifiers and subpath of a purl.
func PurlBase(purl string) string {
	purl = stripQualifiers(purl)
	slash := strings.LastIndex(purl, "/")
	if at := strings.LastIndex(purl, "@"); at > slash {
		return purl[:at]
	}
	return purl
}

func stripQualifiers(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

func normalizeText(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

func textID(text string) string {
	sum := sha256.Sum256([]byte(normalizeText(text)))
	return hex.EncodeToString(sum[:])[:12]
}

func uniqueSorted(values []string) []string {
	out := uniqueStable(values)
	sort.Strings(out)
	return out
}

func uniqueStable(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
