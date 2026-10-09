// Command gen regenerates internal/cwe/catalog.json from the MITRE CWE XML.
//
//	go generate ./internal/cwe            # downloads cwec_latest.xml.zip
//	go run ./internal/cwe/gen -in cwec_v4.20.xml.zip -out internal/cwe/catalog.json
//
// Named sets come from MITRE's own views, never a hand-kept list: the latest
// final "CWE Top 25" view (ranked by member order) and the latest final
// "OWASP Top Ten (YYYY)" view with one set per category. Release candidates
// ("RC1") are skipped.
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const latestURL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// researchView is Research Concepts (View 1000), the hierarchy cwe-tree walks.
const researchView = "1000"

// categorizationView is "Comprehensive Categorization for Software Assurance
// Trends" (View 1400): every weakness in exactly one of ~22 developer-facing
// categories (Injection, Encryption, Access Control, …).
const categorizationView = "1400"

// categoryPrefix is stripped from View 1400 category names for display.
const categoryPrefix = "Comprehensive Categorization: "

type xmlCatalog struct {
	Version    string        `xml:"Version,attr"`
	Date       string        `xml:"Date,attr"`
	Weaknesses []xmlWeakness `xml:"Weaknesses>Weakness"`
	Categories []xmlCategory `xml:"Categories>Category"`
	Views      []xmlView     `xml:"Views>View"`
}

type xmlWeakness struct {
	ID          string       `xml:"ID,attr"`
	Name        string       `xml:"Name,attr"`
	Abstraction string       `xml:"Abstraction,attr"`
	Status      string       `xml:"Status,attr"`
	Related     []xmlRelated `xml:"Related_Weaknesses>Related_Weakness"`
}

type xmlRelated struct {
	Nature string `xml:"Nature,attr"`
	CWEID  string `xml:"CWE_ID,attr"`
	ViewID string `xml:"View_ID,attr"`
}

type xmlCategory struct {
	ID      string      `xml:"ID,attr"`
	Name    string      `xml:"Name,attr"`
	Status  string      `xml:"Status,attr"`
	Members []xmlMember `xml:"Relationships>Has_Member"`
}

type xmlView struct {
	ID      string      `xml:"ID,attr"`
	Name    string      `xml:"Name,attr"`
	Status  string      `xml:"Status,attr"`
	Members []xmlMember `xml:"Members>Has_Member"`
}

type xmlMember struct {
	CWEID  string `xml:"CWE_ID,attr"`
	ViewID string `xml:"View_ID,attr"`
}

// Output mirrors cwe.Catalog's JSON shape; gen cannot import the package it
// generates for (the embed would not exist on a first run).
type outEntry struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Abstraction string `json:"abstraction"`
	Status      string `json:"status"`
	Parents     []int  `json:"parents,omitempty"`
	Category    string `json:"category,omitempty"`
}

type outSet struct {
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	SourceID int    `json:"source_id"`
	Members  []int  `json:"members"`
	Ranked   bool   `json:"ranked,omitempty"`
}

type outCatalog struct {
	Version string     `json:"version"`
	Date    string     `json:"date"`
	Entries []outEntry `json:"entries"`
	Sets    []outSet   `json:"sets"`
}

var (
	top25ViewName = regexp.MustCompile(`^Weaknesses in the (\d{4}) CWE Top 25 Most Dangerous Software Weaknesses$`)
	owaspViewName = regexp.MustCompile(`^Weaknesses in OWASP Top Ten \((\d{4})\)$`)
	owaspCategory = regexp.MustCompile(`^OWASP Top Ten \d{4} Category (A(\d{2}):\d{4}) - (.+)$`)
)

func main() {
	in := flag.String("in", "", "path to cwec_*.xml or cwec_*.xml.zip (default: download the latest)")
	out := flag.String("out", "catalog.json", "output path")
	flag.Parse()

	raw, err := readInput(*in)
	if err != nil {
		fail(err)
	}
	catalog, err := build(raw)
	if err != nil {
		fail(err)
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(*out, append(encoded, '\n'), 0o600); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s: CWE %s (%s), %d entries, %d sets\n", *out, catalog.Version, catalog.Date, len(catalog.Entries), len(catalog.Sets))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "cwe gen:", err)
	os.Exit(1)
}

func readInput(path string) ([]byte, error) {
	var raw []byte
	if path == "" {
		client := &http.Client{Timeout: 2 * time.Minute}
		response, err := client.Get(latestURL)
		if err != nil {
			return nil, fmt.Errorf("download %s: %w", latestURL, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("download %s: %s", latestURL, response.Status)
		}
		raw, err = io.ReadAll(io.LimitReader(response.Body, 64<<20))
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		raw, err = os.ReadFile(path) // #nosec G304 -- developer-supplied generator input.
		if err != nil {
			return nil, err
		}
	}
	if !bytes.HasPrefix(raw, []byte("PK")) {
		return raw, nil
	}
	archive, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, err
	}
	for _, file := range archive.File {
		if !strings.HasSuffix(file.Name, ".xml") {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(io.LimitReader(reader, 256<<20))
	}
	return nil, errors.New("zip has no .xml member")
}

func build(raw []byte) (*outCatalog, error) {
	var source xmlCatalog
	if err := xml.Unmarshal(raw, &source); err != nil {
		return nil, fmt.Errorf("parse catalog xml: %w", err)
	}
	if source.Version == "" {
		return nil, errors.New("catalog xml has no Version attribute")
	}

	catalog := &outCatalog{Version: source.Version, Date: source.Date}
	known := map[int]struct{}{}
	for _, weakness := range source.Weaknesses {
		id, err := strconv.Atoi(weakness.ID)
		if err != nil {
			return nil, fmt.Errorf("weakness id %q: %w", weakness.ID, err)
		}
		entry := outEntry{
			ID:          id,
			Name:        strings.TrimSpace(weakness.Name),
			Abstraction: strings.ToLower(weakness.Abstraction),
			Status:      strings.ToLower(weakness.Status),
		}
		seenParent := map[int]struct{}{}
		for _, related := range weakness.Related {
			if related.Nature != "ChildOf" || related.ViewID != researchView {
				continue
			}
			parent, err := strconv.Atoi(related.CWEID)
			if err != nil {
				continue
			}
			if _, dup := seenParent[parent]; dup {
				continue
			}
			seenParent[parent] = struct{}{}
			entry.Parents = append(entry.Parents, parent)
		}
		sort.Ints(entry.Parents)
		catalog.Entries = append(catalog.Entries, entry)
		known[id] = struct{}{}
	}
	categories := map[string]xmlCategory{}
	for _, category := range source.Categories {
		id, err := strconv.Atoi(category.ID)
		if err != nil {
			return nil, fmt.Errorf("category id %q: %w", category.ID, err)
		}
		catalog.Entries = append(catalog.Entries, outEntry{
			ID:          id,
			Name:        strings.TrimSpace(category.Name),
			Abstraction: "category",
			Status:      strings.ToLower(category.Status),
		})
		known[id] = struct{}{}
		categories[category.ID] = category
	}
	sort.Slice(catalog.Entries, func(i, j int) bool { return catalog.Entries[i].ID < catalog.Entries[j].ID })

	top25, ok := latestView(source.Views, top25ViewName)
	if !ok {
		return nil, errors.New("no CWE Top 25 view in catalog")
	}
	members := viewMembers(top25.view, known)
	if len(members) != 25 {
		return nil, fmt.Errorf("top 25 view %s has %d members, want 25", top25.view.ID, len(members))
	}
	catalog.Sets = append(catalog.Sets, outSet{
		Slug:     "top25",
		Name:     fmt.Sprintf("CWE Top 25 (%d)", top25.year),
		Kind:     "ranking",
		SourceID: mustAtoi(top25.view.ID),
		Members:  members,
		Ranked:   true,
	})

	owasp, ok := latestView(source.Views, owaspViewName)
	if !ok {
		return nil, errors.New("no final OWASP Top Ten view in catalog")
	}
	var union []int
	var categorySets []outSet
	for _, member := range owasp.view.Members {
		category, ok := categories[member.CWEID]
		if !ok {
			continue
		}
		match := owaspCategory.FindStringSubmatch(strings.TrimSpace(category.Name))
		if match == nil {
			return nil, fmt.Errorf("unexpected OWASP category name %q", category.Name)
		}
		var cweMembers []int
		for _, has := range category.Members {
			if has.ViewID != owasp.view.ID {
				continue
			}
			id, err := strconv.Atoi(has.CWEID)
			if err != nil {
				continue
			}
			if _, ok := known[id]; ok {
				cweMembers = append(cweMembers, id)
			}
		}
		cweMembers = dedupe(cweMembers)
		sort.Ints(cweMembers)
		union = append(union, cweMembers...)
		categorySets = append(categorySets, outSet{
			Slug:     "owasp-a" + match[2],
			Name:     fmt.Sprintf("OWASP %s %s", match[1], strings.TrimSpace(match[3])),
			Kind:     "owasp",
			SourceID: mustAtoi(category.ID),
			Members:  cweMembers,
		})
	}
	if len(categorySets) != 10 {
		return nil, fmt.Errorf("OWASP view %s has %d categories, want 10", owasp.view.ID, len(categorySets))
	}
	union = dedupe(union)
	sort.Ints(union)
	catalog.Sets = append(catalog.Sets, outSet{
		Slug:     "owasp-top10",
		Name:     fmt.Sprintf("OWASP Top 10 (%d)", owasp.year),
		Kind:     "owasp",
		SourceID: mustAtoi(owasp.view.ID),
		Members:  union,
	})
	sort.Slice(categorySets, func(i, j int) bool { return categorySets[i].Slug < categorySets[j].Slug })
	catalog.Sets = append(catalog.Sets, categorySets...)

	categorySetsByView, err := comprehensiveCategories(source.Views, categories, known)
	if err != nil {
		return nil, err
	}
	categoryOf := map[int]string{}
	for _, set := range categorySetsByView {
		for _, member := range set.Members {
			if previous, dup := categoryOf[member]; dup {
				return nil, fmt.Errorf("CWE-%d is in two categories (%s, %s); View %s promises one", member, previous, set.Slug, categorizationView)
			}
			categoryOf[member] = set.Slug
		}
	}
	for index := range catalog.Entries {
		catalog.Entries[index].Category = categoryOf[catalog.Entries[index].ID]
	}
	catalog.Sets = append(catalog.Sets, categorySetsByView...)
	return catalog, nil
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// comprehensiveCategories turns View 1400's categories into named sets
// ("injection", "access-control", …), one per category.
func comprehensiveCategories(views []xmlView, categories map[string]xmlCategory, known map[int]struct{}) ([]outSet, error) {
	var view *xmlView
	for index := range views {
		if views[index].ID == categorizationView {
			view = &views[index]
		}
	}
	if view == nil {
		return nil, fmt.Errorf("catalog has no View %s", categorizationView)
	}
	out := make([]outSet, 0, len(view.Members))
	for _, member := range view.Members {
		category, ok := categories[member.CWEID]
		if !ok {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSpace(category.Name), categoryPrefix)
		var members []int
		for _, has := range category.Members {
			if has.ViewID != categorizationView {
				continue
			}
			id, err := strconv.Atoi(has.CWEID)
			if err != nil {
				continue
			}
			if _, ok := known[id]; ok {
				members = append(members, id)
			}
		}
		members = dedupe(members)
		sort.Ints(members)
		out = append(out, outSet{
			Slug:     strings.Trim(nonSlug.ReplaceAllString(strings.ToLower(name), "-"), "-"),
			Name:     name,
			Kind:     "category",
			SourceID: mustAtoi(category.ID),
			Members:  members,
		})
	}
	if len(out) < 10 {
		return nil, fmt.Errorf("view %s has %d categories, expected about 22", categorizationView, len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

type datedView struct {
	view xmlView
	year int
}

func latestView(views []xmlView, pattern *regexp.Regexp) (datedView, bool) {
	best := datedView{}
	for _, view := range views {
		match := pattern.FindStringSubmatch(strings.TrimSpace(view.Name))
		if match == nil || strings.EqualFold(view.Status, "deprecated") {
			continue
		}
		year := mustAtoi(match[1])
		if year > best.year {
			best = datedView{view: view, year: year}
		}
	}
	return best, best.year > 0
}

func viewMembers(view xmlView, known map[int]struct{}) []int {
	out := make([]int, 0, len(view.Members))
	for _, member := range view.Members {
		id, err := strconv.Atoi(member.CWEID)
		if err != nil {
			continue
		}
		if _, ok := known[id]; ok {
			out = append(out, id)
		}
	}
	return dedupe(out)
}

func dedupe(ids []int) []int {
	out := make([]int, 0, len(ids))
	seen := map[int]struct{}{}
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func mustAtoi(value string) int {
	parsed, err := strconv.Atoi(value)
	if err != nil {
		panic(err)
	}
	return parsed
}
