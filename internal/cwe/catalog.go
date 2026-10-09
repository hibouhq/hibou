package cwe

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:generate go run ./gen -out catalog.json

// catalogJSON is generated from the MITRE CWE XML by ./gen. It is embedded so
// air-gapped installs need no download; a new CWE release is a regenerate and
// a hibou release.
//
//go:embed catalog.json
var catalogJSON []byte

// Entry is one catalog weakness or category.
type Entry struct {
	ID int `json:"id"`
	// Name is the MITRE title shown wherever the id is ("Improper
	// Neutralization of Input During Web Page Generation ('Cross-site Scripting')").
	Name string `json:"name"`
	// Abstraction is pillar|class|base|variant for weaknesses, category for
	// categories.
	Abstraction string `json:"abstraction"`
	// Status is MITRE's lowercased status (stable, draft, incomplete, deprecated, …).
	Status string `json:"status"`
	// Parents are the ChildOf targets in Research View 1000.
	Parents []int `json:"parents,omitempty"`
	// Category is the slug of the one View 1400 category ("injection",
	// "encryption", …) the weakness belongs to; empty for categories and for
	// deprecated entries MITRE no longer categorizes.
	Category string `json:"category,omitempty"`
}

// Deprecated reports whether MITRE retired the entry. Deprecated ids stay in
// the catalog so old scanner claims keep a title; they are never remapped.
func (e Entry) Deprecated() bool { return e.Status == "deprecated" }

// Set kinds. Rankings and OWASP lists are what cwe-set selects; categories
// (MITRE View 1400, one per weakness) are what cwe-category selects.
const (
	SetKindRanking  = "ranking"
	SetKindOWASP    = "owasp"
	SetKindCategory = "category"
)

// Set is a named group of CWEs taken from a MITRE view or category.
type Set struct {
	Slug string `json:"slug"`
	Kind string `json:"kind"`
	// Name carries the edition ("CWE Top 25 (2025)") so a gate reason says
	// which list it applied.
	Name string `json:"name"`
	// SourceID is the MITRE view or category the members came from.
	SourceID int `json:"source_id"`
	// Members are ordered; for a ranked set, position+1 is the rank.
	Members []int `json:"members"`
	Ranked  bool  `json:"ranked,omitempty"`
}

// Rank returns the 1-based rank of id in a ranked set.
func (s Set) Rank(id int) (int, bool) {
	if !s.Ranked {
		return 0, false
	}
	for index, member := range s.Members {
		if member == id {
			return index + 1, true
		}
	}
	return 0, false
}

// Catalog is the embedded MITRE snapshot.
type Catalog struct {
	// Version is the MITRE catalog version ("4.20").
	Version string  `json:"version"`
	Date    string  `json:"date"`
	Entries []Entry `json:"entries"`
	Sets    []Set   `json:"sets"`

	byID       map[int]int
	bySet      map[string]int
	children   map[int][]int
	setsByCWE  map[int][]string
	categories []string
}

var (
	loadOnce sync.Once
	loaded   *Catalog
	loadErr  error
)

// Default returns the embedded catalog. A malformed embed is a build defect,
// so it panics rather than letting every caller handle an impossible error.
func Default() *Catalog {
	loadOnce.Do(func() {
		loaded, loadErr = parseCatalog(catalogJSON)
	})
	if loadErr != nil {
		panic(fmt.Sprintf("cwe: embedded catalog is invalid: %v", loadErr))
	}
	return loaded
}

func parseCatalog(raw []byte) (*Catalog, error) {
	var catalog Catalog
	if err := json.Unmarshal(raw, &catalog); err != nil {
		return nil, err
	}
	if catalog.Version == "" || len(catalog.Entries) == 0 {
		return nil, errors.New("catalog has no version or entries")
	}
	catalog.index()
	return &catalog, nil
}

func (c *Catalog) index() {
	c.byID = make(map[int]int, len(c.Entries))
	c.children = make(map[int][]int)
	for index, entry := range c.Entries {
		c.byID[entry.ID] = index
		for _, parent := range entry.Parents {
			c.children[parent] = append(c.children[parent], entry.ID)
		}
	}
	c.bySet = make(map[string]int, len(c.Sets))
	c.setsByCWE = make(map[int][]string)
	for index, set := range c.Sets {
		c.bySet[set.Slug] = index
		if set.Kind == SetKindCategory {
			c.categories = append(c.categories, set.Slug)
			continue
		}
		for _, member := range set.Members {
			c.setsByCWE[member] = append(c.setsByCWE[member], set.Slug)
		}
	}
}

// Lookup returns the entry for id.
func (c *Catalog) Lookup(id int) (Entry, bool) {
	index, ok := c.byID[id]
	if !ok {
		return Entry{}, false
	}
	return c.Entries[index], true
}

// Name returns the title for id, or "" when the catalog does not know it.
func (c *Catalog) Name(id int) string {
	entry, _ := c.Lookup(id)
	return entry.Name
}

// Set returns the named ranking or OWASP set for slug (case-insensitive).
// Categories are not sets in this sense; see Category.
func (c *Catalog) Set(slug string) (Set, bool) {
	index, ok := c.bySet[normalizeSetSlug(slug)]
	if !ok || c.Sets[index].Kind == SetKindCategory {
		return Set{}, false
	}
	return c.Sets[index], true
}

// Category returns the View 1400 category for slug (case-insensitive).
func (c *Catalog) Category(slug string) (Set, bool) {
	index, ok := c.bySet[normalizeSetSlug(slug)]
	if !ok || c.Sets[index].Kind != SetKindCategory {
		return Set{}, false
	}
	return c.Sets[index], true
}

// CategorySlugs lists every category slug, in catalog order.
func (c *Catalog) CategorySlugs() []string {
	return c.categories
}

// CategoryRef names the category id belongs to, or nil when it has none.
func (c *Catalog) CategoryRef(id int) *SetRef {
	entry, ok := c.Lookup(id)
	if !ok || entry.Category == "" {
		return nil
	}
	category, ok := c.Category(entry.Category)
	if !ok {
		return nil
	}
	return &SetRef{Slug: category.Slug, Name: category.Name}
}

// SetsOf returns the slugs of every ranking/OWASP set id belongs to, in
// catalog order.
func (c *Catalog) SetsOf(id int) []string {
	return c.setsByCWE[id]
}

// Ancestors returns every transitive View 1000 parent of id, nearest first
// (breadth-first; a CWE with two parents lists both before grandparents).
func (c *Catalog) Ancestors(id int) []int {
	out := []int{}
	seen := map[int]struct{}{id: {}}
	for queue := []int{id}; len(queue) > 0; {
		entry, ok := c.Lookup(queue[0])
		queue = queue[1:]
		if !ok {
			continue
		}
		for _, parent := range entry.Parents {
			if _, dup := seen[parent]; dup {
				continue
			}
			seen[parent] = struct{}{}
			out = append(out, parent)
			queue = append(queue, parent)
		}
	}
	return out
}

// ByAbstraction lists the non-deprecated entries of the given abstractions
// (pillar, class, …), by id.
func (c *Catalog) ByAbstraction(abstractions ...string) []Entry {
	wanted := map[string]struct{}{}
	for _, abstraction := range abstractions {
		wanted[strings.ToLower(strings.TrimSpace(abstraction))] = struct{}{}
	}
	out := []Entry{}
	for _, entry := range c.Entries {
		if _, ok := wanted[entry.Abstraction]; ok && !entry.Deprecated() {
			out = append(out, entry)
		}
	}
	return out
}

// Descendants returns id and every transitive View 1000 child of it.
func (c *Catalog) Descendants(id int) []int {
	out := []int{id}
	seen := map[int]struct{}{id: {}}
	for queue := []int{id}; len(queue) > 0; {
		next := queue[0]
		queue = queue[1:]
		for _, child := range c.children[next] {
			if _, dup := seen[child]; dup {
				continue
			}
			seen[child] = struct{}{}
			out = append(out, child)
			queue = append(queue, child)
		}
	}
	return out
}

// Search matches entries by id ("79", "CWE-79") or by a case-insensitive
// substring of the title, ranking exact id, then id prefix, then title
// matches; deprecated entries sort last.
func (c *Catalog) Search(query string, limit int) []Entry {
	query = strings.TrimSpace(query)
	if limit <= 0 {
		limit = 20
	}
	if query == "" {
		return nil
	}
	type scored struct {
		entry Entry
		score int
	}
	lowerQuery := strings.ToLower(query)
	idQuery := ""
	if id, ok := Parse(query); ok {
		idQuery = strconv.Itoa(id)
	}
	matches := make([]scored, 0, limit)
	for _, entry := range c.Entries {
		score := -1
		idText := strconv.Itoa(entry.ID)
		switch {
		case idQuery != "" && idText == idQuery:
			score = 0
		case idQuery != "" && strings.HasPrefix(idText, idQuery):
			score = 1
		case strings.Contains(strings.ToLower(entry.Name), lowerQuery):
			score = 2
		}
		if score < 0 {
			continue
		}
		if entry.Deprecated() {
			score += 10
		}
		matches = append(matches, scored{entry: entry, score: score})
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score < matches[j].score
		}
		return matches[i].entry.ID < matches[j].entry.ID
	})
	if len(matches) > limit {
		matches = matches[:limit]
	}
	out := make([]Entry, 0, len(matches))
	for _, match := range matches {
		out = append(out, match.entry)
	}
	return out
}

// Ref is the compact CWE shape every API surface returns: the id plus its
// title, so no client ever shows a bare number (ADR-037 §6).
type Ref struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Refs resolves ids against the catalog, keeping order; unknown ids keep an
// empty name.
func (c *Catalog) Refs(ids []int) []Ref {
	out := make([]Ref, 0, len(ids))
	for _, id := range Dedupe(ids) {
		out = append(out, Ref{ID: id, Name: c.Name(id)})
	}
	return out
}

// SetRef names one named set a CWE belongs to; Rank is its position in a
// ranked set (Top 25), zero otherwise.
type SetRef struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Rank int    `json:"rank,omitempty"`
}

// SetRefs lists the named sets id belongs to, in catalog order.
func (c *Catalog) SetRefs(id int) []SetRef {
	slugs := c.SetsOf(id)
	out := make([]SetRef, 0, len(slugs))
	for _, slug := range slugs {
		set, ok := c.Set(slug)
		if !ok {
			continue
		}
		rank, _ := set.Rank(id)
		out = append(out, SetRef{Slug: set.Slug, Name: set.Name, Rank: rank})
	}
	return out
}

// SetSlugs lists every ranking/OWASP set slug, in catalog order.
func (c *Catalog) SetSlugs() []string {
	out := make([]string, 0, len(c.Sets))
	for _, set := range c.Sets {
		if set.Kind != SetKindCategory {
			out = append(out, set.Slug)
		}
	}
	return out
}
