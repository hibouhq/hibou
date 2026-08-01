# ADR-021: Intelligent search bar

## Status

Accepted — implementing incrementally (client-side intelligence first).

## Context

The global search box is a plain substring match. The bar in
[AppLayout.vue](../../site/src/layouts/AppLayout.vue) debounces the raw text and
navigates to [SearchView.vue](../../site/src/views/SearchView.vue), which calls
`GET /orgs/{provider}/{slug}/search?q=&type=&severity=`
([search.go](../../internal/server/search.go)) and renders a flat list across
advisories, components, vulnerabilities, and clients. Problems:

- **No suggestions.** You type, wait, and land on a results page. There is no
  autocomplete, no keyboard navigation, no "top hit".
- **No type awareness.** `CVE-2021-44228`, `pkg:maven/log4j`, a commit SHA, and
  `payments service` are all treated as the same opaque substring. The user has
  to know to also set the `type` and `severity` query params by hand.
- **Two disconnected grammars.** The per-tab [FilterBar](../../site/src/components/FilterBar.vue)
  already parses rich boolean filter expressions (ADR-013), but the global bar
  ignores all of it, so knowledge does not transfer.

We want the GitHub command-bar experience: type, get grouped typed suggestions
as you go, and have the bar recognize what you meant (a CVE, a package, a repo)
and route you there.

## Decision

The search bar becomes a parser + a suggestion dropdown backed by a lightweight
suggest endpoint. Three parts.

### 1. Query grammar (shared with ADR-013)

A query is free text plus zero or more `qualifier:value` tokens, reusing the
ADR-013 tokenizer so the global bar and the tab filters speak the same language:

```
log4j severity:high repo:api ecosystem:maven
cve:CVE-2021-44228
status:confirmed payments
```

Supported qualifiers at launch: `type:`, `severity:`, `repo:`, `ecosystem:`,
`status:`, `cve:`. Unknown qualifiers fall back to free text so nothing is a
hard error.

### 2. Entity detection

Before hitting the network, the client classifies the current token to bias the
results and offer a direct action:

| Pattern | Detected as | Action hint |
|---|---|---|
| `CVE-\d{4}-\d{4,}` | advisory (CVE) | "Open advisory" |
| `GHSA-[0-9a-z]{4}-...` | advisory (GHSA) | "Open advisory" |
| `pkg:` purl or `ecosystem:x name` | component | "Find component" |
| 7–40 hex chars | commit / snapshot | "Open snapshot" |
| otherwise | full-text | grouped results |

Detection only *ranks and hints*; it never hides the other categories.

### 3. Command-palette overlay + suggest endpoint

Search is an **overlay**, not a page change. Focusing the bar (or `⌘K` / `Ctrl-K`)
opens a centered command palette over the current page — the page underneath does
**not** navigate. The palette has the input at the top and live, grouped,
typed suggestions below; the user stays in context and only leaves when they
choose to.

Overlay behavior:

- Grouped suggestions with an icon per type; the whole palette is keyboard-first.
- Arrow keys move the highlight; **`Enter` on a highlighted suggestion opens that
  entity**; **`Enter` on free text (nothing highlighted) navigates to the full
  results page**; `Esc` closes the overlay and returns to the untouched page.
- Recognized entities show an inline hint ("Looks like a CVE — Enter to open
  advisory").
- Selected qualifiers render as chips; typing `severity:` offers the allowed
  values as completions.
- The backing data is `GET .../search?q=&per_page=6` in v1 (below); a dedicated
  `search/suggest` endpoint is the follow-up optimization.

The full-results [SearchView](../../site/src/views/SearchView.vue) remains the
"see everything" destination — reached only by `Enter` on free text — and now
understands the qualifiers too.

## Consequences

- Users reach a specific advisory/component/repo in one or two keystrokes
  instead of scanning a flat list.
- One grammar across the global bar and tab filters — learn it once.
- A new suggest endpoint must stay fast; it returns few rows and can be capped
  and cached per `(org, q-prefix)` without correctness risk (typeahead is
  advisory, not authoritative).

## Alternatives considered

- **Client-only heuristics over the existing search.** Rejected for suggestions:
  returning the whole result set on every keystroke to filter client-side is
  wasteful; a purpose-built suggest endpoint returns less and ranks better. The
  client still does the cheap entity *detection* locally for instant hints.
- **A dedicated search index (e.g. an external engine).** Overkill for the
  current corpus; Postgres queries already back search. Revisit only if suggest
  latency at scale demands it.
- **Reuse `FilterBar` as the global bar.** Rejected: FilterBar is tied to a
  single tab's dataset and columns; the global bar spans entity types and needs
  its own suggestion model. They share the *grammar*, not the component.
