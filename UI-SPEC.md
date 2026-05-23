# UI Specification for Hibou

NOTE: DO NOT FOLLOW BLINDLY THESES specs... the wanted result may have changed... SPEC.md take precedence over this UI-SPEC.md.
FOr example no more plotly.... we should use https://www.chartjs.org/ instead.

## 1. Design System

### Theme & Colors

The existing SPA uses a dark-first, GitHub-inspired visual system that has already proven readable for dense security data, tables, graphs, and dashboards. This palette should be preserved as the default Hibou theme because it already balances contrast, hierarchy, and long-session usability. But support dark white mode please, setting in user, by default in sync with system.

Exact design tokens from the current `main.css`:

```css
@theme {
  --font-sans: "Inter", system-ui, -apple-system, sans-serif;
  --font-mono: "JetBrains Mono", "Fira Code", monospace;

  --color-surface: #0d1117;
  --color-surface-raised: #161b22;
  --color-surface-overlay: #1c2128;
  --color-surface-border: #30363d;
  --color-surface-border-subtle: #21262d;

  --color-accent: #58a6ff;
  --color-accent-hover: #79c0ff;
  --color-accent-muted: #388bfd66;

  --color-sev-critical: #f85149;
  --color-sev-high: #e6550d;
  --color-sev-medium: #d29922;
  --color-sev-low: #8b949e;
  --color-sev-info: #58a6ff;

  --color-ok: #3fb950;
  --color-ok-muted: #238636;
  --color-warn: #d29922;
  --color-warn-muted: #9e6a03;
  --color-danger: #f85149;
  --color-danger-muted: #da3633;
}
```

Recommended semantic usage:

| Token | Value | Use |
| --- | --- | --- |
| Base surface | `#0d1117` | App background, graph canvas, filter inputs |
| Raised surface | `#161b22` | Cards, sidebars, dropdown panels |
| Overlay surface | `#1c2128` | Sticky headers, hover panels, toolbars |
| Border | `#30363d` | Card borders, table dividers, focus containers |
| Accent | `#58a6ff` | Links, active states, selected tabs, focus treatment |
| Accent hover | `#79c0ff` | Interactive hover states |
| Critical | `#f85149` | Highest severity, dangerous states |
| High | `#e6550d` | High severity |
| Medium | `#d29922` | Warning / medium severity |
| Low | `#8b949e` | Low severity / muted emphasis |
| Info | `#58a6ff` | Informational tags |
| OK | `#3fb950` | Passing, healthy, fixed |
| Warn | `#d29922` | Warning, stale, partial |
| Danger | `#f85149` | Broken, critical, failing |

Typography:

| Role | Font |
| --- | --- |
| Body, navigation, cards, tables | `Inter` |
| Code, versions, commit hashes, PURLs, CVEs | `JetBrains Mono` |

Notes:

- This palette has already been battle-tested for readability in security workflows.
- Hibou should remain dark-first even if a light theme is added later.
- Focus styling should use the existing accent blue with a soft outer ring rather than browser defaults.

### Component Design Tokens

Shared component patterns worth carrying forward directly:

| Pattern | Proven implementation |
| --- | --- |
| Card shell | `background: #161b22; border: 1px solid #30363d; border-radius: 0.75rem; padding: 1.25rem;` |
| Card header | Flex row, title + action area, `padding-bottom: 0.75rem`, bottom border `#30363d` |
| Table header | Sticky headers with `background: #1c2128`, uppercase labels, `top: 0`, `z-index: 10` |
| Table rows | `0.625rem 0.75rem` cell padding, subtle row border, hover tint `rgba(88, 166, 255, 0.04)` |
| Numeric cells | `tabular-nums` / `font-variant-numeric: tabular-nums` |
| Severity badges | Pill shape, translucent background plus matching foreground color |
| Scrollbars | `6px` width and height, transparent track, thumb `#30363d`, hover `#484f58` |
| Hover transitions | `0.15s ease` for hover and interactive tinting |
| Layout transitions | `0.2s ease` for sidebars, chevrons, overlays |

Canonical badge examples:

```css
.sev-critical { background: rgba(248, 81, 73, 0.15); color: #f85149; }
.sev-high     { background: rgba(230, 85, 13, 0.15); color: #e6550d; }
.sev-medium   { background: rgba(210, 153, 34, 0.15); color: #d29922; }
.sev-low      { background: rgba(139, 148, 158, 0.15); color: #8b949e; }
.sev-info     { background: rgba(88, 166, 255, 0.12); color: #58a6ff; }
```

## 2. Core Components to Port

### DepGraph (Dependency Graph)

Purpose:

- Interactive dependency exploration for large SBOM trees.
- Used to answer "why is this component present" and "where does risk sit in the graph".

Key features:

- D3 force-directed rendering with `d3-force`, `d3-zoom`, `d3-drag`, and `d3-selection`.
- Progressive breadth-first expansion from the root node.
- Click node to expand or collapse descendants.
- Search supports exact `ecosystem:name` syntax such as `maven:commons-io` and plain free text.
- Search can auto-expand the hidden parent chain when the target is outside the currently visible subgraph.
- Toolbar includes search input, reset, expand-all, collapse-all, and visible node count.
- Hover tooltip shows component name, version, ecosystem, vulnerability count, and child count.
- Collapsed nodes with children display a `+N` badge.
- Drag interaction lets users manually reposition nodes.

Interaction model:

- Initial state expands only the root node.
- Expansion is BFS-based, so users reveal graph depth incrementally instead of loading the entire tree at once.
- Clicking a node with children toggles expansion.
- `Expand all` only expands currently visible nodes and skips nodes with more than `100` children to avoid browser overload.
- Search highlights matches with an orange ring `#ffa657` and SVG drop-shadow glow.
- During search, non-matching nodes dim to `15%` opacity and unrelated links dim to `6%` opacity.
- Programmatic `focusOn(name, ecosystem?)` support already exists and should be preserved for modal-to-graph linking.

Visual rules:

| Node state | Rule |
| --- | --- |
| Root / application node | `18px`, purple `#bc8cff` |
| High dependency count | `14px` when child count `> 50` |
| Mid dependency count | `11px` when child count `> 10` |
| Vulnerable node | `9px`, red `#f85149` |
| Leaf node | `7px`, green `#3fb950` |
| Collapsed branch node | gray `#8b949e` |

Technical approach to keep:

- Maintain a full node/edge map in memory.
- Build the visible graph by BFS from `rootRef`, including only nodes whose parents are in the expanded set.
- Build a parent map from the full graph for auto-expanding hidden search results.
- Use `forceLink`, `forceManyBody`, `forceCenter`, and `forceCollide`.
- Keep an exposed imperative `focusOn` method on the component instance.

Link opacity rules:

- Dense source nodes with `100+` children render links at `12%` opacity.
- Dense source nodes with `30+` children render links at `25%` opacity.
- Normal links render at `50%` opacity.
- Search mode reduces non-highlighted links to `6%` opacity.

What was good:

- Progressive expansion makes very large graphs usable.
- Search with auto-expand is one of the most valuable workflows in the app.
- The graph exposes transitive dependency context better than a table can.

What to improve in Hibou:

- Add keyboard navigation and focus management.
- Add ARIA labels to interactive SVG elements.
- Consider WebGL or canvas rendering for `10k+` visible nodes.
- Add a dedicated "jump from modal to graph" affordance.

### DepTable (Dependency / Vulnerability Table)

Purpose:

- High-density triage table for dependency risk.
- Complements the graph with sortable, filterable vulnerability detail.

Columns to preserve:

| Column | Behavior |
| --- | --- |
| Tools | Badge chips, one row can show multiple tools |
| DB | Database source badges such as NVD, OSV, GHSA |
| Severity | Shared severity badge |
| CVSS | Monospace numeric display |
| CVE | External link, tooltip can show summary |
| CWE | External link, tooltip can show weakness name |
| Library | Clickable action opening `LibDetailModal` |
| Version | Monospace |
| Fixed | Green if available |
| Branches / refs | Optional compact chip list |

Filter bar pattern:

- Text search across CVE, library, CWE, version, severity.
- Severity dropdown.
- Tool dropdown.
- Status dropdown: `all`, `vulnerable`, `clean`, each with counts.
- Filter count indicator showing `N / total`.

Technical approach:

- Pre-normalize tool data into a consistent shape before render.
- Auto-populate filter option values from current data where possible.
- Use a scrollable table container with `max-height: 70vh` and sticky headers.
- Keep row-level interactions lightweight; the modal should handle heavy detail.

What was good:

- The filter combination of text + severity + tool + status is very fast for triage.
- The `N / total` count gives users immediate feedback on filter scope.

What to improve in Hibou:

- Add column sorting.
- Add virtual scrolling for `1000+` rows.
- Add keyboard row navigation and enter-to-open behavior.
- Replace hardcoded tool classes with a registry-driven badge system.

### LibDetailModal (Library Detail Overlay)

Purpose:

- Full context view for a single dependency.
- Bridges tabular vulnerability data with transitive dependency placement.

Interaction model:

- Opens as a full-screen teleported overlay.
- Closes on backdrop click, close button, or `Escape`.
- Uses backdrop blur and a slide-in animation from `translateY(16px)` to `0` over `0.2s`.

Content structure:

- Header: library name, version, ecosystem badge, tool badges, PURL.
- Vulnerability table: severity, CVSS, CVE, CWE, summary, fix version, affected refs.
- Empty healthy state: green checkmark and "No known vulnerabilities".
- "Where is it used?" section: dependency chains shown as root-to-target path chips.

Technical approach:

- Build usage paths from the graph by constructing a child-to-parents map.
- Prefer exact match on name + ecosystem + version, then progressively relax matching.
- Limit chain rendering to a reasonable max count to avoid runaway overlays.

What was good:

- The dependency chain section is extremely effective at explaining transitive risk.
- The modal consolidates everything needed for a component investigation in one place.

What to improve in Hibou:

- Add a "highlight in graph" or "jump to graph" action.
- Add copy-to-clipboard for PURL and package coordinates.
- Consider side-panel mode on ultra-wide screens.

### FindingTable (Generic Finding Table)

Purpose:

- Generic pattern derived from the current code quality issue table and static analysis flaw table.
- Should become the default finding surface for SARIF and other normalized findings.

#### Current Implementation A: Code Quality Issue Table

Columns:

- Severity.
- Type such as `bug`, `vulnerability`, `code_smell`, or `security_hotspot`.
- Rule, with an info popup entry point.
- Component path.
- Line number.
- Status such as `open`, `confirmed`, `reopened`, `resolved`, or `closed`.
- Message.
- Creation date.

Filters:

- Severity dropdown.
- Type dropdown.
- Status dropdown.
- Reset button.

Rule info popup pattern:

- Teleported overlay or centered panel.
- Shows rule name.
- Shows severity badge.
- Shows type tag.
- Shows description.
- Shows remediation guidance.
- Shows effort estimate.

Key pattern to preserve:

- Status-colored badges should remain visually distinct: `open` uses accent blue, `confirmed` and `reopened` use warning treatment, and `resolved` and `closed` use a muted resolved style.
- The rule popup keeps the table compact while still exposing deep context on demand.

#### Current Implementation B: Static Analysis Flaw Table

Columns:

- Severity badge.
- CWE ID, linked to the canonical CWE definition.
- CWE name.
- Application or module.
- Remediation status.
- Flaw count.

Filters:

- Severity dropdown.
- CWE dropdown.
- Application dropdown.
- Reset button.

Key pattern to preserve:

- Remediation status coloring should stay explicit: `fixed` uses green, `open` uses red, and `mitigated` uses yellow.
- The data shape naturally supports CWE-based grouping and rollups.

Different from implementation A:

- This table focuses on CWE categories rather than individual file locations.
- It groups findings by application or module context instead of centering the workflow on per-file rule inspection.

#### Hibou Generalized FindingTable

Hibou should generalize these two proven patterns into a single normalized finding surface that can render SARIF and other finding feeds without losing the workflows they support.

The generalized table should preserve from implementation A:

- Rule-level detail overlays for tools that expose canonical rules.
- Status-colored badge treatment for issue lifecycle states.
- File and line level rendering when the source format includes precise locations.

The generalized table should preserve from implementation B:

- CWE-linked categorization when the source format includes weakness metadata.
- Application or module grouping when findings are aggregated above the file level.
- Remediation-state coloring for tools whose workflow is centered on fix status instead of issue state.

Hibou version should generalize to:

| Column | Notes |
| --- | --- |
| Severity | Shared severity badge |
| Tool | Badge driven by finding source |
| Rule | Linked when source has a canonical rule URL |
| File / location | Path plus line or region |
| Line | Monospace numeric |
| Status | Open, fixed, ignored, accepted risk, etc. |
| First seen | Date of first observation |

What was good:

- The generalized design can reuse the compact rule-inspection workflow from the code quality issue table without losing the category-level aggregation pattern from the static analysis flaw table.

What to improve in Hibou:

- Group by rule with collapsible sections.
- Add inline code snippet preview.
- Add cross-tool normalization so status and severity are consistent.

### MetricTile

Purpose:

- Compact KPI block for dashboards and detail headers.

Proven structure:

- Label in uppercase tiny text.
- Large value.
- Optional subtitle.
- Optional left-border accent for severity or status.
- Optional link mode rendered as `<a>`.

Why it works:

- Fast to scan.
- Minimal chrome.
- Reusable across overview, detail pages, and dashboard sections.

### SevBadge

Purpose:

- Shared severity rendering primitive.

Behavior to keep:

- Maps variations such as `Very High`, `V.High`, and `CRITICAL` into canonical classes.
- Uses pill styling with translucent background and matching foreground color.
- Should be the single severity component used across tables, graphs, cards, and overlays.

### RefPicker

Purpose:

- Large heading-style selector for the current ref context.

Interaction model:

- Styled as a heading rather than a compact form control.
- Opens dropdown on focus or input.
- Supports search-as-you-type filtering.
- Click-outside closes the dropdown.
- Selecting an item navigates to the corresponding detail page.

Visual rules from current CSS:

- Font size `1.5rem`, weight `700`.
- Transparent idle state, elevated hover/focus state.
- Focus ring `0 0 0 2px rgba(88, 166, 255, 0.25)`.
- Dropdown min width `360px`, max height `380px`, radius `0.75rem`.

Hibou reuse:

- Use for branches, releases, tags, pull requests, comparisons, and any other ref context.

### BranchSelector

Purpose:

- Multi-branch comparison selector for trend and dashboard views.
- Lets users build a small working set of refs for side-by-side charts and summary tables.

Current proven shell behavior:

- Selected refs render as removable chips above the input.
- Search input opens the dropdown on focus or input.
- Dropdown filters out already selected refs.
- Click-outside closes the dropdown.
- Default selections are view-owned, not component-owned. Current comparison views pre-populate the first `5` to `6` refs.

Visual rules from the current component:

| Element | Proven value |
| --- | --- |
| Chip padding | `0.625rem 0.25rem` container equivalent via `px-2.5 py-1` |
| Chip radius | `9999px` |
| Chip colors | `background: rgba(88, 166, 255, 0.15); color: #58a6ff; border: 1px solid rgba(88, 166, 255, 0.30)` |
| Remove button | `1rem x 1rem`, rounded, hover tint `rgba(88, 166, 255, 0.30)` |
| Input surface | `background: #1c2128; border: 1px solid #30363d; border-radius: 0.5rem` |
| Input focus | border changes to `#58a6ff` |
| Dropdown shell | `background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; max-height: 15rem` |

Comparison workflow to preserve in Hibou:

- Chips should behave as toggleable comparison tokens, with one-click remove.
- Add explicit `Select all` and `Select none` bulk actions above the dropdown or in the card header when the comparison surface supports many refs.
- Each selected ref should get a stable chart color from the shared comparison palette so the chip list, chart traces, and legends stay aligned.

Shared branch comparison palette:

```ts
[
  "#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#f0883e",
  "#79c0ff", "#56d364", "#e3b341", "#d2a8ff", "#a5d6ff", "#ff7b72",
]
```

Where it is used:

- Multi-branch trend pages.
- Branch comparison dashboard pages.
- Any future base-vs-many comparison workflow.

### DetailTabs

Purpose:

- Lightweight tab navigation for detail views.

Pattern to keep:

- Horizontal tab row with underline-active treatment.
- Tab counts such as `Dependencies (42)`.
- State stored in URL query param so links remain shareable.

Hibou default tabs:

- Weaknesses
- Dependencies
- Runtime
- Secrets

### CommitDeltaBadge

Purpose:

- Simple freshness indicator that communicates how stale a scan or datasource is.

Behavior:

- `0` commits behind: green.
- `1-3`: green.
- `4-8`: yellow.
- `9+`: red.
- Optional link to compare or diff view.

Hibou usage:

- Scan freshness relative to the latest commit.
- PR artifact freshness.
- Data source sync freshness.

### AppSidebar

Purpose:

- Primary navigation shell.

Proven behavior:

- Collapsible desktop mode with smooth width transition.
- Mobile overlay mode with backdrop and close button.
- Grouped nav sections with collapsible groups.
- Active route highlighting.
- Icon-only display when collapsed.
- Footer metadata region.
- Thin custom scrollbar for long navigation lists.

Implementation details to keep:

- Expanded width `240px`.
- Collapsed width `56px`.
- Transition duration `0.2s`.
- Active link uses accent tint background and accent text.

Hibou additions:

- Tenant selector at top.
- Organization / repository hierarchy.
- Space for auth identity and role context.

### SbomTable

Purpose:

- Inventory-first component table for the full software bill of materials.
- Distinct from `DepTable`, which is vulnerability-first and row-oriented around findings.

Columns to preserve:

| Column | Behavior |
| --- | --- |
| Tools | Tool badges for sources that reported the component |
| Ecosystem | Shared ecosystem badge based on PURL type |
| Library | Clickable library name opening the library detail overlay |
| Version | Monospace component version |
| Fixed | Highest known fix version, green when present |
| Vulns | Count badge or muted `0` |

Filter and sort behavior:

- Free-text search across library, version, ecosystem, namespace, and PURL.
- Ecosystem dropdown built from live inventory data.
- Status dropdown with exact buckets: `all`, `vulnerable`, `clean`.
- Filter count display as `N / total`.
- Sort vulnerable components first by descending vulnerability count, then alphabetically by library name.

Interaction model:

- Library name opens `LibDetailModal`.
- Leading graph icon emits a `show-in-graph` event with `{ name, ecosystem }`.
- Rows with vulnerabilities get a left accent border using the high-severity color.

Visual rules from the current component:

| Element | Proven value |
| --- | --- |
| Table container | `max-height: 70vh` with both horizontal and vertical scroll |
| Graph action button | `1.25rem x 1.25rem`, transparent, `opacity: 0.5`, hover color `#58a6ff` |
| Vulnerable row accent | `border-left-width: 2px; border-left-color: #e6550d` |

Why it matters:

- This table is the handoff point from broad component inventory review into either deep library detail or graph navigation.
- It should remain separate from the vulnerability-centric dependency table so users can pivot between inventory and findings without losing context.

## 3. Layout Patterns

### Sidebar + Main

The application shell should stay as a two-column layout:

| Area | Proven sizing |
| --- | --- |
| Sidebar expanded | `240px` |
| Sidebar collapsed | `56px` |
| Main content | Remaining width |
| Mobile sidebar | Overlay with backdrop |

This layout already works well for dense navigation trees and data-heavy content.

### Card Grid

Use the current responsive grid for KPI dashboards:

```html
grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3
```

Preferred card behavior:

- Border-left accent for severity or KPI status.
- Keep metric cards short and visually uniform.

### Card with Header

The standard content card pattern should be reused everywhere:

- Header row with title on the left and actions / counts on the right.
- Header separated by bottom border.
- Tables inside cards should use the current full-bleed trick: negative horizontal margin on the table container so rows reach the card edges while preserving outer card padding.

### Tab + Content

The detail page pattern should remain:

1. Ref picker as the page title.
2. Metadata row under the title.
3. Tab bar.
4. Tab content region below.

This is already a strong structure for ref-specific workflows.

### Alert / All-Clear Pattern

The overview page already uses a reliable conditional summary banner pattern that should be kept for any top-level risk dashboard.

Pattern:

- When actionable high-risk rows exist, show a card with a strong left border and a danger-colored title.
- When no actionable rows exist, swap the whole card for a success state with a green left border and short explanatory copy.
- Both states should stay in the same layout slot directly under the KPI row so the page does not jump structurally.

Exact current values:

| State | Proven styling |
| --- | --- |
| Alert banner | `border-left-width: 4px; border-left-color: #f85149` |
| All-clear banner | `border-left-width: 4px; border-left-color: #3fb950` |
| Count label | muted microcopy in `text-2xs` |

Content rules:

- Alert state uses a compact risk table with links to the affected detail pages.
- All-clear state uses one short confirmation sentence, not a large empty illustration.

### List View Pattern

The branch list, release list, and client delivery pages share a common overview-table composition that should become a standard page template.

Pattern:

- Optional picker or filter control above the table.
- One summary card containing a title, row count, and a full-width table.
- Primary entity in the first column as the main link target.
- Severity or status columns centered for fast scanning.
- Updated timestamps aligned at the right edge of the information hierarchy.

Sorting and prioritization rules:

- Branch and release overview tables should sort highest-risk rows first so severe refs stay above healthy refs.
- Client or delivery tables can stay chronology-first or entity-first, but the link still belongs in the first entity or version column.

Column families to preserve:

| View family | Common columns |
| --- | --- |
| Ref overview list | Ref name, score, severity counts, policy or quality status, client count, freshness delta, updated timestamp |
| Client or delivery list | Client, version or ref link, tag, delivered date, delivery method, commit |

Implementation details to keep:

- Tables live inside a card with the existing negative-margin full-bleed table container.
- First-column links use the accent color and underline on hover.
- Status-heavy numeric columns stay center-aligned.

### Mobile Shell Pattern

The root shell already defines a compact mobile navigation pattern that should remain the baseline.

Pattern:

- Fixed mobile top bar on small screens.
- Hamburger action toggles the sidebar drawer.
- A backdrop overlay darkens and blurs the page while the drawer is open.
- Main content adds top padding on mobile to clear the fixed bar.

Exact current values:

| Element | Proven value |
| --- | --- |
| Mobile top bar height | `3.5rem` |
| Top bar background | `rgba(1, 4, 9, 0.95)` |
| Top bar border | `1px solid #30363d` on the bottom edge |
| Mobile backdrop | `background: rgba(0, 0, 0, 0.5)` with `backdrop-blur(2px)` |
| Main mobile offset | `padding-top: 3.5rem` |
| Main shell transition | `transition-[margin] duration-200` |

Content rules:

- Keep branding in the top bar minimal: menu button plus short product label.
- Close the mobile drawer when the backdrop is clicked.
- Preserve the desktop sidebar collapse behavior rather than maintaining separate navigation systems.

## 4. Chart Patterns

### Chart.js with Dark Theme

Hibou uses [Chart.js](https://www.chartjs.org/) instead of Plotly. The current project used Plotly, but Chart.js provides a smaller bundle, better tree-shaking, and simpler integration with Vue. The proven dark-theme values and interaction patterns below must be carried forward into Chart.js configuration.

Shared Chart.js defaults to replicate:

```ts
export const CHART_DEFAULTS = {
  font: {
    family: "Inter, system-ui, -apple-system, sans-serif",
    size: 12,
    color: "#e6edf3",
  },
  backgroundColor: "transparent",
  responsive: true,
  maintainAspectRatio: false,
  interaction: {
    mode: "index",     // equivalent to Plotly's "x unified" hovermode
    intersect: false,
  },
  plugins: {
    tooltip: {
      backgroundColor: "#161b22",
      borderColor: "#30363d",
      borderWidth: 1,
      titleFont: { family: "Inter, system-ui", size: 12 },
      bodyFont: { family: "Inter, system-ui", size: 12 },
      titleColor: "#e6edf3",
      bodyColor: "#e6edf3",
    },
    legend: {
      position: "bottom",
      labels: {
        color: "#8b949e",
        font: { size: 11 },
        padding: 16,
      },
    },
  },
  scales: {
    x: {
      grid: { color: "#21262d" },
      border: { color: "#30363d" },
      ticks: { color: "#8b949e", font: { size: 12 } },
    },
    y: {
      grid: { color: "#21262d" },
      border: { color: "#30363d" },
      ticks: { color: "#8b949e", font: { size: 12 } },
    },
  },
}
```

Grid and axis rules (same proven values):

- Axis border: `#30363d`
- Grid line: `#21262d`
- Tick text: `#8b949e`
- Axis title text: `#8b949e` at `12px`
- Legend centered below the chart to preserve vertical space

Color palettes already proven:

| Context | Palette |
| --- | --- |
| Severity | `#f85149`, `#e6550d`, `#d29922`, `#8b949e` |
| Multi-branch comparison | `#58a6ff`, `#f85149`, `#3fb950`, `#d29922`, `#bc8cff`, `#f0883e`, `#79c0ff`, `#56d364`, `#e3b341`, `#d2a8ff`, `#a5d6ff`, `#ff7b72` |
| Ecosystem | `maven #e6550d`, `npm #3fb950`, `pypi #58a6ff`, `nuget #bc8cff`, `golang #79c0ff`, `cargo #f0883e`, `gem #f85149`, `deb #d6336c`, `rpm #dbab55`, `oci #6e96b4` |

Shared composable pattern:

- Create a `useChart` composable (replacing the current `usePlotly`) that ensures the canvas element exists before render.
- Handle cleanup on unmount (call `chart.destroy()`).
- Use `ResizeObserver` for responsive behavior.
- Heavy chart components should keep this mount-timing protection.

### Chart Types Used

Proven chart families to preserve:

| Chart type | Purpose |
| --- | --- |
| Stacked area severity trend | Security severity over time |
| Line with fill | Coverage trend |
| Line charts | Score, hotspots, tech debt, issue counts |
| Multi-branch comparison | Small multiples or grouped line charts |
| Grouped / horizontal bars | CWE and ecosystem distribution |
| Heatmap | Library presence / vulnerability distribution across refs |
| Sunburst | Dependency inventory composition |

Hibou should keep all of these and add:

- PR delta bar chart.
- Comparison-focused charts for base vs target ref.

## 5. Interaction Patterns

### Filter Bar Pattern

All data tables should use a consistent filter row:

- Left-aligned controls.
- Text input first when free text exists.
- Then dropdown filters.
- Then reset button.
- Then filter count badge.

Current input styling to keep:

```css
.dep-filter-input {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 0.375rem;
  color: #e6edf3;
  font-size: 0.8rem;
  padding: 0.375rem 0.75rem;
  min-width: 220px;
}
```

Required behavior:

- Dropdown options should be derived from live data when possible.
- Reset must clear all filters at once.
- Show active scope as `N / total` whenever filtering reduces the dataset.

### Info Tooltip

Keep the current CSS-only tooltip pattern for simple metadata:

- Triggered on `.info-tip:hover`.
- Content sourced from `data-tip`.
- Centered above the trigger.
- Dark overlay surface with border and shadow.
- No JavaScript required.

This works well for CWE names, summaries, and component path hints.

### Overlay / Modal Pattern

Shared modal rules:

- Teleport to `body`.
- Fixed backdrop with dark overlay and blur.
- Centered or top-aligned panel depending on content height.
- Close on backdrop click.
- Close button always visible.
- `Escape` support.
- Slide-in animation from `translateY(16px)`.

### Dependency Visualization Flow

The dependency detail view is not just a graph component. It is a coordinated flow across KPIs, a visualization sub-tab shell, the inventory table, and the library detail overlay.

Sub-tab shell pattern:

- The dependency card header contains local sub-tabs separate from the page-level detail tabs.
- Sub-tabs are exactly `Tree` and `Graph`.
- `Tree` renders the sunburst overview and re-renders on activation.
- `Graph` renders the interactive dependency graph only when graph data exists.

Interaction contract:

| Action | Result |
| --- | --- |
| Click `Tree` | Activates the sunburst inventory view |
| Click `Graph` | Swaps the card body to the interactive graph |
| Click library name in `SbomTable` | Opens `LibDetailModal` |
| Click graph icon in `SbomTable` | Switches to `Graph` and calls `focusOn(name, ecosystem)` on `DepGraph` |

Why this matters:

- Users can start in the dense table, identify one component, then jump directly to its graph location without manually searching again.
- The `Tree` view provides composition context, while the `Graph` view provides path and relationship context.
- Keeping both inside the same card avoids route changes during dependency triage.

Implementation details to preserve:

- The graph jump is event-driven from `SbomTable` via `show-in-graph`.
- The detail view owns the sub-tab state and performs `nextTick()` before calling the graph's imperative `focusOn` method.
- The graph sub-tab should stay conditionally available only when a graph payload exists.

### Loading / Empty / Error States

The current app uses lightweight state handling. Hibou should formalize it as a standard pattern:

| State | Pattern |
| --- | --- |
| Loading | Centered spinner or `Loading...` text with muted styling |
| Empty | Centered message plus muted icon |
| Error | Centered error state with icon and retry action |

The current implementation already uses centered text states consistently. Hibou should keep the placement and add a reusable component.

## 6. Ecosystem Type System

The PURL ecosystem badge system is already strong and should be preserved as a platform-wide type language.

| Ecosystem | Background | Text |
| --- | --- | --- |
| maven | `rgba(230, 85, 13, 0.2)` | `#e6550d` |
| npm | `rgba(63, 185, 80, 0.2)` | `#3fb950` |
| pypi | `rgba(88, 166, 255, 0.2)` | `#58a6ff` |
| nuget | `rgba(188, 140, 255, 0.2)` | `#bc8cff` |
| golang | `rgba(121, 192, 255, 0.2)` | `#79c0ff` |
| cargo | `rgba(240, 136, 62, 0.2)` | `#f0883e` |
| gem | `rgba(248, 81, 73, 0.2)` | `#f85149` |
| deb | `rgba(214, 51, 132, 0.2)` | `#d6336c` |
| rpm | `rgba(219, 171, 85, 0.2)` | `#dbab55` |
| oci | `rgba(110, 150, 180, 0.2)` | `#6e96b4` |
| unknown / other | `#21262d` | `#8b949e` |

Usage locations:

- Dependency tables.
- Dependency graph tooltip and future node legend.
- Library detail modal.
- Any package-centric dashboard card.

## 7. Data Flow Pattern (Current -> Hibou)

Current pattern:

```text
static JSON fetch() -> Pinia store -> views
```

Hibou target pattern:

```text
authenticated REST API -> Pinia store -> views
```

Store architecture to preserve:

- One central navigation store for refs, metadata, and top-level bootstrap state.
- Lazy-loaded detail slices per route or feature.
- Caching inside the store to avoid duplicate requests.
- Loading and error state tracked in the store.

Current proven behaviors worth keeping:

- Bootstrap only essential shell data first.
- Load detail payloads when the user actually enters that view.
- Keep helper getters for resolving current branch / release / ref detail.

Hibou additions:

- Auth state in the store: user, tenant, permissions.
- Request cancellation or stale-request protection for fast route changes.
- API client layer separated from store logic.

## 8. Migration Notes

Changes required for Hibou:

1. Replace static file fetches with authenticated REST API calls.
2. Add auth and permission state to the store.
3. Add tenant context to the sidebar and to every API call.
4. Generalize tool-specific dashboards into unified finding and dependency views.
5. Add a PR view with delta summary and finding diff.
6. Add a ref comparison view with base and target selection plus dependency diff.
7. Add admin and settings views.
8. Use Chart.js for all charting (not Plotly).

Charting note:

- Chart.js provides smaller bundles, better tree-shaking, and simpler Vue integration than Plotly.
- Ensure the dark-theme defaults and color palettes from the current project are carried forward.
- The proven interaction patterns (hover tooltips, stacked areas, line fills) are all achievable with Chart.js.

## 9. CSS Architecture

The current CSS architecture is good and should be preserved.

Current approach:

- Single `main.css` for system-wide tokens and shared classes.
- Tailwind v4 `@theme` block for design tokens.
- Utility classes for layout and spacing.
- Named CSS classes for complex components like tables, tooltips, overlays, graphs, and pickers.
- Scoped styles only for truly component-local behavior.

Recommended Hibou rule:

- Keep the hybrid model.
- Do not force everything into raw utilities.
- Use shared semantic classes for any complex component with repeated behavior.

This is especially important for:

- Graph styling.
- Sticky table shells.
- Modal overlays.
- Ref picker.
- Shared badges.

## 10. Accessibility & Performance Notes

The current UI is strong visually but Hibou should close the remaining gaps.

Accessibility work to add:

- Keyboard navigation for all interactive elements.
- Focus ring styles aligned with the accent system.
- ARIA labels on graph nodes and controls.
- Proper dialog semantics for modals.
- Better screen-reader labeling for icons and counts.

Performance work to add:

- Virtual scrolling for tables with `500+` rows.
- Lazy loading for heavy graph and chart components.
- Route-level code splitting, which already fits the current architecture.
- Search debouncing where needed for API-backed views.
- Background prefetch only for high-probability next views, not the whole app.

## Porting Guidance Summary

What to keep almost unchanged:

- Dark theme tokens and typography.
- Sidebar shell and detail page layout.
- Card, table, badge, tooltip, and ref-picker patterns.
- Dependency graph interaction model.
- Library detail modal concept.
- Shared Chart.js dark theme defaults.
- Store-level lazy loading and caching.

What to rebuild with deliberate improvements:

- Generic finding table abstraction.
- API-backed data client layer.
- Accessibility across graph, tables, and overlays.
- Large dataset performance for tables and graphs.
- Tenant-aware navigation and auth-aware state.

This specification should be treated as the UI baseline for Hibou. The goal is not to redesign from scratch; it is to preserve what already works, generalize the parts that were previously tool-specific, and spend engineering time on new capabilities instead of rediscovering solved UI patterns.