# ADR-033: Org-shared search presets

## Status

Proposed — deferred. Not scheduled; personal presets cover the immediate need.

## Context

The findings filter bar (repository and organization vulnerability lists) has
saved **search presets**: a name plus the exact bar text, applied in one click
from a **Presets** button next to the filter buttons. Today there are two kinds:

- **Built-in**: *Open risk* and *Exploited open risk*. Defined in the frontend,
  always present, not deletable.
- **Personal**: saved by each user, visible only to them, on every findings
  list they open.

Personal presets do not help a team triage the same way. Everyone rebuilds
"critical dependencies" or "disputed suppressions" on their own, slightly
differently, and there is nothing to point a newcomer at. This ADR adds presets
shared by an organization: **team presets**.

## Decision

### Scope and permissions

A team preset belongs to one organization. The org findings list and every
repository findings list in that org show the same team presets. There is no
per-repository or per-team level: most useful queries do not depend on the
repository, and a preset that does not fit a list (for example one using
`file:` on the org list) is already shown greyed out.

| | Org admin | Other org members | Scoped API token |
|---|---|---|---|
| See and apply team presets | yes | yes | no |
| Create, edit, delete team presets | yes | no | no |

Admin-only writes keep the list curated. Widening writes to `developer` later
is a policy change with no data change. Personal presets stay private; admins
never see other people's.

### UX

#### Presets menu

One button, one menu. The new **Team** section sits between the built-ins and
the user's own presets, so the most shared choices come first:

```
[ 🔖 Team · Critical deps ▾ ]

  Built-in
    Open risk
    Exploited open risk
  ─────────────────────────────
  Team                         (shown when it has presets, or to admins)
  ✓ Critical deps                         🗑   ← delete: admins only
    Disputed suppressions                 🗑
  ─────────────────────────────
  Mine
    My SAST triage                    👥  🗑   ← 👥 "Share with org": admins only
  ─────────────────────────────
  ⊕ Save current query…
```

- **Button label**: the active preset's name, prefixed `Team · ` when it is a
  team preset, so a team preset and a personal one with the same name are
  never confused. `Presets` when nothing matches.
- **Matching order**: if the current query matches presets in several
  sections, the label shows the first match in menu order (Built-in, Team,
  Mine).
- **Row actions** appear on hover, as today. Members never see write controls
  on team rows.
- **Unusable presets** (filters the current list does not have) stay greyed
  out with the tooltip "Uses filters this list does not have", as today.
- **Loading and errors are per section**: if team presets fail to load, the
  Team section shows "Team presets could not be loaded." and the other
  sections still work.
- **Empty Team section**: hidden for members. Admins see "No team presets
  yet — save a query and tick *Share with org*."

#### Saving

The existing save dialog (query shown with the bar's colouring, name field)
gains one control for admins:

```
┌ 🔖 Save search preset ───────────────────────────────┐
│ QUERY                                                 │
│ (status:detected OR …) AND type:dependency            │
│                                                       │
│ NAME                                                  │
│ [ Critical deps                                    ]  │
│                                                       │
│ ☐ Share with org — everyone in Acme sees it           │  ← admins only
│                                                       │
│ ⚠ Critical deps already exists in Team — saving       │
│   replaces its query.                                 │
│                                    [Cancel] [Replace] │
└───────────────────────────────────────────────────────┘
```

- Unticked: saves to **Mine** (today's behaviour). Ticked: saves to **Team**.
- The "already exists" note and the **Replace** button check the section
  being saved to, and the note names it ("in Team" / "in Mine").
- "Save current query…" stays disabled when the query already matches any
  preset in any section ("Already saved as “X”").
- After saving, the menu button shows the new preset's label and a toast
  confirms "Saved team preset “X”" or "Saved preset “X”".

#### Sharing an existing personal preset

The 👥 action on a **Mine** row opens the same dialog with the box ticked and
the name and query prefilled. Saving **copies** the preset to Team. The
personal one stays, so an admin later editing or deleting the team copy never
changes anyone's private list.

#### Deleting

The existing delete dialog (name plus coloured query, red **Delete** button).
For a team preset the title reads **Delete team preset** and the dialog adds
"Removes it for everyone in Acme."

#### Renaming or changing a team preset's query

No separate edit screen. Changing the query = save the new query under the
same name and confirm **Replace**. Renaming = save under the new name, then
delete the old one. This keeps the UI to the two dialogs that already exist.

### Audit

Every create, update and delete of a team preset is written to the org audit
log, with the preset's name, query and list (`findings`); an update also
records the previous name and query. New actions
`search_preset.create | update | delete`, resource type `search_preset`.
Personal presets are not audited.

### Database

Personal presets live in `search_presets` (migration 00039). Team presets use
the same table with a different owner. Target shape:

| Column | Type | Notes |
|---|---|---|
| `id` | uuid PK | |
| `scope_type` | text | `'user'` or `'org'` |
| `owner_user_id` | uuid → users, ON DELETE CASCADE | set only for `'user'` |
| `org_id` | uuid → organizations, ON DELETE CASCADE | set only for `'org'` |
| `created_by` | uuid → users, ON DELETE SET NULL | author; a team preset survives its author's deletion |
| `surface` | text | which filter bar; only `'findings'` today |
| `name` | text | 1–80 characters |
| `query` | text | 1–2000 characters, valid for the server's query parser |
| `created_at`, `updated_at` | timestamptz | |

Constraints:

- exactly one owner: `'user'` ⇒ `owner_user_id` set and `org_id` NULL;
  `'org'` ⇒ `org_id` set and `owner_user_id` NULL;
- unique name, ignoring case, per `(owner_user_id, surface)` for personal
  presets and per `(org_id, surface)` for team presets;
- at most 100 presets per owner and surface (enforced by the API).

Differences from 00039 as written today: `owner_user_id` is NOT NULL and the
only owner, there is no `created_by`, and a placeholder `scope_id` column has
no foreign key. If 00039 is still unreleased when this work starts, change it
in place. Otherwise add a migration that adds `created_by` (backfilled from
`owner_user_id`) and `org_id`, drops `scope_id`, relaxes `owner_user_id` and
replaces the scope check and indexes.

### API

Same shape as the personal endpoints; browser sessions only (scoped API
tokens are refused, as for personal presets).

| Method | Path | Who | Result |
|---|---|---|---|
| GET | `/api/v1/orgs/{provider}/{slug}/search-presets?surface=findings` | org members | 200, list ordered by name |
| POST | `/api/v1/orgs/{provider}/{slug}/search-presets` | org admins | 201, created preset |
| PUT | `/api/v1/orgs/{provider}/{slug}/search-presets/{id}` | org admins | 200, updated preset |
| DELETE | `/api/v1/orgs/{provider}/{slug}/search-presets/{id}` | org admins | 204 |

Bodies: POST `{surface, name, query}`; PUT `{name, query}`. Response items are
the same as the personal endpoint, with `scope_type: "org"`:

```json
{ "id": "…", "scope_type": "org", "surface": "findings",
  "name": "Critical deps", "query": "severity:critical type:dependency",
  "created_at": "…", "updated_at": "…" }
```

Errors: 400 invalid name, query, surface or limit reached; 403 not an org
admin; 404 unknown org, no role in it, or a preset id belonging to another
org; 409 name already used by a team preset of that org.

## Not in scope

- An org **default** preset (the list opening on, say, *Open risk*).
- Team- or repository-level presets.
- Ordering, pinning, usage counts.
- Notifying anyone when a team preset changes; the audit log is the record.

## Consequences

- Members of orgs without team presets see no change.
- Admins take on a small curation duty, reviewable in the audit log.
- The schema change is the main cost, and it is cheapest before 00039 ships.

## Open questions

- Is admin-only too strict in practice? Widening to `developer` is the
  expected next step.
