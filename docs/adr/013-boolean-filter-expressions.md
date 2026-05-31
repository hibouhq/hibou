# ADR-013: Boolean filter expressions for vulnerabilities

## Status

Proposed

## Context

Hibou's vulnerability list currently accepts individual query parameters such as `type=sast&severity=high&status=detected`. That model works for straightforward narrowing because every filter is combined with an implicit `AND`, but it stops short of the boolean expressions users expect from issue trackers and code-hosting products.

The current approach cannot express:

- cross-field `OR`, such as `type:sast OR type:secret`
- grouped conditions, such as `(type:sast OR type:dependency) AND severity:critical`
- mixed boolean expressions that combine reusable qualifiers with precise precedence

GitHub Issues and pull requests support qualifier-based boolean filters such as `(label:bug OR label:enhancement) AND status:open`. Hibou should provide a comparable query surface for vulnerability exploration while preserving the existing query-parameter API.

## Decision

Hibou will add a `q` query parameter for vulnerability-list endpoints. The `q` parameter accepts boolean filter expressions built from the same qualifier keys the API already supports today.

When `q` is present:

- the frontend parses the expression for highlighting, validation, and canonical serialization
- the backend parses the same expression and converts it into parameterized SQL
- `q` takes precedence over individual query parameters

When `q` is absent, the existing individual query parameters continue to work unchanged.

### Supported syntax

- `key:value` qualifiers
- supported keys: `type`, `severity`, `status`, `scanner`, `language`, `file`
- whitespace between qualifiers means implicit `AND`
- explicit `AND` keyword, case-insensitive
- explicit `OR` keyword, case-insensitive
- parentheses for grouping
- `key:val1,val2` as shorthand for `OR` within the same key
- operator precedence: `AND` binds tighter than `OR`, unless parentheses override it

Examples:

- `type:sast severity:critical`
- `type:sast OR type:secret`
- `(type:sast AND severity:critical) OR type:secret`
- `(type:sast OR type:dependency) AND severity:critical,high`

## Implementation

The implementation is split across frontend and backend parsing layers:

- frontend parser in `site/src/lib/filter-parser.ts`
- backend parser and SQL builder in `internal/filterquery/`
- dynamic SQL execution in the vulnerability store for `q`-driven filtering

The backend SQL builder must remain fully parameterized. It may assemble SQL structure dynamically, but it must never interpolate user-provided values directly into the query string.

## Backward Compatibility

The existing API surface remains valid:

- `type=sast&severity=high` continues to work
- existing UI state based on individual query params continues to work
- `q` only changes behavior when it is present, and then it takes precedence over the individual params

## Consequences

Benefits:

- users can express cross-field `OR` and grouped conditions without expanding the API surface with more dedicated parameters
- frontend and backend share one consistent expression model
- the new query surface matches familiar GitHub-style qualifier workflows

Tradeoffs:

- Hibou now owns parser logic in both TypeScript and Go
- vulnerability listing requires a hand-written dynamic SQL path alongside sqlc-generated static queries
- invalid `q` expressions must be validated and surfaced cleanly to the caller
