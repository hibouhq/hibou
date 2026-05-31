# ADR-008: Coverage report integration

## Status
Accepted

## Context
Code coverage is a key software quality signal. Teams want to correlate security posture (SBOM/SARIF) with code health (coverage) in one platform. Today, coverage data lives in separate tools (Codecov, Coveralls, SonarQube) with no connection to vulnerability and dependency data.

Most CI pipelines already produce coverage reports in standard formats. Supporting coverage upload through the same unified endpoint and CLI keeps the developer experience consistent.

## Decision

### Supported formats
The upload endpoint auto-detects coverage format from file content:

| Format | Detection | Producers |
|--------|-----------|-----------|
| Cobertura XML | `<coverage>` root + `line-rate` or `branch-rate` attr | Go (gocover-cobertura), Python (coverage.py), Java (Maven/Gradle plugins), JS (Istanbul) |
| JaCoCo XML | `<report>` root + `jacoco` in content | Java, Kotlin (Gradle, Maven) |
| Clover XML | `<coverage>` root + `clover` in content | PHP (PHPUnit), Atlassian tools |
| LCOV | `TN:` or `SF:` line prefix | gcov, Istanbul/nyc, llvm-cov, genhtml |
| Go cover profile | `mode:` prefix (`set`, `count`, or `atomic`) | `go test -coverprofile` |

### Unified upload path
Coverage uses the same `POST /api/v1/upload` endpoint as SBOM and SARIF. The CLI command `hibou upload coverage.xml` auto-detects the format. No separate endpoint or flag needed.

### Storage model
Coverage reports are stored as snapshot artifacts like SBOMs and SARIF files. A future coverage parser will extract per-file and per-package metrics for:
- Line coverage percentage
- Branch coverage percentage
- Coverage delta on PRs
- Coverage trend over time
- Quality gate integration (e.g., "block if coverage drops below 80%")

### Coverage UX
When a PR coverage snapshot arrives, Hibou compares its total line coverage percentage against the latest snapshot on the PR target branch. Hibou surfaces the delta in PR status checks and comments so reviewers can see whether coverage improved or regressed without opening a separate report.

Coverage quality gates are configurable per branch in `.hibou.yaml` under `quality_gates[].coverage`:
- `min_coverage` defines an absolute line coverage floor. The gate fails when total line coverage falls below this percentage.
- `grace` defines the allowed regression percentage versus the target branch. The default is `0`, so any total coverage drop fails unless teams opt into slack.
- `diff_minimum` defines the minimum line coverage percentage required on changed lines only, catching PRs that add uncovered code even when total coverage stays flat.

Repository-wide exclude patterns live under `coverage.exclude` at the config root. They accept glob strings such as `["*_test.go", "testutil/**"]` and remove matching files from aggregate coverage metrics and PR comparisons.

The PR experience also includes per-file line coverage visibility. Hibou shows which files gained or lost coverage so reviewers can localize regressions instead of relying only on a repository-wide number.

### Snapshot grouping
Multiple uploads for the same `ref` and `commit_sha` are grouped into one logical snapshot. This lets CI pipelines publish coverage from several jobs or packages without creating fragmented PR results.

Snapshot completion and gate evaluation follow three strategies, in priority order:

1. **Explicit completion (default)**: The upload API accepts a `complete` flag, defaulting to `true`. When the CLI uploads multiple files in one invocation, it automatically sends `complete: false` for intermediate files and `complete: true` on the last one. Gate evaluation runs immediately on the completing upload, giving instant feedback. Multi-job pipelines set `--complete=false` on intermediate jobs and use `hibou upload --complete` (with no files) in a final dependent job to close the snapshot.

2. **Expected count (opt-in)**: For parallel pipelines where no single job knows it is last, each upload declares `--expect N`. The server counts distinct `POST /upload` API calls for the snapshot and auto-completes once N are received. This avoids the need for a dedicated completion step.

3. **Window timeout (forced close)**: `upload.window` (configured in `.hibou.yaml`, default `10m`) is a safety net that force-closes the snapshot if neither `complete` nor `--expect` triggers completion — for example, when a parallel job crashes and the expected count is never reached. It is not a passive fallback for normal operation.

4. **Single upload**: A single `hibou upload file.xml` sends `complete: true` by default, so single-file workflows get instant gate results with no extra flags.

Within an open snapshot, Hibou deduplicates by content hash: re-uploading the same file replaces the previous artifact entry instead of double-counting it. If CI reruns after the snapshot is completed or the window closes, Hibou creates a new snapshot for the same `ref` and `commit_sha` so historical retries remain auditable.

## Consequences
- The unified upload endpoint handles three artifact families: SBOM, SARIF, coverage
- Coverage detection adds ~20 lines to `detectArtifactType` with no new dependencies
- Coverage uploads now define a concrete PR UX: branch comparisons, coverage deltas, and per-file visibility
- `.hibou.yaml` must support coverage thresholds, exclude patterns, and snapshot upload window configuration
- Snapshot lifecycle expands from single-upload artifacts to grouped, deduplicated coverage snapshots per `ref` and `commit_sha`
- Gate evaluation runs immediately when an upload signals completion or expected count is reached, with `upload.window` as a forced-close safety net for crashed jobs
- The CLI and CI actions still work for coverage uploads with zero command changes because detection remains automatic
