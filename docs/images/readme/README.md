# README Captures

Captured on 2026-10-10 from https://hibouhq.com. Organization overview and Hibou's
own dependency, coverage, and release summaries are included at the owner's request.
Vulnerability examples use the public
[hibou-sample-project](https://github.com/hibouhq/hibou-sample-project), an
intentionally vulnerable scanner fixture, not a production application.

All PNGs and the GIF use a 1980 x 1238 viewport at device scale 1 and browser zoom
100%. No stretching or decorative browser frame is applied. The height preserves
the requested 8:5 proportions to the nearest whole pixel. GitHub scales the images
to the README container; clicking them opens the full-size asset.

Inter and JetBrains Mono, the fonts declared by the application, were supplied
locally to avoid Linux fallback-font differences. Application CSS colors were not changed.

| Asset | View |
| --- | --- |
| `organization.png` | Organization overview, scan freshness, and repository risk. |
| `repository.png` | Main-branch overview, security posture, components, coverage, and artifacts. |
| `findings.png` | Findings list with severity, CVSS, EPSS, sources, and triage controls. |
| `advanced-query.png` | Grouped OR/AND query, autocomplete, and exploited findings. |
| `finding-detail.png` | Log4j finding detail, exploitation context, and remediation. |
| `dependencies.png` | Hibou's real SBOM inventory and SPDX licenses. |
| `coverage.png` | Hibou coverage summary and file-level report. |
| `releases.png` | Hibou release history and client associations. |
| `walkthrough.gif` | Organization-first navigation, query typing, finding detail, repo switch, dependencies, coverage, and releases. |

The GIF loops at 10 fps. It uses lossless PNG browser screencast frames rather than
an intermediate compressed video, preserving sharp text before GIF palette encoding.
It is an interaction recording, not a slideshow of the screenshots.
Capture performed read-only: no scans, triage changes, releases, or deployments were submitted.
