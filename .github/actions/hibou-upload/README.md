# hibou-upload

Composite action for **GitHub Actions** and **Forgejo Actions** that downloads the `hibou` CLI from the target Hibou server, then uploads artifact files through the unified `hibou upload` command with server-side content detection.

For **GitLab CI**, see [`templates/upload/`](../../../templates/upload/) — a [CI/CD Component](https://gitlab.com/explore/catalog) with the same capabilities.

## Inputs

- `server`: Hibou server URL.
- `token`: Hibou API token.
- `org`: Optional. Organization in `provider/slug` form (e.g. `github/my-org`). Auto-detected from CI environment.
- `repo`: Optional. Repository slug. Auto-detected from CI environment.
- `file`: Path(s) to artifact files. Supports glob patterns (e.g., `*.sarif`) and newline-separated paths.
- `tool`: Optional tool name override. Only needed for findings uploads or SARIF files that lack `runs[0].tool.driver.name`.
- `ref`: Optional git ref. Auto-detected from CI environment.
- `sha`: Optional commit SHA. Auto-detected from CI environment.

## Auto-detection

The action auto-detects as much as possible from the CI environment:

| Field | GitHub | Forgejo/Gitea |
|-------|--------|---------------|
| `org` | `github/$GITHUB_REPOSITORY_OWNER` | `forgejo/$GITEA_REPOSITORY_OWNER` |
| `repo` | from `$GITHUB_REPOSITORY` | from `$GITEA_REPOSITORY` |
| `ref` | `$GITHUB_REF` | `$GITEA_REF` |
| `sha` | `$GITHUB_SHA` | `$GITEA_SHA` |

Artifact type detection happens on the server from file content.

## Behavior

The action queries the target server for its current CLI version, reuses an already-installed `hibou` binary when versions match, and otherwise downloads the matching CLI directly from `${server}/api/v1/bin/{runner-os}/{runner-arch}` for the current runner platform.

## Example

Minimal — only `server`, `token`, and `file` are required:

```yaml
jobs:
  security-upload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/hibou-upload
        with:
          server: ${{ secrets.HIBOU_SERVER }}
          token: ${{ secrets.HIBOU_TOKEN }}
          file: results.sarif
```

### Upload everything at once

```yaml
      - uses: ./.github/actions/hibou-upload
        with:
          server: ${{ secrets.HIBOU_SERVER }}
          token: ${{ secrets.HIBOU_TOKEN }}
          file: |
            sbom.cdx.json
            codeql.sarif
            semgrep.sarif
```

### Glob pattern

```yaml
      - uses: ./.github/actions/hibou-upload
        with:
          server: ${{ secrets.HIBOU_SERVER }}
          token: ${{ secrets.HIBOU_TOKEN }}
          file: "reports/*.sarif"
```

All other fields (`org`, `repo`, `ref`, `sha`) are auto-detected. Override any of them explicitly if needed.
