# hibou-upload

Composite action for **GitHub Actions** and **Forgejo Actions** that runs a `hibou` CLI you supply (or a checksum-pinned download), then uploads artifact files through the unified `hibou upload` command with server-side content detection.

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
- `cli-path`: Recommended. Absolute path to a `hibou` binary you built or verified (e.g. a cosign-verified release asset). Nothing is downloaded when set.
- `cli-sha256`: Expected SHA-256 of the CLI for the runner's OS/arch. Required to download the CLI from the server; a mismatch fails the step.

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

The CLI runs with your API token, so the action never executes an unverified binary:

1. `cli-path` set: that binary is used as-is.
2. Otherwise, `cli-sha256` set: the CLI is downloaded from `${server}/api/v1/bin/{runner-os}/{runner-arch}` into a fresh temp directory and used only if its SHA-256 matches.
3. Otherwise, a `hibou` already on `PATH` (installed by your workflow) is used.
4. Otherwise the step fails.

The binary is invoked by absolute path. The action does not modify `GITHUB_PATH`.

Run the upload in its own job with minimal permissions (`contents: read`) and only the Hibou token, separate from jobs that hold release, registry or signing credentials.

## Example

Minimal — `server`, `token`, `file`, plus `cli-path` or `cli-sha256`:

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
          # SHA-256 of the CLI for this runner (linux/amd64), from the release checksums.
          cli-sha256: ${{ vars.HIBOU_CLI_SHA256 }}
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
