# hibou-upload (GitLab CI/CD Component)

GitLab CI/CD component that downloads the `hibou` CLI from the target Hibou server and uploads SBOM, SARIF, or findings artifacts.

For **GitHub Actions** and **Forgejo Actions**, see [`.github/actions/hibou-upload/`](../../.github/actions/hibou-upload/).

## Usage

```yaml
include:
  - component: gitlab.com/hibouhq/lehibou/upload@main
    inputs:
      server: $HIBOU_SERVER
      token: $HIBOU_TOKEN
      file: sbom.cdx.json
```

All other fields (`org`, `repo`, `ref`, `sha`) are auto-detected from GitLab CI variables.

## Inputs

- `server`: Hibou server URL.
- `token`: Hibou API token.
- `file`: Path(s) to artifact files. Supports glob patterns and newline-separated paths.
- `org`: Optional. Defaults to `gitlab/$CI_PROJECT_NAMESPACE`.
- `repo`: Optional. Defaults to `$CI_PROJECT_NAME`.
- `tool`: Optional tool name override. Only needed for findings uploads or SARIF files that lack `runs[0].tool.driver.name`.
- `ref`: Optional. Defaults to `refs/heads/$CI_COMMIT_REF_NAME`.
- `sha`: Optional. Defaults to `$CI_COMMIT_SHA`.
- `stage`: Pipeline stage. Defaults to `test`.

## Examples

### Upload multiple files

```yaml
include:
  - component: gitlab.com/hibouhq/lehibou/upload@main
    inputs:
      server: $HIBOU_SERVER
      token: $HIBOU_TOKEN
      file: |
        sbom.cdx.json
        semgrep.sarif
```

### Glob pattern

```yaml
include:
  - component: gitlab.com/hibouhq/lehibou/upload@main
    inputs:
      server: $HIBOU_SERVER
      token: $HIBOU_TOKEN
      file: "reports/*.sarif"
```

Tool name is extracted automatically from each SARIF file's `runs[0].tool.driver.name`. The `tool` input is only needed as a fallback for files that lack it.
