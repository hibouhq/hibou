# Offline third-party notices

`hibou deps notices` generates attribution from local package files, without
calling Hibou, registries, package managers or third-party APIs.

```sh
hibou deps notices --write THIRD_PARTY_NOTICES.md
hibou deps notices --check THIRD_PARTY_NOTICES.md
hibou deps notices --format text --write THIRD_PARTY_NOTICES.txt
hibou deps notices app.cdx.json frontend.spdx.json --write THIRD_PARTY_NOTICES.md
hibou deps notices --strict --check THIRD_PARTY_NOTICES.md
```

Install dependencies before generating or checking. Directory inputs use the
existing offline lockfile/manifest inventory, not installed `node_modules`
metadata: installed dev packages must not become shipped packages by losing
their lockfile scope. Explicit binary, archive and SBOM targets reuse the
deliverable inventory. No target means the current directory. For one directory
target, its local `.hibou.yaml`/`.hibou.yml` is discovered automatically;
`--config` selects a different file.

## What ships

Only shipped components are attributed. The built-in not-shipped defaults and
`dependencies.not_shipped`/`dependencies.shipped` rules apply offline.
Dev/test scopes are skipped by default; `notices.dev_scopes: keep` retains them.
Exclusion totals and reasons go to stderr, not the document.

Use the build's SBOM or a compiled binary when a lockfile includes test-only
or build-only dependencies it cannot distinguish. These are candidate shipping
inventories, not proof of bundler reachability. Server-side organization/repository
lists are not fetched. A private registry does **not** make a package first-party:
`dependencies.private_namespaces` is deliberately not an attribution exclusion.
Use explicit, justified `notices.exclude` entries for your own code.

## Evidence and gaps

Sources are the package's original LICENSE/COPYING/copyright and NOTICE files:

| Ecosystem | Local source | Override |
|---|---|---|
| Go | `GOMODCACHE`, `GOPATH/pkg/mod`, then vendor directories | `--gomodcache` |
| Go runtime | Matching local installation, checked against its VERSION file | `--goroot` |
| npm | `node_modules` beside the module, including nested/scoped copies | Directory/SBOM target |
| Maven | `MAVEN_REPO_LOCAL` or `~/.m2/repository`, root/META-INF files in JARs | `--maven-repo` |
| Python | Installed dist-info, including PEP 639 `licenses/`, in local virtualenvs | Repeatable `--site-packages` |
| Cargo | `CARGO_HOME/registry/src`, then vendor directories | `--cargo-home` |

Files are bounded to 1 MiB and 24 evidence files per package, including NOTICE.
Unreadable, oversized, symlinked or corrupt evidence is reported as a gap;
it is never executed. Included manual files are bounded and confined to the
configuration directory, including across symlinks.

The classifier is pinned and its version appears in the document. Copyright
lines and NOTICE content come from actual package files. Distinct normalized
license texts are printed once. Compound AND expressions retain all obligations,
OR alternatives choose the least-demanding recognized alternative (or the
configured choice), and WITH exceptions remain attached to their license.
All observed license texts are retained conservatively, even after an OR choice.
Source/relinking and other beyond-attribution obligations are listed for human
review, never claimed as fulfilled.

Missing packages/text, unknown licenses, declaration/text mismatches, missing
copyright lines and invalid choices remain explicit gaps. Identifier or
copyright overrides cannot manufacture a missing license text. An unresolved
shipped package identity, invalid configuration, or incomplete inventory is an
input error rather than a silently omitted component. Unidentified files in a
deliverable also require a resolved build SBOM instead of a completeness claim.

```yaml
version: 1
notices:
  dev_scopes: skip
  include:
    - NOTICES.manual.md
  overrides:
    - purl: "pkg:npm/example@1.2.3"
      license: "MIT AND ISC"
      reason: "The package's LICENSE includes both texts"
    - purl: "pkg:cargo/example"
      choose: "Apache-2.0"
      reason: "Select the alternative explicitly offered by upstream"
  exclude:
    - purl: "pkg:npm/@our-project/*"
      reason: "Our own code, not third-party"
```

Version-specific overrides win over versionless ones. Every override/exclusion
requires a reason. `include` appends manually maintained attribution for ported
or vendored code that has no inventory entry.

## Exit codes and repeatability

- **0:** generation/check succeeded.
- **1:** `--check` found a difference, or `--strict` found gaps.
- **2:** input, configuration, inventory, file or other operational error.

Without `--write`/`--check`, the document goes to stdout; the report goes to
stderr. `--check` never writes the file. `--write` and `--check` are mutually
exclusive. Format is Markdown unless `.txt` selects text or `--format` is set.
There is no timestamp, absolute cache location or Hibou build version in the
document. A classifier upgrade may intentionally change it.

Hibou's `make notices` builds a local binary to identify linked Go modules, then
combines it with the frontend's lockfile inventory. It does not install npm
dependencies or fetch license evidence. Run `make check-notices` with identical
caches/toolchain after regeneration. Review remaining gaps before distribution;
`make check-notices` only checks drift, not legal completeness. CI enforcement,
embedded/downloadable notices and server-side evidence are later ADR-051 phases.
