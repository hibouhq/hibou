# ADR 011: Reproducible Builds

## Status

Accepted

## Context

Supply-chain security requires that any auditor or developer can rebuild the exact same binary from the same source commit. Without reproducibility, it is impossible to verify that a released artifact matches its claimed source, undermining trust in the entire release pipeline.

Go supports reproducible builds natively when certain conditions are met, but several common build patterns break reproducibility:

1. **Timestamps** — embedding `date -u` output creates a different binary every second.
2. **Absolute paths** — Go embeds the build directory into debug info and stack traces.
3. **Floating base images** — `golang:1.26-bookworm` resolves to different images over time as patches are applied.
4. **Build version control info** — `go build` embeds VCS metadata by default, which varies across machines.

## Decision

We adopt the following reproducibility guarantees:

### Go binaries (bit-for-bit reproducible)

- **`-trimpath`** — strips absolute filesystem paths from the binary. Added to both `Makefile` (`GO_BUILD_FLAGS`) and `Dockerfile`.
- **`-buildvcs=false`** — prevents Go from embedding VCS state that varies across build environments. Already in place.
- **Deterministic timestamp** — `DATE` is derived from `git log -1 --format=%cI` (author date of HEAD commit) instead of wall-clock time. Same commit always produces the same `DATE` value. The Dockerfile default is the Unix epoch.
- **`CGO_ENABLED=0`** — static linking, no dependency on host C libraries. Already in place for cross-compilation.

Given identical Go toolchain version, `go build -trimpath -buildvcs=false -ldflags "..."` with the same ldflags produces identical binaries regardless of build machine or time.

### Docker images (fully reproducible)

- **Pinned base images by digest** — `node:22-bookworm-slim@sha256:...`, `golang:1.26-bookworm@sha256:...` for build stages, and `cgr.dev/chainguard/static@sha256:...` (Wolfi-based) for the runtime image.
- **Chainguard/Wolfi runtime** — Wolfi images are built with apko (declarative, reproducible by design), ship with built-in SBOMs for every package, and typically carry 0 known CVEs. The `static` variant is used since our Go binary is fully statically linked (`CGO_ENABLED=0`).
- **`SOURCE_DATE_EPOCH`** — passed as a build arg, set to the git commit timestamp (`git log -1 --format=%ct`). BuildKit clamps all file timestamps in layers to this epoch, producing identical layer digests across rebuilds.
- **`npm ci`** — installs from lockfile only, deterministic dependency resolution.
- **Whitelist `.dockerignore`** — only source files enter the build context, preventing stray files from invalidating layers or leaking into the image.

Same commit with same base image digests produces an identical image ID.

### Verification

To verify reproducibility:

```bash
# Go binary: rebuild and compare checksum against dist/
make build
make check-reproducible

# Docker image: build twice, compare image IDs
make check-reproducible-image
```

### Digest update process

Base image digests are pinned in the `Dockerfile`. When updating a base image (e.g., Go patch release, Node update), update the digest and record the change in the commit message. Renovate is configured to propose these updates automatically.

## Consequences

- **Same commit = same binary**, regardless of when or where it is built.
- Developers must update pinned digests when upgrading base images (automated via Renovate).
- `-trimpath` removes local paths from panic stack traces, which is the correct behavior for production binaries.
- Using `git log -1 --format=%cI` for `DATE` means the build timestamp reflects when the code was committed, not when the build ran — this is intentional and preferred for reproducibility.
