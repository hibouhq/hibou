#!/usr/bin/env bash
# Regenerate the pinned SHA256SUMS block of .devcontainer/Dockerfile from each
# upstream's published checksums, for the versions currently set in its ARGs.
#
# Run after bumping a tool version (Renovate PRs included): the build fails
# closed on any download whose URL has no pinned checksum.
#
#   .devcontainer/scripts/update-checksums.sh          # rewrite the block in place
#   .devcontainer/scripts/update-checksums.sh --print  # print it only
#
# Sources: release checksum files (or the artifact's .sha256 next to it), the
# GitHub release asset digest when the project publishes no checksum file
# (sqlc). The docker-in-docker install script has no published checksum: it is
# pinned to the sha256 of the file at the feature's release tag.
set -euo pipefail

dockerfile="$(cd "$(dirname "$0")/.." && pwd)/Dockerfile"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

arg() {
    local v
    v="$(sed -nE "s/^ARG $1='?([^' ]+)'?\$/\1/p" "${dockerfile}" | head -n1)"
    [ -n "${v}" ] || { echo "ARG $1 not found in ${dockerfile}" >&2; exit 1; }
    printf '%s' "${v}"
}

fetch() { # url -> cached local path
    local f
    f="${tmp}/$(printf '%s' "$1" | sha256sum | cut -c1-16)"
    [ -f "${f}" ] || curl -fsSL --retry 3 -o "${f}" "$1"
    printf '%s' "${f}"
}

emit() { # sha url
    [[ "$1" =~ ^[0-9a-f]{64}$ ]] || { echo "bad sha256 '$1' for $2" >&2; exit 1; }
    printf '%s  %s\n' "$1" "$2"
}

# Artifact listed by basename in a checksums file.
from_sums() { # url sums_url
    local name sha
    name="$(basename "$1")"
    sha="$(awk -v n="${name}" '{ f=$2; sub(/^[*]/, "", f); sub(/^[.][/]/, "", f) } f == n { print $1; exit }' "$(fetch "$2")")"
    [ -n "${sha}" ] || { echo "no checksum for ${name} in $2" >&2; exit 1; }
    emit "${sha}" "$1"
}

# Artifact with a sibling file holding its checksum (first field).
from_sibling() { # url suffix
    emit "$(awk '{ print $1; exit }' "$(fetch "$1$2")")" "$1"
}

# GitHub release asset digest (for projects without a checksums file).
from_gh_digest() { # url owner/repo tag
    local name auth=() sha
    name="$(basename "$1")"
    [ -z "${GITHUB_TOKEN:-}" ] || auth=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
    sha="$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/$2/releases/tags/$3" \
        | python3 -c 'import json,sys; n=sys.argv[1]; print(next(a["digest"] for a in json.load(sys.stdin)["assets"] if a["name"]==n).removeprefix("sha256:"))' "${name}")"
    emit "${sha}" "$1"
}

gh_dl() { printf 'https://github.com/%s/releases/download/%s' "$1" "$2"; }

GO_VERSION="$(arg GO_VERSION)"
NODE_VERSION="$(arg NODE_VERSION)"
GOLANGCI_LINT_VERSION="$(arg GOLANGCI_LINT_VERSION)"
GOSEC_VERSION="$(arg GOSEC_VERSION)"
SQLC_VERSION="$(arg SQLC_VERSION)"
SWAG_VERSION="$(arg SWAG_VERSION)"
GOTESTSUM_VERSION="$(arg GOTESTSUM_VERSION)"
TRIVY_VERSION="$(arg TRIVY_VERSION)"
GITLEAKS_VERSION="$(arg GITLEAKS_VERSION)"
TRUFFLEHOG_VERSION="$(arg TRUFFLEHOG_VERSION)"
BETTERLEAKS_VERSION="$(arg BETTERLEAKS_VERSION)"
RTK_VERSION="$(arg RTK_VERSION)"
GH_CLI_VERSION="$(arg GH_CLI_VERSION)"
KUBECTL_VERSION="$(arg KUBECTL_VERSION)"
K9S_VERSION="$(arg K9S_VERSION)"
OPENTOFU_VERSION="$(arg OPENTOFU_VERSION)"
HELM_VERSION="$(arg HELM_VERSION)"
ORAS_VERSION="$(arg ORAS_VERSION)"
VCLUSTER_VERSION="$(arg VCLUSTER_VERSION)"
APKO_VERSION="$(arg APKO_VERSION)"
DIND_FEATURE_VERSION="$(arg DIND_FEATURE_VERSION)"

block() {
    local a x86 x64 swag trivy rtk_target u
    for a in amd64 arm64; do
        if [ "${a}" = amd64 ]; then
            x86=x86_64 x64=x64 swag=x86_64 trivy=64bit rtk_target=x86_64-unknown-linux-musl
        else
            x86=aarch64 x64=arm64 swag=arm64 trivy=ARM64 rtk_target=aarch64-unknown-linux-gnu
        fi
        : "${x86}"

        from_sibling "https://dl.google.com/go/go${GO_VERSION}.linux-${a}.tar.gz" .sha256
        from_sums "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${x64}.tar.gz" \
            "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt"

        u="$(gh_dl golangci/golangci-lint "v${GOLANGCI_LINT_VERSION}")"
        from_sums "${u}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${a}.tar.gz" "${u}/golangci-lint-${GOLANGCI_LINT_VERSION}-checksums.txt"
        u="$(gh_dl securego/gosec "v${GOSEC_VERSION}")"
        from_sums "${u}/gosec_${GOSEC_VERSION}_linux_${a}.tar.gz" "${u}/gosec_${GOSEC_VERSION}_checksums.txt"
        u="$(gh_dl sqlc-dev/sqlc "v${SQLC_VERSION}")"
        from_gh_digest "${u}/sqlc_${SQLC_VERSION}_linux_${a}.tar.gz" sqlc-dev/sqlc "v${SQLC_VERSION}"
        u="$(gh_dl swaggo/swag "v${SWAG_VERSION}")"
        from_sums "${u}/swag_${SWAG_VERSION}_Linux_${swag}.tar.gz" "${u}/checksums.txt"
        u="$(gh_dl gotestyourself/gotestsum "v${GOTESTSUM_VERSION}")"
        from_sums "${u}/gotestsum_${GOTESTSUM_VERSION}_linux_${a}.tar.gz" "${u}/gotestsum-${GOTESTSUM_VERSION}-checksums.txt"
        u="$(gh_dl aquasecurity/trivy "v${TRIVY_VERSION}")"
        from_sums "${u}/trivy_${TRIVY_VERSION}_Linux-${trivy}.tar.gz" "${u}/trivy_${TRIVY_VERSION}_checksums.txt"
        u="$(gh_dl gitleaks/gitleaks "v${GITLEAKS_VERSION}")"
        from_sums "${u}/gitleaks_${GITLEAKS_VERSION}_linux_${x64}.tar.gz" "${u}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"
        u="$(gh_dl trufflesecurity/trufflehog "v${TRUFFLEHOG_VERSION}")"
        from_sums "${u}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${a}.tar.gz" "${u}/trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt"
        u="$(gh_dl betterleaks/betterleaks "v${BETTERLEAKS_VERSION}")"
        from_sums "${u}/betterleaks_${BETTERLEAKS_VERSION}_linux_${x64}.tar.gz" "${u}/checksums.txt"
        u="$(gh_dl rtk-ai/rtk "v${RTK_VERSION}")"
        from_sums "${u}/rtk-${rtk_target}.tar.gz" "${u}/checksums.txt"
        u="$(gh_dl cli/cli "v${GH_CLI_VERSION}")"
        from_sums "${u}/gh_${GH_CLI_VERSION}_linux_${a}.tar.gz" "${u}/gh_${GH_CLI_VERSION}_checksums.txt"

        from_sibling "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${a}/kubectl" .sha256
        u="$(gh_dl derailed/k9s "v${K9S_VERSION}")"
        from_sums "${u}/k9s_Linux_${a}.tar.gz" "${u}/checksums.sha256"
        u="$(gh_dl opentofu/opentofu "v${OPENTOFU_VERSION}")"
        from_sums "${u}/tofu_${OPENTOFU_VERSION}_linux_${a}.tar.gz" "${u}/tofu_${OPENTOFU_VERSION}_SHA256SUMS"
        from_sibling "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${a}.tar.gz" .sha256sum
        u="$(gh_dl oras-project/oras "v${ORAS_VERSION}")"
        from_sums "${u}/oras_${ORAS_VERSION}_linux_${a}.tar.gz" "${u}/oras_${ORAS_VERSION}_checksums.txt"
        u="$(gh_dl loft-sh/vcluster "v${VCLUSTER_VERSION}")"
        from_sums "${u}/vcluster-linux-${a}" "${u}/checksums.txt"
        u="$(gh_dl chainguard-dev/apko "v${APKO_VERSION}")"
        from_sums "${u}/apko_${APKO_VERSION}_linux_${a}.tar.gz" "${u}/checksums.txt"
    done

    u="https://raw.githubusercontent.com/devcontainers/features/feature_docker-in-docker_${DIND_FEATURE_VERSION}/src/docker-in-docker/install.sh"
    emit "$(sha256sum "$(fetch "${u}")" | cut -d' ' -f1)" "${u}"
}

sums="$(block)"

if [ "${1:-}" = "--print" ]; then
    printf '%s\n' "${sums}"
    exit 0
fi

begin="COPY <<'EOF' /usr/local/share/devcontainer/SHA256SUMS"
grep -qxF "${begin}" "${dockerfile}" || { echo "marker not found: ${begin}" >&2; exit 1; }
BEGIN_LINE="${begin}" SUMS="${sums}" awk '
    BEGIN { begin = ENVIRON["BEGIN_LINE"]; sums = ENVIRON["SUMS"] }
    $0 == begin { print; print sums; skip = 1; next }
    skip && $0 == "EOF" { skip = 0 }
    !skip { print }
' "${dockerfile}" > "${tmp}/Dockerfile"
cat "${tmp}/Dockerfile" > "${dockerfile}"
echo "updated $(printf '%s\n' "${sums}" | wc -l) checksums in ${dockerfile}"
