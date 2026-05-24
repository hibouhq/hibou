# syntax=docker/dockerfile:1

FROM mcr.microsoft.com/devcontainers/base:noble AS development
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]
ARG TARGETARCH

# renovate: datasource=golang-version packageName=go
ARG GO_VERSION='1.23.9'

# renovate: datasource=github-releases packageName=golangci/golangci-lint
ARG GOLANGCI_LINT_VERSION='1.64.8'

# renovate: datasource=node-version packageName=node
ARG NODE_MAJOR='22'

# renovate: datasource=github-releases packageName=rtk-ai/rtk
ARG RTK_VERSION='0.39.0'

RUN <<EOF
    packages=(
        postgresql-client
        ca-certificates
        curl
        gnupg
    )
    apt-get update
    apt-get install -y --no-install-recommends "${packages[@]}"
    apt-get clean -y
    rm -rf /var/lib/apt/lists/*
EOF

RUN <<EOF
    curl -fsSL "https://dl.google.com/go/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
        | tar -xz -C /usr/local
    echo 'export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"' > /etc/profile.d/go.sh
EOF

ENV PATH="/usr/local/go/bin:/home/vscode/go/bin:${PATH}"

RUN <<EOF
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -
    apt-get install -y --no-install-recommends nodejs
    apt-get clean -y
    rm -rf /var/lib/apt/lists/*
    corepack enable

    npm install -g @playwright/cli@latest
    playwright-cli --version
EOF

RUN <<EOF
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
        | sh -s -- -b /usr/local/bin "v${GOLANGCI_LINT_VERSION}"
    golangci-lint --version

    arch="$(echo "${TARGETARCH}" | sed 's/arm64/aarch64/' | sed 's/amd64/x86_64/')"
    rtk_target='unknown-linux-gnu'
    if [ "${TARGETARCH}" = 'amd64' ]; then
        rtk_target='unknown-linux-musl'
    fi
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/v${RTK_VERSION}/rtk-${arch}-${rtk_target}.tar.gz" \
        | tar -xzf - -C /usr/local/bin rtk
    rtk --version
EOF
