# syntax=docker/dockerfile:1

# renovate: datasource=github-releases packageName=chainguard-dev/apko
ARG APKO_VERSION='1.2.14'
# renovate: datasource=golang-version packageName=go
ARG GO_VERSION='1.26.3'
# renovate: datasource=github-releases packageName=golangci/golangci-lint
ARG GOLANGCI_LINT_VERSION='2.12.2'
# renovate: datasource=github-releases packageName=helm/helm
ARG HELM_VERSION='4.2.0'
# renovate: datasource=node-version packageName=node
ARG NODE_MAJOR='26'
# renovate: datasource=github-releases packageName=opentofu/opentofu
ARG OPENTOFU_VERSION='1.12.1'
# renovate: datasource=github-releases packageName=loft-sh/vcluster
ARG VCLUSTER_VERSION='0.34.0'
# renovate: datasource=github-releases packageName=derailed/k9s
ARG K9S_VERSION='0.50.18'
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
ARG KUBECTL_VERSION='1.36.1'
# renovate: datasource=github-releases packageName=rtk-ai/rtk
ARG RTK_VERSION='0.42.0'

FROM mcr.microsoft.com/devcontainers/base:noble AS base
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]
ARG TARGETARCH
ARG GO_VERSION GOLANGCI_LINT_VERSION NODE_MAJOR RTK_VERSION

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

    npm install -g @playwright/cli@latest
    playwright-cli --version
EOF

RUN <<EOF
    GOBIN=/usr/local/bin go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VERSION}"
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

FROM base AS build-tools-infra
ARG TARGETARCH
ARG APKO_VERSION KUBECTL_VERSION K9S_VERSION OPENTOFU_VERSION HELM_VERSION VCLUSTER_VERSION

RUN <<EOF
    mkdir -p /tmp/output-bin/
	wget -qO /tmp/output-bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl"
	chmod +x /tmp/output-bin/kubectl
	/tmp/output-bin/kubectl version --client

    wget -qO /tmp/k9s.tar.gz "https://github.com/derailed/k9s/releases/download/v${K9S_VERSION}/k9s_Linux_${TARGETARCH}.tar.gz"
	tar -xzf /tmp/k9s.tar.gz -C /tmp/output-bin/ "k9s"
	rm -f /tmp/k9s.tar.gz
	/tmp/output-bin/k9s version

    wget -qO /tmp/tofu.zip \
        "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_${TARGETARCH}.zip"
    unzip -q /tmp/tofu.zip -d /tmp/output-bin
    rm -f /tmp/tofu.zip
    /tmp/output-bin/tofu version

    wget -qO /tmp/helm.tar.gz "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz"
	tar -xzf /tmp/helm.tar.gz -C /tmp/output-bin/ "linux-${TARGETARCH}/helm" --strip-components=1
	rm /tmp/helm.tar.gz
	/tmp/output-bin/helm version

	wget -qO /tmp/output-bin/vcluster "https://github.com/loft-sh/vcluster/releases/download/v${VCLUSTER_VERSION}/vcluster-linux-${TARGETARCH}"
	chmod +x /tmp/output-bin/vcluster
	/tmp/output-bin/vcluster version

    wget -qO /tmp/apko.tar.gz "https://github.com/chainguard-dev/apko/releases/download/v${APKO_VERSION}/apko_${APKO_VERSION}_linux_${TARGETARCH}.tar.gz"
    tar -xzf /tmp/apko.tar.gz -C /tmp/output-bin/ --strip-components=1 --wildcards '*/apko'
    rm -f /tmp/apko.tar.gz
    /tmp/output-bin/apko version
EOF

FROM base as final

COPY --from=build-tools-infra /tmp/output-bin/ /usr/local/bin/
