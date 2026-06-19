# syntax=docker/dockerfile:1

# renovate: datasource=github-releases packageName=chainguard-dev/apko
ARG APKO_VERSION='1.2.14'
# renovate: datasource=github-releases depName=cli/cli extractVersion=^v(?<version>.+)$
ARG GH_CLI_VERSION='2.74.0'
# renovate: datasource=golang-version packageName=go
ARG GO_VERSION='1.26.3'
# renovate: datasource=github-releases packageName=golangci/golangci-lint
ARG GOLANGCI_LINT_VERSION='2.12.2'
# renovate: datasource=github-releases depName=securego/gosec extractVersion=^v(?<version>.+)$
ARG GOSEC_VERSION='2.27.0'
# renovate: datasource=github-releases depName=sqlc-dev/sqlc extractVersion=^v(?<version>.+)$
ARG SQLC_VERSION='1.31.1'
# renovate: datasource=github-releases depName=swaggo/swag extractVersion=^v(?<version>.+)$
ARG SWAG_VERSION='1.16.6'
# renovate: datasource=github-releases depName=gotestyourself/gotestsum extractVersion=^v(?<version>.+)$
ARG GOTESTSUM_VERSION='1.13.0'
# renovate: datasource=github-releases packageName=helm/helm
ARG HELM_VERSION='4.2.0'
# renovate: datasource=github-releases packageName=oras-project/oras
ARG ORAS_VERSION='1.3.0'
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

# renovate: datasource=github-tags depName=devcontainers/features extractVersion=^feature_docker-in-docker_(?<version>.+)$
ARG DIND_FEATURE_VERSION='3.0.1'

FROM mcr.microsoft.com/devcontainers/base:noble AS base
SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]
ARG TARGETARCH
ARG GH_CLI_VERSION GO_VERSION GOLANGCI_LINT_VERSION GOSEC_VERSION GOTESTSUM_VERSION NODE_MAJOR RTK_VERSION SQLC_VERSION SWAG_VERSION

RUN <<EOF
    packages=(
        postgresql-client
        ca-certificates
        curl
        gnupg
        dnsutils
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
    arch="$(echo "${TARGETARCH}" | sed 's/arm64/aarch64/' | sed 's/amd64/x86_64/')"
    # swag release assets use x86_64/arm64 naming (not aarch64)
    swag_arch="$(echo "${TARGETARCH}" | sed 's/amd64/x86_64/')"

    # Install Go tools from prebuilt release binaries rather than `go install`.
    # `go install` compiles from source under Go ${GO_VERSION}, and these pinned
    # versions reference golang.org/x/tools v0.8.0-v0.25.0, which fail to build
    # on Go 1.25+ (golang/go#74462: "invalid array length -delta * delta").
    curl -fsSL "https://github.com/golangci/golangci-lint/releases/download/v${GOLANGCI_LINT_VERSION}/golangci-lint-${GOLANGCI_LINT_VERSION}-linux-${TARGETARCH}.tar.gz" \
        | tar -xzf - --strip-components=1 -C /usr/local/bin --wildcards '*/golangci-lint'
    golangci-lint --version

    curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${TARGETARCH}.tar.gz" \
        | tar -xzf - -C /usr/local/bin gosec
    gosec --version

    GOBIN=/usr/local/bin go install "github.com/go-delve/delve/cmd/dlv@latest"
    dlv version

    curl -fsSL "https://github.com/sqlc-dev/sqlc/releases/download/v${SQLC_VERSION}/sqlc_${SQLC_VERSION}_linux_${TARGETARCH}.tar.gz" \
        | tar -xzf - -C /usr/local/bin sqlc
    sqlc version

    curl -fsSL "https://github.com/swaggo/swag/releases/download/v${SWAG_VERSION}/swag_${SWAG_VERSION}_Linux_${swag_arch}.tar.gz" \
        | tar -xzf - -C /usr/local/bin swag
    swag --version

    curl -fsSL "https://github.com/gotestyourself/gotestsum/releases/download/v${GOTESTSUM_VERSION}/gotestsum_${GOTESTSUM_VERSION}_linux_${TARGETARCH}.tar.gz" \
        | tar -xzf - -C /usr/local/bin gotestsum
    gotestsum --version

    rtk_target='unknown-linux-gnu'
    if [ "${TARGETARCH}" = 'amd64' ]; then
        rtk_target='unknown-linux-musl'
    fi
    curl -fsSL "https://github.com/rtk-ai/rtk/releases/download/v${RTK_VERSION}/rtk-${arch}-${rtk_target}.tar.gz" \
        | tar -xzf - -C /usr/local/bin rtk
    rtk --version

    curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_$(dpkg --print-architecture).tar.gz" \
        | tar -xzf - --strip-components=2 -C /usr/local/bin --wildcards '*/bin/gh'
    gh --version
EOF

FROM base AS build-tools-infra
ARG TARGETARCH
ARG APKO_VERSION KUBECTL_VERSION K9S_VERSION OPENTOFU_VERSION HELM_VERSION ORAS_VERSION VCLUSTER_VERSION

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

	wget -qO /tmp/oras.tar.gz "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${TARGETARCH}.tar.gz"
	tar -xzf /tmp/oras.tar.gz -C /tmp/output-bin/ "oras"
	rm -f /tmp/oras.tar.gz
	/tmp/output-bin/oras version

	wget -qO /tmp/output-bin/vcluster "https://github.com/loft-sh/vcluster/releases/download/v${VCLUSTER_VERSION}/vcluster-linux-${TARGETARCH}"
	chmod +x /tmp/output-bin/vcluster
	/tmp/output-bin/vcluster version

    wget -qO /tmp/apko.tar.gz "https://github.com/chainguard-dev/apko/releases/download/v${APKO_VERSION}/apko_${APKO_VERSION}_linux_${TARGETARCH}.tar.gz"
    tar -xzf /tmp/apko.tar.gz -C /tmp/output-bin/ --strip-components=1 --wildcards '*/apko'
    rm -f /tmp/apko.tar.gz
    /tmp/output-bin/apko version
EOF

FROM base AS final
ARG DIND_FEATURE_VERSION

ARG DIND_FEATURE_VERSION
RUN <<EOF
	curl -fsSL "https://raw.githubusercontent.com/devcontainers/features/feature_docker-in-docker_${DIND_FEATURE_VERSION}/src/docker-in-docker/install.sh" -o /tmp/docker-in-docker-install.sh
	chmod +x /tmp/docker-in-docker-install.sh

	VERSION="latest" \
	MOBY="true" \
	DOCKERDASHCOMPOSEVERSION="v2" \
	USERNAME="vscode" \
	INSTALLDOCKERBUILDX="true" \
	/tmp/docker-in-docker-install.sh

	rm -f /tmp/docker-in-docker-install.sh
EOF

COPY --from=build-tools-infra /tmp/output-bin/ /usr/local/bin/
