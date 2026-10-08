variable "REPO" {
    default = "ghcr.io/hibouhq/hibou"
}

variable "RELEASE_VERSION" {
    default = ""
}

variable "SOURCE_DATE_EPOCH" {
    default = "0"
}

variable "BASE_IMAGE" {
    default = "hibou-base:latest"
}

variable "GITHUB_SHA" {
    default = ""
}

variable "PUSH" {
    default = false
}

variable "CACHE_PUSH" {
    default = false
}

variable "LATEST" {
    default = false
}

variable "STABLE_RELEASE" {
    default = false
}

variable "SHA_TAG" {
    default = ""
}

variable "CACHE_REPO" {
    default = ""
}

variable "GIT_BRANCH" {
    default = ""
}

variable "GIT_TARGET_BRANCH" {
    default = ""
}

variable "GIT_DEFAULT_BRANCH" {
    default = "main"
}

variable "INCLUDE_EXTRA_CLI_BINARIES" {
    default = false
}

variable "PLATFORMS" {
    default = "linux/amd64,linux/arm64"
}

target "default" {
    context    = "."
    platforms  = split(",", PLATFORMS)
    output     = PUSH ? ["type=registry"] : ["type=docker"]
    tags = compact([
        RELEASE_VERSION != "" ? "${REPO}:${RELEASE_VERSION}" : "",
        RELEASE_VERSION != "" && STABLE_RELEASE ? "${REPO}:${join(".", slice(split(".", RELEASE_VERSION), 0, 2))}" : "",
        RELEASE_VERSION != "" && STABLE_RELEASE && LATEST ? "${REPO}:latest" : "",
        SHA_TAG != "" ? "${REPO}:${SHA_TAG}" : "",
    ])
    labels = {
        "org.opencontainers.image.licenses" = "AGPL-3.0-only"
        "org.opencontainers.image.source"   = "https://github.com/hibouhq/hibou"
        "org.opencontainers.image.version"  = coalesce(RELEASE_VERSION, SHA_TAG, "dev")
        "org.opencontainers.image.revision" = GITHUB_SHA
        "org.opencontainers.image.created"  = timestamp()
    }
    annotations = [
        "index,manifest:org.opencontainers.image.licenses=AGPL-3.0-only",
        "index,manifest:org.opencontainers.image.source=https://github.com/hibouhq/hibou",
        "index,manifest:org.opencontainers.image.version=${coalesce(RELEASE_VERSION, SHA_TAG, "dev")}",
        "index,manifest:org.opencontainers.image.revision=${GITHUB_SHA}",
        "index,manifest:org.opencontainers.image.created=${timestamp()}",
    ]
    args = {
        SOURCE_DATE_EPOCH          = SOURCE_DATE_EPOCH
        BASE_IMAGE                 = BASE_IMAGE
        INCLUDE_EXTRA_CLI_BINARIES = INCLUDE_EXTRA_CLI_BINARIES ? "true" : "false"
    }
    cache-from = compact([
    "type=registry,ref=${CACHE_REPO}:buildcache-${GIT_DEFAULT_BRANCH}",
    GIT_TARGET_BRANCH != "" && GIT_TARGET_BRANCH != GIT_DEFAULT_BRANCH ? "type=registry,ref=${CACHE_REPO}:buildcache-${GIT_TARGET_BRANCH}" : "",
    GIT_BRANCH != "" && GIT_BRANCH != GIT_DEFAULT_BRANCH && GIT_BRANCH != GIT_TARGET_BRANCH ? "type=registry,ref=${CACHE_REPO}:buildcache-${GIT_BRANCH}" : "",
  ])
    cache-to = CACHE_PUSH ? ["type=registry,ref=${CACHE_REPO}:buildcache-${GIT_BRANCH},mode=max"] : []
}
