variable "REPO" {
    default = "ghcr.io/hibouhq/hibou"
}

variable "VERSION" {
    default = "dev"
}

variable "MAJOR_MINOR" {
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

variable "GIT_BRANCH" {
    default = ""
}

variable "GIT_TARGET_BRANCH" {
    default = ""
}

variable "GIT_DEFAULT_BRANCH" {
    default = "main"
}

target "default" {
    context    = "."
    platforms  = ["linux/amd64", "linux/arm64"]
    output     = PUSH ? ["type=registry"] : ["type=docker"]
    tags = compact([
    "${REPO}:${VERSION}",
    MAJOR_MINOR != "" ? "${REPO}:${MAJOR_MINOR}" : "",
    LATEST ? "${REPO}:latest" : "",
  ])
    labels = {
        "org.opencontainers.image.source"   = "https://github.com/hibouhq/hibou"
        "org.opencontainers.image.version"  = VERSION
        "org.opencontainers.image.revision" = GITHUB_SHA
        "org.opencontainers.image.created"  = timestamp()
    }
    args = {
        SOURCE_DATE_EPOCH = SOURCE_DATE_EPOCH
        BASE_IMAGE        = BASE_IMAGE
    }
    cache-from = compact([
    "type=registry,ref=${REPO}:buildcache-${GIT_DEFAULT_BRANCH}",
    GIT_TARGET_BRANCH != "" && GIT_TARGET_BRANCH != GIT_DEFAULT_BRANCH ? "type=registry,ref=${REPO}:buildcache-${GIT_TARGET_BRANCH}" : "",
    GIT_BRANCH != "" && GIT_BRANCH != GIT_DEFAULT_BRANCH && GIT_BRANCH != GIT_TARGET_BRANCH ? "type=registry,ref=${REPO}:buildcache-${GIT_BRANCH}" : "",
  ])
    cache-to = CACHE_PUSH ? ["type=registry,ref=${REPO}:buildcache-${GIT_BRANCH},mode=max"] : []
}
