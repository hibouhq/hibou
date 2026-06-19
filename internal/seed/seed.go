package seed

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: SHA1 is used only for deterministic fake git hashes in seed data.
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/store"
	"github.com/hibouhq/hibou/internal/store/dbgen"
)

type seededOrg struct {
	name     string
	slug     string
	provider string
	teams    []string
	repos    []seededRepo
}

type seededRepo struct {
	name       string
	slug       string
	team       string
	label      string
	providerID string
	components []seededComponent
	findings   []seededFinding
}

type seededComponent struct {
	purl      string
	name      string
	version   string
	ecosystem string
}

type seededFinding struct {
	tool     string
	ruleID   string
	severity store.SeverityLevel
	status   string
	filePath string
	start    int32
	end      int32
	message  string
	metadata json.RawMessage
}

type seededSnapshotState struct {
	snapshotID   uuid.UUID
	componentIDs map[string]uuid.UUID
}

type seededAffectedRange struct {
	ecosystem    string
	packageName  string
	introduced   string
	fixed        string
	lastAffected string
	source       string
}

type seededMatchTarget struct {
	repoKey       string
	componentPURL string
}

type seededAdvisory struct {
	canonicalID string
	title       string
	description string
	severity    store.SeverityLevel
	isMalware   bool
	malwareType any
	publishedAt time.Time
	ranges      []seededAffectedRange
	targets     []seededMatchTarget
}

var seedOrgs = []seededOrg{
	{
		name:     "Acme Corp",
		slug:     "acme",
		provider: "github",
		teams:    []string{"backend", "frontend", "security"},
		repos: []seededRepo{
			{
				name:  "api-gateway",
				slug:  "api-gateway",
				team:  "backend",
				label: "v1.0.0",
				components: []seededComponent{
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go"),
					component("pkg:golang/github.com/gin-gonic/gin@1.9.1", "github.com/gin-gonic/gin", "1.9.1", "go"),
					component("pkg:npm/jsonwebtoken@9.0.2", "jsonwebtoken", "9.0.2", "npm"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:golang/github.com/jackc/pgx/v5@5.5.4", "github.com/jackc/pgx/v5", "5.5.4", "go"),
					component("pkg:golang/github.com/spf13/cobra@1.8.0", "github.com/spf13/cobra", "1.8.0", "go"),
				},
				findings: []seededFinding{
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "internal/handler/auth.go", 47, 47, "JWT signing secret is hardcoded in the authentication handler.", map[string]any{"confidence": "high", "category": "credentials"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/repository/users.go", 83, 86, "SQL query concatenates user input into the WHERE clause.", map[string]any{"owasp": "A03:2021-Injection"}),
					finding("codeql", "path-traversal", store.SeverityLevelHigh, "open", "internal/http/download.go", 66, 72, "Download handler joins user input into a filesystem path without normalization.", map[string]any{"cwe": "CWE-22"}),
					finding("semgrep", "ssrf-via-user-input", store.SeverityLevelMedium, "ignored", "internal/http/proxy.go", 51, 57, "Webhook preview endpoint fetches arbitrary user-supplied URLs.", map[string]any{"reason": "test fixture only"}),
					finding("gitleaks", "aws-access-key-exposed", store.SeverityLevelCritical, "fixed", "deploy/bootstrap.env", 12, 12, "Bootstrap environment file previously contained an AWS access key.", map[string]any{"ticket": "SEC-101"}),
					finding("semgrep", "insecure-deserialization", store.SeverityLevelLow, "false_positive", "internal/cache/session.go", 28, 34, "Gob decode path was flagged as unsafe deserialization but only reads trusted cache entries.", map[string]any{"reviewed_by": "appsec"}),
				},
			},
			{
				name:  "web-dashboard",
				slug:  "web-dashboard",
				team:  "frontend",
				label: "v1.2.0",
				components: []seededComponent{
					component("pkg:npm/react@18.2.0", "react", "18.2.0", "npm"),
					component("pkg:npm/axios@1.6.0", "axios", "1.6.0", "npm"),
					component("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm"),
					component("pkg:npm/express@4.18.2", "express", "4.18.2", "npm"),
					component("pkg:npm/event-stream@3.3.6", "event-stream", "3.3.6", "npm"),
					component("pkg:npm/next@14.1.0", "next", "14.1.0", "npm"),
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelHigh, "open", "src/components/AdminPanel.tsx", 118, 121, "Dashboard renders raw HTML from markdown previews without sanitization.", map[string]any{"cwe": "CWE-79"}),
					finding("trufflehog", "github-token-exposed", store.SeverityLevelCritical, "open", "src/api/client.ts", 14, 14, "Frontend bundle contains a GitHub token used for local API calls.", map[string]any{"exposure": "client-side"}),
					finding("gitleaks", "private-key-detected", store.SeverityLevelCritical, "fixed", "certs/dev-dashboard.pem", 1, 27, "Development TLS key was committed to the repository.", map[string]any{"rotation": "completed"}),
					finding("eslint-security", "prototype-pollution", store.SeverityLevelHigh, "open", "src/lib/mergeFilters.ts", 37, 45, "User-controlled filter objects are merged recursively into application state.", map[string]any{"package": "lodash.merge"}),
					finding("eslint-security", "unsafe-eval-usage", store.SeverityLevelMedium, "open", "src/utils/featureFlags.ts", 22, 24, "Feature flag expressions are evaluated with eval during preview mode.", map[string]any{"surface": "preview"}),
					finding("semgrep", "cors-misconfiguration", store.SeverityLevelLow, "false_positive", "server/dev-proxy.ts", 19, 25, "Wildcard CORS origin is enabled only in isolated local proxy mode.", map[string]any{"environment": "local"}),
					finding("semgrep", "open-redirect", store.SeverityLevelInfo, "ignored", "src/routes/LoginCallback.tsx", 41, 49, "Login callback trusts a next parameter for redirection after auth.", map[string]any{"tracked": "WEB-220"}),
				},
			},
			{
				name:  "auth-service",
				slug:  "auth-service",
				team:  "security",
				label: "v1.1.3",
				components: []seededComponent{
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go"),
					component("pkg:pypi/cryptography@41.0.4", "cryptography", "41.0.4", "pypi"),
					component("pkg:npm/jsonwebtoken@9.0.2", "jsonwebtoken", "9.0.2", "npm"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:pypi/PyJWT@2.8.0", "PyJWT", "2.8.0", "pypi"),
					component("pkg:golang/golang.org/x/oauth2@0.18.0", "golang.org/x/oauth2", "0.18.0", "go"),
				},
				findings: []seededFinding{
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelMedium, "open", "internal/token/digest.go", 31, 33, "Authentication digest fallback relies on MD5 for compatibility mode.", map[string]any{"algorithm": "md5"}),
					finding("gosec", "insecure-tls-version", store.SeverityLevelHigh, "open", "internal/idp/client.go", 77, 84, "Identity provider client accepts TLS versions below 1.2.", map[string]any{"service": "oidc"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "fixed", "cmd/bootstrap/main.go", 19, 19, "Bootstrap flow committed an emergency admin password into source control.", map[string]any{"rotation": "completed"}),
					finding("codeql", "command-injection", store.SeverityLevelHigh, "open", "internal/provision/hooks.go", 58, 66, "Provisioning hook shells out using an unvalidated tenant identifier.", map[string]any{"sink": "exec.Command"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "ignored", "internal/store/session_store.go", 102, 105, "Session lookup query is assembled with string concatenation.", map[string]any{"reason": "legacy migration path"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelLow, "false_positive", "deploy/nginx.conf", 41, 48, "Ingress template flags deprecated ciphers even though this profile is not deployed.", map[string]any{"surface": "edge"}),
				},
			},
			{
				name:  "mobile-app",
				slug:  "mobile-app",
				team:  "frontend",
				label: "v1.0.5",
				components: []seededComponent{
					component("pkg:npm/react@18.2.0", "react", "18.2.0", "npm"),
					component("pkg:npm/axios@1.6.0", "axios", "1.6.0", "npm"),
					component("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm"),
					component("pkg:npm/ua-parser-js@0.7.29", "ua-parser-js", "0.7.29", "npm"),
					component("pkg:maven/com.squareup.okhttp3/okhttp@4.12.0", "com.squareup.okhttp3:okhttp", "4.12.0", "maven"),
					component("pkg:maven/androidx.core/core-ktx@1.12.0", "androidx.core:core-ktx", "1.12.0", "maven"),
				},
				findings: []seededFinding{
					finding("trufflehog", "generic-api-token", store.SeverityLevelCritical, "open", "src/config/mobile.ts", 9, 9, "Mobile client embeds an API signing key in the application bundle.", map[string]any{"platform": "ios"}),
					finding("semgrep", "open-redirect", store.SeverityLevelMedium, "open", "src/navigation/DeepLinkHandler.ts", 74, 81, "Deep link router accepts arbitrary fallback redirect targets.", map[string]any{"surface": "deep-link"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelHigh, "fixed", "src/native/Secrets.ts", 13, 13, "Android build helper previously embedded a push signing secret.", map[string]any{"platform": "android"}),
					finding("eslint-security", "unsafe-eval-usage", store.SeverityLevelLow, "fixed", "src/debug/PreviewConsole.tsx", 32, 36, "Debug console used eval to replay captured actions.", map[string]any{"build": "debug"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "open", "android/app/src/main/java/com/acme/network/TlsConfig.kt", 44, 48, "Android network stack allows TLS 1.1 for legacy endpoints.", map[string]any{"platform": "android"}),
					finding("codeql", "path-traversal", store.SeverityLevelMedium, "false_positive", "android/app/src/main/java/com/acme/storage/ExportLogs.kt", 21, 29, "Log export path is derived from an intent extra but normalized before write.", map[string]any{"reviewed": true}),
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelInfo, "ignored", "scripts/release-notes/main.go", 17, 20, "Release notes generator uses MD5 only to derive non-security cache keys.", map[string]any{"usage": "cache-key"}),
				},
			},
		},
	},
	{
		name:     "Cloud Native Foundation",
		slug:     "cloudnative",
		provider: "github",
		teams:    []string{"infrastructure", "contributors"},
		repos: []seededRepo{
			{
				name:  "service-mesh",
				slug:  "service-mesh",
				team:  "infrastructure",
				label: "v1.0.0",
				components: []seededComponent{
					component("pkg:golang/github.com/gin-gonic/gin@1.9.1", "github.com/gin-gonic/gin", "1.9.1", "go"),
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go"),
					component("pkg:pypi/requests@2.31.0", "requests", "2.31.0", "pypi"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:golang/github.com/opencontainers/runc@1.1.11", "github.com/opencontainers/runc", "1.1.11", "go"),
					component("pkg:maven/io.fabric8/kubernetes-client@6.10.0", "io.fabric8:kubernetes-client", "6.10.0", "maven"),
				},
				findings: []seededFinding{
					finding("checkov", "privileged-container", store.SeverityLevelHigh, "open", "deploy/mesh/daemonset.yaml", 34, 47, "DaemonSet runs the proxy sidecar with privileged=true.", map[string]any{"resource": "DaemonSet/mesh-proxy"}),
					finding("checkov", "missing-network-policy", store.SeverityLevelMedium, "open", "deploy/mesh/namespace.yaml", 1, 18, "Namespace ships without a default deny NetworkPolicy.", map[string]any{"namespace": "mesh-system"}),
					finding("checkov", "container-writable-rootfs", store.SeverityLevelLow, "ignored", "deploy/mesh/daemonset.yaml", 59, 64, "Writable root filesystem retained for eBPF debug sidecar.", map[string]any{"approved_by": "platform"}),
					finding("gosec", "insecure-tls-version", store.SeverityLevelHigh, "open", "cmd/proxy/main.go", 88, 95, "Proxy bootstrap leaves MinVersion unset on TLS listeners.", map[string]any{"cluster": "staging"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelMedium, "false_positive", "controlplane/store/filters.go", 52, 54, "Dynamic search filter is appended directly into the SQL statement.", map[string]any{"input": "label_selector"}),
					finding("trivy", "hardcoded-secret-in-source", store.SeverityLevelCritical, "fixed", "deploy/charts/mesh/values.yaml", 12, 12, "Helm chart committed a bootstrap token for control plane registration.", map[string]any{"rotation_ticket": "SEC-241"}),
				},
			},
			{
				name:  "container-runtime",
				slug:  "container-runtime",
				team:  "infrastructure",
				label: "v1.3.0",
				components: []seededComponent{
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go"),
					component("pkg:pypi/flask@3.0.0", "flask", "3.0.0", "pypi"),
					component("pkg:pypi/cryptography@41.0.4", "cryptography", "41.0.4", "pypi"),
					component("pkg:npm/axios@1.6.0", "axios", "1.6.0", "npm"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:golang/github.com/opencontainers/runc@1.1.11", "github.com/opencontainers/runc", "1.1.11", "go"),
				},
				findings: []seededFinding{
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelLow, "open", "pkg/cache/checksum.go", 23, 26, "Image layer checksum fallback uses MD5 for performance reasons.", map[string]any{"component": "cache"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "hack/dev-cluster.sh", 11, 11, "Cluster bootstrap script exposes a registry password in plain text.", map[string]any{"environment": "dev"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "fixed", "pkg/registry/client.go", 67, 72, "Registry client previously accepted TLS 1.1 for mirror endpoints.", map[string]any{"fix_version": "v1.3.0"}),
					finding("codeql", "command-injection", store.SeverityLevelHigh, "open", "cmd/runtime/install.go", 44, 52, "Installer constructs a tar extraction command from unvalidated image metadata.", map[string]any{"surface": "runtime"}),
					finding("checkov", "privileged-container", store.SeverityLevelCritical, "open", "deploy/runtime/daemonset.yaml", 48, 55, "Runtime daemon requires privileged access in the shipped manifest.", map[string]any{"resource": "DaemonSet/runtime"}),
					finding("checkov", "container-writable-rootfs", store.SeverityLevelMedium, "ignored", "deploy/runtime/daemonset.yaml", 67, 71, "Root filesystem remains writable to support low-level checkpoint restore tests.", map[string]any{"exception": "checkpoint-restore"}),
				},
			},
			{
				name:  "observability-stack",
				slug:  "observability-stack",
				team:  "contributors",
				label: "v1.4.2",
				components: []seededComponent{
					component("pkg:pypi/django@4.2.7", "django", "4.2.7", "pypi"),
					component("pkg:pypi/requests@2.31.0", "requests", "2.31.0", "pypi"),
					component("pkg:npm/express@4.18.2", "express", "4.18.2", "npm"),
					component("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm"),
					component("pkg:npm/react@18.2.0", "react", "18.2.0", "npm"),
					component("pkg:maven/org.apache.logging.log4j/log4j-core@2.22.1", "org.apache.logging.log4j:log4j-core", "2.22.1", "maven"),
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "ui/src/views/AlertDetail.tsx", 201, 206, "Alert detail page writes raw Markdown HTML into the DOM.", map[string]any{"surface": "dashboard"}),
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelHigh, "fixed", "collector/config/defaults.go", 34, 34, "Example SMTP credential shipped as the package default.", map[string]any{"status_reason": "rotated"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelLow, "open", "deploy/grafana.ini", 8, 12, "Grafana sidecar TLS minimum version remains unset.", map[string]any{"service": "grafana"}),
					finding("eslint-security", "prototype-pollution", store.SeverityLevelMedium, "ignored", "ui/src/lib/filterState.ts", 29, 37, "Filter state hydrator recursively merges URL parameters into existing config.", map[string]any{"surface": "dashboards"}),
					finding("codeql", "path-traversal", store.SeverityLevelHigh, "open", "collector/export/archive.go", 57, 64, "Archive exporter joins metric labels into output paths without validation.", map[string]any{"sink": "os.Create"}),
					finding("gitleaks", "private-key-detected", store.SeverityLevelCritical, "false_positive", "examples/certs/README.pem", 1, 22, "Documentation fixture contains a clearly marked example private key.", map[string]any{"fixture": true}),
				},
			},
		},
	},
	{
		name:     "DevTools Inc",
		slug:     "devtools",
		provider: "forgejo",
		teams:    []string{"platform", "integrations"},
		repos: []seededRepo{
			{
				name:  "ci-pipeline",
				slug:  "ci-pipeline",
				team:  "platform",
				label: "v1.0.1",
				components: []seededComponent{
					component("pkg:npm/express@4.18.2", "express", "4.18.2", "npm"),
					component("pkg:npm/axios@1.6.0", "axios", "1.6.0", "npm"),
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go"),
					component("pkg:npm/node-ipc@10.1.0", "node-ipc", "10.1.0", "npm"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:maven/org.yaml/snakeyaml@2.2", "org.yaml:snakeyaml", "2.2", "maven"),
				},
				findings: []seededFinding{
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "pipelines/github/actions.ts", 41, 41, "Reusable CI action hardcodes a package signing token.", map[string]any{"surface": "github-actions"}),
					finding("gosec", "insecure-tls-version", store.SeverityLevelMedium, "open", "cmd/runner/main.go", 56, 61, "Runner webhook client does not pin TLS 1.2 or newer.", map[string]any{"service": "webhook"}),
					finding("trivy", "use-of-weak-hash-md5", store.SeverityLevelLow, "fixed", "internal/cache/artifacts.go", 17, 19, "Artifact cache key derivation used MD5 before the current release.", map[string]any{"fix_commit": "ab12cd3"}),
					finding("codeql", "command-injection", store.SeverityLevelHigh, "open", "internal/runner/shell.go", 92, 103, "Pipeline runner shells out using an unvalidated matrix value.", map[string]any{"source": "workflow input"}),
					finding("checkov", "missing-network-policy", store.SeverityLevelMedium, "ignored", "deploy/runner/namespace.yaml", 1, 14, "Runner namespace does not define a default deny policy in sandbox clusters.", map[string]any{"cluster": "sandbox"}),
					finding("gitleaks", "aws-access-key-exposed", store.SeverityLevelCritical, "false_positive", "fixtures/sample.env", 8, 8, "Fixture env file contains fake credentials used in parser tests.", map[string]any{"fixture": true}),
				},
			},
			{
				name:  "code-analyzer",
				slug:  "code-analyzer",
				team:  "integrations",
				label: "v1.6.0",
				components: []seededComponent{
					component("pkg:pypi/flask@3.0.0", "flask", "3.0.0", "pypi"),
					component("pkg:pypi/requests@2.31.0", "requests", "2.31.0", "pypi"),
					component("pkg:pypi/cryptography@41.0.4", "cryptography", "41.0.4", "pypi"),
					component("pkg:npm/lodash@4.17.21", "lodash", "4.17.21", "npm"),
					component("pkg:pypi/colourama@0.4.6", "colourama", "0.4.6", "pypi"),
					component("pkg:pypi/bandit@1.7.8", "bandit", "1.7.8", "pypi"),
				},
				findings: []seededFinding{
					finding("bandit", "hardcoded-database-password", store.SeverityLevelHigh, "open", "analyzers/python/db.py", 17, 17, "Analyzer config falls back to a hardcoded PostgreSQL password.", map[string]any{"plugin": "B105"}),
					finding("bandit", "shell-injection", store.SeverityLevelCritical, "open", "analyzers/python/git_wrapper.py", 48, 53, "Repository URL is interpolated into a shell command used for cloning.", map[string]any{"plugin": "B602"}),
					finding("trufflehog", "github-token-exposed", store.SeverityLevelCritical, "fixed", "internal/scm/github.go", 26, 26, "GitHub integration token is committed into a local development helper.", map[string]any{"provider": "github"}),
					finding("semgrep", "insecure-deserialization", store.SeverityLevelMedium, "open", "analyzers/python/cache_loader.py", 22, 28, "Cached analysis results are deserialized from pickle without integrity checks.", map[string]any{"format": "pickle"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "fixed", "internal/transport/http.go", 48, 54, "HTTP client previously permitted TLS 1.0 for third-party plugins.", map[string]any{"fixed_in": "v1.6.0"}),
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelLow, "ignored", "web/src/pages/report.tsx", 93, 97, "Static analysis report page injects HTML annotations that are already sanitized server-side.", map[string]any{"renderer": "markdown"}),
				},
			},
			{
				name:  "package-registry",
				slug:  "package-registry",
				team:  "platform",
				label: "v1.2.4",
				components: []seededComponent{
					component("pkg:npm/express@4.18.2", "express", "4.18.2", "npm"),
					component("pkg:npm/jsonwebtoken@9.0.2", "jsonwebtoken", "9.0.2", "npm"),
					component("pkg:pypi/django@4.2.7", "django", "4.2.7", "pypi"),
					component("pkg:golang/github.com/gin-gonic/gin@1.9.1", "github.com/gin-gonic/gin", "1.9.1", "go"),
					component("pkg:nuget/Zlib.Portable@1.11.0", "Zlib.Portable", "1.11.0", "nuget"),
					component("pkg:maven/org.apache.maven/maven-artifact@3.9.6", "org.apache.maven:maven-artifact", "3.9.6", "maven"),
				},
				findings: []seededFinding{
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/search/packages.go", 112, 118, "Package search builds ORDER BY clauses from unvalidated request input.", map[string]any{"vector": "sort"}),
					finding("trivy", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "deploy/registry.env", 4, 4, "Registry signing passphrase is stored in a checked-in env file.", map[string]any{"scope": "release"}),
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelLow, "fixed", "internal/signing/legacy.go", 28, 32, "Legacy compatibility layer still references MD5 while verification is disabled.", map[string]any{"compatibility": true}),
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "web/src/components/PackageReadme.tsx", 64, 70, "Rendered README content is inserted without HTML sanitization.", map[string]any{"content_source": "user-upload"}),
					finding("grype", "CVE-2023-45853", store.SeverityLevelMedium, "ignored", "sbom/packages.json", 201, 201, "Known zlib advisory tracked for mirrored package metadata.", map[string]any{"package": "Zlib.Portable"}),
					finding("codeql", "path-traversal", store.SeverityLevelHigh, "false_positive", "internal/uploads/extract.go", 33, 40, "Archive extraction joins entry names into target paths but canonicalization prevents traversal.", map[string]any{"reviewed_by": "platform"}),
				},
			},
			{
				name:       "k9s",
				slug:       "k9s",
				team:       "platform",
				label:      "initial",
				providerID: "hibou-admin/k9s",
			},
		},
	},
}

var seedAdvisories = []seededAdvisory{
	{
		canonicalID: "MAL-2018-3553",
		title:       "event-stream malicious dependency",
		description: "Malicious event-stream release carried a backdoored flatmap-stream payload intended to steal cryptocurrency wallets.",
		severity:    store.SeverityLevelCritical,
		isMalware:   true,
		malwareType: "backdoor",
		publishedAt: time.Date(2018, time.November, 26, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "npm", packageName: "event-stream", introduced: "3.3.6", lastAffected: "3.3.6", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("acme", "web-dashboard"), componentPURL: "pkg:npm/event-stream@3.3.6"}},
	},
	{
		canonicalID: "MAL-2021-1024",
		title:       "ua-parser-js supply chain attack",
		description: "Compromised ua-parser-js packages shipped credential harvesting and cryptomining payloads.",
		severity:    store.SeverityLevelCritical,
		isMalware:   true,
		malwareType: "cryptominer",
		publishedAt: time.Date(2021, time.October, 23, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "npm", packageName: "ua-parser-js", introduced: "0.7.29", lastAffected: "0.7.29", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("acme", "mobile-app"), componentPURL: "pkg:npm/ua-parser-js@0.7.29"}},
	},
	{
		canonicalID: "MAL-2022-0001",
		title:       "colourama typosquat package",
		description: "A typosquatted colourama package was used to capture environment data and exfiltrate credentials from developer machines.",
		severity:    store.SeverityLevelHigh,
		isMalware:   true,
		malwareType: "data_exfiltration",
		publishedAt: time.Date(2022, time.January, 11, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "pypi", packageName: "colourama", introduced: "0.4.6", lastAffected: "0.4.6", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("devtools", "code-analyzer"), componentPURL: "pkg:pypi/colourama@0.4.6"}},
	},
	{
		canonicalID: "MAL-2022-0856",
		title:       "node-ipc protestware",
		description: "Malicious node-ipc release overwrote files on selected systems and behaved as a backdoored protestware package.",
		severity:    store.SeverityLevelCritical,
		isMalware:   true,
		malwareType: "backdoor",
		publishedAt: time.Date(2022, time.March, 15, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "npm", packageName: "node-ipc", introduced: "10.1.0", lastAffected: "10.1.0", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("devtools", "ci-pipeline"), componentPURL: "pkg:npm/node-ipc@10.1.0"}},
	},
	{
		canonicalID: "CVE-2023-44487",
		title:       "HTTP/2 Rapid Reset",
		description: "golang.org/x/net HTTP/2 server implementations may be vulnerable to the Rapid Reset attack leading to denial of service.",
		severity:    store.SeverityLevelHigh,
		publishedAt: time.Date(2023, time.October, 10, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "golang.org/x/net", introduced: "0", fixed: "0.17.0", source: "seed"}},
		targets: []seededMatchTarget{
			{repoKey: repoSeedKey("acme", "api-gateway"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("acme", "auth-service"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("cloudnative", "service-mesh"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("devtools", "ci-pipeline"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
		},
	},
	{
		canonicalID: "CVE-2023-39325",
		title:       "golang.org/x/net HTTP/2 resource consumption",
		description: "Certain HTTP/2 requests can consume excessive resources in affected golang.org/x/net versions.",
		severity:    store.SeverityLevelHigh,
		publishedAt: time.Date(2023, time.September, 6, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "golang.org/x/net", introduced: "0", fixed: "0.17.0", source: "seed"}},
		targets: []seededMatchTarget{
			{repoKey: repoSeedKey("acme", "api-gateway"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("acme", "auth-service"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("cloudnative", "service-mesh"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
			{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:golang/golang.org/x/net@0.16.0"},
		},
	},
	{
		canonicalID: "CVE-2024-21626",
		title:       "runc container escape",
		description: "Affected runc versions may permit a crafted image or container to escape intended filesystem boundaries.",
		severity:    store.SeverityLevelCritical,
		publishedAt: time.Date(2024, time.January, 31, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "github.com/opencontainers/runc", introduced: "0", fixed: "1.1.12", source: "seed"}},
		targets: []seededMatchTarget{
			{repoKey: repoSeedKey("cloudnative", "service-mesh"), componentPURL: "pkg:golang/github.com/opencontainers/runc@1.1.11"},
			{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:golang/github.com/opencontainers/runc@1.1.11"},
		},
	},
	{
		canonicalID: "CVE-2023-45853",
		title:       "zlib buffer overflow",
		description: "Affected Zlib.Portable packages bundle a vulnerable zlib version that may permit buffer overflow conditions during decompression.",
		severity:    store.SeverityLevelMedium,
		publishedAt: time.Date(2023, time.December, 1, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "nuget", packageName: "Zlib.Portable", introduced: "0", fixed: "1.12.0", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("devtools", "package-registry"), componentPURL: "pkg:nuget/Zlib.Portable@1.11.0"}},
	},
}

func Run(ctx context.Context, db *sql.DB, log zerolog.Logger) error {
	queries := store.NewQueries(db)

	existingOrg, err := queries.GetOrganizationByProviderAndSlug(ctx, "github", "acme")
	if err != nil {
		return fmt.Errorf("checking existing seed data: %w", err)
	}
	if existingOrg != nil {
		log.Info().Str("org_slug", "acme").Msg("seed data already present, skipping")
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning seed transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	queries = queries.WithTx(tx)
	devUser, err := queries.UpsertUser(ctx, "admin@localhost", "Dev Admin", nil, "local", "dev-admin")
	if err != nil {
		return fmt.Errorf("upserting dev user: %w", err)
	}

	seededSnapshots := make(map[string]seededSnapshotState)

	for orgIndex, orgSeed := range seedOrgs {
		org, err := queries.CreateOrganization(ctx, orgSeed.name, orgSeed.slug, orgSeed.name, orgSeed.provider)
		if err != nil {
			return fmt.Errorf("creating organization %s: %w", orgSeed.slug, err)
		}

		if err := queries.AddOrgMember(ctx, org.ID, devUser.ID, "admin"); err != nil {
			return fmt.Errorf("adding dev user to organization %s: %w", orgSeed.slug, err)
		}

		teams := make(map[string]*store.Team, len(orgSeed.teams))
		for _, teamSlug := range orgSeed.teams {
			team, err := queries.CreateTeam(ctx, org.ID, titleFromSlug(teamSlug), teamSlug)
			if err != nil {
				return fmt.Errorf("creating team %s/%s: %w", orgSeed.slug, teamSlug, err)
			}
			teams[teamSlug] = team
		}

		for repoIndex, repoSeed := range orgSeed.repos {
			team := teams[repoSeed.team]
			if team == nil {
				return fmt.Errorf("seed repo %s/%s references unknown team %s", orgSeed.slug, repoSeed.slug, repoSeed.team)
			}

			providerID := repoSeed.providerID
			if providerID == "" {
				providerID = fmt.Sprintf("%s-%s", orgSeed.slug, repoSeed.slug)
			}
			repo, err := queries.CreateRepository(ctx, org.ID, &team.ID, repoSeed.name, repoSeed.slug, orgSeed.provider, providerID, "main", "synced")
			if err != nil {
				return fmt.Errorf("creating repository %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			commitSHA := fakeCommitSHA(orgIndex, repoIndex)
			branchRef, err := queries.CreateRef(ctx, repo.ID, "main", store.RefTypeBranch, nil, nil, &commitSHA)
			if err != nil {
				return fmt.Errorf("creating ref for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			snapshot, err := queries.CreateSnapshot(ctx, branchRef.ID, commitSHA, store.SnapshotStatusComplete)
			if err != nil {
				return fmt.Errorf("creating snapshot for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			componentIDs, err := seedComponentsForSnapshot(ctx, tx, snapshot.ID, repoSeed.components)
			if err != nil {
				return fmt.Errorf("seeding components for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			if err := seedFindings(ctx, queries, snapshot.ID, repoSeed.findings); err != nil {
				return fmt.Errorf("seeding findings for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			if err := seedRepoHistory(ctx, tx, queries, historyParams{
				repoID:           repo.ID,
				branchRefID:      branchRef.ID,
				latestSnapshotID: snapshot.ID,
				latestCreatedAt:  snapshot.CreatedAt,
				repoSeed:         repoSeed,
				orgIndex:         orgIndex,
				repoIndex:        repoIndex,
			}); err != nil {
				return fmt.Errorf("seeding history for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			seededSnapshots[repoSeedKey(orgSeed.slug, repoSeed.slug)] = seededSnapshotState{
				snapshotID:   snapshot.ID,
				componentIDs: componentIDs,
			}
		}
	}

	if err := seedAdvisoryData(ctx, queries, tx, seededSnapshots); err != nil {
		return fmt.Errorf("seeding advisories: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing seed transaction: %w", err)
	}

	log.Info().Int("organizations", len(seedOrgs)).Msg("development seed data created")
	return nil
}

func seedComponentsForSnapshot(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, components []seededComponent) (map[string]uuid.UUID, error) {
	const insertComponent = `
		INSERT INTO components (purl, name, version, ecosystem)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (purl, version) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`
	const linkSnapshotComponent = `
		INSERT INTO snapshot_components (snapshot_id, component_id)
		VALUES ($1, $2)
		ON CONFLICT DO NOTHING
	`

	componentIDs := make(map[string]uuid.UUID, len(components))

	for _, seededComponent := range components {
		var componentID uuid.UUID
		if err := tx.QueryRowContext(ctx, insertComponent, seededComponent.purl, seededComponent.name, seededComponent.version, seededComponent.ecosystem).Scan(&componentID); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, linkSnapshotComponent, snapshotID, componentID); err != nil {
			return nil, err
		}
		componentIDs[seededComponent.purl] = componentID
	}

	return componentIDs, nil
}

func seedAdvisoryData(ctx context.Context, queries *store.Queries, tx *sql.Tx, snapshots map[string]seededSnapshotState) error {
	const insertAdvisory = `
		INSERT INTO advisories (canonical_id, title, description, severity, is_malware, malware_type, published_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`
	const insertAffectedRange = `
		INSERT INTO affected_ranges (advisory_id, ecosystem, package_name, introduced, fixed, last_affected, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`
	qtx := queries.WithTx(tx)

	for _, advisory := range seedAdvisories {
		var advisoryID uuid.UUID
		if err := tx.QueryRowContext(
			ctx,
			insertAdvisory,
			advisory.canonicalID,
			advisory.title,
			advisory.description,
			advisory.severity,
			advisory.isMalware,
			advisory.malwareType,
			advisory.publishedAt,
		).Scan(&advisoryID); err != nil {
			return err
		}

		affectedRangeIDs := make([]uuid.UUID, 0, len(advisory.ranges))
		for _, affectedRange := range advisory.ranges {
			var affectedRangeID uuid.UUID
			if err := tx.QueryRowContext(
				ctx,
				insertAffectedRange,
				advisoryID,
				affectedRange.ecosystem,
				affectedRange.packageName,
				affectedRange.introduced,
				affectedRange.fixed,
				affectedRange.lastAffected,
				affectedRange.source,
			).Scan(&affectedRangeID); err != nil {
				return err
			}
			affectedRangeIDs = append(affectedRangeIDs, affectedRangeID)
		}

		var affectedRangeID any
		if len(affectedRangeIDs) > 0 {
			affectedRangeID = affectedRangeIDs[0]
		}

		for _, target := range advisory.targets {
			snapshotState, ok := snapshots[target.repoKey]
			if !ok {
				return fmt.Errorf("missing seeded snapshot for %s", target.repoKey)
			}
			componentID, ok := snapshotState.componentIDs[target.componentPURL]
			if !ok {
				return fmt.Errorf("missing component %s for %s", target.componentPURL, target.repoKey)
			}
			componentName, componentVersion, componentPURL, ecosystem, err := loadSeedComponent(ctx, tx, componentID)
			if err != nil {
				return err
			}
			vulnType := "dependency"
			if advisory.isMalware {
				vulnType = "malware"
			}
			_, err = qtx.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
				Type:              vulnType,
				SnapshotID:        snapshotState.snapshotID,
				Title:             advisory.title,
				Description:       advisory.description,
				PrimaryIdentifier: json.RawMessage(fmt.Sprintf(`{"type":"advisory","value":%q}`, advisory.canonicalID)),
				Identifiers:       json.RawMessage(`[]`),
				OriginalSeverity:  advisory.severity,
				Severity:          advisory.severity,
				Status:            "detected",
				ScannerName:       "seed",
				Fingerprint:       dependencySeedFingerprint(advisoryID, componentID),
				ComponentID:       uuid.NullUUID{UUID: componentID, Valid: true},
				ComponentName:     nullSeedString(componentName),
				ComponentVersion:  nullSeedString(componentVersion),
				ComponentPurl:     nullSeedString(componentPURL),
				Ecosystem:         nullSeedString(ecosystem),
				AdvisoryID:        uuid.NullUUID{UUID: advisoryID, Valid: true},
				AffectedRangeID:   nullSeedUUID(affectedRangeID),
			})
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func seedFindings(ctx context.Context, queries *store.Queries, snapshotID uuid.UUID, findings []seededFinding) error {
	for _, seededFinding := range findings {
		startLine := seededFinding.start
		endLine := seededFinding.end
		locationHash := findingLocationHash(seededFinding.tool, seededFinding.ruleID, seededFinding.filePath, startLine, endLine)

		_, err := queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type:              seededFindingType(seededFinding.tool),
			SnapshotID:        snapshotID,
			Title:             truncateSeedText(seededFinding.message, 200),
			Description:       seededFinding.message,
			PrimaryIdentifier: json.RawMessage(fmt.Sprintf(`{"type":"rule","value":%q}`, seededFinding.ruleID)),
			Identifiers:       json.RawMessage(`[]`),
			OriginalSeverity:  seededFinding.severity,
			Severity:          seededFinding.severity,
			Status:            normalizeSeedFindingStatus(seededFinding.status),
			ScannerName:       seededFinding.tool,
			FilePath:          nullSeedString(seededFinding.filePath),
			StartLine:         sql.NullInt32{Int32: startLine, Valid: startLine > 0},
			EndLine:           sql.NullInt32{Int32: endLine, Valid: endLine > 0},
			LocationHash:      nullSeedString(locationHash),
			Fingerprint:       locationHash,
			Metadata:          seededFinding.metadata,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func repoSeedKey(orgSlug, repoSlug string) string {
	return orgSlug + "/" + repoSlug
}

// --- Snapshot history, coverage, and extra refs (snapshot/coverage test data) ---

const defaultSeedTag = "v1.0.0"

type coverageFileSpec struct {
	path    string
	valid   int
	covered int
}

type coverageSpec struct {
	format string
	files  []coverageFileSpec
}

type snapshotMeta struct {
	tag       *string
	runNumber *string
	createdAt time.Time
}

// historyParams bundles the per-repo context needed to seed snapshot history.
type historyParams struct {
	repoID           uuid.UUID
	branchRefID      uuid.UUID
	latestSnapshotID uuid.UUID
	latestCreatedAt  time.Time
	repoSeed         seededRepo
	orgIndex         int
	repoIndex        int
}

var historySteps = []struct {
	daysAgo int
	status  store.SnapshotStatus
	rate    float64
}{
	{28, store.SnapshotStatusComplete, 0.61},
	{21, store.SnapshotStatusComplete, 0.66},
	{14, store.SnapshotStatusFailed, 0},
	{7, store.SnapshotStatusComplete, 0.72},
}

// seedRepoHistory enriches a repo's main branch with coverage on the latest
// snapshot, a backdated snapshot history (incl. a failed build), and — for the
// first repo of each org — a release tag and an in-flight pull request. This is
// what exercises the snapshot selector, coverage tab, trends, and PR views.
func seedRepoHistory(ctx context.Context, tx *sql.Tx, queries *store.Queries, p historyParams) error {
	if len(p.repoSeed.components) == 0 {
		return nil // unscanned repo (e.g. discovered-only) — leave empty
	}

	// Coverage for the current/latest snapshot (highest rate of the series).
	if err := seedCoverage(ctx, tx, p.latestSnapshotID, p.latestCreatedAt, coverageSpecForRepo(p.repoSeed, 0.78)); err != nil {
		return err
	}
	// Test results for the current snapshot (one failing case for visibility).
	if err := seedTests(ctx, tx, p.latestSnapshotID, p.latestCreatedAt, p.repoSeed, 1); err != nil {
		return err
	}

	if err := seedMainBranchHistory(ctx, tx, queries, p); err != nil {
		return err
	}

	// Only the first repo of each org grows a release tag + an open PR.
	if p.repoIndex != 0 {
		return nil
	}
	return seedExtraRefs(ctx, tx, queries, p)
}

// seedMainBranchHistory creates the backdated snapshots on the main branch.
func seedMainBranchHistory(ctx context.Context, tx *sql.Tx, queries *store.Queries, p historyParams) error {
	for i, step := range historySteps {
		createdAt := p.latestCreatedAt.AddDate(0, 0, -step.daysAgo)
		commitSHA := fakeHistorySHA(p.orgIndex, p.repoIndex, i)
		runNumber := strconv.Itoa(40 + i)
		snapshotID, err := insertSnapshotRaw(ctx, tx, p.branchRefID, commitSHA, step.status, snapshotMeta{runNumber: &runNumber, createdAt: createdAt})
		if err != nil {
			return err
		}
		if step.status == store.SnapshotStatusFailed {
			continue // failed build ingested nothing
		}
		if _, err := seedComponentsForSnapshot(ctx, tx, snapshotID, p.repoSeed.components); err != nil {
			return err
		}
		if err := seedFindings(ctx, queries, snapshotID, subsetFindings(p.repoSeed.findings, i+2)); err != nil {
			return err
		}
		if err := seedCoverage(ctx, tx, snapshotID, createdAt, coverageSpecForRepo(p.repoSeed, step.rate)); err != nil {
			return err
		}
		// Older snapshots had more failing tests (improving over time).
		if err := seedTests(ctx, tx, snapshotID, createdAt, p.repoSeed, 4-i); err != nil {
			return err
		}
	}
	return nil
}

// seedExtraRefs adds a release tag and an in-flight pull request to a repo.
func seedExtraRefs(ctx context.Context, tx *sql.Tx, queries *store.Queries, p historyParams) error {
	tagName := p.repoSeed.label
	if tagName == "" || tagName == "initial" {
		tagName = defaultSeedTag
	}
	tagCommit := fakeHistorySHA(p.orgIndex, p.repoIndex, 90)
	tagCreatedAt := p.latestCreatedAt.AddDate(0, 0, -3)
	tagRef, err := queries.CreateRef(ctx, p.repoID, tagName, store.RefTypeTag, nil, nil, &tagCommit)
	if err != nil {
		return err
	}
	tagSnapshotID, err := insertSnapshotRaw(ctx, tx, tagRef.ID, tagCommit, store.SnapshotStatusComplete, snapshotMeta{tag: &tagName, createdAt: tagCreatedAt})
	if err != nil {
		return err
	}
	if _, err := seedComponentsForSnapshot(ctx, tx, tagSnapshotID, p.repoSeed.components); err != nil {
		return err
	}
	if err := seedCoverage(ctx, tx, tagSnapshotID, tagCreatedAt, coverageSpecForRepo(p.repoSeed, 0.74)); err != nil {
		return err
	}

	// In-flight pull request targeting main: its snapshot is still pending.
	prCommit := fakeHistorySHA(p.orgIndex, p.repoIndex, 42)
	prRef, err := queries.CreateRef(ctx, p.repoID, "refs/pull/42/head", store.RefTypePullRequest, nil, &p.branchRefID, &prCommit)
	if err != nil {
		return err
	}
	if err := setSeedPRMetadata(ctx, tx, prRef.ID, "open", "Add request rate limiting middleware", "feature/rate-limit"); err != nil {
		return err
	}
	prSnapshotID, err := insertSnapshotRaw(ctx, tx, prRef.ID, prCommit, store.SnapshotStatusPending, snapshotMeta{createdAt: p.latestCreatedAt.Add(-2 * time.Hour)})
	if err != nil {
		return err
	}
	_, err = seedComponentsForSnapshot(ctx, tx, prSnapshotID, p.repoSeed.components)
	return err
}

type seededTestCase struct {
	suite     string
	name      string
	classname string
	status    string
	message   string
	duration  float64
}

// seedTests inserts a JUnit-style test report for a snapshot. failures > 0 marks
// the first `failures` cases as failed so the Tests tab shows mixed results.
func seedTests(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, createdAt time.Time, repoSeed seededRepo, failures int) error {
	cases := testCasesForRepo(repoSeed, failures)
	if len(cases) == 0 {
		return nil
	}

	total := len(cases)
	passed, failed, skipped, errs := 0, 0, 0, 0
	duration := 0.0
	for _, c := range cases {
		duration += c.duration
		switch c.status {
		case "failed":
			failed++
		case "error":
			errs++
		case "skipped":
			skipped++
		default:
			passed++
		}
	}

	const insertReport = `
		INSERT INTO test_reports (snapshot_id, format, total, passed, failed, skipped, errors, duration_seconds, created_at)
		VALUES ($1, 'junit', $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (snapshot_id) DO NOTHING
		RETURNING id
	`
	var reportID uuid.UUID
	if err := tx.QueryRowContext(ctx, insertReport, snapshotID, total, passed, failed, skipped, errs, duration, createdAt).Scan(&reportID); err != nil {
		return err
	}

	const insertCase = `
		INSERT INTO test_cases (test_report_id, suite, name, classname, status, duration_seconds, message)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	for _, c := range cases {
		if _, err := tx.ExecContext(ctx, insertCase, reportID, c.suite, c.name, c.classname, c.status, c.duration, c.message); err != nil {
			return err
		}
	}

	return nil
}

func testCasesForRepo(repoSeed seededRepo, failures int) []seededTestCase {
	suite := repoSeed.slug
	names := []string{
		"TestHealthEndpoint", "TestAuthFlow", "TestConfigDefaults", "TestRequestValidation",
		"TestPagination", "TestErrorMapping", "TestRetryBackoff", "TestSerialization",
	}
	cases := make([]seededTestCase, 0, len(names))
	for i, name := range names {
		c := seededTestCase{
			suite:     suite,
			name:      name,
			classname: repoSeed.slug,
			status:    "passed",
			duration:  0.02 + float64(i%5)*0.013,
		}
		if i < failures {
			c.status = "failed"
			c.message = "assertion failed: expected 200 but got 500 (" + name + ")"
			c.duration += 0.05
		} else if i == failures {
			// one skipped case after the failures
			c.status = "skipped"
			c.message = "flaky on CI"
		}
		cases = append(cases, c)
	}
	return cases
}

func insertSnapshotRaw(ctx context.Context, tx *sql.Tx, refID uuid.UUID, commitSHA string, status store.SnapshotStatus, meta snapshotMeta) (uuid.UUID, error) {
	const insertSnapshot = `
		INSERT INTO snapshots (ref_id, commit_sha, status, tag, run_number, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`
	var snapshotID uuid.UUID
	err := tx.QueryRowContext(ctx, insertSnapshot, refID, commitSHA, string(status), nullSeedString(deref(meta.tag)), nullSeedString(deref(meta.runNumber)), meta.createdAt).Scan(&snapshotID)
	return snapshotID, err
}

func seedCoverage(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, createdAt time.Time, spec coverageSpec) error {
	if len(spec.files) == 0 {
		return nil
	}

	totalValid := 0
	totalCovered := 0
	for _, file := range spec.files {
		totalValid += file.valid
		totalCovered += file.covered
	}

	const insertReport = `
		INSERT INTO coverage_reports (snapshot_id, format, line_rate, lines_valid, lines_covered, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (snapshot_id, format) DO NOTHING
		RETURNING id
	`
	var reportID uuid.UUID
	if err := tx.QueryRowContext(ctx, insertReport, snapshotID, spec.format, coverageRate(totalCovered, totalValid), totalValid, totalCovered, createdAt).Scan(&reportID); err != nil {
		return err
	}

	const insertFile = `
		INSERT INTO coverage_files (coverage_report_id, file_path, line_rate, lines_valid, lines_covered)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (coverage_report_id, file_path) DO NOTHING
	`
	for _, file := range spec.files {
		if _, err := tx.ExecContext(ctx, insertFile, reportID, file.path, coverageRate(file.covered, file.valid), file.valid, file.covered); err != nil {
			return err
		}
	}

	return nil
}

func coverageSpecForRepo(repoSeed seededRepo, rate float64) coverageSpec {
	format := "lcov"
	if len(repoSeed.components) > 0 {
		switch repoSeed.components[0].ecosystem {
		case "go":
			format = "gocover"
		case "pypi":
			format = "cobertura"
		case "maven":
			format = "jacoco"
		default:
			format = "lcov"
		}
	}

	// Derive plausible file paths from the repo's findings, falling back to synthesized names.
	paths := make([]string, 0, 6)
	seen := make(map[string]struct{})
	for _, f := range repoSeed.findings {
		if f.filePath == "" {
			continue
		}
		if _, ok := seen[f.filePath]; ok {
			continue
		}
		seen[f.filePath] = struct{}{}
		paths = append(paths, f.filePath)
		if len(paths) == 6 {
			break
		}
	}
	for len(paths) < 4 {
		paths = append(paths, fmt.Sprintf("src/module_%d.go", len(paths)+1))
	}

	files := make([]coverageFileSpec, 0, len(paths))
	for i, path := range paths {
		valid := 80 + (i*17)%60 // 80..139, deterministic spread
		// Vary per-file rate around the target so the file table isn't uniform.
		fileRate := rate + float64((i%3)-1)*0.07
		if fileRate < 0 {
			fileRate = 0
		}
		if fileRate > 1 {
			fileRate = 1
		}
		covered := int(float64(valid)*fileRate + 0.5)
		files = append(files, coverageFileSpec{path: path, valid: valid, covered: covered})
	}

	return coverageSpec{format: format, files: files}
}

func setSeedPRMetadata(ctx context.Context, tx *sql.Tx, refID uuid.UUID, state, title, sourceBranch string) error {
	const update = `UPDATE refs SET pr_state = $2, pr_title = $3, pr_source_branch = $4 WHERE id = $1`
	_, err := tx.ExecContext(ctx, update, refID, state, title, sourceBranch)
	return err
}

func subsetFindings(findings []seededFinding, count int) []seededFinding {
	if count <= 0 || count >= len(findings) {
		return findings
	}
	return findings[:count]
}

func coverageRate(covered, valid int) float64 {
	if valid <= 0 {
		return 0
	}
	return float64(covered) / float64(valid)
}

func fakeHistorySHA(orgIndex, repoIndex, step int) string {
	//nolint:gosec // G401: SHA1 is used only for deterministic fake git commit hashes in seed data.
	sum := sha1.Sum([]byte(fmt.Sprintf("hist-%d-%d-%d", orgIndex, repoIndex, step)))
	return hex.EncodeToString(sum[:])[:7]
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func component(purl, name, version, ecosystem string) seededComponent {
	return seededComponent{purl: purl, name: name, version: version, ecosystem: ecosystem}
}

func finding(tool, ruleID string, severity store.SeverityLevel, status, filePath string, start, end int32, message string, metadata map[string]any) seededFinding {
	body, _ := json.Marshal(metadata)
	return seededFinding{
		tool:     tool,
		ruleID:   ruleID,
		severity: severity,
		status:   status,
		filePath: filePath,
		start:    start,
		end:      end,
		message:  message,
		metadata: body,
	}
}

func fakeCommitSHA(orgIndex, repoIndex int) string {
	//nolint:gosec // G401: SHA1 is used only for deterministic fake git commit hashes.
	sum := sha1.Sum([]byte(fmt.Sprintf("%d-%d", orgIndex, repoIndex)))
	return hex.EncodeToString(sum[:])[:7]
}

func findingLocationHash(tool, ruleID, filePath string, startLine, endLine int32) string {
	//nolint:gosec // G401: SHA1 is used only for deterministic seed location hashes.
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%s|%d|%d", tool, ruleID, filePath, startLine, endLine)))
	return hex.EncodeToString(sum[:])
}

func titleFromSlug(value string) string {
	parts := strings.Split(value, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func normalizeSeedFindingStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "fixed", "revoked", "rotating":
		return "resolved"
	case "ignored", "false_positive":
		return "dismissed"
	default:
		return "detected"
	}
}

func seededFindingType(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "gitleaks", "trufflehog":
		return "secret"
	default:
		return "sast"
	}
}

func truncateSeedText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}

func loadSeedComponent(ctx context.Context, tx *sql.Tx, componentID uuid.UUID) (string, string, string, string, error) {
	const query = `SELECT name, version, purl, ecosystem FROM components WHERE id = $1`
	var name string
	var version string
	var purl string
	var ecosystem string
	if err := tx.QueryRowContext(ctx, query, componentID).Scan(&name, &version, &purl, &ecosystem); err != nil {
		return "", "", "", "", err
	}
	return name, version, purl, ecosystem, nil
}

func nullSeedString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullSeedUUID(value any) uuid.NullUUID {
	id, ok := value.(uuid.UUID)
	if !ok || id == uuid.Nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: id, Valid: true}
}

func dependencySeedFingerprint(advisoryID, componentID uuid.UUID) string {
	return advisoryID.String() + ":" + componentID.String()
}
