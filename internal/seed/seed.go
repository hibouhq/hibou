package seed

import (
	"context"
	"crypto/sha1" // #nosec G505 -- SHA1 is used only for deterministic fake git hashes in seed data.
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/hibou/internal/advisory"
	"github.com/hibouhq/hibou/internal/provider/rawratings"
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
	// sinceDaysAgo / untilDaysAgo bound when the repository carried the
	// component (0 = always / still). Dependency findings follow the
	// component, so history, releases and Insights trends move with it.
	sinceDaysAgo int
	untilDaysAgo int
}

// presentAt reports whether the component was in a snapshot taken daysAgo.
func (c seededComponent) presentAt(daysAgo int) bool {
	return (c.sinceDaysAgo == 0 || daysAgo <= c.sinceDaysAgo) && (c.untilDaysAgo == 0 || daysAgo > c.untilDaysAgo)
}

// added and retired give a component a lifetime in the seeded history.
func (c seededComponent) added(daysAgo int) seededComponent {
	c.sinceDaysAgo = daysAgo
	return c
}

func (c seededComponent) retired(daysAgo int) seededComponent {
	c.untilDaysAgo = daysAgo
	return c
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
	// history is every other snapshot of the repo (main history, tags,
	// branches, PR), each with the components it carried: dependency
	// findings are matched on all of them, not only the latest.
	history []datedSnapshot
}

type datedSnapshot struct {
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
	isMalware   bool
	malwareType any
	publishedAt time.Time
	ranges      []seededAffectedRange
	targets     []seededMatchTarget
	// cwes as NVD maps them, so dependency findings join the CWE views.
	cwes []int
	// sources are provider records as the provider returns them, trimmed to
	// the rating fields: severity and CVSS are derived from them by the same
	// code as live data (ADR-038 §8), never set by hand.
	sources []seededSource
}

type seededSource struct {
	provider   string
	providerID string
	raw        string
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
					// Upgraded 10 days ago: Terrapin (CVE-2023-48795) shows as fixed.
					component("pkg:golang/golang.org/x/crypto@0.14.0", "golang.org/x/crypto", "0.14.0", "go").retired(10),
					component("pkg:golang/golang.org/x/crypto@0.17.0", "golang.org/x/crypto", "0.17.0", "go").added(10),
					component("pkg:golang/github.com/gin-gonic/gin@1.9.1", "github.com/gin-gonic/gin", "1.9.1", "go"),
					component("pkg:npm/jsonwebtoken@9.0.2", "jsonwebtoken", "9.0.2", "npm"),
					component("pkg:golang/golang.org/x/net@0.16.0", "golang.org/x/net", "0.16.0", "go"),
					component("pkg:golang/github.com/jackc/pgx/v5@5.5.4", "github.com/jackc/pgx/v5", "5.5.4", "go"),
					component("pkg:golang/github.com/spf13/cobra@1.8.0", "github.com/spf13/cobra", "1.8.0", "go"),
					component("pkg:golang/stdlib@1.13.6", "stdlib", "1.13.6", "go"),
				},
				findings: []seededFinding{
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "internal/handler/auth.go", 47, 47, "JWT signing secret is hardcoded in the authentication handler.", map[string]any{"confidence": "high", "category": "credentials"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/repository/users.go", 83, 86, "SQL query concatenates user input into the WHERE clause.", map[string]any{"owasp": "A03:2021-Injection"}),
					finding("codeql", "path-traversal", store.SeverityLevelHigh, "open", "internal/http/download.go", 66, 72, "Download handler joins user input into a filesystem path without normalization.", map[string]any{}),
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
					// Pulled in by event-stream two weeks ago: malware appears mid-history.
					component("pkg:npm/flatmap-stream@0.1.1", "flatmap-stream", "0.1.1", "npm").added(14),
					component("pkg:npm/next@14.1.0", "next", "14.1.0", "npm"),
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelHigh, "open", "src/components/AdminPanel.tsx", 118, 121, "Dashboard renders raw HTML from markdown previews without sanitization.", map[string]any{}),
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
					component("pkg:golang/github.com/opencontainers/runc@1.1.11", "github.com/opencontainers/runc", "1.1.11", "go").added(21),
					// The RHEL base image came in a week ago (ADR-038 distro rating).
					component("pkg:rpm/redhat/openssl@3.0.7-6.el9_2?distro=redhat-9.2&epoch=1", "openssl", "1:3.0.7-6.el9_2", "rpm").added(7),
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
					// Arrived 10 days ago: the current release ships it, v0.9.0 does not.
					component("pkg:npm/getcookies@1.0.0", "getcookies", "1.0.0", "npm").added(10),
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
	// Malware: real OSSF malicious-packages records as OSV serves them. An
	// invented MAL id is resolved by the first advisory scan pass, which only
	// keeps ranges a provider re-reports (scanner.matchComponentRanges): the
	// seed must use ids OSV actually returns for these packages.
	{
		// The payload behind the 2018 event-stream compromise.
		canonicalID: "MAL-2025-20690",
		title:       "Malicious code in flatmap-stream (npm)",
		description: "The package flatmap-stream was found to contain malicious code. It was the payload pulled in by the compromised event-stream 3.3.6, targeting cryptocurrency wallets.",
		isMalware:   true,
		malwareType: "data_exfiltration",
		publishedAt: time.Date(2025, time.August, 14, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "npm", packageName: "flatmap-stream", introduced: "0", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("acme", "web-dashboard"), componentPURL: "pkg:npm/flatmap-stream@0.1.1"}},
		sources: []seededSource{
			{provider: "osv", providerID: "MAL-2025-20690", raw: `{"id":"MAL-2025-20690","summary":"Malicious code in flatmap-stream (npm)"}`},
		},
	},
	{
		canonicalID: "MAL-2025-21368",
		title:       "Malicious code in getcookies (npm)",
		description: "The package getcookies was found to contain malicious code: a backdoor that let an attacker run code on servers using it.",
		isMalware:   true,
		malwareType: "backdoor",
		publishedAt: time.Date(2025, time.August, 14, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "npm", packageName: "getcookies", introduced: "0", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("devtools", "ci-pipeline"), componentPURL: "pkg:npm/getcookies@1.0.0"}},
		sources: []seededSource{
			{provider: "osv", providerID: "MAL-2025-21368", raw: `{"id":"MAL-2025-21368","summary":"Malicious code in getcookies (npm)"}`},
		},
	},
	{
		// Fixed by an upgrade 10 days ago on api-gateway, still open on
		// container-runtime: resolved in one repo's trend, open in another's.
		canonicalID: "CVE-2023-48795",
		cwes:        []int{345, 354},
		title:       "Prefix Truncation Attack against ChaCha20-Poly1305 and Encrypt-then-MAC aka Terrapin",
		description: "The SSH transport protocol with certain OpenSSH extensions lets a man-in-the-middle drop messages at the start of the secure channel (Terrapin), downgrading connection security.",
		publishedAt: time.Date(2023, time.December, 18, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "golang.org/x/crypto", introduced: "0.1.0", fixed: "0.17.0", source: "seed"}},
		targets: []seededMatchTarget{
			{repoKey: repoSeedKey("acme", "api-gateway"), componentPURL: "pkg:golang/golang.org/x/crypto@0.14.0"},
			{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:golang/golang.org/x/crypto@0.14.0"},
		},
		sources: []seededSource{
			{provider: "osv", providerID: "GHSA-45x7-px36-x8w8", raw: `{"id":"GHSA-45x7-px36-x8w8","aliases":["CVE-2023-48795","GO-2023-2402"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}],"database_specific":{"severity":"MODERATE"}}`},
		},
	},
	{
		canonicalID: "CVE-2023-44487",
		cwes:        []int{400},
		title:       "HTTP/2 Rapid Reset",
		// GitHub rates it moderate (A:L, 5.3) where NVD says high (A:H, 7.5):
		// the list marks the disagreement.
		sources: []seededSource{
			{provider: "osv", providerID: "GHSA-qppj-fm5r-hxr3", raw: `{"id":"GHSA-qppj-fm5r-hxr3","aliases":["CVE-2023-44487"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:H"},{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:A"}],"database_specific":{"severity":"MODERATE"}}`},
			{provider: "trivy", providerID: "CVE-2023-44487", raw: `{"vulnerability_id":"CVE-2023-44487","cvss":{"nvd":{"v3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","v3_score":7.5}}}`},
		},
		description: "golang.org/x/net HTTP/2 server implementations may be vulnerable to the Rapid Reset attack leading to denial of service.",
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
		cwes:        []int{770},
		title:       "golang.org/x/net HTTP/2 resource consumption",
		sources: []seededSource{
			{provider: "trivy", providerID: "CVE-2023-39325", raw: `{"vulnerability_id":"CVE-2023-39325","cvss":{"nvd":{"v3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H","v3_score":7.5}}}`},
		},
		description: "Certain HTTP/2 requests can consume excessive resources in affected golang.org/x/net versions.",
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
		cwes:        []int{403},
		title:       "runc container escape",
		sources: []seededSource{
			{provider: "osv", providerID: "GHSA-xr7r-f8xq-vfvv", raw: `{"id":"GHSA-xr7r-f8xq-vfvv","aliases":["CVE-2024-21626","GO-2024-2491"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"}],"database_specific":{"severity":"HIGH"}}`},
			{provider: "trivy", providerID: "CVE-2024-21626", raw: `{"vulnerability_id":"CVE-2024-21626","cvss":{"nvd":{"v3_vector":"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H","v3_score":8.6}}}`},
		},
		description: "Affected runc versions may permit a crafted image or container to escape intended filesystem boundaries.",
		publishedAt: time.Date(2024, time.January, 31, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "github.com/opencontainers/runc", introduced: "0", fixed: "1.1.12", source: "seed"}},
		targets: []seededMatchTarget{
			{repoKey: repoSeedKey("cloudnative", "service-mesh"), componentPURL: "pkg:golang/github.com/opencontainers/runc@1.1.11"},
			{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:golang/github.com/opencontainers/runc@1.1.11"},
		},
	},
	{
		canonicalID: "CVE-2023-45853",
		cwes:        []int{190},
		title:       "zlib buffer overflow",
		sources: []seededSource{
			{provider: "trivy", providerID: "CVE-2023-45853", raw: `{"vulnerability_id":"CVE-2023-45853","cvss":{"nvd":{"v3_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","v3_score":9.8}}}`},
		},
		description: "Affected Zlib.Portable packages bundle a vulnerable zlib version that may permit buffer overflow conditions during decompression.",
		publishedAt: time.Date(2023, time.December, 1, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "nuget", packageName: "Zlib.Portable", introduced: "0", fixed: "1.12.0", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("devtools", "package-registry"), componentPURL: "pkg:nuget/Zlib.Portable@1.11.0"}},
	},
	{
		// What the Trivy server reports on RHEL 9.2: Red Hat labels it Low
		// although its own CVSS is 4.7, and other vendors say medium. The RHEL
		// finding takes Red Hat's rating (ADR-038 §2).
		canonicalID: "CVE-2024-13176",
		cwes:        []int{385},
		title:       "openssl: Timing side-channel in ECDSA signature computation",
		description: "A timing side-channel in OpenSSL's ECDSA signature computation may let an attacker with local measurement access recover the private key.",
		publishedAt: time.Date(2025, time.January, 20, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "rpm", packageName: "openssl", introduced: "0", lastAffected: "1:3.0.7-6.el9_2", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("cloudnative", "container-runtime"), componentPURL: "pkg:rpm/redhat/openssl@3.0.7-6.el9_2?distro=redhat-9.2&epoch=1"}},
		sources: []seededSource{
			{provider: "trivy", providerID: "CVE-2024-13176", raw: `{"vulnerability_id":"CVE-2024-13176","severity":"LOW","severity_source":"redhat","vendor_severity":{"alma":"MEDIUM","amazon":"MEDIUM","azure":"MEDIUM","cbl-mariner":"MEDIUM","julia":"MEDIUM","oracle-oval":"MEDIUM","photon":"MEDIUM","redhat":"LOW","rocky":"MEDIUM","ubuntu":"LOW"},"cvss":{"julia":{"v3_vector":"CVSS:3.1/AV:P/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L","v3_score":4.1},"redhat":{"v3_vector":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N","v3_score":4.7}}}`},
		},
	},
	{
		// CurveBall in the Go standard library. The Go vulnerability database
		// publishes no severity (GO-2022-0535), so without the CVE feed it is
		// unknown — not info (ADR-038 §3). With the feed loaded, the CNA's
		// rating reaches it through the CVE alias.
		canonicalID: "CVE-2020-0601",
		cwes:        []int{295},
		title:       "Certificate validation bypass on Windows in crypto/x509",
		description: "On Windows, crypto/x509 delegated certificate validation to the system API, which accepted spoofed ECC certificates (CurveBall).",
		publishedAt: time.Date(2020, time.January, 14, 0, 0, 0, 0, time.UTC),
		ranges:      []seededAffectedRange{{ecosystem: "go", packageName: "stdlib", introduced: "1.13.0-0", fixed: "1.13.7", source: "seed"}},
		targets:     []seededMatchTarget{{repoKey: repoSeedKey("acme", "api-gateway"), componentPURL: "pkg:golang/stdlib@1.13.6"}},
		sources: []seededSource{
			{provider: "osv", providerID: "GO-2022-0535", raw: `{"id":"GO-2022-0535","aliases":["BIT-golang-2020-0601","CVE-2020-0601"]}`},
		},
	},
}

func Run(ctx context.Context, db *sql.DB, log zerolog.Logger) error {
	queries := store.NewQueries(db)

	existingOrg, err := queries.GetOrganizationByProviderAndSlug(ctx, "github", "acme")
	if err != nil {
		return fmt.Errorf("checking existing seed data: %w", err)
	}
	if existingOrg != nil {
		log.Info().Str("org_slug", "acme").Msg("seed data already present, skipping; refreshing seeded advisory ratings")
		return refreshSeedRatings(ctx, db, queries)
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

		clientIDs, err := seedClients(ctx, queries, org.ID)
		if err != nil {
			return fmt.Errorf("seeding clients for %s: %w", orgSeed.slug, err)
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

			componentIDs, err := seedComponentsForSnapshot(ctx, tx, snapshot.ID, repoSeed.components, 0)
			if err != nil {
				return fmt.Errorf("seeding components for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			if err := seedFindings(ctx, queries, snapshot.ID, repoSeed.findings); err != nil {
				return fmt.Errorf("seeding findings for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}
			if repoIndex == 0 && len(repoSeed.components) > 0 {
				if err := seedManualFinding(ctx, queries, snapshot.ID, repo.ID, devUser.ID); err != nil {
					return fmt.Errorf("seeding manual finding for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
				}
			}

			var history []datedSnapshot
			if err := seedRepoHistory(ctx, tx, queries, historyParams{
				repoID:           repo.ID,
				branchRefID:      branchRef.ID,
				latestSnapshotID: snapshot.ID,
				latestCreatedAt:  snapshot.CreatedAt,
				repoSeed:         repoSeed,
				orgIndex:         orgIndex,
				repoIndex:        repoIndex,
				clientIDs:        clientIDs,
				history:          &history,
			}); err != nil {
				return fmt.Errorf("seeding history for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			seededSnapshots[repoSeedKey(orgSeed.slug, repoSeed.slug)] = seededSnapshotState{
				snapshotID:   snapshot.ID,
				componentIDs: componentIDs,
				history:      history,
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

func seedComponentsForSnapshot(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, components []seededComponent, daysAgo int) (map[string]uuid.UUID, error) {
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
		if !seededComponent.presentAt(daysAgo) {
			continue
		}
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
		INSERT INTO advisories (canonical_id, title, description, is_malware, malware_type, published_at)
		VALUES ($1, $2, $3, $4, $5, $6)
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
			advisory.isMalware,
			advisory.malwareType,
			advisory.publishedAt,
		).Scan(&advisoryID); err != nil {
			return err
		}
		if err := qtx.AddAdvisoryCWEs(ctx, advisoryID, advisory.cwes); err != nil {
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
			// Every snapshot that carried the component gets the finding, so
			// history, releases and trends show when it arrived and left.
			dated := append([]datedSnapshot{{snapshotID: snapshotState.snapshotID, componentIDs: snapshotState.componentIDs}}, snapshotState.history...)
			matched := 0
			for _, snapshot := range dated {
				componentID, ok := snapshot.componentIDs[target.componentPURL]
				if !ok {
					continue
				}
				matched++
				if err := seedMatchedFinding(ctx, qtx, tx, snapshot.snapshotID, componentID, advisoryID, affectedRangeID, advisory); err != nil {
					return err
				}
			}
			if matched == 0 {
				return fmt.Errorf("component %s is in no snapshot of %s", target.componentPURL, target.repoKey)
			}
		}
		if err := seedAdvisoryRatings(ctx, qtx, advisoryID, advisory); err != nil {
			return fmt.Errorf("rate %s: %w", advisory.canonicalID, err)
		}
	}

	return nil
}

// seedMatchedFinding creates the dependency or malware finding a scan would
// create for a component matching the advisory. Severity is a placeholder:
// seedAdvisoryRatings derives it afterwards, for every snapshot at once.
func seedMatchedFinding(ctx context.Context, qtx *store.Queries, tx *sql.Tx, snapshotID, componentID, advisoryID uuid.UUID, affectedRangeID any, seeded seededAdvisory) error {
	componentName, componentVersion, componentPURL, ecosystem, err := loadSeedComponent(ctx, tx, componentID)
	if err != nil {
		return err
	}
	vulnType := "dependency"
	if seeded.isMalware {
		vulnType = "malware"
	}
	_, err = qtx.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   vulnType,
		SnapshotID:             snapshotID,
		Title:                  seeded.title,
		Description:            seeded.description,
		PrimaryIdentifierKind:  "advisory",
		PrimaryIdentifierValue: seeded.canonicalID,
		OriginalSeverity:       store.SeverityLevelUnknown,
		Severity:               store.SeverityLevelUnknown,
		Status:                 "detected",
		ScannerName:            "seed",
		Fingerprint:            dependencySeedFingerprint(advisoryID, componentID),
		ComponentID:            uuid.NullUUID{UUID: componentID, Valid: true},
		ComponentName:          nullSeedString(componentName),
		ComponentVersion:       nullSeedString(componentVersion),
		ComponentPurl:          nullSeedString(componentPURL),
		Ecosystem:              nullSeedString(ecosystem),
		AdvisoryID:             uuid.NullUUID{UUID: advisoryID, Valid: true},
		AffectedRangeID:        nullSeedUUID(affectedRangeID),
	})
	return err
}

// refreshSeedRatings brings advisories an older seed created up to the
// current rating model (ADR-038 §8): their aliases, provider records and the
// severity derived from them. It touches only the seed's own canonical IDs.
func refreshSeedRatings(ctx context.Context, db *sql.DB, queries *store.Queries) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	qtx := queries.WithTx(tx)
	for _, seeded := range seedAdvisories {
		existing, err := qtx.GetAdvisoryByCanonicalID(ctx, seeded.canonicalID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		// A real scan may have stored a provider's record since: it wins over
		// the seed's trimmed copy.
		stored, err := qtx.ListSourcesByAdvisory(ctx, existing.ID)
		if err != nil {
			return err
		}
		have := make(map[string]bool, len(stored))
		for _, source := range stored {
			have[source.Provider] = true
		}
		missing := seeded
		missing.sources = nil
		for _, source := range seeded.sources {
			if !have[source.provider] {
				missing.sources = append(missing.sources, source)
			}
		}
		if err := seedAdvisoryRatings(ctx, qtx, existing.ID, missing); err != nil {
			return fmt.Errorf("rate %s: %w", seeded.canonicalID, err)
		}
	}
	return tx.Commit()
}

// seedAdvisoryRatings stores the advisory's provider records and derives its
// severity, and its findings', exactly as ingest does.
func seedAdvisoryRatings(ctx context.Context, qtx *store.Queries, advisoryID uuid.UUID, seeded seededAdvisory) error {
	// Ingest records every identifier as an alias; the CVE-feed rating and
	// EPSS reach an advisory through them.
	aliases := []string{seeded.canonicalID}
	for _, source := range seeded.sources {
		aliases = append(aliases, source.providerID)
	}
	for _, alias := range aliases {
		if err := qtx.UpsertAdvisoryAlias(ctx, dbgen.UpsertAdvisoryAliasParams{AdvisoryID: advisoryID, Alias: alias}); err != nil {
			return err
		}
	}
	for _, source := range seeded.sources {
		sourceID, err := qtx.UpsertAdvisorySource(ctx, dbgen.UpsertAdvisorySourceParams{
			AdvisoryID:     advisoryID,
			Provider:       source.provider,
			ProviderID:     source.providerID,
			RawData:        json.RawMessage(source.raw),
			FetchedAt:      time.Now().UTC(),
			RatingsVersion: advisory.RatingsVersion,
		})
		if err != nil {
			return err
		}
		ratings, err := rawratings.FromRaw(source.provider, json.RawMessage(source.raw))
		if err != nil {
			return err
		}
		if err := advisory.SyncSourceRatings(ctx, qtx, sourceID, ratings); err != nil {
			return err
		}
	}
	_, err := advisory.Rerate(ctx, qtx, advisoryID)
	return err
}

// seedRuleCWEs gives seeded rules the CWEs those scanners report in their
// SARIF (ADR-037 survey). ESLint, Checkov and Trivy misconfiguration rules
// carry none on purpose: the demo shows real coverage gaps under cwe:none.
// Secret-scanner findings are CWE-798 by type, without a rule.
var seedRuleCWEs = map[string][]int{
	"semgrep/sql-injection-via-string-concatenation":     {89},
	"semgrep/hardcoded-secret-in-source":                 {798},
	"semgrep/go.lang.security.audit.xss.no-direct-write": {79},
	"semgrep/open-redirect":                              {601},
	"semgrep/insecure-deserialization":                   {502},
	"semgrep/ssrf-via-user-input":                        {918},
	"semgrep/missing-burst-ceiling":                      {770},
	"semgrep/cors-misconfiguration":                      {942},
	"gosec/use-of-weak-hash-md5":                         {328},
	"gosec/insecure-tls-version":                         {327},
	"gosec/hardcoded-secret-in-source":                   {798},
	"gosec/G115":                                         {190},
	"codeql/path-traversal":                              {22, 23, 36},
	"codeql/command-injection":                           {78, 88},
	"bandit/shell-injection":                             {78},
	"bandit/hardcoded-database-password":                 {259},
}

// seedRule upserts the scan rule a seeded finding references when the
// scanner would classify it, and records its CWEs.
func seedRule(ctx context.Context, queries *store.Queries, tool, ruleID string) (uuid.NullUUID, error) {
	cwes, ok := seedRuleCWEs[tool+"/"+ruleID]
	if !ok {
		return uuid.NullUUID{}, nil
	}
	id, err := queries.UpsertScanRule(ctx, dbgen.UpsertScanRuleParams{
		Tool: tool, RuleID: ruleID, Name: ruleID, Tags: []string{"security"}, Properties: json.RawMessage(`{}`),
	})
	if err != nil {
		return uuid.NullUUID{}, err
	}
	if err := queries.SyncScanRuleCWEs(ctx, map[uuid.UUID][]int{id: cwes}); err != nil {
		return uuid.NullUUID{}, err
	}
	return uuid.NullUUID{UUID: id, Valid: true}, nil
}

func seedFindings(ctx context.Context, queries *store.Queries, snapshotID uuid.UUID, findings []seededFinding) error {
	for _, seededFinding := range findings {
		ruleRef, err := seedRule(ctx, queries, seededFinding.tool, seededFinding.ruleID)
		if err != nil {
			return err
		}
		startLine := seededFinding.start
		endLine := seededFinding.end
		locationHash := findingLocationHash(seededFinding.tool, seededFinding.ruleID, seededFinding.filePath, startLine, endLine)

		_, err = queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
			Type:                   seededFindingType(seededFinding.tool),
			SnapshotID:             snapshotID,
			Title:                  truncateSeedText(seededFinding.message, 200),
			Description:            seededFinding.message,
			PrimaryIdentifierKind:  "rule",
			PrimaryIdentifierValue: seededFinding.ruleID,
			OriginalSeverity:       seededFinding.severity,
			Severity:               seededFinding.severity,
			Status:                 normalizeSeedFindingStatus(seededFinding.status),
			ScannerName:            seededFinding.tool,
			FilePath:               nullSeedString(seededFinding.filePath),
			StartLine:              sql.NullInt32{Int32: startLine, Valid: startLine > 0},
			EndLine:                sql.NullInt32{Int32: endLine, Valid: endLine > 0},
			LocationHash:           nullSeedString(locationHash),
			Fingerprint:            locationHash,
			Metadata:               seededFinding.metadata,
			RuleRefID:              ruleRef,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// seedManualFinding files a finding by hand, as a reviewer would after a
// code review, with the CWEs they declared (ADR-037): the one source of CWEs
// no scanner provides.
func seedManualFinding(ctx context.Context, queries *store.Queries, snapshotID, repoID, userID uuid.UUID) error {
	const fingerprint = "manual:review-2026-q3-tenant-isolation"
	finding, err := queries.CreateVulnerability(ctx, dbgen.CreateVulnerabilityParams{
		Type:                   string(store.VulnerabilityTypeManual),
		SnapshotID:             snapshotID,
		Title:                  "Tenant id taken from the URL without an ownership check",
		Description:            "Found in the Q3 security review: the handler loads the tenant named in the path and never checks that the caller belongs to it, so any authenticated user can read another tenant's records.",
		PrimaryIdentifierKind:  "rule",
		PrimaryIdentifierValue: "review-tenant-isolation",
		OriginalSeverity:       store.SeverityLevelHigh,
		Severity:               store.SeverityLevelHigh,
		Status:                 string(store.VulnerabilityStatusDetected),
		FilePath:               nullSeedString("internal/handler/tenants.go"),
		StartLine:              sql.NullInt32{Int32: 42, Valid: true},
		EndLine:                sql.NullInt32{Int32: 58, Valid: true},
		LocationHash:           nullSeedString(fingerprint),
		Fingerprint:            fingerprint,
		Solution:               nullSeedString("Resolve the tenant from the caller's membership, not from the path."),
		Metadata:               json.RawMessage(`{}`),
		Origin:                 dbgen.FindingOriginHuman,
		CreatedBy:              uuid.NullUUID{UUID: userID, Valid: true},
	})
	if err != nil {
		return err
	}
	// CWE-639 (authorization bypass through a user-controlled key) and
	// CWE-862 (missing authorization).
	return queries.ReplaceDeclaredFindingCWEs(ctx, repoID, finding.Fingerprint, []int{639, 862}, store.FindingCWEDeclarer{UserID: uuid.NullUUID{UUID: userID, Valid: true}})
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
	clientIDs        []uuid.UUID
	// history collects the snapshots created here for advisory matching.
	history *[]datedSnapshot
}

// recordComponents links the components the repo carried daysAgo to a
// history snapshot and remembers it for advisory matching.
func (p historyParams) recordComponents(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, daysAgo int) error {
	componentIDs, err := seedComponentsForSnapshot(ctx, tx, snapshotID, p.repoSeed.components, daysAgo)
	if err != nil {
		return err
	}
	if p.history != nil {
		*p.history = append(*p.history, datedSnapshot{snapshotID: snapshotID, componentIDs: componentIDs})
	}
	return nil
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
// snapshot, a backdated snapshot history (incl. a failed build), a compareable
// feature branch on every repo, and — for the first repo of each org — a release
// tag plus an in-flight pull request. This is what exercises the snapshot
// selector, coverage tab, trends, and compare / PR views.
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
	if _, err := seedCompareBranch(ctx, tx, queries, p); err != nil {
		return err
	}

	// Only the first repo of each org grows a release tag + an open PR.
	if p.repoIndex != 0 {
		return nil
	}
	return seedExtraRefs(ctx, tx, queries, p)
}

func seedCompareBranch(ctx context.Context, tx *sql.Tx, queries *store.Queries, p historyParams) (string, error) {
	branchName := compareBranchName(p)
	branchCommit := fakeHistorySHA(p.orgIndex, p.repoIndex, 41)
	branchRef, err := queries.CreateRef(ctx, p.repoID, branchName, store.RefTypeBranch, nil, nil, &branchCommit)
	if err != nil {
		return "", err
	}

	branchCreatedAt := p.latestCreatedAt.Add(-90 * time.Minute)
	branchSnapshotID, err := insertSnapshotRaw(ctx, tx, branchRef.ID, branchCommit, store.SnapshotStatusComplete, snapshotMeta{createdAt: branchCreatedAt})
	if err != nil {
		return "", err
	}
	if err := p.recordComponents(ctx, tx, branchSnapshotID, 0); err != nil {
		return "", err
	}
	if err := seedFindings(ctx, queries, branchSnapshotID, compareBranchFindings(p.repoSeed, branchName)); err != nil {
		return "", err
	}
	if err := seedCoverage(ctx, tx, branchSnapshotID, branchCreatedAt, coverageSpecForRepo(p.repoSeed, 0.81)); err != nil {
		return "", err
	}
	if err := seedTests(ctx, tx, branchSnapshotID, branchCreatedAt, p.repoSeed, 2); err != nil {
		return "", err
	}

	return branchName, nil
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
		if err := p.recordComponents(ctx, tx, snapshotID, step.daysAgo); err != nil {
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
	branchName := compareBranchName(p)
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
	if err := p.recordComponents(ctx, tx, tagSnapshotID, 3); err != nil {
		return err
	}
	if err := seedCoverage(ctx, tx, tagSnapshotID, tagCreatedAt, coverageSpecForRepo(p.repoSeed, 0.74)); err != nil {
		return err
	}
	// The shipped tag still carries most of the branch findings so the release
	// shows a real risk posture on the Releases tab.
	if err := seedFindings(ctx, queries, tagSnapshotID, subsetFindings(p.repoSeed.findings, len(p.repoSeed.findings)-1)); err != nil {
		return err
	}
	if err := seedReleases(ctx, queries, p, tagRef.ID, tagSnapshotID, tagName, tagCreatedAt, tx); err != nil {
		return err
	}

	// Pull request targeting main, scanned (complete) so it produces a rich diff
	// against the base branch: most findings carry over (unchanged), the last two
	// base findings are gone (resolved), and the PR introduces two new findings.
	// Coverage and tests also move, so the compare/PR-review POC shows changes on
	// every dimension via `make start-quick`.
	prCommit := fakeHistorySHA(p.orgIndex, p.repoIndex, 42)
	prRef, err := queries.CreateRef(ctx, p.repoID, "refs/pull/42", store.RefTypePullRequest, nil, &p.branchRefID, &prCommit)
	if err != nil {
		return err
	}
	if err := setSeedPRMetadata(ctx, tx, prRef.ID, "open", "Add request rate limiting middleware", branchName); err != nil {
		return err
	}
	prCreatedAt := p.latestCreatedAt.Add(-2 * time.Hour)
	prSnapshotID, err := insertSnapshotRaw(ctx, tx, prRef.ID, prCommit, store.SnapshotStatusComplete, snapshotMeta{createdAt: prCreatedAt})
	if err != nil {
		return err
	}
	if err := p.recordComponents(ctx, tx, prSnapshotID, 0); err != nil {
		return err
	}

	prFindings := append([]seededFinding{}, subsetFindings(p.repoSeed.findings, len(p.repoSeed.findings)-2)...)
	prFindings = append(prFindings,
		finding("gosec", "G115", store.SeverityLevelHigh, "open", "internal/middleware/ratelimit.go", 64, 64, "Integer overflow converting the rate window to int32 in the new limiter.", map[string]any{"introduced_by": "pr-42"}),
		finding("semgrep", "missing-burst-ceiling", store.SeverityLevelMedium, "open", "internal/middleware/ratelimit.go", 88, 95, "New rate limiter lacks an upper burst ceiling, allowing short request spikes.", map[string]any{"surface": "middleware"}),
	)
	if err := seedFindings(ctx, queries, prSnapshotID, prFindings); err != nil {
		return err
	}
	// Base latest coverage is 0.78; the PR raises it to 0.83 (both sides present).
	if err := seedCoverage(ctx, tx, prSnapshotID, prCreatedAt, coverageSpecForRepo(p.repoSeed, 0.83)); err != nil {
		return err
	}
	// Base latest has 1 failing test; the PR fixes it (status change in the diff).
	return seedTests(ctx, tx, prSnapshotID, prCreatedAt, p.repoSeed, 0)
}

func compareBranchName(p historyParams) string {
	if p.repoIndex == 0 {
		return "feature/rate-limit"
	}
	return "feature/compare-demo"
}

func compareBranchFindings(repoSeed seededRepo, branchName string) []seededFinding {
	keep := len(repoSeed.findings) - 1
	if keep <= 0 {
		keep = len(repoSeed.findings)
	}
	findings := append([]seededFinding{}, subsetFindings(repoSeed.findings, keep)...)
	findings = append(findings, finding(
		"semgrep",
		"compare-demo-regression",
		store.SeverityLevelMedium,
		"open",
		fmt.Sprintf("internal/compare/%s.go", repoSeed.slug),
		17,
		25,
		fmt.Sprintf("Compare demo branch %s introduces a regression for %s.", branchName, repoSeed.slug),
		map[string]any{"surface": "compare-demo", "branch": branchName},
	))
	return findings
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
		INSERT INTO test_reports (snapshot_id, source, format, total, passed, failed, skipped, errors, duration_seconds, created_at)
		VALUES ($1, 'seed', 'junit', $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (snapshot_id, source) DO NOTHING
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
	// #nosec G401 -- SHA1 is used only for deterministic fake git commit hashes in seed data.
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
	// #nosec G401 -- SHA1 is used only for deterministic fake git commit hashes.
	sum := sha1.Sum([]byte(fmt.Sprintf("%d-%d", orgIndex, repoIndex)))
	return hex.EncodeToString(sum[:])[:7]
}

func findingLocationHash(tool, ruleID, filePath string, startLine, endLine int32) string {
	// #nosec G401 -- SHA1 is used only for deterministic seed location hashes.
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
		// Migration 00017 collapsed the status axes: a tool reporting a finding
		// as ignored is a scanner-side suppression, not a Hibou decision
		// (those live in finding_acceptances, ADR-023).
		return "suppressed"
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

// seedClients creates the org's downstream clients (ADR-024): the parties the
// Releases tab assigns releases to.
func seedClients(ctx context.Context, queries *store.Queries, orgID uuid.UUID) ([]uuid.UUID, error) {
	specs := []struct {
		name       string
		slug       string
		clientType string
		labels     string
		contact    string
		email      string
	}{
		{"Globex Corporation", "globex", "external", `{"region":"eu-west","tier":"gold"}`, "Hank Scorpio", "hank@globex.example"},
		{"Initech", "initech", "external", `{"region":"us-east","tier":"silver"}`, "Bill Lumbergh", "bill@initech.example"},
		{"Internal Platform", "internal-platform", "internal", `{"region":"eu-central"}`, "", ""},
	}

	ids := make([]uuid.UUID, 0, len(specs))
	for _, spec := range specs {
		var contactName, contactEmail *string
		if spec.contact != "" {
			contactName = &spec.contact
		}
		if spec.email != "" {
			contactEmail = &spec.email
		}
		client, err := queries.CreateClient(ctx, orgID, spec.name, spec.slug, json.RawMessage(spec.labels), spec.clientType, contactEmail, contactName, nil, nil)
		if err != nil {
			return nil, err
		}
		ids = append(ids, client.ID)
	}
	return ids, nil
}

// seedReleases derives the demo releases the way production does (ADR-024):
// the current tag plus an older shipped version, snapshots pinned, clients on
// them via deployments — current rollout on the latest, a laggard client on
// the old build, and superseded history from the rollout that moved forward.
func seedReleases(ctx context.Context, queries *store.Queries, p historyParams, tagRefID, tagSnapshotID uuid.UUID, tagName string, tagCreatedAt time.Time, tx *sql.Tx) error {
	forgeURL := fmt.Sprintf("https://github.com/acme/%s/releases/tag/%s", p.repoSeed.slug, tagName)
	current, err := queries.UpsertRelease(ctx, store.UpsertReleaseParams{
		RepoID:      p.repoID,
		RefID:       tagRefID,
		SnapshotID:  &tagSnapshotID,
		Version:     tagName,
		HTMLURL:     &forgeURL,
		Source:      store.ReleaseSourceForge,
		PublishedAt: &tagCreatedAt,
	})
	if err != nil {
		return err
	}
	if _, err := queries.UpdateSnapshotRetentionFlags(ctx, tagSnapshotID, true, false); err != nil {
		return err
	}

	// Older shipped version: its own tag, snapshot, and the full finding set —
	// the laggard client is visibly worse off than the current rollout.
	oldTagName := "v0.9.0"
	oldCommit := fakeHistorySHA(p.orgIndex, p.repoIndex, 91)
	oldCreatedAt := p.latestCreatedAt.AddDate(0, 0, -30)
	oldRef, err := queries.CreateRef(ctx, p.repoID, oldTagName, store.RefTypeTag, nil, nil, &oldCommit)
	if err != nil {
		return err
	}
	oldSnapshotID, err := insertSnapshotRaw(ctx, tx, oldRef.ID, oldCommit, store.SnapshotStatusComplete, snapshotMeta{tag: &oldTagName, createdAt: oldCreatedAt})
	if err != nil {
		return err
	}
	if err := p.recordComponents(ctx, tx, oldSnapshotID, 30); err != nil {
		return err
	}
	if err := seedFindings(ctx, queries, oldSnapshotID, p.repoSeed.findings); err != nil {
		return err
	}
	previous, err := queries.UpsertRelease(ctx, store.UpsertReleaseParams{
		RepoID:      p.repoID,
		RefID:       oldRef.ID,
		SnapshotID:  &oldSnapshotID,
		Version:     oldTagName,
		Source:      store.ReleaseSourceTag,
		PublishedAt: &oldCreatedAt,
	})
	if err != nil {
		return err
	}
	if _, err := queries.UpdateSnapshotRetentionFlags(ctx, oldSnapshotID, true, false); err != nil {
		return err
	}

	if len(p.clientIDs) < 2 {
		return nil
	}
	deployedBy := "release-bot"
	// Client 0 moved forward: superseded on the old release, active on the new.
	if _, err := queries.CreateDeployment(ctx, p.clientIDs[0], previous.ID, "production", store.DeploymentStatusSuperseded, oldCreatedAt.Add(2*time.Hour), &deployedBy, nil, nil); err != nil {
		return err
	}
	if _, err := queries.CreateDeployment(ctx, p.clientIDs[0], current.ID, "production", store.DeploymentStatusActive, tagCreatedAt.Add(90*time.Minute), &deployedBy, nil, nil); err != nil {
		return err
	}
	// Client 1 lags on the old build.
	if _, err := queries.CreateDeployment(ctx, p.clientIDs[1], previous.ID, "production", store.DeploymentStatusActive, oldCreatedAt.Add(26*time.Hour), &deployedBy, nil, nil); err != nil {
		return err
	}
	// The internal platform runs the new build in staging.
	if len(p.clientIDs) > 2 {
		if _, err := queries.CreateDeployment(ctx, p.clientIDs[2], current.ID, "staging", store.DeploymentStatusActive, tagCreatedAt.Add(30*time.Minute), &deployedBy, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
