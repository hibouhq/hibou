package seed

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/hibouhq/lehibou/internal/store"
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
				},
				findings: []seededFinding{
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "internal/handler/auth.go", 47, 47, "JWT signing secret is hardcoded in the authentication handler.", map[string]any{"confidence": "high", "category": "credentials"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/repository/users.go", 83, 86, "SQL query concatenates user input into the WHERE clause.", map[string]any{"owasp": "A03:2021-Injection"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "fixed", "cmd/server/main.go", 129, 133, "TLS configuration still allows TLS 1.0 for upstream service calls.", map[string]any{"policy": "transport-security"}),
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "internal/http/render.go", 58, 59, "Unescaped user-controlled HTML is written directly to the response writer.", map[string]any{"framework": "net/http"}),
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
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelHigh, "open", "src/components/AdminPanel.tsx", 118, 121, "Dashboard renders raw HTML from markdown previews without sanitization.", map[string]any{"cwe": "CWE-79"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "src/api/client.ts", 14, 14, "Frontend bundle contains a hardcoded bearer token used for local API calls.", map[string]any{"exposure": "client-side"}),
					finding("trivy", "use-of-weak-hash-md5", store.SeverityLevelLow, "fixed", "scripts/build-assets.js", 22, 24, "Legacy asset digest still uses MD5 for cache keys.", map[string]any{"standard": "NIST SP 800-131A"}),
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
				},
				findings: []seededFinding{
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelMedium, "open", "internal/token/digest.go", 31, 33, "Authentication digest fallback relies on MD5 for compatibility mode.", map[string]any{"algorithm": "md5"}),
					finding("gosec", "insecure-tls-version", store.SeverityLevelHigh, "open", "internal/idp/client.go", 77, 84, "Identity provider client accepts TLS versions below 1.2.", map[string]any{"service": "oidc"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "fixed", "cmd/bootstrap/main.go", 19, 19, "Bootstrap flow committed an emergency admin password into source control.", map[string]any{"rotation": "completed"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/store/session_store.go", 102, 105, "Session lookup query is assembled with string concatenation.", map[string]any{"table": "sessions"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelLow, "open", "deploy/nginx.conf", 41, 48, "Ingress fallback listener permits deprecated TLS ciphers.", map[string]any{"surface": "edge"}),
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
					component("pkg:npm/jsonwebtoken@9.0.2", "jsonwebtoken", "9.0.2", "npm"),
				},
				findings: []seededFinding{
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelHigh, "open", "src/config/mobile.ts", 9, 9, "Mobile client embeds an API signing key in the application bundle.", map[string]any{"platform": "ios"}),
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelLow, "fixed", "src/screens/SupportWebView.tsx", 61, 65, "Support web view injects unsanitized HTML into the embedded browser.", map[string]any{"surface": "webview"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "open", "android/app/src/main/java/com/acme/network/TlsConfig.kt", 44, 48, "Android network stack allows TLS 1.1 for legacy endpoints.", map[string]any{"platform": "android"}),
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelMedium, "open", "scripts/release-notes/main.go", 17, 20, "Release notes generator uses MD5 to derive cache keys.", map[string]any{"usage": "cache-key"}),
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
				},
				findings: []seededFinding{
					finding("gosec", "insecure-tls-version", store.SeverityLevelHigh, "open", "cmd/proxy/main.go", 88, 95, "Proxy bootstrap leaves MinVersion unset on TLS listeners.", map[string]any{"cluster": "staging"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelMedium, "open", "controlplane/store/filters.go", 52, 54, "Dynamic search filter is appended directly into the SQL statement.", map[string]any{"input": "label_selector"}),
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
				},
				findings: []seededFinding{
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelLow, "open", "pkg/cache/checksum.go", 23, 26, "Image layer checksum fallback uses MD5 for performance reasons.", map[string]any{"component": "cache"}),
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "hack/dev-cluster.sh", 11, 11, "Cluster bootstrap script exposes a registry password in plain text.", map[string]any{"environment": "dev"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "fixed", "pkg/registry/client.go", 67, 72, "Registry client previously accepted TLS 1.1 for mirror endpoints.", map[string]any{"fix_version": "v1.3.0"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/audit/history.go", 74, 79, "Audit history search builds a SQL IN clause from request parameters.", map[string]any{"dataset": "events"}),
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
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "ui/src/views/AlertDetail.tsx", 201, 206, "Alert detail page writes raw Markdown HTML into the DOM.", map[string]any{"surface": "dashboard"}),
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelHigh, "fixed", "collector/config/defaults.go", 34, 34, "Example SMTP credential shipped as the package default.", map[string]any{"status_reason": "rotated"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelLow, "open", "deploy/grafana.ini", 8, 12, "Grafana sidecar TLS minimum version remains unset.", map[string]any{"service": "grafana"}),
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
				},
				findings: []seededFinding{
					finding("semgrep", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "pipelines/github/actions.ts", 41, 41, "Reusable CI action hardcodes a package signing token.", map[string]any{"surface": "github-actions"}),
					finding("gosec", "insecure-tls-version", store.SeverityLevelMedium, "open", "cmd/runner/main.go", 56, 61, "Runner webhook client does not pin TLS 1.2 or newer.", map[string]any{"service": "webhook"}),
					finding("trivy", "use-of-weak-hash-md5", store.SeverityLevelLow, "fixed", "internal/cache/artifacts.go", 17, 19, "Artifact cache key derivation used MD5 before the current release.", map[string]any{"fix_commit": "ab12cd3"}),
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/builds/history.go", 70, 74, "Build history endpoint appends raw branch filters into SQL.", map[string]any{"source": "query param"}),
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
				},
				findings: []seededFinding{
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "web/src/pages/report.tsx", 93, 97, "Static analysis report page injects unsanitized HTML annotations.", map[string]any{"renderer": "markdown"}),
					finding("gosec", "hardcoded-secret-in-source", store.SeverityLevelHigh, "open", "internal/scm/github.go", 26, 26, "GitHub integration token is committed into a local development helper.", map[string]any{"provider": "github"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "fixed", "internal/transport/http.go", 48, 54, "HTTP client previously permitted TLS 1.0 for third-party plugins.", map[string]any{"fixed_in": "v1.6.0"}),
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
				},
				findings: []seededFinding{
					finding("semgrep", "sql-injection-via-string-concatenation", store.SeverityLevelHigh, "open", "internal/search/packages.go", 112, 118, "Package search builds ORDER BY clauses from unvalidated request input.", map[string]any{"vector": "sort"}),
					finding("trivy", "hardcoded-secret-in-source", store.SeverityLevelCritical, "open", "deploy/registry.env", 4, 4, "Registry signing passphrase is stored in a checked-in env file.", map[string]any{"scope": "release"}),
					finding("gosec", "use-of-weak-hash-md5", store.SeverityLevelLow, "fixed", "internal/signing/legacy.go", 28, 32, "Legacy compatibility layer still references MD5 while verification is disabled.", map[string]any{"compatibility": true}),
					finding("semgrep", "go.lang.security.audit.xss.no-direct-write", store.SeverityLevelMedium, "open", "web/src/components/PackageReadme.tsx", 64, 70, "Rendered README content is inserted without HTML sanitization.", map[string]any{"content_source": "user-upload"}),
					finding("trivy", "insecure-tls-version", store.SeverityLevelMedium, "open", "cmd/mirror/main.go", 87, 92, "Registry mirror client supports deprecated TLS versions.", map[string]any{"remote": "partner-mirror"}),
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

			snapshot, err := queries.CreateSnapshot(ctx, branchRef.ID, commitSHA, &repoSeed.label, store.SnapshotStatusComplete, nil)
			if err != nil {
				return fmt.Errorf("creating snapshot for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			if err := seedComponents(ctx, tx, snapshot.ID, repoSeed.components); err != nil {
				return fmt.Errorf("seeding components for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}

			if err := seedFindings(ctx, queries, snapshot.ID, repoSeed.findings); err != nil {
				return fmt.Errorf("seeding findings for %s/%s: %w", orgSeed.slug, repoSeed.slug, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing seed transaction: %w", err)
	}

	log.Info().Int("organizations", len(seedOrgs)).Msg("development seed data created")
	return nil
}

func seedComponents(ctx context.Context, tx *sql.Tx, snapshotID uuid.UUID, components []seededComponent) error {
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

	for _, seededComponent := range components {
		var componentID uuid.UUID
		if err := tx.QueryRowContext(ctx, insertComponent, seededComponent.purl, seededComponent.name, seededComponent.version, seededComponent.ecosystem).Scan(&componentID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, linkSnapshotComponent, snapshotID, componentID); err != nil {
			return err
		}
	}

	return nil
}

func seedFindings(ctx context.Context, queries *store.Queries, snapshotID uuid.UUID, findings []seededFinding) error {
	for _, seededFinding := range findings {
		startLine := seededFinding.start
		endLine := seededFinding.end
		locationHash := findingLocationHash(seededFinding.tool, seededFinding.ruleID, seededFinding.filePath, startLine, endLine)

		_, err := queries.CreateFinding(
			ctx,
			snapshotID,
			seededFinding.tool,
			seededFinding.ruleID,
			seededFinding.severity,
			seededFinding.status,
			seededFinding.filePath,
			&startLine,
			&endLine,
			locationHash,
			seededFinding.message,
			nil,
			seededFinding.metadata,
		)
		if err != nil {
			return err
		}
	}

	return nil
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
	sum := sha1.Sum([]byte(fmt.Sprintf("%d-%d", orgIndex, repoIndex)))
	return hex.EncodeToString(sum[:])[:7]
}

func findingLocationHash(tool, ruleID, filePath string, startLine, endLine int32) string {
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
