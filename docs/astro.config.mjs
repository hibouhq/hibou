import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import { execFileSync } from "node:child_process";

// Version is set via DOCS_VERSION env var during CI builds.
// Defaults to "latest" for local dev.
const version = process.env.PUBLIC_DOCS_VERSION || process.env.DOCS_VERSION || "latest";
const base = process.env.DOCS_BASE || `/${version}`;
let release = process.env.DOCS_RELEASE || version;
if (!/(?:^|[.-])(alpha|beta)(?=[.-]|$)/i.test(release) && !/^v?\d+\.\d+\.\d+(?:[-+].*)?$/.test(release)) {
    try {
        release = execFileSync("git", ["describe", "--tags", "--match", "v[0-9]*", "--abbrev=0"], {
            cwd: new URL("..", import.meta.url),
            encoding: "utf8",
            stdio: ["ignore", "pipe", "ignore"],
        }).trim();
    } catch { }
}
const releaseStage = release.match(/(?:^|[.-])(alpha|beta)(?=[.-]|$)/i)?.[1].toLowerCase() || "";

export default defineConfig({
    base,
    vite: {
        define: { "import.meta.env.HIBOU_RELEASE_STAGE": JSON.stringify(releaseStage) },
    },
    integrations: [
        starlight({
            title: "hibou",
            description: "Security intelligence for the whole SDLC. Eyes on what you ship.",
            logo: {
                src: "./src/assets/logomark.svg",
                alt: "Hibou",
            },
            favicon: "/favicon.svg",
            customCss: ["./src/styles/brand.css"],
            expressiveCode: { defaultProps: { wrap: true } },
            head: [
                { tag: "link", attrs: { rel: "apple-touch-icon", href: `${base}/icon-192.png` } },
                { tag: "link", attrs: { rel: "manifest", href: `${base}/site.webmanifest` } },
                { tag: "link", attrs: { rel: "preconnect", href: "https://fonts.googleapis.com" } },
                { tag: "link", attrs: { rel: "preconnect", href: "https://fonts.gstatic.com", crossorigin: "anonymous" } },
                { tag: "link", attrs: { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" } },
            ],
            social: [
                {
                    icon: "github",
                    label: "Source",
                    href: "https://github.com/hibouhq/hibou",
                },
            ],
            components: {
                // Add version selector next to the site title
                SiteTitle: "./src/components/SiteTitle.astro",
                ThemeProvider: "./src/components/ThemeProvider.astro",
                ThemeSelect: "./src/components/ThemeSelect.astro",
                Banner: "./src/components/PrereleaseBanner.astro",
            },
            sidebar: [
                {
                    label: "Getting Started",
                    items: [
                        { label: "Introduction", slug: "getting-started/introduction" },
                        { label: "Quick Start", slug: "getting-started/quickstart" },
                    ],
                },
                {
                    label: "Administration",
                    items: [
                        { label: "Configuration", slug: "admin/configuration" },
                        { label: "Forge Providers", slug: "admin/forge-providers" },
                        { label: "Authentication", slug: "admin/authentication" },
                        { label: "Docker Deployment", slug: "admin/docker" },
                        { label: "Kubernetes Deployment", slug: "admin/kubernetes" },
                    ],
                },
                {
                    label: "User Guide",
                    items: [
                        { label: "Organizations", slug: "guide/organizations" },
                        { label: "Repositories", slug: "guide/repositories" },
                        { label: "Security Scans", slug: "guide/security-scans" },
                        { label: "License Gating", slug: "guide/license-gating" },
                        { label: "Dependency Inventory", slug: "guide/dependency-inventory" },
                        { label: "IDE Extensions", slug: "guide/ide-extensions" },
                        { label: "Webhooks", slug: "guide/webhooks" },
                    ],
                },
                {
                    label: "Reference",
                    items: [
                        { label: "REST API", slug: "reference/api" },
                        { label: "Environment Variables", slug: "reference/environment" },
                        { label: "Threat Model", slug: "reference/threat-model" },
                        { label: "Press Kit", slug: "reference/press-kit" },
                    ],
                },
            ],
        }),
    ],
});
