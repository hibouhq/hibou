import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// Version is set via DOCS_VERSION env var during CI builds.
// Defaults to "latest" for local dev.
const version = process.env.DOCS_VERSION || "latest";
const base = process.env.DOCS_BASE || `/${version}`;

export default defineConfig({
    base,
    integrations: [
        starlight({
            title: "Hibou",
            description: "DevSecOps security platform documentation",
            social: [
                {
                    icon: "github",
                    label: "Source",
                    href: "https://github.com/hibouhq/lehibou",
                },
            ],
            components: {
                // Add version selector next to the site title
                SiteTitle: "./src/components/SiteTitle.astro",
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
                        { label: "Webhooks", slug: "guide/webhooks" },
                    ],
                },
                {
                    label: "Reference",
                    items: [
                        { label: "REST API", slug: "reference/api" },
                        { label: "Environment Variables", slug: "reference/environment" },
                    ],
                },
            ],
        }),
    ],
});
