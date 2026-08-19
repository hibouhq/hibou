import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/',
      component: () => import('@/layouts/AppLayout.vue'),
      children: [
        { path: '', redirect: '/orgs' },
        { path: 'orgs', name: 'orgs', component: () => import('@/views/OrgsView.vue') },
        {
          path: 'orgs/:provider/:slug',
          component: () => import('@/views/OrgDetailView.vue'),
          children: [
            { path: '', name: 'org-detail', redirect: to => ({ name: 'org-overview', params: to.params }) },
            { path: 'overview', name: 'org-overview', component: () => import('@/views/org/OverviewTab.vue') },
            { path: 'insights', name: 'org-insights', component: () => import('@/views/org/InsightsTab.vue') },
            { path: 'vulnerabilities', name: 'org-vulnerabilities', component: () => import('@/views/org/VulnerabilitiesTab.vue') },
            { path: 'dependencies', name: 'org-dependencies', component: () => import('@/views/org/DependenciesTab.vue') },
            { path: 'clients', name: 'org-clients', component: () => import('@/views/org/ClientsTab.vue') },
            // The Access tab moved under Settings.
            { path: 'access', redirect: to => ({ name: 'org-settings-access', params: to.params }) },
            {
              path: 'settings',
              component: () => import('@/views/org/SettingsTab.vue'),
              children: [
                { path: '', name: 'org-settings', redirect: to => ({ name: 'org-settings-general', params: to.params }) },
                { path: 'general', name: 'org-settings-general', component: () => import('@/views/org/settings/GeneralSettings.vue') },
                { path: 'access', name: 'org-settings-access', component: () => import('@/views/org/settings/AccessSettings.vue') },
                { path: 'members', name: 'org-settings-members', component: () => import('@/views/org/settings/MembersSettings.vue') },
                { path: 'quality-gates', name: 'org-settings-gates', component: () => import('@/views/org/settings/GatesSettings.vue') },
                { path: 'integrations', name: 'org-settings-integrations', component: () => import('@/views/org/settings/IntegrationsSettings.vue') },
                { path: 'notifications', name: 'org-settings-notifications', component: () => import('@/views/org/settings/NotificationsSettings.vue') },
                { path: 'audit', name: 'org-settings-audit', component: () => import('@/views/org/settings/AuditSettings.vue') },
              ],
            },
          ],
        },
        { path: 'orgs/:provider/:slug/search', name: 'search', component: () => import('@/views/SearchView.vue') },
        { path: 'orgs/:provider/:slug/repos', name: 'repos', component: () => import('@/views/ReposView.vue') },
        {
          path: 'orgs/:provider/:slug/clients/:clientSlug',
          component: () => import('@/views/ClientDetailView.vue'),
          children: [
            { path: '', name: 'client-detail', redirect: to => ({ name: 'client-overview', params: to.params }) },
            { path: 'overview', name: 'client-overview', component: () => import('@/views/client/OverviewTab.vue') },
            { path: 'history', name: 'client-history', component: () => import('@/views/client/HistoryTab.vue') },
          ],
        },
        {
          path: 'orgs/:provider/:slug/repos/:repoSlug/compare',
          name: 'repo-compare',
          component: () => import('@/views/CompareView.vue'),
        },
        {
          path: 'orgs/:provider/:slug/repos/:repoSlug/sbom-compare',
          name: 'sbom-compare',
          component: () => import('@/views/SBOMCompareView.vue'),
        },
        {
          // The standalone PR-gate page is gone (ADR-023): the compare view is
          // the one PR surface. Old forge-comment links land here; new comments
          // link to compare with base/head directly.
          path: 'orgs/:provider/:slug/repos/:repoSlug/pulls/:pr',
          redirect: to => ({ name: 'repo-compare', params: { provider: to.params.provider, slug: to.params.slug, repoSlug: to.params.repoSlug }, query: to.query }),
        },
        {
          path: 'orgs/:provider/:slug/repos/:repoSlug',
          component: () => import('@/views/RepoDetailView.vue'),
          children: [
            { path: '', redirect: to => ({ name: 'repo-overview', params: to.params, query: to.query }) },
            {
              path: 'overview',
              name: 'repo-overview',
              component: () => import('@/views/repo/OverviewTab.vue'),
            },
            {
              path: 'vulnerabilities',
              name: 'repo-vulnerabilities',
              component: () => import('@/views/repo/VulnerabilitiesTab.vue'),
            },
            {
              path: 'dependencies',
              name: 'repo-dependencies',
              component: () => import('@/views/repo/DependenciesTab.vue'),
            },
            {
              // Not ref-scoped like the analysis tabs: releases span tags and
              // pinned snapshots and bring their own filters (ADR-024).
              path: 'releases',
              name: 'repo-releases',
              component: () => import('@/views/repo/ReleasesTab.vue'),
            },
            {
              // Placeholder for the ADR-024 §8 phase; fenced with Releases.
              path: 'deployments',
              name: 'repo-deployments',
              component: () => import('@/views/repo/DeploymentsTab.vue'),
            },
            {
              path: 'coverage',
              name: 'repo-coverage',
              component: () => import('@/views/repo/CoverageTab.vue'),
            },
            {
              path: 'tests',
              name: 'repo-tests',
              component: () => import('@/views/repo/TestsTab.vue'),
            },
            {
              path: 'insights',
              name: 'repo-insights',
              component: () => import('@/views/repo/InsightsTab.vue'),
            },
            {
              path: 'settings',
              component: () => import('@/views/repo/SettingsTab.vue'),
              children: [
                { path: '', name: 'repo-settings', redirect: to => ({ name: 'repo-settings-general', params: to.params }) },
                { path: 'general', name: 'repo-settings-general', component: () => import('@/views/repo/settings/GeneralSettings.vue') },
                { path: 'configuration', name: 'repo-settings-config', component: () => import('@/views/repo/settings/ConfigSettings.vue') },
                { path: 'audit', name: 'repo-settings-audit', component: () => import('@/views/repo/settings/AuditSettings.vue') },
              ],
            },
          ],
        },
        { path: 'orgs/:provider/:slug/teams', name: 'teams', component: () => import('@/views/TeamsView.vue') },
        // The standalone audit page moved under org Settings → Audit log.
        { path: 'orgs/:provider/:slug/audit', redirect: to => ({ name: 'org-settings-audit', params: to.params, query: to.query }) },
        {
          path: 'settings',
          component: () => import('@/views/SettingsView.vue'),
          children: [
            { path: '', name: 'settings', redirect: { name: 'settings-api-keys' } },
            { path: 'api-keys', name: 'settings-api-keys', component: () => import('@/views/settings/ApiKeysSettings.vue') },
            { path: 'banners', name: 'settings-banners', component: () => import('@/views/settings/BannersSettings.vue') },
            { path: 'admins', name: 'settings-instance-admins', component: () => import('@/views/settings/InstanceAdminsSettings.vue') },
            { path: 'audit', name: 'settings-instance-audit', component: () => import('@/views/settings/InstanceAuditSettings.vue') },
          ],
        },
        { path: '/:pathMatch(.*)*', redirect: '/orgs' },
      ],
    },
  ],
})

export default router
