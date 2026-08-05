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
            { path: 'vulnerabilities', name: 'org-vulnerabilities', component: () => import('@/views/org/VulnerabilitiesTab.vue') },
            { path: 'dependencies', name: 'org-dependencies', component: () => import('@/views/org/DependenciesTab.vue') },
            { path: 'access', name: 'org-access', component: () => import('@/views/org/AccessTab.vue') },
          ],
        },
        { path: 'orgs/:provider/:slug/search', name: 'search', component: () => import('@/views/SearchView.vue') },
        { path: 'orgs/:provider/:slug/repos', name: 'repos', component: () => import('@/views/ReposView.vue') },
        { path: 'orgs/:provider/:slug/clients', name: 'clients', component: () => import('@/views/ClientsView.vue') },
        {
          path: 'orgs/:provider/:slug/clients/:clientSlug',
          name: 'client-detail',
          component: () => import('@/views/ClientDetailView.vue'),
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
          path: 'orgs/:provider/:slug/repos/:repoSlug/pulls/:pr',
          name: 'repo-pr-gate',
          component: () => import('@/views/PRGateView.vue'),
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
              path: 'coverage',
              name: 'repo-coverage',
              component: () => import('@/views/repo/CoverageTab.vue'),
            },
            {
              path: 'tests',
              name: 'repo-tests',
              component: () => import('@/views/repo/TestsTab.vue'),
            },
          ],
        },
        { path: 'orgs/:provider/:slug/teams', name: 'teams', component: () => import('@/views/TeamsView.vue') },
        { path: 'orgs/:provider/:slug/audit', name: 'audit', component: () => import('@/views/AuditLogsView.vue') },
        {
          path: 'settings',
          component: () => import('@/views/SettingsView.vue'),
          children: [
            { path: '', name: 'settings', redirect: { name: 'settings-api-keys' } },
            { path: 'api-keys', name: 'settings-api-keys', component: () => import('@/views/settings/ApiKeysSettings.vue') },
          ],
        },
        { path: '/:pathMatch(.*)*', redirect: '/orgs' },
      ],
    },
  ],
})

export default router
