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
        { path: 'orgs/:provider/:slug', name: 'org-detail', component: () => import('@/views/OrgDetailView.vue') },
        { path: 'orgs/:provider/:slug/search', name: 'search', component: () => import('@/views/SearchView.vue') },
        { path: 'orgs/:provider/:slug/repos', name: 'repos', component: () => import('@/views/ReposView.vue') },
        { path: 'orgs/:provider/:slug/clients', name: 'clients', component: () => import('@/views/ClientsView.vue') },
        {
          path: 'orgs/:provider/:slug/clients/:clientSlug',
          name: 'client-detail',
          component: () => import('@/views/ClientDetailView.vue'),
        },
        {
          path: 'orgs/:provider/:slug/repos/:repoSlug/pr/:number',
          name: 'pr-review',
          component: () => import('@/views/PRReviewView.vue'),
        },
        {
          path: 'orgs/:provider/:slug/repos/:repoSlug/compare',
          name: 'repo-compare',
          component: () => import('@/views/CompareView.vue'),
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
              path: 'weaknesses',
              name: 'repo-weaknesses',
              component: () => import('@/views/repo/WeaknessesTab.vue'),
            },
            {
              path: 'dependencies',
              name: 'repo-dependencies',
              component: () => import('@/views/repo/DependenciesTab.vue'),
            },
            {
              path: 'trends',
              name: 'repo-trends',
              component: () => import('@/views/repo/TrendsTab.vue'),
            },
            {
              path: 'malware',
              name: 'repo-malware',
              component: () => import('@/views/repo/MalwareTab.vue'),
            },
            {
              path: 'runtime',
              name: 'repo-runtime',
              component: () => import('@/views/repo/RuntimeTab.vue'),
            },
            {
              path: 'secrets',
              name: 'repo-secrets',
              component: () => import('@/views/repo/SecretsTab.vue'),
            },
          ],
        },
        { path: 'orgs/:provider/:slug/teams', name: 'teams', component: () => import('@/views/TeamsView.vue') },
        { path: 'orgs/:provider/:slug/audit', name: 'audit', component: () => import('@/views/AuditLogsView.vue') },
        { path: 'settings', name: 'settings', component: () => import('@/views/SettingsView.vue') },
        { path: '/:pathMatch(.*)*', redirect: '/orgs' },
      ],
    },
  ],
})

export default router
