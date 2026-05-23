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
        { path: '', name: 'dashboard', component: () => import('@/views/DashboardView.vue') },
        { path: 'orgs', name: 'orgs', component: () => import('@/views/OrgsView.vue') },
        { path: 'orgs/:slug', name: 'org-detail', component: () => import('@/views/OrgDetailView.vue') },
        { path: 'orgs/:slug/repos', name: 'repos', component: () => import('@/views/ReposView.vue') },
        {
          path: 'orgs/:slug/repos/:repoSlug',
          name: 'repo-detail',
          component: () => import('@/views/RepoDetailView.vue'),
        },
        { path: 'orgs/:slug/teams', name: 'teams', component: () => import('@/views/TeamsView.vue') },
        { path: 'uploads', name: 'uploads', component: () => import('@/views/UploadsView.vue') },
        { path: 'settings', name: 'settings', component: () => import('@/views/SettingsView.vue') },
      ],
    },
  ],
})

export default router