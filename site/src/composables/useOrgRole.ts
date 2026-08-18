import { computed } from 'vue'
import { useRoute } from 'vue-router'

import { useOrgStore } from '@/stores/org'

// Role of the current user in the org named by the route. `role` is served on
// the org list/detail responses; admin-only UI hides on top of the server-side
// enforcement, it never replaces it.
export function useOrgRole() {
  const route = useRoute()
  const orgStore = useOrgStore()

  const role = computed(() => {
    const provider = typeof route.params.provider === 'string' ? route.params.provider : ''
    const slug = typeof route.params.slug === 'string' ? route.params.slug : ''
    const org = orgStore.orgs.find((entry) => entry.provider === provider && entry.slug === slug)
    return org?.role ?? ''
  })

  const isOrgAdmin = computed(() => role.value === 'admin')

  // Release lifecycle affordances (create/delete releases, assign clients) —
  // server-enforced; this only decides whether to render the controls.
  const isReleaseManager = computed(() => role.value === 'admin' || role.value === 'release_manager')

  return { role, isOrgAdmin, isReleaseManager }
}
