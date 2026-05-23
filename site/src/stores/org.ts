import { defineStore } from 'pinia'
import { ref } from 'vue'

import { api, type Organization } from '@/api/client'

export const useOrgStore = defineStore('org', () => {
  const orgs = ref<Organization[]>([])
  const currentOrg = ref<Organization | null>(null)
  const loading = ref(false)

  async function fetchOrgs() {
    loading.value = true
    try {
      const res = await api.listOrgs()
      orgs.value = res.data
    } catch {
      orgs.value = []
    } finally {
      loading.value = false
    }
  }

  function setCurrentOrg(org: Organization) {
    currentOrg.value = org
  }

  return { orgs, currentOrg, loading, fetchOrgs, setCurrentOrg }
})