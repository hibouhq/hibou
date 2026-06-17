import { defineStore } from 'pinia'
import { ref } from 'vue'

import { api, type OnboardableAccount, type Organization } from '@/api/client'

const KNOWN_ORGS_STORAGE_KEY = 'hibou:known-orgs'

function orgKey(org: Pick<Organization, 'provider' | 'slug'>) {
  return `${org.provider}:${org.slug}`
}

function readKnownOrgKeys() {
  if (typeof window === 'undefined') {
    return { hasBaseline: false, keys: [] as string[] }
  }

  const stored = window.sessionStorage.getItem(KNOWN_ORGS_STORAGE_KEY)
  if (!stored) {
    return { hasBaseline: false, keys: [] as string[] }
  }

  try {
    const parsed = JSON.parse(stored)
    return { hasBaseline: true, keys: Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === 'string') : [] }
  } catch {
    return { hasBaseline: true, keys: [] as string[] }
  }
}

function writeKnownOrgKeys(orgs: Organization[]) {
  if (typeof window === 'undefined') {
    return
  }
  window.sessionStorage.setItem(KNOWN_ORGS_STORAGE_KEY, JSON.stringify(orgs.map(orgKey)))
}

export const useOrgStore = defineStore('org', () => {
  const orgs = ref<Organization[]>([])
  const onboardable = ref<OnboardableAccount[]>([])
  const currentOrg = ref<Organization | null>(null)
  const loading = ref(false)
  const onboardableLoading = ref(false)
  const error = ref('')
  const onboardableError = ref('')
  const claimedOrgs = ref<Organization[]>([])

  async function fetchOrgs(options?: { suppressClaimToast?: boolean }) {
    loading.value = true
    error.value = ''
    try {
      const res = await api.listOrgs()
      orgs.value = res.data
      const previous = readKnownOrgKeys()
      writeKnownOrgKeys(res.data)
      if (!options?.suppressClaimToast && previous.hasBaseline) {
        const existing = new Set(previous.keys)
        claimedOrgs.value = res.data.filter((org) => !existing.has(orgKey(org)))
      } else {
        claimedOrgs.value = []
      }
      return res.data
    } catch (caught) {
      orgs.value = []
      claimedOrgs.value = []
      error.value = caught instanceof Error ? caught.message : 'Failed to load organizations.'
      throw caught
    } finally {
      loading.value = false
    }
  }

  async function fetchOnboardable() {
    onboardableLoading.value = true
    onboardableError.value = ''
    try {
      const res = await api.listOnboardableOrgs()
      onboardable.value = res.data
      return res.data
    } catch (caught) {
      onboardable.value = []
      onboardableError.value = caught instanceof Error ? caught.message : 'Failed to load onboardable accounts.'
      throw caught
    } finally {
      onboardableLoading.value = false
    }
  }

  async function importOrg(account: OnboardableAccount) {
    const response = await api.createOrg({
      name: account.account,
      slug: account.slug,
      display_name: account.account,
      provider: account.provider,
    })
    await Promise.all([
      fetchOrgs({ suppressClaimToast: true }),
      fetchOnboardable(),
    ])
    return response.data
  }

  function consumeClaimedOrgs() {
    const next = [...claimedOrgs.value]
    claimedOrgs.value = []
    return next
  }

  function setCurrentOrg(org: Organization) {
    currentOrg.value = org
  }

  return {
    orgs,
    onboardable,
    currentOrg,
    loading,
    onboardableLoading,
    error,
    onboardableError,
    fetchOrgs,
    fetchOnboardable,
    importOrg,
    consumeClaimedOrgs,
    setCurrentOrg,
  }
})