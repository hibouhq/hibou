<template>
  <div class="mx-auto max-w-7xl">
    <div class="px-4 pt-6">
      <RouterLink
        :to="{ name: 'tools' }"
        class="text-xs text-gray-500 hover:text-accent"
      >
        ← Tools
      </RouterLink>
      <!-- Optional repository: with one, snapshots can be compared too. -->
      <div class="mt-3 flex flex-wrap items-end gap-3">
        <label class="block">
          <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">Organization</span>
          <select
            :value="orgKey"
            class="rounded-md border border-surface-border bg-surface px-2 py-1.5 text-sm text-gray-200"
            @change="selectOrg(($event.target as HTMLSelectElement).value)"
          >
            <option value="">
              None (local files only)
            </option>
            <option
              v-for="org in orgStore.orgs"
              :key="`${org.provider}/${org.slug}`"
              :value="`${org.provider}/${org.slug}`"
            >
              {{ org.display_name || org.name }}
            </option>
          </select>
        </label>
        <label
          v-if="orgKey"
          class="block"
        >
          <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">Repository</span>
          <select
            :value="selection.repoSlug"
            class="rounded-md border border-surface-border bg-surface px-2 py-1.5 text-sm text-gray-200"
            @change="selectRepo(($event.target as HTMLSelectElement).value)"
          >
            <option value="">
              None (local files only)
            </option>
            <option
              v-for="repo in repos"
              :key="repo.slug"
              :value="repo.slug"
            >
              {{ repo.name }}
            </option>
          </select>
        </label>
      </div>
    </div>
    <SBOMCompareView
      :key="`${orgKey}/${selection.repoSlug}`"
      :provider="selection.repoSlug ? selection.provider : ''"
      :slug="selection.repoSlug ? selection.slug : ''"
      :repo-slug="selection.repoSlug"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Repository } from '@/api/client'
import { useOrgStore } from '@/stores/org'
import SBOMCompareView from '@/views/SBOMCompareView.vue'

const route = useRoute()
const router = useRouter()
const orgStore = useOrgStore()
const repos = ref<Repository[]>([])

// The choice lives in the query (?repo=provider/org/repo) so a link keeps it.
const selection = computed(() => {
  const [provider = '', slug = '', repoSlug = ''] = (typeof route.query.repo === 'string' ? route.query.repo : '').split('/')
  return { provider, slug, repoSlug }
})
const orgKey = computed(() => (selection.value.provider && selection.value.slug ? `${selection.value.provider}/${selection.value.slug}` : ''))

function setRepoQuery(value: string) {
  const query = { ...route.query }
  if (value) query.repo = value
  else delete query.repo
  void router.replace({ query })
}

function selectOrg(key: string) {
  setRepoQuery(key ? `${key}/` : '')
}

function selectRepo(repoSlug: string) {
  setRepoQuery(repoSlug ? `${orgKey.value}/${repoSlug}` : `${orgKey.value}/`)
}

watch(orgKey, async (key) => {
  repos.value = []
  if (!key) return
  try {
    const response = await api.listRepos(selection.value.provider, selection.value.slug)
    repos.value = response.data ?? []
  } catch {
    repos.value = []
  }
}, { immediate: true })

onMounted(async () => {
  if (orgStore.orgs.length === 0) await orgStore.fetchOrgs()
})
</script>
