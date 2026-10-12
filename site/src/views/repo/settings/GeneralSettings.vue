<template>
  <div class="space-y-6">
    <!-- Repository identity / state -->
    <section>
      <h2 class="border-b border-surface-border pb-2 text-base font-semibold text-white">
        Repository
      </h2>
      <dl class="mt-3 grid gap-x-8 gap-y-2 text-sm sm:grid-cols-2">
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Full name
          </dt>
          <dd class="text-gray-200 sm:mt-0.5">
            <a
              v-if="safeHref(repo?.html_url)"
              :href="safeHref(repo?.html_url)"
              target="_blank"
              rel="noopener noreferrer"
              class="text-accent hover:underline"
            >{{ repo?.full_name || repo?.name }}</a>
            <template v-else>
              {{ repo?.full_name || repo?.name || '—' }}
            </template>
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Visibility
          </dt>
          <dd class="capitalize text-gray-200 sm:mt-0.5">
            {{ repo?.visibility || (repo?.private ? 'private' : 'public') }}
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Status
          </dt>
          <dd class="sm:mt-0.5">
            <span
              class="rounded-full border px-2 py-0.5 text-xs font-medium capitalize"
              :class="repo?.status === 'active' ? 'border-ok/40 text-ok' : 'border-surface-border text-gray-400'"
            >{{ repo?.status || 'unknown' }}</span>
          </dd>
        </div>
        <div class="flex justify-between gap-4 sm:block">
          <dt class="text-gray-500">
            Last scanned
          </dt>
          <dd class="text-gray-200 sm:mt-0.5">
            {{ repo?.last_scanned ? relativeTime(repo.last_scanned) : 'never' }}
            <span
              v-if="repo?.outdated"
              class="ml-1 rounded-full border border-warn/40 px-1.5 py-0.5 text-[11px] text-warn"
            >outdated</span>
          </dd>
        </div>
      </dl>
    </section>

    <!-- Editable fields -->
    <section>
      <div class="flex items-center justify-between border-b border-surface-border pb-2">
        <h2 class="text-base font-semibold text-white">
          Scanning
        </h2>
        <span
          v-if="!isOrgAdmin"
          class="text-xs text-gray-500"
        >Read-only — org admins can change these</span>
      </div>

      <div class="mt-3 space-y-4">
        <div class="flex flex-col gap-1.5 sm:max-w-sm">
          <label
            class="text-sm font-medium text-gray-200"
            for="repo-default-branch"
          >Default branch</label>
          <input
            id="repo-default-branch"
            v-model="defaultBranch"
            type="text"
            class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 font-mono text-sm text-gray-200 focus:border-accent/50 focus:outline-none disabled:opacity-60"
            :disabled="!isOrgAdmin"
          >
          <p class="text-xs text-gray-500">
            The branch Hibou treats as the baseline: trends, "new code" comparisons and PR
            gates are computed against it. It follows the forge's default branch automatically;
            a manual value only bridges the gap until the forge reports again.
          </p>
        </div>

        <div
          v-if="isOrgAdmin"
          class="flex items-center gap-3"
        >
          <button
            class="rounded-md bg-ok-muted px-3 py-1.5 text-sm font-medium text-white transition hover:bg-ok-muted/80 disabled:cursor-not-allowed disabled:opacity-50"
            type="button"
            :disabled="saving || !isDirty"
            @click="save"
          >
            {{ saving ? 'Saving…' : 'Save changes' }}
          </button>
          <span
            v-if="saveError"
            class="text-xs text-danger"
          >{{ saveError }}</span>
          <span
            v-else-if="saved"
            class="text-xs text-ok"
          >Saved.</span>
        </div>
      </div>
    </section>

    <!-- Danger zone -->
    <section v-if="isOrgAdmin">
      <h2 class="border-b border-danger/30 pb-2 text-base font-semibold text-danger">
        Danger zone
      </h2>
      <div class="mt-3 flex flex-col gap-3 rounded-lg border border-danger/30 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div class="text-sm font-medium text-gray-100">
            Remove this repository from Hibou
          </div>
          <div class="text-xs text-gray-500">
            Deletes its snapshots, findings, and history from Hibou. The repository on the forge is untouched;
            it can be enrolled again later, starting from scratch.
          </div>
        </div>
        <button
          type="button"
          class="shrink-0 rounded-md border border-danger/50 px-3 py-1.5 text-xs font-medium text-danger transition hover:bg-danger/10 disabled:opacity-50"
          :disabled="removing"
          @click="removeRepo"
        >
          Remove repository
        </button>
      </div>
      <p
        v-if="removeError"
        class="mt-2 text-xs text-danger"
      >
        {{ removeError }}
      </p>
    </section>
  </div>
</template>

<script setup lang="ts">
import { safeHref } from '@/lib/safeUrl'
import type { Ref } from 'vue'
import { computed, inject, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type Repository } from '@/api/client'
import { useDialog } from '@/composables/useDialog'
import { useOrgRole } from '@/composables/useOrgRole'
import { relativeTime } from '@/lib/datetime'

const route = useRoute()
const router = useRouter()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const repo = inject<Ref<Repository | null>>('repo', ref(null))
const { isOrgAdmin } = useOrgRole()
const { confirmDialog } = useDialog()

const defaultBranch = ref('')
const saving = ref(false)
const saved = ref(false)
const saveError = ref('')

watch(
  repo,
  (value) => {
    defaultBranch.value = value?.default_branch ?? ''
  },
  { immediate: true },
)

const isDirty = computed(() => Boolean(repo.value) && defaultBranch.value.trim() !== repo.value?.default_branch)

async function save() {
  saving.value = true
  saved.value = false
  saveError.value = ''
  try {
    const res = await api.updateRepo(provider.value, slug.value, repoSlug.value, {
      default_branch: defaultBranch.value.trim(),
    })
    if (repo.value) {
      repo.value.default_branch = res.data.default_branch
    }
    defaultBranch.value = res.data.default_branch
    saved.value = true
  } catch (error) {
    saveError.value = error instanceof Error ? error.message : 'Failed to save changes'
  } finally {
    saving.value = false
  }
}

const removing = ref(false)
const removeError = ref('')

async function removeRepo() {
  const confirmed = await confirmDialog({
    title: 'Remove this repository from Hibou',
    message: 'This removes the repository and all its Hibou data (snapshots, findings, history). The repository on the forge is untouched.',
    confirmLabel: 'Remove repository',
    tone: 'danger',
    requireText: repoSlug.value,
  })
  if (!confirmed) {
    return
  }
  removing.value = true
  removeError.value = ''
  try {
    await api.removeRepo(provider.value, slug.value, repoSlug.value)
    await router.push(`/orgs/${provider.value}/${slug.value}/repos`)
  } catch (error) {
    removeError.value = error instanceof Error ? error.message : 'Failed to remove repository'
  } finally {
    removing.value = false
  }
}
</script>
