<template>
  <div class="px-4 pt-5 pb-8">
    <div class="compare-rise flex flex-wrap items-baseline gap-x-3 gap-y-1">
      <p class="flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-gray-500">
        <span class="compare-beacon" />
        <span class="compare-display">SBOM Compare</span>
      </p>
      <h1 class="compare-display text-xl font-semibold tracking-tight text-white sm:text-2xl">
        <span class="compare-ref">{{ baseTitle }}</span>
        <span class="compare-arrow">→</span>
        <span class="compare-ref compare-ref-head">{{ headTitle }}</span>
      </h1>
    </div>

    <p class="compare-rise mt-2 max-w-3xl text-sm text-gray-400">
      Compare repository SBOM artifacts or local SBOM JSON files. Results refresh automatically once both sides are ready.
    </p>

    <div class="compare-rise relative z-20 mt-4 border-b border-surface-border pb-3">
      <div class="compare-comparator grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-start lg:gap-2">
        <div class="min-w-0 flex-1 space-y-2">
          <span class="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-gray-500">
            <span class="compare-dot compare-dot-base" />
            Base
          </span>
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="baseRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            :repo-html-url="repo?.html_url"
            :provider="repo?.provider"
            compact
            block
            @select="selectBase"
          />
          <div class="flex gap-1 rounded-lg bg-surface-raised/60 p-0.5">
            <button
              type="button"
              class="flex-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition"
              :class="baseSource === 'snapshot' ? 'bg-accent/15 text-accent' : 'text-gray-400 hover:text-gray-200'"
              @click="setSource('base', 'snapshot')"
            >
              From snapshot
            </button>
            <button
              type="button"
              class="flex-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition"
              :class="baseSource === 'local' ? 'bg-accent/15 text-accent' : 'text-gray-400 hover:text-gray-200'"
              @click="setSource('base', 'local')"
            >
              Local file
            </button>
          </div>

          <template v-if="baseSource === 'snapshot'">
            <label class="block">
              <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">Snapshot</span>
              <div class="relative">
                <select
                  :value="baseSnapshotId"
                  class="compare-select w-full appearance-none rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 pr-9 text-sm text-gray-200 outline-none"
                  :disabled="snapshotsLoading || !baseRef || baseSnapshots.length === 0"
                  @change="handleSnapshotChange('base', ($event.target as HTMLSelectElement).value)"
                >
                  <option value="">{{ baseSnapshotPlaceholder }}</option>
                  <option
                    v-for="snapshot in baseSnapshots"
                    :key="snapshot.id"
                    :value="snapshot.id"
                  >
                    {{ snapshotOptionLabel(snapshot) }}
                  </option>
                </select>
                <ChevronDown class="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              </div>
            </label>

            <div
              v-if="selectedBaseSnapshot"
              class="flex flex-wrap items-center gap-x-2 gap-y-1 px-1 text-[11px] text-gray-500"
            >
              <span
                class="rounded-full px-2 py-0.5 font-medium"
                :class="snapshotBadgeClass(selectedBaseSnapshot)"
              >
                {{ snapshotStatusLabel(selectedBaseSnapshot) }}
              </span>
              <span class="font-mono text-gray-300">{{ snapshotPrimaryLabel(selectedBaseSnapshot) }}</span>
              <span>{{ snapshotSecondaryLine(selectedBaseSnapshot) }}</span>
            </div>

            <label class="block">
              <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">SBOM artifact</span>
              <div class="relative">
                <select
                  :value="baseArtifactId"
                  class="compare-select w-full appearance-none rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 pr-9 text-sm text-gray-200 outline-none"
                  :disabled="!baseSnapshotId || baseFilesLoading || baseSBOMFiles.length === 0"
                  @change="handleArtifactChange('base', ($event.target as HTMLSelectElement).value)"
                >
                  <option value="">{{ baseArtifactPlaceholder }}</option>
                  <option
                    v-for="file in baseSBOMFiles"
                    :key="file.id"
                    :value="file.id"
                  >
                    {{ artifactLabel(file) }}
                  </option>
                </select>
                <ChevronDown class="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              </div>
            </label>

            <p
              v-if="baseFilesLoading"
              class="text-xs text-gray-500"
            >
              Loading SBOM files…
            </p>
            <p
              v-else-if="baseSnapshotId && baseSBOMFiles.length === 0"
              class="rounded-lg border border-dashed border-surface-border-subtle px-3 py-3 text-xs text-gray-500"
            >
              No SBOM files found in this snapshot.
            </p>
          </template>

          <template v-else>
            <div
              class="rounded-xl border border-dashed px-3 py-4 transition"
              :class="baseDragging ? 'border-accent/60 bg-accent/5' : 'border-surface-border-subtle bg-surface-raised/20'"
              @dragenter.prevent="setDragging('base', true)"
              @dragover.prevent="setDragging('base', true)"
              @dragleave.prevent="setDragging('base', false)"
              @drop.prevent="handleFileDrop('base', $event)"
            >
              <input
                ref="baseFileInput"
                type="file"
                accept=".json,application/json"
                class="hidden"
                @change="handleFileInput('base', $event)"
              >
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <p class="truncate text-sm font-medium text-white">
                    {{ baseLocalFile?.name || 'Drop SBOM JSON here' }}
                  </p>
                  <p class="mt-1 text-xs text-gray-500">
                    {{ baseLocalFile ? `${baseLocalFormat || 'unknown'} · ${formatBytes(baseLocalFile.size)}` : 'Drag and drop or choose an SPDX or CycloneDX JSON file.' }}
                  </p>
                </div>
                <button
                  type="button"
                  class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
                  @click="triggerFilePicker('base')"
                >
                  Choose file
                </button>
              </div>
            </div>
          </template>
        </div>

        <button
          type="button"
          class="compare-swap mx-auto my-1 inline-flex h-10 w-10 shrink-0 self-center items-center justify-center rounded-xl border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/60 hover:text-white"
          :disabled="!baseRef || !headRef"
          title="Swap base and head"
          aria-label="Swap base and head"
          @click="swapSides"
        >
          <ArrowLeftRight class="h-4 w-4" />
        </button>

        <div class="min-w-0 flex-1 space-y-2">
          <span class="flex items-center justify-end gap-2 text-xs uppercase tracking-[0.2em] text-gray-500">
            Head
            <span class="compare-dot compare-dot-head" />
          </span>
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="headRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            :repo-html-url="repo?.html_url"
            :provider="repo?.provider"
            compact
            block
            align="right"
            @select="selectHead"
          />
          <div class="flex gap-1 rounded-lg bg-surface-raised/60 p-0.5">
            <button
              type="button"
              class="flex-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition"
              :class="headSource === 'snapshot' ? 'bg-accent/15 text-accent' : 'text-gray-400 hover:text-gray-200'"
              @click="setSource('head', 'snapshot')"
            >
              From snapshot
            </button>
            <button
              type="button"
              class="flex-1 rounded-md px-2.5 py-1.5 text-xs font-medium transition"
              :class="headSource === 'local' ? 'bg-accent/15 text-accent' : 'text-gray-400 hover:text-gray-200'"
              @click="setSource('head', 'local')"
            >
              Local file
            </button>
          </div>

          <template v-if="headSource === 'snapshot'">
            <label class="block">
              <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">Snapshot</span>
              <div class="relative">
                <select
                  :value="headSnapshotId"
                  class="compare-select w-full appearance-none rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 pr-9 text-sm text-gray-200 outline-none"
                  :disabled="snapshotsLoading || !headRef || headSnapshots.length === 0"
                  @change="handleSnapshotChange('head', ($event.target as HTMLSelectElement).value)"
                >
                  <option value="">{{ headSnapshotPlaceholder }}</option>
                  <option
                    v-for="snapshot in headSnapshots"
                    :key="snapshot.id"
                    :value="snapshot.id"
                  >
                    {{ snapshotOptionLabel(snapshot) }}
                  </option>
                </select>
                <ChevronDown class="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              </div>
            </label>

            <div
              v-if="selectedHeadSnapshot"
              class="flex flex-wrap items-center gap-x-2 gap-y-1 px-1 text-[11px] text-gray-500"
            >
              <span
                class="rounded-full px-2 py-0.5 font-medium"
                :class="snapshotBadgeClass(selectedHeadSnapshot)"
              >
                {{ snapshotStatusLabel(selectedHeadSnapshot) }}
              </span>
              <span class="font-mono text-gray-300">{{ snapshotPrimaryLabel(selectedHeadSnapshot) }}</span>
              <span>{{ snapshotSecondaryLine(selectedHeadSnapshot) }}</span>
            </div>

            <label class="block">
              <span class="mb-1 block text-[11px] uppercase tracking-[0.18em] text-gray-500">SBOM artifact</span>
              <div class="relative">
                <select
                  :value="headArtifactId"
                  class="compare-select w-full appearance-none rounded-lg border border-surface-border bg-surface-overlay px-3 py-2 pr-9 text-sm text-gray-200 outline-none"
                  :disabled="!headSnapshotId || headFilesLoading || headSBOMFiles.length === 0"
                  @change="handleArtifactChange('head', ($event.target as HTMLSelectElement).value)"
                >
                  <option value="">{{ headArtifactPlaceholder }}</option>
                  <option
                    v-for="file in headSBOMFiles"
                    :key="file.id"
                    :value="file.id"
                  >
                    {{ artifactLabel(file) }}
                  </option>
                </select>
                <ChevronDown class="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
              </div>
            </label>

            <p
              v-if="headFilesLoading"
              class="text-xs text-gray-500"
            >
              Loading SBOM files…
            </p>
            <p
              v-else-if="headSnapshotId && headSBOMFiles.length === 0"
              class="rounded-lg border border-dashed border-surface-border-subtle px-3 py-3 text-xs text-gray-500"
            >
              No SBOM files found in this snapshot.
            </p>
          </template>

          <template v-else>
            <div
              class="rounded-xl border border-dashed px-3 py-4 transition"
              :class="headDragging ? 'border-accent/60 bg-accent/5' : 'border-surface-border-subtle bg-surface-raised/20'"
              @dragenter.prevent="setDragging('head', true)"
              @dragover.prevent="setDragging('head', true)"
              @dragleave.prevent="setDragging('head', false)"
              @drop.prevent="handleFileDrop('head', $event)"
            >
              <input
                ref="headFileInput"
                type="file"
                accept=".json,application/json"
                class="hidden"
                @change="handleFileInput('head', $event)"
              >
              <div class="flex items-start justify-between gap-3">
                <div class="min-w-0">
                  <p class="truncate text-sm font-medium text-white">
                    {{ headLocalFile?.name || 'Drop SBOM JSON here' }}
                  </p>
                  <p class="mt-1 text-xs text-gray-500">
                    {{ headLocalFile ? `${headLocalFormat || 'unknown'} · ${formatBytes(headLocalFile.size)}` : 'Drag and drop or choose an SPDX or CycloneDX JSON file.' }}
                  </p>
                </div>
                <button
                  type="button"
                  class="rounded-md border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
                  @click="triggerFilePicker('head')"
                >
                  Choose file
                </button>
              </div>
            </div>
          </template>
        </div>
      </div>
    </div>

    <div
      v-if="artifactLookupLoading"
      class="compare-rise relative mt-4 overflow-hidden rounded-xl border border-dashed border-surface-border-subtle px-4 py-6 text-sm text-gray-500"
    >
      <span class="compare-scan" />
      Resolving artifact snapshots…
    </div>

    <div
      v-else-if="comparisonLoading"
      class="compare-rise relative mt-4 overflow-hidden rounded-xl border border-dashed border-surface-border-subtle px-4 py-6 text-sm text-gray-500"
    >
      <span class="compare-scan" />
      Comparing SBOMs…
    </div>

    <div
      v-else-if="error"
      class="compare-rise mt-4 rounded-2xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-danger"
    >
      {{ error }}
    </div>

    <div
      v-else-if="comparison"
      class="mt-6 space-y-5"
    >
      <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <article
          v-for="(card, index) in summaryCards"
          :key="card.label"
          class="compare-stat rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-5"
          :style="{ '--i': index }"
        >
          <div class="flex items-start justify-between gap-3">
            <div>
              <p class="text-[11px] uppercase tracking-[0.18em] text-gray-500">
                {{ card.label }}
              </p>
              <p
                class="mt-2 text-3xl font-semibold"
                :class="card.valueClass"
              >
                {{ card.value }}
              </p>
            </div>
            <div
              class="rounded-xl border px-2.5 py-2"
              :class="card.shellClass"
            >
              <component
                :is="card.icon"
                class="h-4 w-4"
                :class="card.valueClass"
              />
            </div>
          </div>
          <p class="mt-3 text-xs text-gray-500">
            {{ card.hint }}
          </p>
        </article>
      </div>

      <section class="compare-rise rounded-2xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3 text-sm text-gray-400">
        Base packages {{ comparison.summary.total_base }} · Head packages {{ comparison.summary.total_head }}
      </section>

      <details
        v-for="section in sections"
        :key="section.key"
        class="compare-rise overflow-hidden rounded-2xl border bg-surface-overlay/30"
        :class="section.shellClass"
        :open="section.defaultOpen"
      >
        <summary class="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 marker:hidden">
          <div class="flex min-w-0 items-center gap-3">
            <div
              class="rounded-xl border px-2.5 py-2"
              :class="section.iconShellClass"
            >
              <component
                :is="section.icon"
                class="h-4 w-4"
                :class="section.iconClass"
              />
            </div>
            <div class="min-w-0">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-sm font-semibold text-white">{{ section.label }}</span>
                <span class="rounded-full border border-surface-border px-2 py-0.5 text-[11px] font-semibold text-gray-300">{{ section.items.length }}</span>
              </div>
              <p class="mt-0.5 text-xs text-gray-500">
                {{ section.hint }}
              </p>
            </div>
          </div>
          <ChevronDown class="details-chevron h-4 w-4 shrink-0 text-gray-500" />
        </summary>

        <div
          v-if="section.items.length === 0"
          class="border-t border-surface-border-subtle px-4 py-5 text-sm text-gray-500"
        >
          No packages in this section.
        </div>

        <div
          v-else
          class="overflow-x-auto border-t border-surface-border-subtle"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">
                  Package
                </th>
                <th class="px-4 py-3 font-medium">
                  Version
                </th>
                <th class="px-4 py-3 font-medium">
                  Ecosystem
                </th>
                <th class="px-4 py-3 font-medium">
                  PURL
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="item in section.items"
                :key="section.key + itemKey(item)"
                class="align-top text-gray-300"
              >
                <td class="px-4 py-3">
                  <div class="font-medium text-white">
                    {{ item.name }}
                  </div>
                </td>
                <td class="px-4 py-3">
                  <template v-if="section.key === 'version_changed'">
                    <div class="flex min-w-[13rem] items-center gap-2 text-xs sm:text-sm">
                      <span class="rounded-full border border-surface-border px-2 py-0.5 text-gray-300">{{ item.base_version || 'unknown' }}</span>
                      <ArrowRight class="h-3.5 w-3.5 shrink-0 text-amber-300" />
                      <span class="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-amber-200">{{ item.head_version || 'unknown' }}</span>
                    </div>
                  </template>
                  <template v-else>
                    <span class="text-gray-300">{{ item.version || item.head_version || item.base_version || 'unknown' }}</span>
                  </template>
                </td>
                <td class="px-4 py-3">
                  <span class="rounded-full border border-surface-border px-2 py-0.5 text-xs uppercase tracking-[0.14em] text-gray-400">
                    {{ item.ecosystem || 'unknown' }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <span
                    class="block max-w-[16rem] truncate font-mono text-xs text-gray-500 sm:max-w-[28rem]"
                    :title="item.purl || 'No package URL available'"
                  >
                    {{ item.purl || '—' }}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </div>

    <div
      v-else
      class="compare-rise mt-6 rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-center text-sm text-gray-500"
    >
      Select snapshot artifacts or local SBOM files on both sides to load the comparison.
    </div>
  </div>
</template>

<script setup lang="ts">
import { ArrowLeftRight, ArrowRight, ChevronDown, Minus, Package, Plus } from 'lucide-vue-next'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { api, type CompareSBOMsRequest, type ComponentDelta, type EnhancedRef, type Repository, type SBOMCompareFormat, type SBOMDiff, type Snapshot, type SnapshotFile } from '@/api/client'
import BranchPRSelector from '@/components/BranchPRSelector.vue'

type Side = 'base' | 'head'
type SourceMode = 'snapshot' | 'local'

type SectionConfig = {
  key: 'added' | 'removed' | 'version_changed' | 'unchanged'
  label: string
  hint: string
  icon: typeof Plus
  items: ComponentDelta[]
  defaultOpen: boolean
  shellClass: string
  iconShellClass: string
  iconClass: string
}

const route = useRoute()
const router = useRouter()

const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const loadingRefs = ref(true)
const allSnapshots = ref<Snapshot[]>([])
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const snapshotsLoading = ref(false)
let pendingSnapshotLoads = 0
const baseRef = ref('')
const headRef = ref('')
const baseSnapshotId = ref('')
const headSnapshotId = ref('')
const baseArtifactId = ref('')
const headArtifactId = ref('')
const baseFiles = ref<SnapshotFile[]>([])
const headFiles = ref<SnapshotFile[]>([])
const baseFilesLoading = ref(false)
const headFilesLoading = ref(false)
const baseSource = ref<SourceMode>('snapshot')
const headSource = ref<SourceMode>('snapshot')
const baseLocalFile = ref<File | null>(null)
const headLocalFile = ref<File | null>(null)
const baseLocalContent = ref('')
const headLocalContent = ref('')
const baseLocalFormat = ref<SBOMCompareFormat | ''>('')
const headLocalFormat = ref<SBOMCompareFormat | ''>('')
const baseDragging = ref(false)
const headDragging = ref(false)
const baseFileInput = ref<HTMLInputElement | null>(null)
const headFileInput = ref<HTMLInputElement | null>(null)
const comparison = ref<SBOMDiff | null>(null)
const comparisonLoading = ref(false)
const artifactLookupLoading = ref(false)
const error = ref('')

const snapshotFilesCache = new Map<string, SnapshotFile[]>()
const snapshotFilesRequests = new Map<string, Promise<SnapshotFile[]>>()
const loadedSnapshotRefs = new Set<string>()

const selectedBaseRef = computed(() => refs.value.find((item) => item.name === baseRef.value) ?? null)
const selectedHeadRef = computed(() => refs.value.find((item) => item.name === headRef.value) ?? null)
const baseSnapshots = computed(() => allSnapshots.value.filter((snapshot) => snapshot.ref_id === selectedBaseRef.value?.id))
const headSnapshots = computed(() => allSnapshots.value.filter((snapshot) => snapshot.ref_id === selectedHeadRef.value?.id))
const selectedBaseSnapshot = computed(() => resolveSelectedSnapshot(baseSnapshots.value, baseSnapshotId.value))
const selectedHeadSnapshot = computed(() => resolveSelectedSnapshot(headSnapshots.value, headSnapshotId.value))
const baseSBOMFiles = computed(() => baseFiles.value.filter((file) => file.kind === 'sbom'))
const headSBOMFiles = computed(() => headFiles.value.filter((file) => file.kind === 'sbom'))
const selectedBaseArtifact = computed(() => baseSBOMFiles.value.find((file) => file.id === baseArtifactId.value) ?? null)
const selectedHeadArtifact = computed(() => headSBOMFiles.value.find((file) => file.id === headArtifactId.value) ?? null)

const baseTitle = computed(() => baseLocalFile.value?.name || selectedBaseArtifact.value?.filename || baseRef.value || 'Base')
const headTitle = computed(() => headLocalFile.value?.name || selectedHeadArtifact.value?.filename || headRef.value || 'Head')

const baseArtifactPlaceholder = computed(() => {
  if (!baseRef.value) return 'Select a ref first'
  if (!baseSnapshotId.value) return 'Select a snapshot first'
  if (baseFilesLoading.value) return 'Loading SBOM files…'
  if (baseSBOMFiles.value.length === 0) return 'No SBOM files found'
  return 'Select an SBOM file'
})

const headArtifactPlaceholder = computed(() => {
  if (!headRef.value) return 'Select a ref first'
  if (!headSnapshotId.value) return 'Select a snapshot first'
  if (headFilesLoading.value) return 'Loading SBOM files…'
  if (headSBOMFiles.value.length === 0) return 'No SBOM files found'
  return 'Select an SBOM file'
})

const baseSnapshotPlaceholder = computed(() => {
  if (!baseRef.value) return 'Select a ref first'
  if (snapshotsLoading.value) return 'Loading snapshots…'
  if (baseSnapshots.value.length === 0) return 'No snapshots found'
  return 'Select a snapshot'
})

const headSnapshotPlaceholder = computed(() => {
  if (!headRef.value) return 'Select a ref first'
  if (snapshotsLoading.value) return 'Loading snapshots…'
  if (headSnapshots.value.length === 0) return 'No snapshots found'
  return 'Select a snapshot'
})

const baseReady = computed(() => baseSource.value === 'snapshot' ? Boolean(baseArtifactId.value) : Boolean(baseLocalContent.value && baseLocalFormat.value))
const headReady = computed(() => headSource.value === 'snapshot' ? Boolean(headArtifactId.value) : Boolean(headLocalContent.value && headLocalFormat.value))

const summaryCards = computed(() => {
  if (!comparison.value) return []
  return [
    {
      label: 'Added',
      value: comparison.value.summary.added,
      hint: 'Packages present only in the head artifact.',
      icon: Plus,
      valueClass: 'text-emerald-300',
      shellClass: 'border-emerald-500/20 bg-emerald-500/10',
    },
    {
      label: 'Removed',
      value: comparison.value.summary.removed,
      hint: 'Packages that disappeared from the head artifact.',
      icon: Minus,
      valueClass: 'text-danger',
      shellClass: 'border-danger/20 bg-danger/10',
    },
    {
      label: 'Version Changed',
      value: comparison.value.summary.version_changed,
      hint: 'Packages that stayed but moved to a different version.',
      icon: ArrowRight,
      valueClass: 'text-amber-300',
      shellClass: 'border-amber-500/20 bg-amber-500/10',
    },
    {
      label: 'Unchanged',
      value: comparison.value.summary.unchanged,
      hint: 'Packages identical across both artifacts.',
      icon: Package,
      valueClass: 'text-gray-300',
      shellClass: 'border-surface-border bg-surface-raised/40',
    },
  ]
})

const sections = computed<SectionConfig[]>(() => {
  const diff = comparison.value
  if (!diff) return []
  return [
    {
      key: 'added',
      label: 'Added',
      hint: 'New packages introduced on head.',
      icon: Plus,
      items: diff.added,
      defaultOpen: diff.added.length > 0,
      shellClass: 'border-emerald-500/20',
      iconShellClass: 'border-emerald-500/20 bg-emerald-500/10',
      iconClass: 'text-emerald-300',
    },
    {
      key: 'removed',
      label: 'Removed',
      hint: 'Packages present on base but gone from head.',
      icon: Minus,
      items: diff.removed,
      defaultOpen: diff.removed.length > 0,
      shellClass: 'border-danger/20',
      iconShellClass: 'border-danger/20 bg-danger/10',
      iconClass: 'text-danger',
    },
    {
      key: 'version_changed',
      label: 'Version Changed',
      hint: 'Same package identity, different version.',
      icon: ArrowRight,
      items: diff.version_changed,
      defaultOpen: diff.version_changed.length > 0,
      shellClass: 'border-amber-500/20',
      iconShellClass: 'border-amber-500/20 bg-amber-500/10',
      iconClass: 'text-amber-300',
    },
    {
      key: 'unchanged',
      label: 'Unchanged',
      hint: 'Packages with no material difference. Collapsed by default.',
      icon: Package,
      items: diff.unchanged,
      defaultOpen: false,
      shellClass: 'border-surface-border-subtle',
      iconShellClass: 'border-surface-border bg-surface-raised/40',
      iconClass: 'text-gray-300',
    },
  ]
})

async function loadSnapshotsForRef(refName: string) {
  if (!refName || loadedSnapshotRefs.has(refName)) return
  const reqProvider = provider.value
  const reqSlug = slug.value
  const reqRepoSlug = repoSlug.value
  loadedSnapshotRefs.add(refName)
  pendingSnapshotLoads += 1
  snapshotsLoading.value = true
  try {
    const response = await api.listSnapshots(reqProvider, reqSlug, reqRepoSlug, { ref: refName, per_page: 100 })
    if (reqProvider !== provider.value || reqSlug !== slug.value || reqRepoSlug !== repoSlug.value) return
    const seen = new Set(allSnapshots.value.map((snapshot) => snapshot.id))
    const merged = allSnapshots.value.slice()
    for (const snapshot of response.data) {
      if (!seen.has(snapshot.id)) {
        merged.push(snapshot)
        seen.add(snapshot.id)
      }
    }
    allSnapshots.value = merged
  } catch {
    loadedSnapshotRefs.delete(refName)
  } finally {
    pendingSnapshotLoads -= 1
    if (pendingSnapshotLoads <= 0) {
      pendingSnapshotLoads = 0
      snapshotsLoading.value = false
    }
  }
}

watch(
  () => [provider.value, slug.value, repoSlug.value] as const,
  async ([nextProvider, nextSlug, nextRepoSlug], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    loadingRefs.value = true
    snapshotsLoading.value = true
    error.value = ''
    comparison.value = null
    repo.value = null
    refs.value = []
    allSnapshots.value = []
    baseRef.value = ''
    headRef.value = ''
    baseSnapshotId.value = ''
    headSnapshotId.value = ''
    baseArtifactId.value = ''
    headArtifactId.value = ''
    baseSource.value = 'snapshot'
    headSource.value = 'snapshot'
    baseLocalFile.value = null
    headLocalFile.value = null
    baseLocalContent.value = ''
    headLocalContent.value = ''
    baseLocalFormat.value = ''
    headLocalFormat.value = ''
    baseFiles.value = []
    headFiles.value = []
    snapshotFilesCache.clear()
    snapshotFilesRequests.clear()
    loadedSnapshotRefs.clear()

    try {
      const [repoResponse, refsResponse] = await Promise.all([
        api.getRepo(nextProvider, nextSlug, nextRepoSlug),
        api.listRefsEnhanced(nextProvider, nextSlug, nextRepoSlug),
      ])
      if (cancelled) return
      repo.value = repoResponse.data
      refs.value = refsResponse.data

      const defaultBase = refsResponse.data.find((item) => item.name === repoResponse.data.default_branch)?.name || refsResponse.data[0]?.name || ''
      const defaultHead = refsResponse.data.find((item) => item.name !== defaultBase)?.name || defaultBase
      if (!baseRef.value) baseRef.value = defaultBase
      if (!headRef.value) headRef.value = defaultHead
    } catch {
      if (cancelled) return
      error.value = 'Failed to load refs and snapshots for this repository.'
    } finally {
      if (!cancelled) {
        loadingRefs.value = false
        snapshotsLoading.value = false
      }
    }
  },
  { immediate: true },
)

watch(
  [baseRef, headRef],
  ([nextBaseRef, nextHeadRef]) => {
    if (nextBaseRef) void loadSnapshotsForRef(nextBaseRef)
    if (nextHeadRef) void loadSnapshotsForRef(nextHeadRef)
  },
  { immediate: true },
)

watch(
  () => [route.query.base, route.query.head, route.query.base_artifact, route.query.head_artifact, route.query.base_snapshot, route.query.head_snapshot, refs.value, allSnapshots.value] as const,
  ([baseQuery, headQuery, baseArtifactQuery, headArtifactQuery, baseSnapshotQuery, headSnapshotQuery]) => {
    const nextBaseArtifact = typeof baseArtifactQuery === 'string' ? baseArtifactQuery : ''
    const nextHeadArtifact = typeof headArtifactQuery === 'string' ? headArtifactQuery : ''
    const nextBaseSnapshot = typeof baseSnapshotQuery === 'string' ? baseSnapshotQuery : ''
    const nextHeadSnapshot = typeof headSnapshotQuery === 'string' ? headSnapshotQuery : ''

    if (typeof baseQuery === 'string' && baseQuery && baseQuery !== baseRef.value) {
      baseRef.value = baseQuery
    }
    if (typeof headQuery === 'string' && headQuery && headQuery !== headRef.value) {
      headRef.value = headQuery
    }
    if (nextBaseArtifact !== baseArtifactId.value) baseArtifactId.value = nextBaseArtifact
    if (nextHeadArtifact !== headArtifactId.value) headArtifactId.value = nextHeadArtifact
    if (nextBaseSnapshot && nextBaseSnapshot !== baseSnapshotId.value) baseSnapshotId.value = nextBaseSnapshot
    if (nextHeadSnapshot && nextHeadSnapshot !== headSnapshotId.value) headSnapshotId.value = nextHeadSnapshot

    const baseSnapshot = nextBaseSnapshot ? allSnapshots.value.find((snapshot) => snapshot.id === nextBaseSnapshot) : null
    const headSnapshot = nextHeadSnapshot ? allSnapshots.value.find((snapshot) => snapshot.id === nextHeadSnapshot) : null
    if (baseSnapshot) {
      const refMatch = refs.value.find((item) => item.id === baseSnapshot.ref_id)
      if (refMatch && refMatch.name !== baseRef.value) baseRef.value = refMatch.name
    }
    if (headSnapshot) {
      const refMatch = refs.value.find((item) => item.id === headSnapshot.ref_id)
      if (refMatch && refMatch.name !== headRef.value) headRef.value = refMatch.name
    }
  },
  { immediate: true },
)

watch([baseRef, headRef, baseSnapshotId, headSnapshotId, baseArtifactId, headArtifactId, baseSource, headSource], ([nextBaseRef, nextHeadRef, nextBaseSnapshot, nextHeadSnapshot, nextBaseArtifact, nextHeadArtifact, nextBaseSource, nextHeadSource]) => {
  const currentBaseRef = typeof route.query.base === 'string' ? route.query.base : ''
  const currentHeadRef = typeof route.query.head === 'string' ? route.query.head : ''
  const currentBaseSnapshot = typeof route.query.base_snapshot === 'string' ? route.query.base_snapshot : ''
  const currentHeadSnapshot = typeof route.query.head_snapshot === 'string' ? route.query.head_snapshot : ''
  const currentBase = typeof route.query.base_artifact === 'string' ? route.query.base_artifact : ''
  const currentHead = typeof route.query.head_artifact === 'string' ? route.query.head_artifact : ''
  const routeBaseArtifact = nextBaseSource === 'snapshot' ? nextBaseArtifact : ''
  const routeHeadArtifact = nextHeadSource === 'snapshot' ? nextHeadArtifact : ''
  if (
    nextBaseRef === currentBaseRef
    && nextHeadRef === currentHeadRef
    && nextBaseSnapshot === currentBaseSnapshot
    && nextHeadSnapshot === currentHeadSnapshot
    && routeBaseArtifact === currentBase
    && routeHeadArtifact === currentHead
  ) return

  const nextQuery: Record<string, string> = {}
  for (const [key, value] of Object.entries(route.query)) {
    if (typeof value === 'string' && key !== 'base' && key !== 'head' && key !== 'base_artifact' && key !== 'head_artifact' && key !== 'base_snapshot' && key !== 'head_snapshot') {
      nextQuery[key] = value
    }
  }
  if (nextBaseRef) nextQuery.base = nextBaseRef
  if (nextHeadRef) nextQuery.head = nextHeadRef
  if (nextBaseSnapshot) nextQuery.base_snapshot = nextBaseSnapshot
  if (nextHeadSnapshot) nextQuery.head_snapshot = nextHeadSnapshot
  if (routeBaseArtifact) nextQuery.base_artifact = routeBaseArtifact
  if (routeHeadArtifact) nextQuery.head_artifact = routeHeadArtifact
  void router.replace({ query: nextQuery })
})

watch(
  () => [baseRef.value, baseSnapshots.value, snapshotsLoading.value] as const,
  ([nextBaseRef, nextBaseSnapshots]) => {
    if (!nextBaseRef) {
      baseSnapshotId.value = ''
      baseArtifactId.value = ''
      return
    }
    if (nextBaseSnapshots.length === 0) {
      // Keep any URL-restored / pending selection while this ref's snapshots are still loading.
      if (snapshotsLoading.value) return
      baseSnapshotId.value = ''
      baseArtifactId.value = ''
      return
    }
    if (!nextBaseSnapshots.some((snapshot) => snapshot.id === baseSnapshotId.value)) {
      baseSnapshotId.value = nextBaseSnapshots[0]?.id || ''
      baseArtifactId.value = ''
    }
  },
  { immediate: true },
)

watch(
  () => [headRef.value, headSnapshots.value, snapshotsLoading.value] as const,
  ([nextHeadRef, nextHeadSnapshots]) => {
    if (!nextHeadRef) {
      headSnapshotId.value = ''
      headArtifactId.value = ''
      return
    }
    if (nextHeadSnapshots.length === 0) {
      // Keep any URL-restored / pending selection while this ref's snapshots are still loading.
      if (snapshotsLoading.value) return
      headSnapshotId.value = ''
      headArtifactId.value = ''
      return
    }
    if (!nextHeadSnapshots.some((snapshot) => snapshot.id === headSnapshotId.value)) {
      headSnapshotId.value = nextHeadSnapshots[0]?.id || ''
      headArtifactId.value = ''
    }
  },
  { immediate: true },
)

watch(
  () => [baseSnapshotId.value, provider.value, slug.value, repoSlug.value] as const,
  async ([snapshotId, nextProvider, nextSlug, nextRepoSlug], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (!snapshotId) {
      baseFiles.value = []
      return
    }

    baseFilesLoading.value = true
    try {
      const files = await getSnapshotFilesCached(nextProvider, nextSlug, nextRepoSlug, snapshotId)
      if (cancelled) return
      baseFiles.value = files
      if (baseArtifactId.value && !files.some((file) => file.id === baseArtifactId.value)) {
        baseArtifactId.value = ''
      }
    } catch {
      if (cancelled) return
      baseFiles.value = []
      if (!error.value) error.value = 'Failed to load files for the selected base snapshot.'
    } finally {
      if (!cancelled) baseFilesLoading.value = false
    }
  },
  { immediate: true },
)

watch(
  () => [headSnapshotId.value, provider.value, slug.value, repoSlug.value] as const,
  async ([snapshotId, nextProvider, nextSlug, nextRepoSlug], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (!snapshotId) {
      headFiles.value = []
      return
    }

    headFilesLoading.value = true
    try {
      const files = await getSnapshotFilesCached(nextProvider, nextSlug, nextRepoSlug, snapshotId)
      if (cancelled) return
      headFiles.value = files
      if (headArtifactId.value && !files.some((file) => file.id === headArtifactId.value)) {
        headArtifactId.value = ''
      }
    } catch {
      if (cancelled) return
      headFiles.value = []
      if (!error.value) error.value = 'Failed to load files for the selected head snapshot.'
    } finally {
      if (!cancelled) headFilesLoading.value = false
    }
  },
  { immediate: true },
)

watch(
  () => [allSnapshots.value, baseSource.value, headSource.value, baseArtifactId.value, headArtifactId.value, provider.value, slug.value, repoSlug.value] as const,
  async ([availableSnapshots, nextBaseSource, nextHeadSource, nextBaseArtifactId, nextHeadArtifactId, nextProvider, nextSlug, nextRepoSlug], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (availableSnapshots.length === 0 || (!nextBaseArtifactId && !nextHeadArtifactId)) {
      return
    }

    artifactLookupLoading.value = true
    try {
      if (nextBaseSource === 'snapshot' && nextBaseArtifactId && !artifactExistsInFiles(baseFiles.value, nextBaseArtifactId)) {
        const resolved = await findArtifactSnapshot(nextProvider, nextSlug, nextRepoSlug, nextBaseArtifactId)
        if (!cancelled && resolved) {
          const refMatch = refs.value.find((item) => item.id === resolved.snapshot.ref_id)
          if (refMatch) baseRef.value = refMatch.name
          baseSnapshotId.value = resolved.snapshot.id
          baseFiles.value = resolved.files
        }
      }

      if (nextHeadSource === 'snapshot' && nextHeadArtifactId && !artifactExistsInFiles(headFiles.value, nextHeadArtifactId)) {
        const resolved = await findArtifactSnapshot(nextProvider, nextSlug, nextRepoSlug, nextHeadArtifactId)
        if (!cancelled && resolved) {
          const refMatch = refs.value.find((item) => item.id === resolved.snapshot.ref_id)
          if (refMatch) headRef.value = refMatch.name
          headSnapshotId.value = resolved.snapshot.id
          headFiles.value = resolved.files
        }
      }
    } finally {
      if (!cancelled) artifactLookupLoading.value = false
    }
  },
  { immediate: true },
)

watch(
  () => [provider.value, slug.value, repoSlug.value, baseSource.value, headSource.value, baseArtifactId.value, headArtifactId.value, baseLocalContent.value, headLocalContent.value, baseLocalFormat.value, headLocalFormat.value] as const,
  async ([nextProvider, nextSlug, nextRepoSlug], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    error.value = ''
    if (!baseReady.value || !headReady.value) {
      comparison.value = null
      comparisonLoading.value = false
      return
    }

    comparisonLoading.value = true
    try {
      const payload: CompareSBOMsRequest = {}
      if (baseSource.value === 'snapshot') {
        payload.base_artifact_id = baseArtifactId.value
      } else {
        payload.base_content = baseLocalContent.value
        payload.base_format = baseLocalFormat.value || undefined
      }
      if (headSource.value === 'snapshot') {
        payload.head_artifact_id = headArtifactId.value
      } else {
        payload.head_content = headLocalContent.value
        payload.head_format = headLocalFormat.value || undefined
      }

      const response = await api.compareSBOMs(nextProvider, nextSlug, nextRepoSlug, payload)
      if (cancelled) return
      comparison.value = response.data
    } catch (err) {
      if (cancelled) return
      comparison.value = null
      error.value = err instanceof Error ? err.message : 'Failed to compare SBOMs.'
    } finally {
      if (!cancelled) comparisonLoading.value = false
    }
  },
  { immediate: true },
)

function handleSnapshotChange(side: Side, snapshotId: string) {
  error.value = ''
  if (side === 'base') {
    baseSnapshotId.value = snapshotId
    baseArtifactId.value = ''
    return
  }
  headSnapshotId.value = snapshotId
  headArtifactId.value = ''
}

function handleArtifactChange(side: Side, artifactId: string) {
  error.value = ''
  if (side === 'base') {
    baseArtifactId.value = artifactId
    return
  }
  headArtifactId.value = artifactId
}

function selectBase(name: string) {
  if (baseRef.value === name) return
  baseRef.value = name
  baseSnapshotId.value = ''
  baseArtifactId.value = ''
}

function selectHead(name: string) {
  if (headRef.value === name) return
  headRef.value = name
  headSnapshotId.value = ''
  headArtifactId.value = ''
}

function setSource(side: Side, source: SourceMode) {
  error.value = ''
  if (side === 'base') {
    baseSource.value = source
    return
  }
  headSource.value = source
}

function swapSides() {
  const nextBaseRef = headRef.value
  const nextBaseSnapshotId = headSnapshotId.value
  const nextBaseArtifactId = headArtifactId.value
  const nextBaseSource = headSource.value
  const nextBaseLocalFile = headLocalFile.value
  const nextBaseLocalContent = headLocalContent.value
  const nextBaseLocalFormat = headLocalFormat.value
  const nextBaseFiles = headFiles.value

  headRef.value = baseRef.value
  headSnapshotId.value = baseSnapshotId.value
  headArtifactId.value = baseArtifactId.value
  headSource.value = baseSource.value
  headLocalFile.value = baseLocalFile.value
  headLocalContent.value = baseLocalContent.value
  headLocalFormat.value = baseLocalFormat.value
  headFiles.value = baseFiles.value

  baseRef.value = nextBaseRef
  baseSnapshotId.value = nextBaseSnapshotId
  baseArtifactId.value = nextBaseArtifactId
  baseSource.value = nextBaseSource
  baseLocalFile.value = nextBaseLocalFile
  baseLocalContent.value = nextBaseLocalContent
  baseLocalFormat.value = nextBaseLocalFormat
  baseFiles.value = nextBaseFiles
}

function triggerFilePicker(side: Side) {
  if (side === 'base') {
    baseFileInput.value?.click()
    return
  }
  headFileInput.value?.click()
}

function setDragging(side: Side, value: boolean) {
  if (side === 'base') {
    baseDragging.value = value
    return
  }
  headDragging.value = value
}

function handleFileDrop(side: Side, event: DragEvent) {
  setDragging(side, false)
  const file = event.dataTransfer?.files?.[0]
  if (!file) return
  void loadLocalFile(side, file)
}

function handleFileInput(side: Side, event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  void loadLocalFile(side, file)
  input.value = ''
}

async function loadLocalFile(side: Side, file: File) {
  error.value = ''
  try {
    const text = await file.text()
    const format = detectSBOMFormat(text)
    const content = encodeBase64(text)
    if (side === 'base') {
      baseLocalFile.value = file
      baseLocalContent.value = content
      baseLocalFormat.value = format
      return
    }
    headLocalFile.value = file
    headLocalContent.value = content
    headLocalFormat.value = format
  } catch (err) {
    comparison.value = null
    error.value = err instanceof Error ? err.message : 'Failed to read local SBOM file.'
  }
}

async function getSnapshotFilesCached(providerValue: string, slugValue: string, repoSlugValue: string, snapshotId: string) {
  const cached = snapshotFilesCache.get(snapshotId)
  if (cached) return cached

  const inflight = snapshotFilesRequests.get(snapshotId)
  if (inflight) return inflight

  const request = api
    .listSnapshotFiles(providerValue, slugValue, repoSlugValue, snapshotId)
    .then((response) => {
      snapshotFilesCache.set(snapshotId, response.data)
      snapshotFilesRequests.delete(snapshotId)
      return response.data
    })
    .catch((requestError) => {
      snapshotFilesRequests.delete(snapshotId)
      throw requestError
    })

  snapshotFilesRequests.set(snapshotId, request)
  return request
}

async function findArtifactSnapshot(providerValue: string, slugValue: string, repoSlugValue: string, artifactId: string) {
  for (const snapshot of allSnapshots.value) {
    const files = await getSnapshotFilesCached(providerValue, slugValue, repoSlugValue, snapshot.id)
    if (artifactExistsInFiles(files, artifactId)) {
      return { snapshot, files }
    }
  }
  return null
}

function artifactExistsInFiles(files: SnapshotFile[], artifactId: string) {
  return files.some((file) => file.id === artifactId)
}

function resolveSelectedSnapshot(snapshotList: Snapshot[], snapshotId: string) {
  return snapshotList.find((snapshot) => snapshot.id === snapshotId) ?? null
}

function snapshotOptionLabel(snapshot: Snapshot) {
  const parts = [snapshot.commit_sha.slice(0, 7), snapshotStatusLabel(snapshot), formatDateTime(snapshot.created_at)]
  if (snapshot.run_number) parts.push(`#${snapshot.run_number}`)
  if (snapshot.tag) parts.push(snapshot.tag)
  return parts.join(' · ')
}

function snapshotStatusLabel(snapshot: Snapshot) {
  return capitalize(snapshot.status)
}

function snapshotPrimaryLabel(snapshot: Snapshot) {
  return snapshot.tag || snapshot.commit_sha.slice(0, 7)
}

function snapshotSecondaryLine(snapshot: Snapshot) {
  const parts = [formatDateTime(snapshot.created_at)]
  if (snapshot.run_number) parts.push(`#${snapshot.run_number}`)
  return parts.join(' · ')
}

function snapshotBadgeClass(snapshot: Snapshot) {
  switch (snapshot.status) {
    case 'complete':
    case 'passed':
      return 'bg-emerald-500/15 text-emerald-300'
    case 'failed':
      return 'bg-danger/15 text-danger'
    case 'running':
      return 'bg-sky-500/15 text-sky-300'
    default:
      return 'bg-surface-overlay text-gray-300'
  }
}

function artifactLabel(file: SnapshotFile) {
  const parts = [file.filename]
  if (file.format) parts.push(file.format)
  if (file.tool_name) parts.push(file.tool_name)
  return parts.join(' · ')
}

function itemKey(item: ComponentDelta) {
  return item.purl || `${item.name}:${item.version || item.base_version || ''}:${item.head_version || ''}:${item.ecosystem || ''}`
}

function detectSBOMFormat(text: string): SBOMCompareFormat {
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>
    if (typeof parsed.bomFormat === 'string' && parsed.bomFormat.toLowerCase() === 'cyclonedx') {
      return 'cyclonedx-json'
    }
    if (typeof parsed.spdxVersion === 'string' || typeof parsed.SPDXID === 'string') {
      return 'spdx-json'
    }
  } catch {
    throw new Error('Local file must be valid JSON.')
  }
  throw new Error('Unable to detect SBOM format. Use SPDX JSON or CycloneDX JSON.')
}

function encodeBase64(text: string) {
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function capitalize(value: string) {
  if (!value) return value
  return value.charAt(0).toUpperCase() + value.slice(1)
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(value))
}
</script>

<style scoped>
.compare-display {
  font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace;
}

.compare-beacon {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 9999px;
  background: #58a6ff;
}

.compare-ref {
  color: #e6edf3;
}

.compare-ref-head {
  color: #79c0ff;
}

.compare-dot {
  width: 0.45rem;
  height: 0.45rem;
  border-radius: 9999px;
}

.compare-dot-base { background: #8b949e; box-shadow: 0 0 8px rgb(139 148 158 / 0.6); }
.compare-dot-head { background: #58a6ff; box-shadow: 0 0 8px rgb(88 166 255 / 0.7); }

.compare-arrow {
  margin: 0 0.35rem;
  color: #58a6ff;
  text-shadow: 0 0 12px rgb(88 166 255 / 0.5);
}

.compare-select {
  transition: border-color 0.18s ease, box-shadow 0.18s ease;
}

.compare-select:hover,
.compare-select:focus {
  border-color: rgb(88 166 255 / 0.6);
  box-shadow: 0 0 0 1px rgb(88 166 255 / 0.25);
}

.compare-stat {
  position: relative;
  overflow: hidden;
  opacity: 0;
  animation: compare-rise 0.5s cubic-bezier(0.22, 1, 0.36, 1) forwards;
  animation-delay: calc(var(--i, 0) * 70ms + 60ms);
}

.compare-stat::before {
  content: '';
  position: absolute;
  inset: 0 0 auto 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgb(88 166 255 / 0.7), transparent);
  opacity: 0;
  transition: opacity 0.25s ease;
}

.compare-stat:hover::before {
  opacity: 1;
}

.compare-swap:not(:disabled):hover {
  box-shadow: 0 0 0 1px rgb(88 166 255 / 0.3);
  transform: rotate(180deg);
}

.compare-swap {
  transition: transform 0.3s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.2s ease, color 0.2s ease, box-shadow 0.2s ease;
}

.compare-swap:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.compare-scan {
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgb(88 166 255 / 0.08), transparent);
  background-size: 40% 100%;
  background-repeat: no-repeat;
  animation: compare-sweep 1.3s ease-in-out infinite;
}

.compare-rise {
  opacity: 0;
  animation: compare-rise 0.55s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}

details summary::-webkit-details-marker {
  display: none;
}

details[open] .details-chevron {
  transform: rotate(180deg);
}

.details-chevron {
  transition: transform 0.2s ease;
}

@keyframes compare-sweep {
  0% { background-position: -40% 0; }
  100% { background-position: 140% 0; }
}

@keyframes compare-rise {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (prefers-reduced-motion: reduce) {
  .compare-stat,
  .compare-rise {
    opacity: 1;
    animation: none;
  }

  .compare-scan,
  .details-chevron {
    animation: none;
    transition: none;
  }
}
</style>
