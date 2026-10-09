<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-center gap-3">
      <div
        class="inline-flex overflow-hidden rounded-md border border-surface-border text-xs"
        role="group"
        aria-label="Group CWEs by"
      >
        <button
          v-for="option in groupOptions"
          :key="option.key"
          type="button"
          class="px-2.5 py-1 transition"
          :class="groupBy === option.key ? 'bg-accent-muted text-accent' : 'text-gray-400 hover:text-gray-200'"
          :aria-pressed="groupBy === option.key"
          @click="groupBy = option.key"
        >
          {{ option.label }}
        </button>
      </div>
      <span
        v-if="report"
        class="text-xs text-gray-500"
      >
        {{ report.cwes.length }} CWEs across {{ report.total_findings - report.no_cwe }} of {{ report.total_findings }} open vulnerabilities
      </span>
    </div>

    <div
      v-if="loading"
      class="py-10 text-center text-sm text-gray-500"
    >
      Loading CWEs…
    </div>
    <div
      v-else-if="!report || report.total_findings === 0"
      class="py-10 text-center text-sm text-gray-500"
    >
      No open vulnerabilities in scope.
    </div>

    <div
      v-else
      class="overflow-x-auto rounded-xl border border-surface-border"
    >
      <table class="min-w-full text-sm">
        <thead class="bg-surface-overlay text-left text-xs uppercase tracking-[0.14em] text-gray-500">
          <!-- Total, then its breakdown: every vulnerability is in exactly
               one of Code / Dependencies, so they always add up to Total. -->
          <tr>
            <th
              rowspan="2"
              class="px-3 py-2 align-bottom font-medium"
            >
              CWE
            </th>
            <th
              rowspan="2"
              class="px-3 py-2 align-bottom font-medium"
            >
              Weakness
            </th>
            <th
              :colspan="typeColumns.length + 1"
              class="border-b border-surface-border px-3 pb-1 pt-2 text-center font-medium"
            >
              Vulnerabilities
            </th>
            <th
              rowspan="2"
              class="w-32 whitespace-nowrap px-3 py-2 align-bottom font-medium"
            >
              Max severity
            </th>
          </tr>
          <tr>
            <th
              class="w-20 px-3 pb-2 pt-1 text-center font-semibold text-gray-300"
              title="All open vulnerabilities carrying this CWE"
            >
              Total
            </th>
            <th
              v-for="(column, index) in typeColumns"
              :key="column.key"
              class="w-28 px-3 pb-2 pt-1 text-center text-[10px] font-medium normal-case tracking-normal text-gray-500"
              :class="index === 0 ? 'border-l border-surface-border' : ''"
              :title="column.hint"
            >
              {{ column.label }}
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-surface-border">
          <template
            v-for="group in groups"
            :key="group.key"
          >
            <tr
              v-if="group.label"
              class="bg-surface-overlay/40"
            >
              <td
                colspan="3"
                class="px-3 py-1.5 text-xs font-semibold text-gray-300"
              >
                <button
                  v-if="group.query"
                  type="button"
                  class="hover:text-white hover:underline"
                  :title="`Show vulnerabilities: ${group.query}`"
                  @click="$emit('select', group.query)"
                >
                  {{ group.label }}
                </button>
                <span v-else>{{ group.label }}</span>
                <span class="ml-2 font-normal text-gray-500">{{ group.total }}</span>
              </td>
              <td :colspan="typeColumns.length + 2" />
            </tr>
            <tr
              v-for="usage in group.rows"
              :key="usage.id"
              class="hover:bg-surface-overlay/40"
            >
              <td class="whitespace-nowrap px-3 py-2.5 align-top">
                <a
                  :href="mitreCWEUrl(usage.id)"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="font-mono text-xs text-sky-200 hover:underline"
                  :class="usage.deprecated ? 'line-through decoration-gray-500' : ''"
                  :title="`Open CWE-${usage.id} on cwe.mitre.org`"
                >CWE-{{ usage.id }}</a>
              </td>
              <td class="max-w-xl px-3 py-2.5 align-top">
                <button
                  type="button"
                  class="block text-left text-gray-200 transition hover:text-white"
                  :title="`Show vulnerabilities carrying CWE-${usage.id}`"
                  @click="$emit('select', `cwe:${usage.id}`)"
                >
                  {{ usage.name || 'Not in the CWE catalog' }}
                </button>
                <div class="mt-1 flex flex-wrap items-center gap-1.5 text-[11px] text-gray-500">
                  <span v-if="usage.category && groupBy !== 'category'">{{ usage.category.name }}</span>
                  <span
                    v-for="set in displaySets(usage.sets)"
                    :key="set.slug"
                    class="rounded-full bg-surface-overlay px-1.5 py-px text-gray-400"
                  >{{ set.rank ? `${set.name} #${set.rank}` : set.name }}</span>
                  <!-- Only CWEs with more specific kinds under them: the link
                       widens the filter to those (cwe-tree:). -->
                  <button
                    v-if="usage.descendants"
                    type="button"
                    class="text-gray-500 underline decoration-dotted underline-offset-2 transition hover:text-accent"
                    :title="`Show vulnerabilities for CWE-${usage.id} or any of its ${usage.descendants} more specific sub-types (cwe-tree:${usage.id})`"
                    @click="$emit('select', `cwe-tree:${usage.id}`)"
                  >
                    + {{ usage.descendants }} sub-type{{ usage.descendants === 1 ? '' : 's' }}
                  </button>
                </div>
              </td>
              <td class="px-3 py-2.5 text-center align-top font-medium tabular-nums text-gray-100">
                <button
                  type="button"
                  class="rounded px-1 transition hover:bg-surface-overlay hover:text-white"
                  :title="`Show the ${vulnerabilities(usage.total)} carrying CWE-${usage.id}`"
                  @click="$emit('select', `cwe:${usage.id}`)"
                >
                  {{ usage.total }}
                </button>
              </td>
              <td
                v-for="(column, index) in typeColumns"
                :key="column.key"
                class="px-3 py-2.5 text-center align-top text-xs tabular-nums"
                :class="[typeCount(usage, column.types) ? 'text-gray-400' : 'text-gray-700', index === 0 ? 'border-l border-surface-border' : '']"
              >
                <button
                  v-if="typeCount(usage, column.types)"
                  type="button"
                  class="rounded px-1 transition hover:bg-surface-overlay hover:text-white"
                  :title="`Show the ${vulnerabilities(typeCount(usage, column.types), column.label.toLowerCase())} carrying CWE-${usage.id}`"
                  @click="$emit('select', `cwe:${usage.id} ${column.filter}`)"
                >
                  {{ typeCount(usage, column.types) }}
                </button>
                <span v-else>–</span>
              </td>
              <td class="px-3 py-2.5 align-top">
                <span :class="severityClass(usage.max_severity)">{{ usage.max_severity }}</span>
              </td>
            </tr>
          </template>
          <!-- Coverage gaps stay visible: findings whose scanner or advisory
               gives no CWE cannot be found by any CWE filter. -->
          <tr
            v-if="report.no_cwe > 0"
            class="bg-surface-overlay/20"
          >
            <td class="px-3 py-2 font-mono text-xs text-gray-500">
              —
            </td>
            <td class="px-3 py-2">
              <button
                type="button"
                class="text-left text-gray-400 transition hover:text-white"
                @click="$emit('select', 'cwe:none')"
              >
                No CWE
              </button>
              <div class="mt-0.5 text-[11px] text-gray-500">
                Scanners or advisories that classify nothing — invisible to CWE filters and gates
              </div>
            </td>
            <td class="px-3 py-2 text-center tabular-nums text-gray-300">
              {{ report.no_cwe }}
            </td>
            <td :colspan="typeColumns.length + 2" />
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { CWEUsage, CWEUsageReport } from '@/api/client'
import { displaySets, mitreCWEUrl } from '@/lib/cweCatalog'

const props = defineProps<{
  report: CWEUsageReport | null
  loading?: boolean
}>()

defineEmits<{
  // A filter query for the findings list: cwe:79, cwe-tree:74, cwe-category:injection.
  (event: 'select', query: string): void
}>()

type GroupBy = 'flat' | 'category' | 'top25'
const groupOptions: Array<{ key: GroupBy; label: string }> = [
  { key: 'flat', label: 'All' },
  { key: 'category', label: 'By category' },
  { key: 'top25', label: 'Top 25' },
]

const STORAGE_KEY = 'hibou:cwe-group-by'
function readGroupBy(): GroupBy {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    return stored === 'category' || stored === 'top25' ? stored : 'flat'
  } catch {
    return 'flat'
  }
}
const groupBy = ref<GroupBy>(readGroupBy())
watch(groupBy, value => {
  try {
    localStorage.setItem(STORAGE_KEY, value)
  } catch {
    // A remembered grouping is a convenience only.
  }
})

// Two columns, exhaustive and adding up to Total: a dependency (or container
// image, or malicious package) vulnerability, or one in the repository itself.
// Each count links to exactly the vulnerabilities it counts; Code is "not a
// dependency", so its filter is the exclusion, which also covers future types.
const DEPENDENCY_TYPES = 'type:dependency,container,malware'
const typeColumns = [
  {
    key: 'code',
    label: 'Code',
    types: ['sast', 'dast', 'fuzzing', 'generic', 'secret', 'manual'],
    hint: 'In the repository itself: code scanners (SAST, DAST, fuzzing), leaked secrets and manual reports',
    filter: `-${DEPENDENCY_TYPES}`,
  },
  {
    key: 'deps',
    label: 'Dependencies',
    types: ['dependency', 'container', 'malware'],
    hint: 'In third-party packages and container images (CVE advisories, malicious packages)',
    filter: DEPENDENCY_TYPES,
  },
]

function vulnerabilities(count: number, kind = ''): string {
  return `${count} ${kind ? `${kind} ` : ''}${count === 1 ? 'vulnerability' : 'vulnerabilities'}`
}

function typeCount(usage: CWEUsage, types: string[]): number {
  return types.reduce((sum, type) => sum + (usage.by_type[type] ?? 0), 0)
}

interface Group {
  key: string
  label?: string
  query?: string
  total: number
  rows: CWEUsage[]
}

const groups = computed<Group[]>(() => {
  const rows = props.report?.cwes ?? []
  if (groupBy.value === 'category') {
    const byCategory = new Map<string, Group>()
    for (const usage of rows) {
      const key = usage.category?.slug ?? ''
      let group = byCategory.get(key)
      if (!group) {
        group = {
          key: key || 'uncategorized',
          label: usage.category?.name ?? 'Uncategorized',
          query: key ? `cwe-category:${key}` : undefined,
          total: 0,
          rows: [],
        }
        byCategory.set(key, group)
      }
      group.rows.push(usage)
      group.total += usage.total
    }
    return [...byCategory.values()].sort((a, b) => b.total - a.total)
  }
  if (groupBy.value === 'top25') {
    const rank = (usage: CWEUsage) => usage.sets?.find(set => set.slug === 'top25')?.rank
    const ranked = rows.filter(usage => rank(usage) !== undefined).sort((a, b) => (rank(a) ?? 0) - (rank(b) ?? 0))
    const rest = rows.filter(usage => rank(usage) === undefined)
    const topName = ranked[0]?.sets?.find(set => set.slug === 'top25')?.name ?? 'CWE Top 25'
    return [
      { key: 'top25', label: topName, query: 'cwe-set:top25', total: ranked.reduce((sum, usage) => sum + usage.total, 0), rows: ranked },
      { key: 'rest', label: 'Not in the Top 25', total: rest.reduce((sum, usage) => sum + usage.total, 0), rows: rest },
    ].filter(group => group.rows.length > 0)
  }
  return [{ key: 'all', total: rows.reduce((sum, usage) => sum + usage.total, 0), rows }]
})

function severityClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-xs font-semibold text-red-300'
    case 'high': return 'text-xs font-semibold text-orange-300'
    case 'medium': return 'text-xs text-amber-300'
    case 'low': return 'text-xs text-sky-300'
    default: return 'text-xs text-gray-400'
  }
}
</script>
