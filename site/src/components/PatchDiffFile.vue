<template>
  <div class="overflow-hidden rounded-lg border border-surface-border-subtle">
    <div
      v-if="!rows.length"
      class="px-3 py-2 text-xs text-gray-500"
    >
      Diff not available for this file.
    </div>
    <template v-else>
      <div class="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-surface-border-subtle bg-surface-overlay/40 px-3 py-1.5 text-[10px] uppercase tracking-wide text-gray-500">
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-emerald-500/50" /> covered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-red-500/50" /> uncovered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-cyan-400/60" /> newly covered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-amber-400/60" /> newly uncovered</span>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full border-collapse font-mono text-xs leading-relaxed">
          <tbody>
            <tr
              v-for="(row, index) in visibleRows"
              :key="index"
              :class="rowClass(row)"
            >
              <td class="select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] text-gray-600 tabular-nums">
                {{ row.newLine ?? '' }}
              </td>
              <td class="w-4 select-none px-1 text-center align-top text-gray-500">
                {{ marker(row) }}
              </td>
              <td class="whitespace-pre px-2 align-top">
                <span :class="contentClass(row)">{{ row.content || ' ' }}</span>
                <span
                  v-if="badgeFor(row)"
                  class="ml-2 rounded px-1 text-[10px] uppercase tracking-wide"
                  :class="badgeFor(row)!.className"
                >{{ badgeFor(row)!.text }}</span>
              </td>
            </tr>
            <tr v-if="hiddenRowCount > 0">
              <td
                colspan="3"
                class="border-t border-surface-border-subtle bg-surface-overlay/60 px-3 py-1.5 text-[11px] text-gray-500"
              >
                {{ hiddenRowCount }} more diff {{ hiddenRowCount === 1 ? 'line' : 'lines' }} not shown
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// Four coverage states per line: plain covered/uncovered (subtle green/red,
// state unchanged by the PR), and newly covered / newly uncovered (loud
// cyan/amber) — added lines, plus context lines whose state flipped vs base.
import { computed } from 'vue'

type Coverage = 'covered' | 'uncovered' | 'gained' | 'lost' | 'none'

interface DiffRow {
  kind: 'hunk' | 'add' | 'del' | 'context'
  newLine: number | null
  content: string
  coverage: Coverage
}

const props = defineProps<{
  hunks: string
  coveredLines: number[]
  uncoveredLines: number[]
  headCoveredLines?: number[]
  headUncoveredLines?: number[]
  baseCoveredLines?: number[]
  baseUncoveredLines?: number[]
}>()

const hunkHeader = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/

const rows = computed<DiffRow[]>(() => {
  if (!props.hunks) return []
  const changedCovered = new Set(props.coveredLines ?? [])
  const changedUncovered = new Set(props.uncoveredLines ?? [])
  const headCovered = new Set(props.headCoveredLines ?? [])
  const headUncovered = new Set(props.headUncoveredLines ?? [])
  const baseCovered = new Set(props.baseCoveredLines ?? [])
  const baseUncovered = new Set(props.baseUncoveredLines ?? [])
  const out: DiffRow[] = []
  let oldLine = 0
  let newLine = 0
  let inHunk = false

  const contextCoverage = (oldNumber: number, newNumber: number): Coverage => {
    const nowCovered = headCovered.has(newNumber)
    const nowUncovered = headUncovered.has(newNumber)
    if (!nowCovered && !nowUncovered) return 'none'
    if (nowCovered) return baseUncovered.has(oldNumber) ? 'gained' : 'covered'
    return baseCovered.has(oldNumber) ? 'lost' : 'uncovered'
  }

  for (const line of props.hunks.split('\n')) {
    const header = hunkHeader.exec(line)
    if (header) {
      oldLine = Number.parseInt(header[1], 10)
      newLine = Number.parseInt(header[2], 10)
      inHunk = true
      out.push({ kind: 'hunk', newLine: null, content: line, coverage: 'none' })
      continue
    }
    if (!inHunk) continue
    if (line.startsWith('+++') || line.startsWith('---')) continue
    if (line.startsWith('+')) {
      let coverage: Coverage = 'none'
      if (changedCovered.has(newLine)) coverage = 'gained'
      else if (changedUncovered.has(newLine)) coverage = 'lost'
      out.push({ kind: 'add', newLine, content: line.slice(1), coverage })
      newLine++
    } else if (line.startsWith('-')) {
      out.push({ kind: 'del', newLine: null, content: line.slice(1), coverage: 'none' })
      oldLine++
    } else if (line.startsWith('\\')) {
      continue
    } else {
      out.push({ kind: 'context', newLine, content: line.startsWith(' ') ? line.slice(1) : line, coverage: contextCoverage(oldLine, newLine) })
      oldLine++
      newLine++
    }
  }
  return out
})

// Cap rendered rows so a huge file diff cannot lock up the page; the footer
// reports how many were elided.
const MAX_ROWS = 400
const visibleRows = computed(() => rows.value.slice(0, MAX_ROWS))
const hiddenRowCount = computed(() => Math.max(0, rows.value.length - MAX_ROWS))

function rowClass(row: DiffRow): string {
  if (row.kind === 'hunk') return 'bg-surface-overlay/80 text-gray-500'
  switch (row.coverage) {
    case 'gained':
      return 'bg-cyan-400/20 shadow-[inset_3px_0_0_0_theme(colors.cyan.400)]'
    case 'lost':
      return 'bg-amber-400/20 shadow-[inset_3px_0_0_0_theme(colors.amber.400)]'
    case 'covered':
      return 'bg-emerald-500/10 shadow-[inset_3px_0_0_0_theme(colors.emerald.500/50%)]'
    case 'uncovered':
      return 'bg-red-500/10 shadow-[inset_3px_0_0_0_theme(colors.red.500/50%)]'
    default:
      break
  }
  if (row.kind === 'del') return 'bg-danger/5'
  if (row.kind === 'add') return 'bg-white/[0.03]'
  return ''
}

function contentClass(row: DiffRow): string {
  if (row.kind === 'hunk') return 'text-gray-500'
  switch (row.coverage) {
    case 'gained':
      return 'text-cyan-100'
    case 'lost':
      return 'text-amber-100'
    case 'covered':
      return 'text-emerald-200/90'
    case 'uncovered':
      return 'text-red-200/90'
    default:
      break
  }
  if (row.kind === 'del') return 'text-red-300/70 line-through decoration-red-500/30'
  if (row.kind === 'add') return 'text-gray-200'
  return 'text-gray-500'
}

function badgeFor(row: DiffRow): { text: string; className: string } | null {
  if (row.coverage === 'lost') {
    return row.kind === 'add'
      ? { text: 'new · uncovered', className: 'bg-amber-400/20 text-amber-300' }
      : { text: 'lost coverage', className: 'bg-amber-400/20 text-amber-300' }
  }
  if (row.coverage === 'gained' && row.kind === 'context') {
    return { text: 'gained coverage', className: 'bg-cyan-400/20 text-cyan-300' }
  }
  return null
}

function marker(row: DiffRow): string {
  if (row.kind === 'add') return '+'
  if (row.kind === 'del') return '-'
  return ''
}
</script>
