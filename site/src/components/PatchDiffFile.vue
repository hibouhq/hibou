<template>
  <div class="overflow-hidden rounded-lg border border-surface-border-subtle">
    <div
      v-if="!rows.length"
      class="px-3 py-2 text-xs text-gray-500"
    >
      Diff not available for this file.
    </div>
    <div
      v-else
      class="overflow-x-auto"
    >
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
                v-if="row.coverage === 'uncovered'"
                class="ml-2 rounded bg-danger/20 px-1 text-[10px] uppercase tracking-wide text-danger"
              >uncovered</span>
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
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

interface DiffRow {
  kind: 'hunk' | 'add' | 'del' | 'context'
  newLine: number | null
  content: string
  coverage: 'covered' | 'uncovered' | 'none'
}

const props = defineProps<{
  hunks: string
  coveredLines: number[]
  uncoveredLines: number[]
}>()

const hunkHeader = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/

const rows = computed<DiffRow[]>(() => {
  if (!props.hunks) return []
  const covered = new Set(props.coveredLines ?? [])
  const uncovered = new Set(props.uncoveredLines ?? [])
  const out: DiffRow[] = []
  let newLine = 0
  let inHunk = false

  for (const line of props.hunks.split('\n')) {
    const header = hunkHeader.exec(line)
    if (header) {
      newLine = Number.parseInt(header[1], 10)
      inHunk = true
      out.push({ kind: 'hunk', newLine: null, content: line, coverage: 'none' })
      continue
    }
    if (!inHunk) continue
    if (line.startsWith('+++') || line.startsWith('---')) continue
    if (line.startsWith('+')) {
      let coverage: DiffRow['coverage'] = 'none'
      if (covered.has(newLine)) coverage = 'covered'
      else if (uncovered.has(newLine)) coverage = 'uncovered'
      out.push({ kind: 'add', newLine, content: line.slice(1), coverage })
      newLine++
    } else if (line.startsWith('-')) {
      out.push({ kind: 'del', newLine: null, content: line.slice(1), coverage: 'none' })
    } else if (line.startsWith('\\')) {
      // "\ No newline at end of file" — no line movement, skip.
      continue
    } else {
      out.push({ kind: 'context', newLine, content: line.startsWith(' ') ? line.slice(1) : line, coverage: 'none' })
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
  if (row.coverage === 'covered') return 'bg-emerald-500/10'
  if (row.coverage === 'uncovered') return 'bg-danger/10'
  if (row.kind === 'del') return 'bg-danger/5'
  if (row.kind === 'add') return 'bg-white/[0.03]'
  return ''
}

function contentClass(row: DiffRow): string {
  if (row.kind === 'hunk') return 'text-gray-500'
  if (row.coverage === 'covered') return 'text-emerald-200'
  if (row.coverage === 'uncovered') return 'text-red-200'
  if (row.kind === 'del') return 'text-red-300/70 line-through decoration-red-500/30'
  if (row.kind === 'add') return 'text-gray-200'
  return 'text-gray-500'
}

function marker(row: DiffRow): string {
  if (row.kind === 'add') return '+'
  if (row.kind === 'del') return '-'
  return ''
}
</script>
