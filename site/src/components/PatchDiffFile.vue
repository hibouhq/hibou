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
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-blue-500/60" /> covered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-orange-500/60" /> uncovered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-emerald-500/70" /> new covered</span>
        <span class="flex items-center gap-1.5"><span class="h-2 w-2 rounded-sm bg-red-500/70" /> new uncovered</span>
        <div class="ml-auto flex items-center gap-2 normal-case tracking-normal">
          <span
            v-if="splitSuppressed"
            class="text-[10px] text-gray-500"
          >split needs a wider window</span>
          <div class="flex overflow-hidden rounded border border-surface-border">
            <button
              type="button"
              class="px-2 py-0.5 text-[10px] transition"
              :class="effectiveLayout === 'unified' ? 'bg-accent/15 text-white' : 'bg-surface-overlay text-gray-400 hover:text-white'"
              @click="layout = 'unified'"
            >
              Unified
            </button>
            <button
              type="button"
              class="px-2 py-0.5 text-[10px] transition"
              :class="effectiveLayout === 'split' ? 'bg-accent/15 text-white' : 'bg-surface-overlay text-gray-400 hover:text-white'"
              :disabled="!splitFitsViewport"
              :title="splitFitsViewport ? 'Side-by-side: base left, head right' : 'Window too narrow for side-by-side'"
              @click="layout = 'split'"
            >
              Split
            </button>
          </div>
        </div>
      </div>
      <div
        v-if="effectiveLayout === 'unified'"
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

      <div
        v-else
        class="overflow-x-auto"
      >
        <table class="w-full table-fixed border-collapse font-mono text-xs leading-relaxed">
          <colgroup>
            <col class="w-10">
            <col class="w-1/2">
            <col class="w-10">
            <col>
          </colgroup>
          <tbody>
            <template
              v-for="(row, index) in splitRows"
              :key="index"
            >
              <tr v-if="row.kind === 'hunk'">
                <td
                  colspan="4"
                  class="bg-surface-overlay/80 px-2 py-0.5 text-gray-500"
                >
                  {{ row.header }}
                </td>
              </tr>
              <tr v-else>
                <td class="select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] text-gray-600 tabular-nums">
                  {{ row.left?.oldLine ?? '' }}
                </td>
                <td
                  class="whitespace-pre border-r border-surface-border-subtle px-2 align-top"
                  :class="splitCellClass(row.left, 'left')"
                >
                  <span :class="row.left ? contentClass(row.left) : ''">{{ row.left ? (row.left.content || ' ') : '' }}</span>
                </td>
                <td class="select-none border-r border-surface-border-subtle px-2 text-right align-top text-[11px] text-gray-600 tabular-nums">
                  {{ row.right?.newLine ?? '' }}
                </td>
                <td
                  class="whitespace-pre px-2 align-top"
                  :class="splitCellClass(row.right, 'right')"
                >
                  <span :class="row.right ? contentClass(row.right) : ''">{{ row.right ? (row.right.content || ' ') : '' }}</span>
                  <span
                    v-if="row.right && badgeFor(row.right)"
                    class="ml-2 rounded px-1 text-[10px] uppercase tracking-wide"
                    :class="badgeFor(row.right)!.className"
                  >{{ badgeFor(row.right)!.text }}</span>
                </td>
              </tr>
            </template>
            <tr v-if="hiddenRowCount > 0">
              <td
                colspan="4"
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
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'

type Coverage = 'covered' | 'uncovered' | 'gained' | 'lost' | 'none'

interface DiffRow {
  kind: 'hunk' | 'add' | 'del' | 'context'
  newLine: number | null
  // oldLine is the base-side number, needed by the split layout's left column.
  oldLine: number | null
  content: string
  // coverage is the head/new-side state; leftCoverage is the base-side state, so
  // split view can show a regression as green-left / red-right on one row.
  coverage: Coverage
  leftCoverage: Coverage
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

  const baseCoverage = (oldNumber: number): Coverage => {
    if (baseCovered.has(oldNumber)) return 'covered'
    if (baseUncovered.has(oldNumber)) return 'uncovered'
    return 'none'
  }

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
      out.push({ kind: 'hunk', newLine: null, oldLine: null, content: line, coverage: 'none', leftCoverage: 'none' })
      continue
    }
    if (!inHunk) continue
    if (line.startsWith('+++') || line.startsWith('---')) continue
    if (line.startsWith('+')) {
      let coverage: Coverage = 'none'
      if (changedCovered.has(newLine)) coverage = 'gained'
      else if (changedUncovered.has(newLine)) coverage = 'lost'
      out.push({ kind: 'add', newLine, oldLine: null, content: line.slice(1), coverage, leftCoverage: 'none' })
      newLine++
    } else if (line.startsWith('-')) {
      out.push({ kind: 'del', newLine: null, oldLine, content: line.slice(1), coverage: 'none', leftCoverage: baseCoverage(oldLine) })
      oldLine++
    } else if (line.startsWith('\\')) {
      continue
    } else {
      out.push({ kind: 'context', newLine, oldLine, content: line.startsWith(' ') ? line.slice(1) : line, coverage: contextCoverage(oldLine, newLine), leftCoverage: baseCoverage(oldLine) })
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

// ─── Layout: unified (default) vs split, forge-review style ───────────────────
// Sticky per user rather than per file: reviewers pick a layout once.
const LAYOUT_KEY = 'hibou.diffLayout'
type Layout = 'unified' | 'split'
const layout = ref<Layout>(readStoredLayout())

function readStoredLayout(): Layout {
  try {
    return globalThis.localStorage?.getItem(LAYOUT_KEY) === 'split' ? 'split' : 'unified'
  } catch {
    return 'unified'
  }
}

watch(layout, (value) => {
  try {
    globalThis.localStorage?.setItem(LAYOUT_KEY, value)
  } catch {
    // Private browsing: the preference simply does not persist.
  }
})

// Split needs horizontal room; below this it becomes unreadable, so force
// unified and say why instead of rendering something cramped.
const MIN_SPLIT_WIDTH = 900
const viewportWidth = ref(typeof globalThis.innerWidth === 'number' ? globalThis.innerWidth : MIN_SPLIT_WIDTH)
const splitFitsViewport = computed(() => viewportWidth.value >= MIN_SPLIT_WIDTH)
const effectiveLayout = computed<Layout>(() => (layout.value === 'split' && splitFitsViewport.value ? 'split' : 'unified'))
const splitSuppressed = computed(() => layout.value === 'split' && !splitFitsViewport.value)

function onResize() {
  viewportWidth.value = globalThis.innerWidth
}
onMounted(() => globalThis.addEventListener?.('resize', onResize))
onUnmounted(() => globalThis.removeEventListener?.('resize', onResize))

interface SplitRow {
  kind: 'hunk' | 'pair'
  header?: string
  left: DiffRow | null
  right: DiffRow | null
}

// Pair a run of deletions with the following run of additions so a modified
// line sits on one row, base left / head right — the forge review layout.
const splitRows = computed<SplitRow[]>(() => {
  const out: SplitRow[] = []
  const source = visibleRows.value
  let index = 0
  while (index < source.length) {
    const row = source[index]
    if (row.kind === 'hunk') {
      out.push({ kind: 'hunk', header: row.content, left: null, right: null })
      index++
      continue
    }
    if (row.kind === 'context') {
      out.push({ kind: 'pair', left: row, right: row })
      index++
      continue
    }
    const dels: DiffRow[] = []
    const adds: DiffRow[] = []
    while (index < source.length && source[index].kind === 'del') dels.push(source[index++])
    while (index < source.length && source[index].kind === 'add') adds.push(source[index++])
    const pairs = Math.max(dels.length, adds.length)
    for (let i = 0; i < pairs; i++) {
      out.push({ kind: 'pair', left: dels[i] ?? null, right: adds[i] ?? null })
    }
  }
  return out
})

// Split-side styling: left reads base coverage, right reads head coverage.
function splitCellClass(row: DiffRow | null, side: 'left' | 'right'): string {
  if (!row) return 'bg-surface-overlay/30'
  const coverage = side === 'left' ? row.leftCoverage : row.coverage
  switch (coverage) {
    case 'gained':
      return 'bg-emerald-500/30'
    case 'lost':
      return 'bg-red-500/30'
    case 'covered':
      return 'bg-blue-500/15'
    case 'uncovered':
      return 'bg-orange-500/15'
    default:
      break
  }
  if (side === 'left' && row.kind === 'del') return 'bg-danger/10'
  if (side === 'right' && row.kind === 'add') return 'bg-white/[0.03]'
  return ''
}

function rowClass(row: DiffRow): string {
  if (row.kind === 'hunk') return 'bg-surface-overlay/80 text-gray-500'
  switch (row.coverage) {
    case 'gained':
      return 'bg-emerald-500/30 shadow-[inset_3px_0_0_0_theme(colors.emerald.400)]'
    case 'lost':
      return 'bg-red-500/30 shadow-[inset_3px_0_0_0_theme(colors.red.500)]'
    case 'covered':
      return 'bg-blue-500/15 shadow-[inset_3px_0_0_0_theme(colors.blue.400)]'
    case 'uncovered':
      return 'bg-orange-500/15 shadow-[inset_3px_0_0_0_theme(colors.orange.400)]'
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
      return 'text-emerald-100'
    case 'lost':
      return 'text-red-200/90'
    case 'covered':
      return 'text-blue-200/90'
    case 'uncovered':
      return 'text-orange-100'
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
      ? { text: 'new · uncovered', className: 'bg-red-500/25 text-red-300' }
      : { text: 'lost coverage', className: 'bg-red-500/25 text-red-300' }
  }
  if (row.coverage === 'gained' && row.kind === 'context') {
    return { text: 'gained coverage', className: 'bg-emerald-500/25 text-emerald-300' }
  }
  return null
}

function marker(row: DiffRow): string {
  if (row.kind === 'add') return '+'
  if (row.kind === 'del') return '-'
  return ''
}
</script>
