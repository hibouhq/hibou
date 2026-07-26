<template>
  <div class="space-y-2">
    <div class="flex items-center gap-1 text-xs">
      <button
        v-for="(crumb, index) in breadcrumbs"
        :key="crumb.path"
        type="button"
        class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono transition"
        :class="index === breadcrumbs.length - 1 ? 'text-white' : 'text-gray-400 hover:bg-white/5 hover:text-white'"
        @click="rootPath = crumb.path"
      >
        {{ crumb.label }}
        <span
          v-if="index < breadcrumbs.length - 1"
          class="text-gray-600"
        >/</span>
      </button>
    </div>

    <svg
      :viewBox="`0 0 ${WIDTH} ${HEIGHT}`"
      class="w-full select-none rounded-lg border border-surface-border bg-surface-overlay/40"
      role="img"
      aria-label="Coverage treemap"
    >
      <g
        v-for="tile in tiles"
        :key="tile.node.path"
        class="cursor-pointer"
        @click="onTileClick(tile.node)"
        @mousemove="onTileHover($event, tile.node)"
        @mouseleave="hover = null"
      >
        <rect
          :x="tile.x"
          :y="tile.y"
          :width="tile.w"
          :height="tile.h"
          :fill="coverageRateColor(tile.node.rate)"
          :fill-opacity="tile.node.isFile ? 0.88 : 0.72"
          stroke="rgb(13 17 23 / 0.9)"
          stroke-width="1.5"
          rx="2"
        />
        <text
          v-if="tile.w > 60 && tile.h > 18"
          :x="tile.x + 5"
          :y="tile.y + 13"
          fill="white"
          fill-opacity="0.92"
          font-size="10"
          font-family="ui-monospace, monospace"
        >
          {{ tileLabel(tile) }}
        </text>
        <text
          v-if="tile.w > 60 && tile.h > 34"
          :x="tile.x + 5"
          :y="tile.y + 26"
          fill="white"
          fill-opacity="0.6"
          font-size="9"
        >
          {{ formatCoverageRate(tile.node.rate) }} · {{ tile.node.covered }}/{{ tile.node.valid }}
        </text>
      </g>
    </svg>

    <div
      v-if="hover"
      class="pointer-events-none fixed z-30 rounded-lg border border-surface-border bg-surface-raised px-3 py-2 text-xs shadow-xl"
      :style="{ left: `${hover.x + 12}px`, top: `${hover.y + 12}px` }"
    >
      <div class="font-mono text-gray-200">
        {{ hover.node.path }}{{ hover.node.isFile ? '' : '/' }}
      </div>
      <div class="mt-1 text-gray-400">
        {{ formatCoverageRate(hover.node.rate) }} line coverage · {{ hover.node.covered }}/{{ hover.node.valid }} lines
        <template v-if="!hover.node.isFile">
          · {{ hover.node.fileCount }} files
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
// Squarified treemap of the coverage tree, weighted by instrumented lines and
// colored by line rate. Click a directory to drill in, a file to open it.
import { computed, ref, watch } from 'vue'

import {
  buildCoverageTree,
  coverageRateColor,
  findTreeNode,
  formatCoverageRate,
  squarify,
  type CoverageTreeFile,
  type CoverageTreeNode,
  type TreemapTile,
} from '@/lib/coverageTree'

const WIDTH = 960
const HEIGHT = 420

const props = defineProps<{ files: CoverageTreeFile[] }>()
const emit = defineEmits<{ (e: 'select-file', path: string): void }>()

const rootPath = ref('')
const hover = ref<{ node: CoverageTreeNode; x: number; y: number } | null>(null)

const tree = computed(() => buildCoverageTree(props.files))

const currentRoot = computed(() => findTreeNode(tree.value, rootPath.value) ?? tree.value)

const breadcrumbs = computed(() => {
  const crumbs = [{ path: '', label: 'all' }]
  if (!rootPath.value) return crumbs
  const segments = rootPath.value.split('/')
  segments.forEach((segment, index) => {
    crumbs.push({ path: segments.slice(0, index + 1).join('/'), label: segment })
  })
  return crumbs
})

const tiles = computed(() => squarify(currentRoot.value.children.filter((child) => child.valid > 0), 0, 0, WIDTH, HEIGHT))

// Reset the drill-down when the file set changes (ref/snapshot switch).
watch(
  () => props.files,
  () => {
    rootPath.value = ''
  },
)

function onTileClick(node: CoverageTreeNode) {
  if (node.isFile) {
    emit('select-file', node.path)
    return
  }
  rootPath.value = node.path
}

function onTileHover(event: MouseEvent, node: CoverageTreeNode) {
  hover.value = { node, x: event.clientX, y: event.clientY }
}

function tileLabel(tile: TreemapTile): string {
  const label = tile.node.isFile ? tile.node.name : `${tile.node.name}/`
  const maxChars = Math.floor((tile.w - 10) / 6)
  return label.length > maxChars ? `${label.slice(0, Math.max(1, maxChars - 1))}…` : label
}
</script>
