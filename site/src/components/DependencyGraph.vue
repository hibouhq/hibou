<template>
  <div class="space-y-3">
    <div
      v-if="summaryNote"
      class="rounded-xl border border-surface-border bg-surface-overlay/30 px-3 py-2 text-xs text-gray-400"
    >
      {{ summaryNote }}
    </div>

    <div
      ref="viewportRef"
      class="overflow-auto rounded-xl border border-surface-border-subtle bg-surface-overlay/20"
    >
      <svg
        :width="layout.width"
        :height="layout.height"
        class="block min-w-full"
        role="img"
        aria-label="Dependency graph"
      >
        <g>
          <path
            v-for="edge in layout.renderedEdges"
            :key="edge.key"
            :d="edge.path"
            fill="none"
            :stroke="edge.highlighted ? 'rgb(110 231 183 / 0.9)' : 'rgb(107 114 128 / 0.35)'"
            :stroke-width="edge.highlighted ? 2.5 : 1.5"
            stroke-linecap="round"
          />
        </g>

        <g
          v-for="node in layout.renderedNodes"
          :key="node.ref"
          class="cursor-pointer"
          @mouseenter="hoveredRef = node.ref"
          @mouseleave="hoveredRef = null"
          @click="emit('select', node.ref)"
        >
          <rect
            :x="node.x"
            :y="node.y"
            :width="layout.nodeWidth"
            :height="layout.nodeHeight"
            rx="12"
            :fill="nodeFill(node)"
            :stroke="nodeStroke(node)"
            :stroke-width="nodeStrokeWidth(node)"
          />
          <text
            :x="node.x + 14"
            :y="node.y + 20"
            fill="rgb(229 231 235)"
            font-size="13"
            font-weight="600"
          >
            {{ truncateLabel(node.label, 24) }}
          </text>
          <text
            :x="node.x + 14"
            :y="node.y + 35"
            :fill="node.ref === layout.rootRef ? 'rgb(196 181 253)' : 'rgb(156 163 175)'"
            font-size="11"
          >
            {{ nodeSubtitle(node) }}
          </text>
          <circle
            v-if="node.vuln_count > 0"
            :cx="node.x + layout.nodeWidth - 16"
            :cy="node.y + 16"
            r="10"
            fill="rgb(220 38 38 / 0.16)"
            stroke="rgb(239 68 68 / 0.55)"
          />
          <text
            v-if="node.vuln_count > 0"
            :x="node.x + layout.nodeWidth - 16"
            :y="node.y + 20"
            fill="rgb(248 113 113)"
            font-size="11"
            font-weight="700"
            text-anchor="middle"
          >
            {{ node.vuln_count > 99 ? '99+' : node.vuln_count }}
          </text>
        </g>
      </svg>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'

import type { ComponentGraph, ComponentGraphNode } from '@/api/client'
import { parsePurl } from '@/lib/purl'

const props = defineProps<{
  graph: ComponentGraph
  focusedRef?: string | null
}>()

const emit = defineEmits<{
  (event: 'select', purl: string): void
}>()

type LayoutNode = ComponentGraphNode & {
  label: string
  x: number
  y: number
  level: number
}

const viewportRef = ref<HTMLElement | null>(null)
const hoveredRef = ref<string | null>(null)

const MAX_RENDERED_NODES = 220
const MAX_RENDERED_DEPTH = 10
const NODE_WIDTH = 188
const NODE_HEIGHT = 48
const H_GAP = 88
const V_GAP = 20
const PADDING = 28

const layout = computed(() => {
  const nodesByRef = new Map(props.graph.nodes.map((node) => [node.ref, node]))
  const adjacency = buildAdjacency(props.graph, nodesByRef)
  const rootRef = pickRootRef(props.graph, nodesByRef)
  const levelMap = new Map<string, number>()
  const renderedRefs = collectRenderedRefs(adjacency, nodesByRef, rootRef, levelMap, props.focusedRef)
  const levels = groupNodesByLevel(renderedRefs, nodesByRef, levelMap)
  const renderedNodes = buildRenderedNodes(levels)
  const highlightedRefs = new Set<string>([props.focusedRef, hoveredRef.value].filter((ref): ref is string => Boolean(ref)))
  const renderedEdges = buildRenderedEdges(props.graph, renderedNodes, highlightedRefs)
  const maxLevel = Math.max(0, ...renderedNodes.map((node) => node.level))
  const maxRows = Math.max(1, ...Array.from(levels.values()).map((nodes) => nodes.length))

  return {
    renderedNodes,
    renderedEdges,
    rootRef,
    nodeWidth: NODE_WIDTH,
    nodeHeight: NODE_HEIGHT,
    width: PADDING * 2 + NODE_WIDTH + maxLevel * (NODE_WIDTH + H_GAP),
    height: PADDING * 2 + maxRows * (NODE_HEIGHT + V_GAP),
    truncated: props.graph.nodes.length > renderedRefs.size,
    renderedCount: renderedRefs.size,
  }
})

const summaryNote = computed(() => {
  if (props.graph.nodes.length === 0) {
    return 'Graph has no nodes for this ref.'
  }
  if (layout.value.truncated) {
    return `Graph is large. Showing ${layout.value.renderedCount} reachable nodes from the root.`
  }
  return ''
})

watch(
  () => props.focusedRef,
  async (focusedRef) => {
    if (!focusedRef) {
      return
    }

    await nextTick()
    const viewport = viewportRef.value
    const node = layout.value.renderedNodes.find((entry) => entry.ref === focusedRef)
    if (!viewport || !node) {
      return
    }

    viewport.scrollTo({
      left: Math.max(node.x - viewport.clientWidth / 2 + NODE_WIDTH / 2, 0),
      top: Math.max(node.y - viewport.clientHeight / 2 + NODE_HEIGHT / 2, 0),
      behavior: 'smooth',
    })
  },
  { immediate: true },
)

function displayLabel(node: ComponentGraphNode): string {
  return node.name || shortPurl(node.ref)
}

function shortPurl(purl: string): string {
  const parsed = parsePurl(purl)
  if (!parsed) {
    return purl.length > 36 ? `${purl.slice(0, 33)}...` : purl
  }
  return parsed.namespace ? `${parsed.namespace}/${parsed.name}` : parsed.name || purl
}

function truncateLabel(label: string, max: number): string {
  return label.length > max ? `${label.slice(0, max - 3)}...` : label
}

function nodeSubtitle(node: LayoutNode): string {
  if (node.ref === layout.value.rootRef) {
    return 'root component'
  }
  return node.version || shortPurl(node.ref)
}

function isActive(node: LayoutNode): boolean {
  return node.ref === props.focusedRef || node.ref === hoveredRef.value
}

function nodeFill(node: LayoutNode): string {
  if (node.ref === layout.value.rootRef) {
    return isActive(node) ? 'rgb(88 28 135 / 0.55)' : 'rgb(76 29 149 / 0.38)'
  }
  if (node.vuln_count > 0) {
    return isActive(node) ? 'rgb(127 29 29 / 0.65)' : 'rgb(127 29 29 / 0.42)'
  }
  return isActive(node) ? 'rgb(30 41 59 / 0.95)' : 'rgb(15 23 42 / 0.72)'
}

function nodeStroke(node: LayoutNode): string {
  if (node.ref === props.focusedRef) {
    return 'rgb(110 231 183)'
  }
  if (node.vuln_count > 0) {
    return 'rgb(248 113 113 / 0.7)'
  }
  if (node.ref === layout.value.rootRef) {
    return 'rgb(196 181 253 / 0.75)'
  }
  return 'rgb(100 116 139 / 0.6)'
}

function nodeStrokeWidth(node: LayoutNode): number {
  if (node.ref === props.focusedRef) {
    return 2.5
  }
  if (isActive(node)) {
    return 2
  }
  return 1.2
}

function buildAdjacency(graph: ComponentGraph, nodesByRef: Map<string, ComponentGraphNode>): Map<string, string[]> {
  const adjacency = new Map<string, string[]>()
  for (const edge of graph.edges) {
    adjacency.set(edge.ref, edge.depends_on.filter((child) => nodesByRef.has(child)))
  }
  return adjacency
}

function pickRootRef(graph: ComponentGraph, nodesByRef: Map<string, ComponentGraphNode>): string {
  if (graph.root_ref && nodesByRef.has(graph.root_ref)) {
    return graph.root_ref
  }
  return graph.nodes[0]?.ref ?? ''
}

function collectRenderedRefs(
  adjacency: Map<string, string[]>,
  nodesByRef: Map<string, ComponentGraphNode>,
  rootRef: string,
  levelMap: Map<string, number>,
  focusedRef?: string | null,
): Set<string> {
  const { queue, reachable } = initializeTraversal(rootRef, levelMap)

  while (queue.length > 0 && reachable.size < MAX_RENDERED_NODES) {
    const current = queue.shift()
    if (!current) {
      continue
    }

    const currentLevel = levelMap.get(current) ?? 0
    if (currentLevel >= MAX_RENDERED_DEPTH) {
      continue
    }

    visitChildren(current, currentLevel, adjacency, levelMap, queue, reachable)
  }

  if (focusedRef && nodesByRef.has(focusedRef)) {
    reachable.add(focusedRef)
    if (!levelMap.has(focusedRef)) {
      levelMap.set(focusedRef, Math.min(MAX_RENDERED_DEPTH + 1, Math.max(1, levelMap.size)))
    }
  }

  if (reachable.size > 0) {
    return reachable
  }

  return new Set(nodesByRef.keys())
}

function groupNodesByLevel(
  renderedRefs: Set<string>,
  nodesByRef: Map<string, ComponentGraphNode>,
  levelMap: Map<string, number>,
): Map<number, ComponentGraphNode[]> {
  const levels = new Map<number, ComponentGraphNode[]>()
  let fallbackCount = 0

  for (const ref of renderedRefs) {
    const node = nodesByRef.get(ref)
    if (!node || fallbackCount >= MAX_RENDERED_NODES) {
      continue
    }

    fallbackCount += 1
    const level = levelMap.get(ref) ?? 0
    const bucket = levels.get(level)
    if (bucket) {
      bucket.push(node)
      continue
    }
    levels.set(level, [node])
  }

  return levels
}

function buildRenderedNodes(levels: Map<number, ComponentGraphNode[]>): LayoutNode[] {
  const renderedNodes: LayoutNode[] = []
  const sortedLevels = Array.from(levels.entries()).sort((a, b) => a[0] - b[0])

  for (const [level, nodes] of sortedLevels) {
    nodes.sort((left, right) => {
      if (right.vuln_count !== left.vuln_count) {
        return right.vuln_count - left.vuln_count
      }
      return displayLabel(left).localeCompare(displayLabel(right))
    })

    nodes.forEach((node, index) => {
      renderedNodes.push({
        ...node,
        label: displayLabel(node),
        x: PADDING + level * (NODE_WIDTH + H_GAP),
        y: PADDING + index * (NODE_HEIGHT + V_GAP),
        level,
      })
    })
  }

  return renderedNodes
}

function buildRenderedEdges(graph: ComponentGraph, renderedNodes: LayoutNode[], highlightedRefs: Set<string>) {
  const positions = new Map(renderedNodes.map((node) => [node.ref, node]))

  return graph.edges.flatMap((edge) => {
    const parent = positions.get(edge.ref)
    if (!parent) {
      return []
    }

    return (edge.depends_on ?? []).flatMap((childRef) => {
      const child = positions.get(childRef)
      if (!child) {
        return []
      }
      const startX = parent.x + NODE_WIDTH
      const startY = parent.y + NODE_HEIGHT / 2
      const endX = child.x
      const endY = child.y + NODE_HEIGHT / 2
      const controlX = startX + Math.max((endX - startX) / 2, 24)
      return [{
        key: `${parent.ref}->${child.ref}`,
        path: `M ${startX} ${startY} C ${controlX} ${startY}, ${endX - 24} ${endY}, ${endX} ${endY}`,
        highlighted: highlightedRefs.has(parent.ref) || highlightedRefs.has(child.ref),
      }]
    })
  })
}

function initializeTraversal(rootRef: string, levelMap: Map<string, number>) {
  const queue: string[] = []
  const reachable = new Set<string>()

  if (!rootRef) {
    return { queue, reachable }
  }

  queue.push(rootRef)
  levelMap.set(rootRef, 0)
  reachable.add(rootRef)
  return { queue, reachable }
}

function visitChildren(
  currentRef: string,
  currentLevel: number,
  adjacency: Map<string, string[]>,
  levelMap: Map<string, number>,
  queue: string[],
  reachable: Set<string>,
) {
  for (const child of adjacency.get(currentRef) ?? []) {
    const nextLevel = currentLevel + 1
    syncLevel(levelMap, child, nextLevel)
    if (reachable.size >= MAX_RENDERED_NODES || reachable.has(child)) {
      continue
    }
    reachable.add(child)
    queue.push(child)
  }
}

function syncLevel(levelMap: Map<string, number>, childRef: string, nextLevel: number) {
  const knownLevel = levelMap.get(childRef)
  if (knownLevel === undefined || nextLevel < knownLevel) {
    levelMap.set(childRef, nextLevel)
  }
}
</script>