<template>
  <div
    ref="containerRef"
    class="dep-graph-container"
  >
    <div class="dep-graph-toolbar">
      <input
        v-model="searchQuery"
        type="text"
        class="dep-filter-input"
        placeholder="Search dependency... (maven:name)"
        @keydown.enter="highlightSearch"
      >
      <button
        class="dep-graph-btn"
        title="Reset view"
        @click="resetView"
      >
        <svg
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
      </button>
      <button
        class="dep-graph-btn"
        title="Expand all visible"
        @click="expandAll"
      >
        <svg
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"
          />
        </svg>
      </button>
      <button
        class="dep-graph-btn"
        title="Collapse all"
        @click="collapseAll"
      >
        <svg
          class="h-4 w-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="2"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M9 9V4.5M9 9H4.5M9 9L3.75 3.75M9 15v4.5M9 15H4.5M9 15l-5.25 5.25M15 9h4.5M15 9V4.5M15 9l5.25-5.25M15 15h4.5M15 15v4.5m0-4.5l5.25 5.25"
          />
        </svg>
      </button>
      <span class="dep-graph-meta">
        <template v-if="searchMatchCount > 0">
          <span class="dep-graph-meta-accent">{{ searchMatchCount }} match{{ searchMatchCount > 1 ? 'es' : '' }}</span>
          <span> · </span>
        </template>
        {{ visibleNodeCount }} nodes · click to expand · double-click for details · scroll to zoom
      </span>
    </div>

    <svg
      ref="svgRef"
      class="dep-graph-svg"
      role="img"
      aria-label="Dependency graph"
    />

    <div
      v-if="tooltip.visible"
      class="dep-graph-tooltip"
      :style="{ left: `${tooltip.x}px`, top: `${tooltip.y}px` }"
    >
      <div class="dep-graph-tooltip-name">
        {{ tooltip.name }}
      </div>
      <div
        class="dep-graph-tooltip-row"
        :title="tooltip.version"
      >
        {{ truncateTooltipVersion(tooltip.version) }}
      </div>
      <div
        v-if="tooltip.ecosystem"
        class="dep-graph-tooltip-row dep-graph-tooltip-muted"
      >
        {{ tooltip.ecosystem }}
      </div>
      <div
        v-if="tooltip.vulns > 0"
        class="dep-graph-tooltip-row dep-graph-tooltip-critical"
      >
        {{ tooltip.vulns }} vulnerabilities
      </div>
      <div
        v-if="tooltip.children > 0"
        class="dep-graph-tooltip-row dep-graph-tooltip-muted"
      >
        {{ tooltip.children }} dependencies
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force'
import { drag as d3Drag } from 'd3-drag'
import { select } from 'd3-selection'
import 'd3-transition'
import { zoom as d3Zoom, zoomIdentity } from 'd3-zoom'

import type { ComponentGraph, ComponentGraphNode } from '@/api/client'
import { ecosystemKey, parsePurl } from '@/lib/purl'

interface DerivedNode extends ComponentGraphNode {
  childCount: number
}

interface DerivedGraph {
  edges: Map<string, string[]>
  ecosystems: Set<string>
  nodeMap: Map<string, DerivedNode>
  parentMap: Map<string, string>
  rootRef: string
}

interface GNode extends SimulationNodeDatum {
  id: string
  data: DerivedNode
  depth: number
  expanded: boolean
  highlighted: boolean
}

interface GLink extends SimulationLinkDatum<GNode> {
  source: GNode
  target: GNode
}

const props = defineProps<{
  graph: ComponentGraph
  focusedRef?: string | null
}>()

const emit = defineEmits<{
  (e: 'select', purl: string): void
}>()

const containerRef = ref<HTMLDivElement | null>(null)
const svgRef = ref<SVGSVGElement | null>(null)
const searchQuery = ref('')
const visibleNodeCount = ref(0)
const searchMatchCount = ref(0)
const tooltip = ref({
  visible: false,
  x: 0,
  y: 0,
  name: '',
  version: '',
  ecosystem: '',
  vulns: 0,
  children: 0,
})

const GRAPH_HEIGHT = 550
const TOOLBAR_HEIGHT = 44
const MAX_AUTO_EXPAND_MATCHES = 20

let derivedGraph = deriveGraph(props.graph)
let gNodes: GNode[] = []
let gLinks: GLink[] = []
let expandedSet = new Set<string>()
let searchHighlightedRefs = new Set<string>()
let activeFocusRef: string | null = null
let resizeObserver: ResizeObserver | null = null
let simulation: ReturnType<typeof forceSimulation<GNode>> | null = null
let svgG: ReturnType<typeof select<SVGGElement, unknown>> | null = null
let zoomBehavior: ReturnType<typeof d3Zoom<SVGSVGElement, unknown>> | null = null

function deriveGraph(graph: ComponentGraph): DerivedGraph {
  const nodeMap = new Map<string, DerivedNode>()

  for (const node of graph.nodes) {
    nodeMap.set(node.ref, { ...node, childCount: 0 })
  }

  const edges = new Map<string, string[]>()
  const parentMap = new Map<string, string>()
  const ecosystems = new Set<string>()

  for (const node of nodeMap.values()) {
    ecosystems.add(ecosystemKey(node.ecosystem))
  }

  for (const edge of graph.edges) {
    if (!nodeMap.has(edge.ref)) {
      continue
    }

    const children = (edge.depends_on ?? []).filter((childRef) => nodeMap.has(childRef))
    edges.set(edge.ref, children)

    const node = nodeMap.get(edge.ref)
    if (node) {
      node.childCount = children.length
    }

    for (const childRef of children) {
      if (!parentMap.has(childRef)) {
        parentMap.set(childRef, edge.ref)
      }
    }
  }

  const rootRef = nodeMap.has(graph.root_ref)
    ? graph.root_ref
    : (graph.nodes[0]?.ref ?? '')

  return {
    edges,
    ecosystems,
    nodeMap,
    parentMap,
    rootRef,
  }
}

function displayName(node: ComponentGraphNode): string {
  return node.name || shortRef(node.ref)
}

function shortRef(refValue: string): string {
  const parsed = parsePurl(refValue)
  if (!parsed) {
    return refValue.length > 36 ? `${refValue.slice(0, 33)}...` : refValue
  }
  return parsed.namespace ? `${parsed.namespace}/${parsed.name}` : parsed.name || refValue
}

function nodeRadius(node: GNode): number {
  if (node.depth === 0) {
    return 18
  }
  if (node.data.childCount > 50) {
    return 14
  }
  if (node.data.childCount > 10) {
    return 11
  }
  if (node.data.vuln_count > 0) {
    return 9
  }
  return 7
}

function hasHighlight(): boolean {
  return gNodes.some((node) => node.highlighted)
}

function nodeColor(node: GNode): string {
  if (hasHighlight() && !node.highlighted) {
    return '#2d333b'
  }
  if (node.data.vuln_count > 0) {
    return '#f85149'
  }
  if (node.depth <= 1) {
    return '#bc8cff'
  }
  if (node.data.childCount > 0 && !node.expanded) {
    return '#8b949e'
  }
  return '#3fb950'
}

function nodeStroke(node: GNode): string {
  if (node.highlighted) {
    return '#58a6ff'
  }
  if (node.expanded) {
    return '#58a6ff'
  }
  if (node.data.vuln_count > 0) {
    return '#f85149'
  }
  return 'transparent'
}

function normalizeNodeState(node: GNode) {
  node.expanded = expandedSet.has(node.id)
  node.highlighted = node.id === activeFocusRef || searchHighlightedRefs.has(node.id)
}

function buildGraph() {
  gNodes = []
  gLinks = []

  if (!derivedGraph.rootRef || !derivedGraph.nodeMap.has(derivedGraph.rootRef)) {
    visibleNodeCount.value = 0
    searchMatchCount.value = 0
    return
  }

  const nodeObj = new Map<string, GNode>()
  const queue: Array<{ depth: number; ref: string }> = [{ depth: 0, ref: derivedGraph.rootRef }]
  const included = new Set<string>([derivedGraph.rootRef])

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) {
      continue
    }

    const info = derivedGraph.nodeMap.get(current.ref)
    if (!info) {
      continue
    }

    const gNode: GNode = {
      id: current.ref,
      data: info,
      depth: current.depth,
      expanded: expandedSet.has(current.ref),
      highlighted: current.ref === activeFocusRef || searchHighlightedRefs.has(current.ref),
      x: undefined,
      y: undefined,
    }
    gNodes.push(gNode)
    nodeObj.set(current.ref, gNode)

    if (!expandedSet.has(current.ref)) {
      continue
    }

    for (const childRef of derivedGraph.edges.get(current.ref) ?? []) {
      if (included.has(childRef)) {
        continue
      }
      included.add(childRef)
      queue.push({ depth: current.depth + 1, ref: childRef })
    }
  }

  for (const node of gNodes) {
    if (!expandedSet.has(node.id)) {
      continue
    }

    for (const childRef of derivedGraph.edges.get(node.id) ?? []) {
      const childNode = nodeObj.get(childRef)
      if (childNode) {
        gLinks.push({ source: node, target: childNode })
      }
    }
  }

  visibleNodeCount.value = gNodes.length
  searchMatchCount.value = gNodes.filter((node) => node.highlighted).length
}

function runSimulation() {
  const width = containerRef.value?.clientWidth ?? 800
  const height = svgHeight()

  simulation?.stop()

  simulation = forceSimulation<GNode>(gNodes)
    .force(
      'link',
      forceLink<GNode, GLink>(gLinks)
        .id((node) => node.id)
        .distance((link) => {
          const source = link.source as GNode
          const target = link.target as GNode
          return 40 + nodeRadius(source) + nodeRadius(target)
        }),
    )
    .force('charge', forceManyBody<GNode>().strength((node) => (node.depth <= 1 ? -300 : -80)))
    .force('center', forceCenter(width / 2, height / 2))
    .force('collide', forceCollide<GNode>().radius((node) => nodeRadius(node) + 4))
    .alphaDecay(0.08)
    .alphaMin(0.01)
    .velocityDecay(0.4)
    .on('tick', render)
}

function render() {
  if (!svgG) {
    return
  }

  const highlightActive = hasHighlight()
  searchMatchCount.value = gNodes.filter((node) => node.highlighted).length

  const linkOpacityFor = (link: GLink) => {
    const source = link.source as GNode
    const target = link.target as GNode

    if (highlightActive) {
      return source.highlighted || target.highlighted ? 0.7 : 0.06
    }
    if (source.data.childCount > 100) {
      return 0.12
    }
    if (source.data.childCount > 30) {
      return 0.25
    }
    return 0.5
  }

  const linkSelection = svgG
    .selectAll<SVGLineElement, GLink>('line.dep-link')
    .data(gLinks, (link) => `${(link.source as GNode).id}-${(link.target as GNode).id}`)

  linkSelection.exit().remove()

  const mergedLinks = linkSelection.enter().append('line').attr('class', 'dep-link').merge(linkSelection)
  mergedLinks
    .attr('x1', (link) => (link.source as GNode).x ?? 0)
    .attr('y1', (link) => (link.source as GNode).y ?? 0)
    .attr('x2', (link) => (link.target as GNode).x ?? 0)
    .attr('y2', (link) => (link.target as GNode).y ?? 0)
    .attr('stroke-opacity', linkOpacityFor)

  const nodeSelection = svgG
    .selectAll<SVGGElement, GNode>('g.dep-node')
    .data(gNodes, (node) => node.id)

  nodeSelection.exit().remove()

  const nodeEnter = nodeSelection.enter().append('g').attr('class', 'dep-node').attr('cursor', 'pointer')
  nodeEnter.append('circle')
  nodeEnter.append('text').attr('class', 'dep-node-label')
  nodeEnter.append('text').attr('class', 'dep-node-badge')

  const nodeMerge = nodeEnter.merge(nodeSelection)

  nodeMerge.attr('transform', (node) => `translate(${node.x ?? 0},${node.y ?? 0})`)

  nodeMerge
    .select('circle')
    .attr('r', (node) => nodeRadius(node))
    .attr('fill', (node) => nodeColor(node))
    .attr('stroke', (node) => nodeStroke(node))
    .attr('stroke-width', (node) => {
      if (node.highlighted) {
        return 4
      }
      if (node.expanded || node.data.vuln_count > 0) {
        return 2
      }
      return 0
    })
    .attr('opacity', (node) => {
      if (node.highlighted) {
        return 1
      }
      if (highlightActive) {
        return 0.15
      }
      return 0.88
    })
    .attr('filter', (node) => (node.highlighted ? 'url(#highlight-glow)' : ''))

  nodeMerge
    .select('text.dep-node-label')
    .attr('dy', (node) => nodeRadius(node) + 12)
    .attr('text-anchor', 'middle')
    .attr('fill', (node) => {
      if (node.highlighted) {
        return '#58a6ff'
      }
      if (highlightActive) {
        return '#30363d'
      }
      return '#9ca3af'
    })
    .attr('font-size', (node) => (node.highlighted || node.depth <= 1 ? '11px' : '9px'))
    .attr('font-weight', (node) => (node.highlighted ? '700' : '400'))
    .text((node) => truncateLabel(displayName(node.data), 20))

  nodeMerge
    .select('text.dep-node-badge')
    .attr('dy', 4)
    .attr('text-anchor', 'middle')
    .attr('fill', '#ffffff')
    .attr('font-size', '8px')
    .attr('font-weight', '700')
    .text((node) => {
      if (!node.expanded && node.data.childCount > 0) {
        return `+${node.data.childCount}`
      }
      return ''
    })

  nodeMerge
    .on('click', (_event: MouseEvent, node: GNode) => {
      if (node.data.childCount > 0) {
        if (expandedSet.has(node.id)) {
          collapseNode(node.id)
        } else {
          expandedSet.add(node.id)
        }
        rebuild()
        return
      }
      emit('select', node.id)
    })
    .on('dblclick', (event: MouseEvent, node: GNode) => {
      event.preventDefault()
      emit('select', node.id)
    })
    .on('mouseenter', (event: MouseEvent, node: GNode) => {
      const rect = containerRef.value?.getBoundingClientRect()
      if (!rect) {
        return
      }

      tooltip.value = {
        visible: true,
        x: event.clientX - rect.left + 12,
        y: event.clientY - rect.top - 8,
        name: displayName(node.data),
        version: node.data.version,
        ecosystem: node.data.ecosystem,
        vulns: node.data.vuln_count,
        children: node.data.childCount,
      }
    })
    .on('mouseleave', () => {
      tooltip.value.visible = false
    })

  nodeMerge.call(
    d3Drag<SVGGElement, GNode>()
      .on('start', (event, node) => {
        if (!event.active) {
          simulation?.alphaTarget(0.3).restart()
        }
        node.fx = node.x
        node.fy = node.y
      })
      .on('drag', (event, node) => {
        node.fx = event.x
        node.fy = event.y
      })
      .on('end', (event, node) => {
        if (!event.active) {
          simulation?.alphaTarget(0)
        }
        node.fx = null
        node.fy = null
      }),
  )
}

function truncateLabel(value: string, max: number): string {
  if (value.length <= max) {
    return value
  }

  const lastSlash = value.lastIndexOf('/')
  if (lastSlash > 0 && lastSlash < value.length - 1) {
    const segment = value.slice(lastSlash + 1)
    if (segment.length <= max) {
      return segment
    }
    return `${segment.slice(0, max - 3)}...`
  }

  return `${value.slice(0, max - 3)}...`
}

function truncateTooltipVersion(value: string): string {
  if (!value) {
    return ''
  }

  const decoded = value.replace(/%3A/gi, ':')
  const shaMatch = decoded.match(/^(sha256:)([a-f0-9]+)$/i)
  if (shaMatch) {
    return `${shaMatch[1]}${shaMatch[2].slice(0, 12)}...`
  }
  if (decoded.length > 40) {
    return `${decoded.slice(0, 36)}...`
  }
  return decoded
}

function collapseNode(refValue: string) {
  expandedSet.delete(refValue)

  for (const childRef of derivedGraph.edges.get(refValue) ?? []) {
    if (expandedSet.has(childRef)) {
      collapseNode(childRef)
    }
  }
}

function resetZoom() {
  if (svgRef.value && zoomBehavior) {
    select(svgRef.value).call(zoomBehavior.transform, zoomIdentity)
  }
}

function resetExpansion() {
  expandedSet = new Set<string>()
  if (derivedGraph.rootRef) {
    expandedSet.add(derivedGraph.rootRef)
  }
}

function resetHighlights() {
  searchHighlightedRefs = new Set<string>()
  for (const node of gNodes) {
    node.highlighted = node.id === activeFocusRef
  }
}

function rebuild() {
  tooltip.value.visible = false
  buildGraph()
  runSimulation()
}

function resetView() {
  searchQuery.value = ''
  activeFocusRef = props.focusedRef ?? null
  resetExpansion()
  resetHighlights()
  rebuild()
  resetZoom()
}

function expandAll() {
  let changed = false

  for (const node of gNodes) {
    if (node.data.childCount > 0 && node.data.childCount <= 100 && !expandedSet.has(node.id)) {
      expandedSet.add(node.id)
      changed = true
    }
  }

  if (changed) {
    rebuild()
  }
}

function collapseAll() {
  resetExpansion()
  rebuild()
}

function parseSearch(rawQuery: string) {
  const raw = rawQuery.trim().toLowerCase()
  if (!raw) {
    return { ecosystem: '', query: '' }
  }

  const colonIndex = raw.indexOf(':')
  if (colonIndex > 0 && colonIndex < raw.length - 1) {
    const maybeEcosystem = ecosystemKey(raw.slice(0, colonIndex))
    if (derivedGraph.ecosystems.has(maybeEcosystem)) {
      return {
        ecosystem: maybeEcosystem,
        query: raw.slice(colonIndex + 1),
      }
    }
  }

  return { ecosystem: '', query: raw }
}

function matchesNode(node: ComponentGraphNode, query: string, ecosystem: string, exact: boolean) {
  if (!query) {
    return false
  }

  if (ecosystem && ecosystemKey(node.ecosystem) !== ecosystem) {
    return false
  }

  const haystack = node.name.toLowerCase()
  return exact ? haystack === query : haystack.includes(query)
}

function applyHighlights(query: string, ecosystem: string) {
  let matched = false
  const nextHighlights = new Set<string>()

  for (const node of gNodes) {
    if (matchesNode(node.data, query, ecosystem, true)) {
      nextHighlights.add(node.id)
      matched = true
    }
  }

  if (!matched && !ecosystem) {
    for (const node of gNodes) {
      if (matchesNode(node.data, query, ecosystem, false)) {
        nextHighlights.add(node.id)
        matched = true
      }
    }
  }

  searchHighlightedRefs = nextHighlights
  for (const node of gNodes) {
    normalizeNodeState(node)
  }
  render()
  return matched
}

function expandPathTo(refValue: string): boolean {
  if (!derivedGraph.nodeMap.has(refValue)) {
    return false
  }

  let current = refValue
  let foundPath = current === derivedGraph.rootRef

  while (current && current !== derivedGraph.rootRef) {
    const parentRef = derivedGraph.parentMap.get(current)
    if (!parentRef) {
      break
    }
    expandedSet.add(parentRef)
    current = parentRef
    foundPath = true
  }

  return foundPath
}

function zoomToNode(refValue: string, scale = 1.5) {
  const target = gNodes.find((node) => node.id === refValue)
  if (!target || !svgRef.value || !zoomBehavior || target.x == null || target.y == null) {
    return
  }

  const width = containerRef.value?.clientWidth ?? 800
  const height = svgHeight()
  const tx = width / 2 - target.x * scale
  const ty = height / 2 - target.y * scale

  select(svgRef.value)
    .transition()
    .duration(600)
    .call(zoomBehavior.transform, zoomIdentity.translate(tx, ty).scale(scale))
}

function highlightSearch() {
  const { ecosystem, query } = parseSearch(searchQuery.value)

  if (!query) {
    resetHighlights()
    render()
    return
  }

  const matchedVisible = applyHighlights(query, ecosystem)
  if (matchedVisible) {
    const firstMatch = Array.from(searchHighlightedRefs)[0]
    if (firstMatch) {
      zoomToNode(firstMatch)
    }
    return
  }

  const matches: string[] = []
  for (const [refValue, node] of derivedGraph.nodeMap.entries()) {
    if (matchesNode(node, query, ecosystem, true)) {
      matches.push(refValue)
    }
  }

  if (matches.length === 0 && !ecosystem) {
    for (const [refValue, node] of derivedGraph.nodeMap.entries()) {
      if (matchesNode(node, query, ecosystem, false)) {
        matches.push(refValue)
      }
    }
  }

  if (matches.length === 0) {
    resetHighlights()
    render()
    return
  }

  for (const refValue of matches.slice(0, MAX_AUTO_EXPAND_MATCHES)) {
    expandPathTo(refValue)
  }

  rebuild()

  nextTick(() => {
    if (applyHighlights(query, ecosystem)) {
      const firstMatch = Array.from(searchHighlightedRefs)[0]
      if (firstMatch) {
        zoomToNode(firstMatch)
      }
    }
  })
}

function svgHeight() {
  return Math.max((containerRef.value?.clientHeight ?? GRAPH_HEIGHT) - TOOLBAR_HEIGHT, 240)
}

function initSvg() {
  if (!svgRef.value || !containerRef.value) {
    return
  }

  const svg = select(svgRef.value)
  svg.attr('width', containerRef.value.clientWidth).attr('height', svgHeight())
  svg.selectAll('*').remove()

  const defs = svg.append('defs')
  const glow = defs
    .append('filter')
    .attr('id', 'highlight-glow')
    .attr('x', '-50%')
    .attr('y', '-50%')
    .attr('width', '200%')
    .attr('height', '200%')

  glow
    .append('feDropShadow')
    .attr('dx', 0)
    .attr('dy', 0)
    .attr('stdDeviation', 4)
    .attr('flood-color', '#58a6ff')
    .attr('flood-opacity', 0.75)

  defs
    .append('marker')
    .attr('id', 'dep-arrow')
    .attr('viewBox', '0 -3 6 6')
    .attr('refX', 12)
    .attr('refY', 0)
    .attr('markerWidth', 4)
    .attr('markerHeight', 4)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-3L6,0L0,3')
    .attr('fill', '#6e7681')

  svgG = svg.append('g')

  zoomBehavior = d3Zoom<SVGSVGElement, unknown>()
    .scaleExtent([0.1, 5])
    .on('zoom', (event) => {
      svgG?.attr('transform', event.transform)
    })

  svg.call(zoomBehavior)
}

async function focusRef(refValue: string | null | undefined) {
  activeFocusRef = refValue ?? null

  if (!activeFocusRef || !derivedGraph.nodeMap.has(activeFocusRef)) {
    for (const node of gNodes) {
      normalizeNodeState(node)
    }
    render()
    return
  }

  expandPathTo(activeFocusRef)
  rebuild()
  await nextTick()

  for (const node of gNodes) {
    normalizeNodeState(node)
  }
  render()
  zoomToNode(activeFocusRef)
}

function syncGraphState() {
  derivedGraph = deriveGraph(props.graph)
  resetExpansion()
  if (props.focusedRef && derivedGraph.nodeMap.has(props.focusedRef)) {
    expandPathTo(props.focusedRef)
  }
  activeFocusRef = props.focusedRef ?? null
  searchHighlightedRefs = new Set<string>()
  initSvg()
  rebuild()
}

onMounted(() => {
  syncGraphState()

  if (containerRef.value) {
    resizeObserver = new ResizeObserver(() => {
      initSvg()
      rebuild()
      if (activeFocusRef) {
        zoomToNode(activeFocusRef, 1.5)
      }
    })
    resizeObserver.observe(containerRef.value)
  }
})

onBeforeUnmount(() => {
  resizeObserver?.disconnect()
  simulation?.stop()
})

watch(
  () => props.graph,
  async () => {
    searchQuery.value = ''
    syncGraphState()
    if (props.focusedRef) {
      await focusRef(props.focusedRef)
    }
  },
)

watch(
  () => props.focusedRef,
  async (nextRef) => {
    await focusRef(nextRef)
  },
  { immediate: true },
)
</script>

<style scoped>
.dep-graph-container {
  position: relative;
  width: 100%;
  height: 550px;
  overflow: hidden;
  border: 1px solid #30363d;
  border-radius: 0.75rem;
  background: #0d1117;
}

.dep-graph-toolbar {
  position: relative;
  z-index: 2;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0.75rem;
  border-bottom: 1px solid #30363d;
  background: #1c2128;
}

.dep-filter-input {
  width: 100%;
  max-width: 240px;
  padding: 0.4rem 0.65rem;
  border: 1px solid #30363d;
  border-radius: 0.5rem;
  background: #161b22;
  color: #e6edf3;
  font-size: 0.75rem;
  outline: none;
}

.dep-filter-input::placeholder {
  color: #9ca3af;
}

.dep-filter-input:focus {
  border-color: #58a6ff;
  box-shadow: 0 0 0 1px #58a6ff;
}

.dep-graph-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 1.75rem;
  height: 1.75rem;
  border: 1px solid #30363d;
  border-radius: 0.5rem;
  background: transparent;
  color: #9ca3af;
  cursor: pointer;
  transition: all 0.15s ease;
}

.dep-graph-btn:hover {
  border-color: #58a6ff;
  background: #161b22;
  color: #58a6ff;
}

.dep-graph-meta {
  margin-left: auto;
  color: #9ca3af;
  font-size: 0.6875rem;
}

.dep-graph-meta-accent {
  color: #58a6ff;
}

.dep-graph-svg {
  display: block;
  width: 100%;
  height: calc(100% - 44px);
}

.dep-graph-svg :deep(line.dep-link) {
  stroke: #6e7681;
  stroke-width: 0.75;
  stroke-opacity: 0.5;
  marker-end: url(#dep-arrow);
}

.dep-graph-svg :deep(text.dep-node-label),
.dep-graph-svg :deep(text.dep-node-badge) {
  pointer-events: none;
  user-select: none;
  font-family: ui-sans-serif, system-ui, sans-serif;
}

.dep-graph-tooltip {
  position: absolute;
  z-index: 50;
  min-width: 160px;
  max-width: 320px;
  padding: 0.5rem 0.75rem;
  border: 1px solid #30363d;
  border-radius: 0.75rem;
  background: #1c2128;
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
  pointer-events: none;
}

.dep-graph-tooltip-name {
  margin-bottom: 0.25rem;
  color: #e6edf3;
  font-size: 0.8125rem;
  font-weight: 600;
  line-height: 1.3;
  overflow-wrap: break-word;
  word-break: break-word;
}

.dep-graph-tooltip-row {
  margin-bottom: 0.125rem;
  color: #9ca3af;
  font-size: 0.6875rem;
}

.dep-graph-tooltip-muted {
  color: #9ca3af;
}

.dep-graph-tooltip-critical {
  color: #f85149;
}
</style>
