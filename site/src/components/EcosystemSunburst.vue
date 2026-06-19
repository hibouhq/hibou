<template>
  <div class="flex flex-col items-center gap-3">
    <svg
      :viewBox="`0 0 ${size} ${size}`"
      class="max-w-full"
      :style="{ width: `${size}px`, height: `${size}px` }"
      role="img"
      aria-label="Dependency breakdown by ecosystem"
    >
      <!-- Outer ring: namespaces / packages -->
      <path
        v-for="seg in outerSegments"
        :key="`outer-${seg.id}`"
        :d="seg.path"
        :fill="seg.color"
        :opacity="hoverId === null || hoverId === seg.id || hoverId === seg.ecoId ? 1 : 0.35"
        class="cursor-pointer transition-opacity"
        @mouseenter="hoverId = seg.id; hoverLabel = seg.label; hoverCount = seg.count"
        @mouseleave="clearHover"
        @click="$emit('select', seg.ecosystem)"
      />
      <!-- Inner ring: ecosystems -->
      <path
        v-for="seg in innerSegments"
        :key="`inner-${seg.id}`"
        :d="seg.path"
        :fill="seg.color"
        :opacity="hoverId === null || hoverId === seg.id ? 1 : 0.45"
        class="cursor-pointer transition-opacity"
        @mouseenter="hoverId = seg.id; hoverLabel = seg.label; hoverCount = seg.count"
        @mouseleave="clearHover"
        @click="$emit('select', seg.ecosystem)"
      />
      <!-- Inner ring labels -->
      <text
        v-for="seg in innerLabels"
        :key="`label-${seg.id}`"
        :x="seg.x"
        :y="seg.y"
        text-anchor="middle"
        dominant-baseline="middle"
        class="pointer-events-none select-none fill-white/90 text-[9px] font-medium"
      >{{ seg.short }}</text>

      <!-- Center -->
      <circle
        :cx="center"
        :cy="center"
        :r="innerRadius - 4"
        fill="#0d1117"
        stroke="#21262d"
      />
      <text
        :x="center"
        :y="center - 7"
        text-anchor="middle"
        class="pointer-events-none select-none fill-gray-400 text-[10px] uppercase tracking-[0.14em]"
      >{{ hoverLabel || 'Dependencies' }}</text>
      <text
        :x="center"
        :y="center + 12"
        text-anchor="middle"
        class="pointer-events-none select-none fill-white text-lg font-semibold"
      >{{ hoverCount !== null ? hoverCount : total }}</text>
    </svg>

    <!-- Legend -->
    <div class="flex flex-wrap items-center justify-center gap-x-4 gap-y-1.5">
      <button
        v-for="eco in legend"
        :key="eco.id"
        type="button"
        class="flex items-center gap-1.5 text-xs text-gray-400 transition hover:text-gray-100"
        @mouseenter="hoverId = eco.id; hoverLabel = eco.label; hoverCount = eco.count"
        @mouseleave="clearHover"
        @click="$emit('select', eco.ecosystem)"
      >
        <span
          class="h-2.5 w-2.5 shrink-0 rounded-sm"
          :style="{ backgroundColor: eco.color }"
        />
        <span>{{ eco.label }}</span>
        <span class="text-gray-600">{{ eco.count }}</span>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'

import type { ComponentWithVulns } from '@/api/client'
import { ecosystemKey, parsePurl } from '@/lib/purl'

const props = defineProps<{
  components: ComponentWithVulns[]
}>()

defineEmits<{
  (event: 'select', ecosystem: string): void
}>()

const size = 300
const center = size / 2
const innerRadius = 52
const midRadius = 96
const outerRadius = 142

const hoverId = ref<string | null>(null)
const hoverLabel = ref('')
const hoverCount = ref<number | null>(null)

function clearHover() {
  hoverId.value = null
  hoverLabel.value = ''
  hoverCount.value = null
}

const ECO_COLORS: Record<string, string> = {
  maven: '#e6550d',
  npm: '#3fb950',
  pypi: '#58a6ff',
  nuget: '#bc8cff',
  golang: '#79c0ff',
  cargo: '#f0883e',
  gem: '#f85149',
  deb: '#d6336c',
  rpm: '#dbab55',
  oci: '#6e96b4',
  unknown: '#8b949e',
}

function colorFor(eco: string): string {
  return ECO_COLORS[ecosystemKey(eco)] ?? '#8b949e'
}

interface EcoGroup {
  ecosystem: string
  key: string
  label: string
  count: number
  children: Array<{ label: string; count: number }>
}

const total = computed(() => props.components.length)

const groups = computed<EcoGroup[]>(() => {
  const byEco = new Map<string, EcoGroup>()

  for (const component of props.components) {
    const key = ecosystemKey(component.ecosystem)
    let group = byEco.get(key)
    if (!group) {
      group = { ecosystem: component.ecosystem || key, key, label: key, count: 0, children: [] }
      byEco.set(key, group)
    }
    group.count += 1

    const parsed = parsePurl(component.purl)
    const childLabel = parsed?.namespace || parsed?.name || component.name || '—'
    const existing = group.children.find((child) => child.label === childLabel)
    if (existing) {
      existing.count += 1
    } else {
      group.children.push({ label: childLabel, count: 1 })
    }
  }

  return Array.from(byEco.values()).sort((a, b) => b.count - a.count)
})

const legend = computed(() => groups.value.map((group) => ({
  id: `eco-${group.key}`,
  ecosystem: group.ecosystem,
  label: group.label,
  count: group.count,
  color: colorFor(group.ecosystem),
})))

function polarToCartesian(radius: number, angle: number) {
  return {
    x: center + radius * Math.cos(angle - Math.PI / 2),
    y: center + radius * Math.sin(angle - Math.PI / 2),
  }
}

function arcPath(rInner: number, rOuter: number, startAngle: number, endAngle: number) {
  const largeArc = endAngle - startAngle > Math.PI ? 1 : 0
  const p1 = polarToCartesian(rOuter, startAngle)
  const p2 = polarToCartesian(rOuter, endAngle)
  const p3 = polarToCartesian(rInner, endAngle)
  const p4 = polarToCartesian(rInner, startAngle)

  return [
    `M ${p1.x} ${p1.y}`,
    `A ${rOuter} ${rOuter} 0 ${largeArc} 1 ${p2.x} ${p2.y}`,
    `L ${p3.x} ${p3.y}`,
    `A ${rInner} ${rInner} 0 ${largeArc} 0 ${p4.x} ${p4.y}`,
    'Z',
  ].join(' ')
}

interface Segment {
  id: string
  ecoId: string
  ecosystem: string
  label: string
  short: string
  count: number
  color: string
  path: string
  mid: number
}

const layout = computed(() => {
  const inner: Segment[] = []
  const outer: Segment[] = []
  const grandTotal = total.value || 1
  let angle = 0

  for (const group of groups.value) {
    const sweep = (group.count / grandTotal) * Math.PI * 2
    const start = angle
    const end = angle + sweep
    const ecoId = `eco-${group.key}`
    const baseColor = colorFor(group.ecosystem)

    inner.push({
      id: ecoId,
      ecoId,
      ecosystem: group.ecosystem,
      label: group.label,
      short: shortLabel(group.label),
      count: group.count,
      color: baseColor,
      path: arcPath(innerRadius, midRadius, start, end),
      mid: (start + end) / 2,
    })

    // outer ring: children sorted, sized within the eco sweep
    const sortedChildren = [...group.children].sort((a, b) => b.count - a.count)
    let childAngle = start
    for (let i = 0; i < sortedChildren.length; i++) {
      const child = sortedChildren[i]
      const childSweep = (child.count / group.count) * sweep
      outer.push({
        id: `${ecoId}-${i}`,
        ecoId,
        ecosystem: group.ecosystem,
        label: `${group.label} / ${child.label}`,
        short: '',
        count: child.count,
        color: baseColor,
        path: arcPath(midRadius + 2, outerRadius, childAngle, childAngle + childSweep),
        mid: (childAngle + childAngle + childSweep) / 2,
      })
      childAngle += childSweep
    }

    angle = end
  }

  return { inner, outer }
})

const innerSegments = computed(() => layout.value.inner)
const outerSegments = computed(() => layout.value.outer)

const innerLabels = computed(() => layout.value.inner
  .filter((seg) => (seg.count / (total.value || 1)) > 0.05)
  .map((seg) => {
    const point = polarToCartesian((innerRadius + midRadius) / 2, seg.mid)
    return { id: seg.id, x: point.x, y: point.y, short: seg.short }
  }))

function shortLabel(label: string): string {
  return label.length > 8 ? `${label.slice(0, 7)}…` : label
}
</script>
