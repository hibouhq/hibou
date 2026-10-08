<template>
  <div class="h-72">
    <Line
      :data="data"
      :options="options"
      aria-label="Risk observations over time"
    />
  </div>
</template>

<script setup lang="ts">
import { Chart as ChartJS, type ChartData, type ChartOptions, Filler, Legend, LineElement, LinearScale, PointElement, Tooltip } from 'chart.js'
import { Line } from 'vue-chartjs'
import { computed } from 'vue'

import { countForMetric, type InsightMetric, type InsightPoint } from '@/lib/insights'

ChartJS.register(Filler, Legend, LineElement, LinearScale, PointElement, Tooltip)

const props = defineProps<{ points: InsightPoint[]; metric: InsightMetric }>()
const emit = defineEmits<{ select: [snapshotId: string] }>()

function formatDate(value: number) {
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short' }).format(new Date(value))
}

const data = computed<ChartData<'line', { x: number; y: number }[]>>(() => ({
  datasets: [{
    label: props.metric === 'vulnerabilities' ? 'Dependency vulnerabilities' : 'Code findings',
    data: props.points.map((point) => ({ x: point.timestamp, y: countForMetric(point, props.metric) })),
    borderColor: props.metric === 'vulnerabilities' ? '#f0a44b' : '#58a6ff',
    backgroundColor: props.metric === 'vulnerabilities' ? '#f0a44b22' : '#58a6ff22',
    fill: true,
    tension: 0.15,
    pointRadius: props.points.length === 1 ? 5 : 3,
    pointHoverRadius: 6,
  }],
}))

const options = computed<ChartOptions<'line'>>(() => ({
  responsive: true,
  maintainAspectRatio: false,
  interaction: { intersect: true, mode: 'nearest' },
  onClick: (_event, elements) => {
    const index = elements[0]?.index
    if (index !== undefined) emit('select', props.points[index].snapshot_id)
  },
  scales: {
    x: { type: 'linear', grid: { color: '#21262d' }, ticks: { color: '#8b949e', maxTicksLimit: 5, callback: (value) => new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' }).format(new Date(Number(value))) } },
    y: { beginAtZero: true, grid: { color: '#21262d' }, ticks: { color: '#8b949e', precision: 0 }, title: { display: true, text: 'Findings', color: '#8b949e' } },
  },
  plugins: { legend: { display: false }, tooltip: { callbacks: { title: (items) => formatDate(items[0]?.parsed.x ?? 0), label: (item) => `${item.dataset.label}: ${item.parsed.y}` } } },
}))
</script>