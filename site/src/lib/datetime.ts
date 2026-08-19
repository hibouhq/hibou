// Shared date helpers. One implementation of "3 hours ago" for the whole app.

export function relativeTime(input: string) {
  const target = new Date(input)
  if (Number.isNaN(target.getTime())) {
    return 'unknown'
  }
  const diffSeconds = Math.round((target.getTime() - Date.now()) / 1000)
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const abs = Math.abs(diffSeconds)
  if (abs >= 86400) {
    return formatter.format(Math.round(diffSeconds / 86400), 'day')
  }
  if (abs >= 3600) {
    return formatter.format(Math.round(diffSeconds / 3600), 'hour')
  }
  if (abs >= 60) {
    return formatter.format(Math.round(diffSeconds / 60), 'minute')
  }
  return formatter.format(diffSeconds, 'second')
}

// Compact duration for job run/wait times: "840ms", "4.2s", "3m 12s", "2h 05m".
export function formatDuration(seconds: number) {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return '—'
  }
  if (seconds < 1) {
    return `${Math.round(seconds * 1000)}ms`
  }
  if (seconds < 60) {
    return `${seconds < 10 ? seconds.toFixed(1) : Math.round(seconds)}s`
  }
  if (seconds < 3600) {
    return `${Math.floor(seconds / 60)}m ${String(Math.round(seconds % 60)).padStart(2, '0')}s`
  }
  return `${Math.floor(seconds / 3600)}h ${String(Math.floor((seconds % 3600) / 60)).padStart(2, '0')}m`
}

export function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(value))
}
