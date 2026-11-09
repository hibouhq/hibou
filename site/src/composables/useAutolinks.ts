import { ref, type Ref } from 'vue'

import { api } from '@/api/client'
import type { Autolink } from '@/lib/autolink'

// The organisation's autolink references, fetched once per org and shared by
// every Autolinked text on the page. `invalidate` after the settings change.
const cache = new Map<string, Ref<Autolink[]>>()

export function useAutolinks(provider: string, slug: string): Ref<Autolink[]> {
  const key = `${provider}/${slug}`
  const existing = cache.get(key)
  if (existing) return existing
  const links = ref<Autolink[]>([])
  cache.set(key, links)
  void load(provider, slug, links)
  return links
}

export function invalidateAutolinks(provider: string, slug: string) {
  const entry = cache.get(`${provider}/${slug}`)
  if (entry) void load(provider, slug, entry)
}

async function load(provider: string, slug: string, target: Ref<Autolink[]>) {
  try {
    const response = await api.listAutolinks(provider, slug)
    target.value = response.data.map(row => ({ prefix: row.prefix, url_template: row.url_template, alphanumeric: row.alphanumeric }))
  } catch {
    // Without the list, text stays plain; nothing else depends on it.
  }
}
