import { computed, readonly, ref } from 'vue'

import { api, type SearchPreset, type SearchPresetSurface } from '@/api/client'

// One cache per surface for the session: the repo and org lists share the
// findings presets, so switching between them must not refetch or diverge.
const presetsBySurface = ref<Partial<Record<SearchPresetSurface, SearchPreset[]>>>({})
const pending = new Map<SearchPresetSurface, Promise<void>>()
let generation = 0

// Presets are personal: a sign-out must not leave them for the next session.
export function resetSearchPresets() {
  generation += 1
  presetsBySurface.value = {}
  pending.clear()
}

function sortByName(presets: SearchPreset[]) {
  return [...presets].sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
}

export function useSearchPresets(surface: SearchPresetSurface) {
  const loadError = ref('')

  function set(presets: SearchPreset[]) {
    presetsBySurface.value = { ...presetsBySurface.value, [surface]: sortByName(presets) }
  }

  function current() {
    return presetsBySurface.value[surface] ?? []
  }

  async function load() {
    if (presetsBySurface.value[surface]) return
    let request = pending.get(surface)
    if (!request) {
      const requestGeneration = generation
      const inFlight: Promise<void> = api.listSearchPresets(surface)
        .then((response) => {
          if (requestGeneration === generation) set(response.data)
        })
        .finally(() => {
          if (pending.get(surface) === inFlight) pending.delete(surface)
        })
      pending.set(surface, inFlight)
      request = inFlight
    }
    try {
      loadError.value = ''
      await request
    } catch (error) {
      loadError.value = error instanceof Error ? error.message : 'Failed to load presets'
    }
  }

  async function create(name: string, query: string) {
    const response = await api.createSearchPreset({ surface, name, query })
    set([...current(), response.data])
    return response.data
  }

  async function update(id: string, name: string, query: string) {
    const response = await api.updateSearchPreset(id, { name, query })
    set(current().map(preset => preset.id === id ? response.data : preset))
    return response.data
  }

  async function remove(id: string) {
    await api.deleteSearchPreset(id)
    set(current().filter(preset => preset.id !== id))
  }

  return {
    presets: computed(() => current()),
    loadError: readonly(loadError),
    load,
    create,
    update,
    remove,
  }
}
