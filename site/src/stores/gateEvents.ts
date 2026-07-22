import { defineStore } from 'pinia'
import { ref } from 'vue'

// Payload broadcast by the server whenever a PR quality gate check updates
// (scan complete, VEX dismissal, override, base-branch move). Field names match
// the server-side JSON (snake_case). Delivered over the shared notifications
// WebSocket under the `gate.updated` message type.
export interface GateUpdatedPayload {
  provider: string
  org_slug: string
  repo_slug: string
  pr_number: string
  head_sha: string
  state: string
  passed: boolean
}

// Bridges `gate.updated` WebSocket messages (recorded by the notifications
// store, which owns the app's single WS) to any component that wants to react
// live. `version` bumps on every event so watchers fire even when consecutive
// payloads are structurally equal.
export const useGateEventsStore = defineStore('gateEvents', () => {
  const lastEvent = ref<GateUpdatedPayload | null>(null)
  const version = ref(0)

  function record(payload: GateUpdatedPayload) {
    lastEvent.value = payload
    version.value += 1
  }

  return { lastEvent, version, record }
})
