import { defineStore } from 'pinia'
import { onScopeDispose, ref } from 'vue'

import { api, type Notification } from '@/api/client'
import { type GateUpdatedPayload, useGateEventsStore } from '@/stores/gateEvents'

const MAX_RECONNECT_MS = 30_000

export const useNotificationsStore = defineStore('notifications', () => {
  const gateEvents = useGateEventsStore()
  const unreadCount = ref(0)
  const items = ref<Notification[]>([])
  const loading = ref(false)
  // Reactive WS connection state; consumers (e.g. the PR gate page) use it to fall
  // back to polling only while the live channel is down.
  const connected = ref(false)
  let hasFetched = false
  let ws: WebSocket | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
  let reconnectAttempt = 0
  let shouldReconnect = true

  function buildWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${protocol}//${window.location.host}/api/v1/ws`
  }

  async function fetchUnreadCount() {
    try {
      const res = await api.getUnreadNotificationCount()
      unreadCount.value = res.data.count
    } catch {
      unreadCount.value = 0
    }
  }

  async function fetchItems(force = false) {
    if (loading.value || (hasFetched && !force)) {
      return
    }

    loading.value = true
    try {
      const res = await api.listNotifications({ per_page: 30 })
      items.value = res.data
      unreadCount.value = res.data.filter((item) => item.status === 'unread').length
      hasFetched = true
    } catch {
      // leave existing items in place on failure
    } finally {
      loading.value = false
    }
  }

  async function markRead(id: string) {
    const target = items.value.find((item) => item.id === id)
    if (!target || target.status === 'read') {
      return
    }

    target.status = 'read'
    unreadCount.value = Math.max(0, unreadCount.value - 1)
    try {
      await api.markNotificationRead(id)
    } catch {
      target.status = 'unread'
      unreadCount.value += 1
    }
  }

  async function markAllRead() {
    if (items.value.every((item) => item.status === 'read')) {
      return
    }

    const snapshot = items.value.map((item) => item.status)
    const previousCount = unreadCount.value
    items.value.forEach((item) => { item.status = 'read' })
    unreadCount.value = 0
    try {
      await api.markAllNotificationsRead()
    } catch {
      items.value.forEach((item, index) => { item.status = snapshot[index] })
      unreadCount.value = previousCount
    }
  }

  function clearReconnectTimer() {
    if (reconnectTimer === null) {
      return
    }

    clearTimeout(reconnectTimer)
    reconnectTimer = null
  }

  function scheduleReconnect() {
    if (!shouldReconnect || reconnectTimer !== null) {
      return
    }

    const delay = Math.min(2 ** reconnectAttempt * 1000, MAX_RECONNECT_MS)
    reconnectAttempt += 1
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      connect()
    }, delay)
  }

  function handleMessage(event: MessageEvent<string>) {
    let message: { type?: string; payload?: unknown }

    try {
      message = JSON.parse(event.data) as { type?: string; payload?: unknown }
    } catch {
      return
    }

    if (message.type === 'notification.new') {
      unreadCount.value += 1
      // Invalidate cached list so the next panel open pulls the new item.
      hasFetched = false
      return
    }

    if (message.type === 'gate.updated' && message.payload) {
      // Fan out to the gate-events store so PR gate views can refresh live.
      gateEvents.record(message.payload as GateUpdatedPayload)
    }
  }

  function connect() {
    shouldReconnect = true

    if (ws !== null && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
      return
    }

    clearReconnectTimer()

    const socket = new WebSocket(buildWebSocketUrl())
    ws = socket

    socket.addEventListener('open', () => {
      if (ws !== socket) {
        return
      }

      reconnectAttempt = 0
      connected.value = true
      socket.send(
        JSON.stringify({
          type: 'topic.subscribe',
          payload: {
            topics: ['notification.new', 'gate.updated'],
          },
        }),
      )
      void fetchUnreadCount()
    })

    socket.addEventListener('message', handleMessage)

    socket.addEventListener('error', () => {
      if (ws !== socket) {
        return
      }

      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
        socket.close()
      }
    })

    socket.addEventListener('close', () => {
      if (ws === socket) {
        ws = null
        connected.value = false
      }

      scheduleReconnect()
    })
  }

  function disconnect() {
    shouldReconnect = false
    clearReconnectTimer()
    reconnectAttempt = 0
    connected.value = false

    if (ws === null) {
      return
    }

    const socket = ws
    ws = null
    socket.close()
  }

  onScopeDispose(() => {
    disconnect()
  })

  return { unreadCount, items, loading, connected, fetchUnreadCount, fetchItems, markRead, markAllRead, connect, disconnect }
})
