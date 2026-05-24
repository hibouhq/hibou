import { defineStore } from 'pinia'
import { onScopeDispose, ref } from 'vue'

import { api } from '@/api/client'

const MAX_RECONNECT_MS = 30_000

export const useNotificationsStore = defineStore('notifications', () => {
  const unreadCount = ref(0)
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
      socket.send(
        JSON.stringify({
          type: 'topic.subscribe',
          payload: {
            topics: ['notification.new'],
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
      }

      scheduleReconnect()
    })
  }

  function disconnect() {
    shouldReconnect = false
    clearReconnectTimer()
    reconnectAttempt = 0

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

  return { unreadCount, fetchUnreadCount, connect, disconnect }
})
