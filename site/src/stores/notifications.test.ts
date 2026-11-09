import { createPinia, setActivePinia } from 'pinia'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { api, type Notification } from '@/api/client'
import { useNotificationsStore } from '@/stores/notifications'

function notification(id: number, status: Notification['status'] = 'unread'): Notification {
  return {
    id: String(id),
    type: 'finding.new',
    title: 'New vulnerability',
    body: 'A new vulnerability was detected',
    link: '/repos/example',
    status,
    created_at: '2026-11-09T12:00:00Z',
  }
}

describe('notification counts', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it.each([82, 130])('preserves the full total of %i when opening the latest 30 items and refreshing', async (count) => {
    vi.spyOn(api, 'getUnreadNotificationCount').mockResolvedValue({ data: { count } })
    const list = vi.spyOn(api, 'listNotifications').mockResolvedValue({
      data: Array.from({ length: 30 }, (_, index) => notification(index)),
      pagination: { page: 1, per_page: 30, total: count },
    })
    const store = useNotificationsStore()

    await store.fetchUnreadCount()
    await store.fetchItems()
    expect(store.items).toHaveLength(30)
    expect(store.unreadCount).toBe(count)
    expect(list).toHaveBeenCalledWith({ per_page: 30 })

    await store.fetchItems()
    expect(list).toHaveBeenCalledTimes(1)
    expect(store.unreadCount).toBe(count)

    setActivePinia(createPinia())
    const refreshedStore = useNotificationsStore()
    await refreshedStore.fetchUnreadCount()
    await refreshedStore.fetchItems()
    expect(refreshedStore.unreadCount).toBe(count)
  })

  it('does not replace the total with the unread subset of a mixed page', async () => {
    vi.spyOn(api, 'listNotifications').mockResolvedValue({
      data: [notification(1), notification(2, 'read')],
      pagination: { page: 1, per_page: 30, total: 100 },
    })
    const store = useNotificationsStore()
    store.unreadCount = 50

    await store.fetchItems()

    expect(store.unreadCount).toBe(50)
  })

  it('decrements the full total only once when an item is read', async () => {
    const markRead = vi.spyOn(api, 'markNotificationRead').mockResolvedValue({ data: notification(1, 'read') })
    const store = useNotificationsStore()
    store.unreadCount = 130
    store.items = [notification(1)]

    await store.markRead('1')
    await store.markRead('1')

    expect(store.unreadCount).toBe(129)
    expect(store.items[0].status).toBe('read')
    expect(markRead).toHaveBeenCalledTimes(1)
  })

  it('restores the total and item when marking it read fails', async () => {
    vi.spyOn(api, 'markNotificationRead').mockRejectedValue(new Error('Request failed'))
    const store = useNotificationsStore()
    store.unreadCount = 130
    store.items = [notification(1)]

    await store.markRead('1')

    expect(store.unreadCount).toBe(130)
    expect(store.items[0].status).toBe('unread')
  })

  it.each([
    { name: 'empty', items: [] },
    { name: 'already read', items: [notification(1, 'read')] },
  ])('marks all read even when the loaded page is $name', async ({ items }) => {
    const markAllRead = vi.spyOn(api, 'markAllNotificationsRead').mockResolvedValue({ data: { updated: 50 } })
    const store = useNotificationsStore()
    store.unreadCount = 50
    store.items = items

    await store.markAllRead()

    expect(markAllRead).toHaveBeenCalledOnce()
    expect(store.unreadCount).toBe(0)
  })

  it('clears the full total and loaded items when marking all read', async () => {
    vi.spyOn(api, 'markAllNotificationsRead').mockResolvedValue({ data: { updated: 130 } })
    const store = useNotificationsStore()
    store.unreadCount = 130
    store.items = [notification(1), notification(2, 'read')]

    await store.markAllRead()

    expect(store.unreadCount).toBe(0)
    expect(store.items.every((item) => item.status === 'read')).toBe(true)
  })

  it('restores the full total and item statuses when marking all read fails', async () => {
    vi.spyOn(api, 'markAllNotificationsRead').mockRejectedValue(new Error('Request failed'))
    const store = useNotificationsStore()
    store.unreadCount = 130
    store.items = [notification(1), notification(2, 'read')]

    await store.markAllRead()

    expect(store.unreadCount).toBe(130)
    expect(store.items.map((item) => item.status)).toEqual(['unread', 'read'])
  })

  it.each([
    [0, '0'],
    [30, '30'],
    [98, '98'],
    [99, '99'],
    [100, '+99'],
    [130, '+99'],
  ])('formats %i unread notifications as %s', (count, label) => {
    const store = useNotificationsStore()
    store.unreadCount = count

    expect(store.unreadCountLabel).toBe(label)
  })
})
