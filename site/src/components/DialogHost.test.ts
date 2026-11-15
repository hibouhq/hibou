import { describe, expect, it } from 'vitest'
import { createSSRApp } from 'vue'
import { renderToString } from 'vue/server-renderer'

import { useDialog, type DialogOptions } from '@/composables/useDialog'
import DialogHost from './DialogHost.vue'

async function renderDialog(options: DialogOptions) {
  const { confirmDialog, settle } = useDialog()
  const result = confirmDialog(options)
  const context: { teleports?: Record<string, string> } = {}
  try {
    await renderToString(createSSRApp(DialogHost), context)
    expect(context.teleports?.body).toBeDefined()
    return context.teleports!.body
  } finally {
    settle({ confirmed: false, value: '' })
    await result
  }
}

describe('destructive acknowledgement', () => {
  it('is unchecked and blocks confirmation even without a text requirement', async () => {
    const html = await renderDialog({
      title: 'Delete repository and history?',
      requiredAcknowledgement: 'Permanently delete inactive deployment history.',
    })
    const checkbox = html.match(/<input[^>]*type="checkbox"[^>]*>/)?.[0]
    expect(checkbox).toBeDefined()
    expect(checkbox).not.toContain('checked')
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*\sdisabled(?:\s|=|>)/)
    expect(html).toContain('Permanently delete inactive deployment history.')
  })

  it('preserves normal confirmations without requiring an acknowledgement', async () => {
    const html = await renderDialog({ title: 'Normal confirmation' })
    expect(html).not.toContain('type="checkbox"')
    expect(html).not.toMatch(/<button[^>]*type="submit"[^>]*\sdisabled(?:\s|=|>)/)
  })

  it('retains the existing type-to-confirm safeguard', async () => {
    const html = await renderDialog({
      title: 'Remove repository',
      requireText: 'fixture-repository',
      requiredAcknowledgement: 'Delete inactive history.',
    })
    expect(html).toContain('fixture-repository')
    expect(html).toMatch(/<button[^>]*type="submit"[^>]*\sdisabled(?:\s|=|>)/)
  })
})
