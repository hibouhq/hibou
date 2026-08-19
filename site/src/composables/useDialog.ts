import { readonly, ref } from 'vue'

// Promise-based replacement for window.confirm / window.prompt. Singleton
// state rendered by DialogHost (mounted once in App.vue), same pattern as
// useToast + ToastViewport. Native dialogs are banned in this codebase: they
// are unstyled, blocking, and browsers offer to suppress them.

export type DialogTone = 'default' | 'danger'

export interface DialogOptions {
  title: string
  message?: string
  confirmLabel?: string
  cancelLabel?: string
  tone?: DialogTone
  /** Type-to-confirm: the confirm button stays disabled until the user types this exact string. */
  requireText?: string
  /** Free-text input (window.prompt replacement). `required` keeps confirm disabled while empty. */
  input?: { label: string; placeholder?: string; required?: boolean }
}

interface DialogResult {
  confirmed: boolean
  value: string
}

interface ActiveDialog extends DialogOptions {
  id: number
  resolve: (result: DialogResult) => void
}

const active = ref<ActiveDialog | null>(null)

let dialogSequence = 0

function open(options: DialogOptions): Promise<DialogResult> {
  // A dialog opening over another cancels the first: dialogs are user-driven,
  // so overlap only happens when a stale handler fires late.
  active.value?.resolve({ confirmed: false, value: '' })
  return new Promise<DialogResult>((resolve) => {
    active.value = { ...options, id: dialogSequence++, resolve }
  })
}

function settle(result: DialogResult) {
  const dialog = active.value
  if (!dialog) return
  active.value = null
  dialog.resolve(result)
}

export function useDialog() {
  return {
    active: readonly(active),
    settle,
    /** Resolves true when confirmed, false when dismissed. */
    async confirmDialog(options: DialogOptions): Promise<boolean> {
      const result = await open(options)
      return result.confirmed
    },
    /** Resolves the typed text when confirmed, null when dismissed. */
    async promptDialog(options: DialogOptions & { input: NonNullable<DialogOptions['input']> }): Promise<string | null> {
      const result = await open(options)
      return result.confirmed ? result.value : null
    },
  }
}
