import { readonly, ref } from 'vue'

export type ToastTone = 'success' | 'error' | 'info'

export interface ToastItem {
  id: string
  title: string
  description?: string
  tone: ToastTone
}

const toasts = ref<ToastItem[]>([])

let toastSequence = 0

function dismiss(id: string) {
  toasts.value = toasts.value.filter((toast) => toast.id !== id)
}

function pushToast(input: {
  title: string
  description?: string
  tone?: ToastTone
  duration?: number
}) {
  const id = `toast-${Date.now()}-${toastSequence++}`
  toasts.value = [...toasts.value, {
    id,
    title: input.title,
    description: input.description,
    tone: input.tone ?? 'info',
  }]

  const duration = input.duration ?? 4200
  if (typeof window !== 'undefined') {
    window.setTimeout(() => dismiss(id), duration)
  }

  return id
}

export function useToast() {
  return {
    toasts: readonly(toasts),
    dismiss,
    pushToast,
    success(title: string, description?: string, duration?: number) {
      return pushToast({ title, description, duration, tone: 'success' })
    },
    error(title: string, description?: string, duration?: number) {
      return pushToast({ title, description, duration, tone: 'error' })
    },
    info(title: string, description?: string, duration?: number) {
      return pushToast({ title, description, duration, tone: 'info' })
    },
  }
}