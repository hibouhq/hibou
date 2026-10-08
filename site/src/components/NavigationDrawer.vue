<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition-opacity duration-150"
      enter-from-class="opacity-0"
      leave-active-class="transition-opacity duration-150"
      leave-to-class="opacity-0"
    >
      <div
        v-if="open"
        class="fixed inset-0 z-[60] bg-black/50"
        aria-hidden="true"
        @click.self="close"
      />
    </Transition>
    <Transition
      enter-active-class="transition-transform duration-200 ease-out"
      enter-from-class="-translate-x-full"
      leave-active-class="transition-transform duration-150 ease-in"
      leave-to-class="-translate-x-full"
    >
      <aside
        v-if="open"
        id="navigation-drawer"
        ref="dialogRef"
        class="fixed bottom-0 left-0 top-0 z-[61] flex w-[19rem] max-w-[85vw] flex-col border-r border-surface-border bg-surface-raised shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-labelledby="navigation-drawer-title"
        @keydown="trapFocus"
      >
        <div class="flex items-center justify-between border-b border-surface-border-subtle px-4 py-3">
          <RouterLink
            id="navigation-drawer-title"
            to="/orgs"
            class="flex items-center gap-2 text-sm font-semibold text-white"
            @click="close"
          >
            <svg
              viewBox="0 0 32 32"
              class="h-6 w-6 text-accent"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
              aria-hidden="true"
            >
              <path
                d="M8 24V12L12 8L16 12L20 8L24 12V24L16 28L8 24Z"
                stroke="currentColor"
                stroke-width="2"
                stroke-linejoin="round"
              />
              <circle
                cx="13"
                cy="16"
                r="2"
                fill="currentColor"
              />
              <circle
                cx="19"
                cy="16"
                r="2"
                fill="currentColor"
              />
              <path
                d="M16 18L14.5 20H17.5L16 18Z"
                fill="currentColor"
              />
            </svg>
            Hibou
          </RouterLink>
          <button
            ref="closeButtonRef"
            class="rounded-md p-1.5 text-gray-400 transition hover:bg-surface-overlay hover:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
            type="button"
            aria-label="Close navigation menu"
            @click="close"
          >
            <X class="h-4 w-4" />
          </button>
        </div>

        <nav
          class="flex-1 overflow-y-auto px-2 py-3"
          aria-label="Navigation"
        >
          <template
            v-for="(section, sectionIndex) in sections"
            :key="section.title"
          >
            <div
              v-if="sectionIndex > 0"
              class="mx-2 my-2 border-t border-surface-border-subtle"
            />
            <div class="flex items-center gap-2 px-2 pb-1 pt-1.5">
              <component
                :is="section.titleIcon"
                v-if="section.titleIcon"
                class="h-3.5 w-3.5 shrink-0 text-gray-500"
              />
              <span class="truncate text-xs font-semibold text-gray-500">{{ section.title }}</span>
            </div>
            <RouterLink
              v-for="item in section.items"
              :key="item.to"
              :to="item.to"
              class="relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
              :class="isActive(item)
                ? 'bg-surface-overlay font-medium text-white before:absolute before:left-0 before:top-1/2 before:h-5 before:w-0.5 before:-translate-y-1/2 before:rounded-full before:bg-accent'
                : 'text-gray-300 hover:bg-surface-overlay/60 hover:text-white'"
              @click="close"
            >
              <component
                :is="item.icon"
                class="h-4 w-4 shrink-0"
                :class="isActive(item) ? 'text-accent' : 'text-gray-500'"
              />
              <span class="truncate">{{ item.label }}</span>
            </RouterLink>
          </template>
        </nav>
      </aside>
    </Transition>
  </Teleport>
</template>

<script setup lang="ts">
import type { Component } from 'vue'
import { nextTick, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { X } from 'lucide-vue-next'

export interface NavigationDrawerItem {
  label: string
  icon: Component
  to: string
}

export interface NavigationDrawerSection {
  title: string
  titleIcon?: Component
  items: NavigationDrawerItem[]
}

const props = defineProps<{
  open: boolean
  sections: NavigationDrawerSection[]
}>()

const emit = defineEmits<{ close: [] }>()
const route = useRoute()
const dialogRef = ref<HTMLElement | null>(null)
const closeButtonRef = ref<HTMLButtonElement | null>(null)
let previousFocus: HTMLElement | null = null
let previousOverflow = ''

watch(
  () => props.open,
  (isOpen) => {
    if (isOpen) {
      previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
      previousOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      void nextTick(() => closeButtonRef.value?.focus())
      return
    }

    const focusTarget = previousFocus
    document.body.style.overflow = previousOverflow
    previousFocus = null
    void nextTick(() => focusTarget?.focus())
  },
)

onBeforeUnmount(() => {
  if (props.open) document.body.style.overflow = previousOverflow
  previousFocus?.focus()
})

function close() {
  emit('close')
}

function isActive(item: NavigationDrawerItem) {
  if (item.to === '/settings') return route.path.startsWith('/settings')
  if (item.to === '/orgs') return route.path === '/orgs'
  return route.path === item.to || route.path.startsWith(`${item.to}/`)
}

function trapFocus(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    event.preventDefault()
    close()
    return
  }

  if (event.key !== 'Tab' || !dialogRef.value) return
  const focusable = Array.from(dialogRef.value.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )).filter((element) => !element.hasAttribute('hidden'))
  if (!focusable.length) return

  const first = focusable[0]
  const last = focusable[focusable.length - 1]
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault()
    last.focus()
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault()
    first.focus()
  }
}
</script>