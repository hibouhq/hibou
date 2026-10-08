<template>
  <div
    ref="rootRef"
    class="space-y-3"
  >
    <div class="relative">
      <div
        class="relative rounded-md border bg-surface-overlay transition-colors focus-within:ring-1 focus-within:ring-inset"
        :class="validationIssues.length > 0
          ? 'border-amber-500/60 focus-within:border-amber-400 focus-within:ring-amber-400'
          : 'border-surface-border focus-within:border-accent focus-within:ring-accent'"
        @click="focusInput"
      >
        <div
          aria-hidden="true"
          class="pointer-events-none absolute inset-0 flex items-center overflow-hidden px-3 py-[5px] pr-10 text-sm"
        >
          <div
            v-if="barQuery"
            class="whitespace-pre"
            :style="{ transform: `translateX(-${inputScrollLeft}px)` }"
          >
            <template
              v-for="(segment, index) in displaySegments"
              :key="`${index}-${segment.text}`"
            >
              <span :class="segment.className">{{ segment.text }}</span>
            </template>
          </div>
        </div>

        <input
          ref="inputRef"
          v-model="barQuery"
          :placeholder="placeholderText"
          type="text"
          spellcheck="false"
          autocomplete="off"
          role="combobox"
          :aria-expanded="showAutocomplete"
          aria-haspopup="listbox"
          aria-autocomplete="list"
          aria-controls="filterbar-autocomplete"
          :aria-activedescendant="showAutocomplete ? autocompleteOptionId(activeAutocompleteIndex) : undefined"
          :aria-invalid="validationIssues.length > 0"
          :aria-describedby="validationIssues.length > 0 ? 'filterbar-issues' : undefined"
          class="relative z-10 w-full bg-transparent px-3 py-[5px] pr-10 text-sm text-transparent caret-gray-100 placeholder:text-gray-500 focus:outline-none focus-visible:shadow-none"
          @focus="handleInputFocus"
          @blur="handleInputBlur"
          @click="updateCursorPosition"
          @input="handleInputEvent"
          @keyup="handleCursorKeyup"
          @keydown="handleInputKeydown"
          @scroll="syncInputScroll"
          @mousemove="syncInputScroll"
          @select="syncInputScroll"
        >

        <button
          v-if="showClearButton"
          class="group absolute right-2 top-1/2 z-20 inline-flex h-5 w-5 -translate-y-1/2 items-center justify-center rounded-full border border-gray-500 text-gray-400 transition hover:border-gray-300 hover:text-gray-100"
          type="button"
          title="Clear filter"
          aria-label="Clear filter"
          @mousedown.prevent
          @click.stop="clearAll"
        >
          <svg
            class="h-3 w-3"
            fill="none"
            viewBox="0 0 12 12"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
          >
            <path d="M2 2l8 8M10 2l-8 8" />
          </svg>
        </button>
      </div>

      <Transition
        enter-active-class="transition duration-150 ease-out"
        enter-from-class="translate-y-1 opacity-0"
        enter-to-class="translate-y-0 opacity-100"
        leave-active-class="transition duration-100 ease-in"
        leave-from-class="translate-y-0 opacity-100"
        leave-to-class="translate-y-1 opacity-0"
      >
        <div
          v-if="showAutocomplete"
          class="absolute top-[calc(100%+0.5rem)] z-40 w-72 max-w-full overflow-hidden rounded-lg border border-surface-border bg-surface-raised shadow-lg"
          :style="{ left: `${autocompleteLeft}px` }"
        >
          <div
            id="filterbar-autocomplete"
            role="listbox"
            class="max-h-72 overflow-y-auto py-1"
          >
            <button
              v-for="(item, index) in autocompleteItems"
              :id="autocompleteOptionId(index)"
              :key="autocompleteItemKey(item, index)"
              role="option"
              :aria-selected="index === activeAutocompleteIndex"
              class="flex w-full items-center gap-3 px-3 py-2 text-left text-sm transition"
              :class="index === activeAutocompleteIndex ? 'bg-accent-muted text-accent' : 'text-gray-300 hover:bg-surface-overlay hover:text-gray-100'"
              type="button"
              @mousedown.prevent
              @mouseenter="activeAutocompleteIndex = index"
              @click="selectAutocomplete(item)"
            >
              <span
                v-if="item.type === 'key'"
                class="flex h-5 min-w-5 shrink-0 items-center justify-center rounded px-1 text-[10px] font-semibold uppercase tracking-[0.08em] text-gray-500"
                :class="index === activeAutocompleteIndex ? 'text-accent/70' : ''"
              >{{ filterKeyBadge(item.key) }}</span>
              <span class="min-w-0 truncate font-medium">{{ item.primary }}</span>
              <span class="ml-auto shrink-0 text-xs text-gray-500">{{ item.secondary }}</span>
            </button>
          </div>
        </div>
      </Transition>
    </div>

    <ul
      v-if="validationIssues.length > 0"
      id="filterbar-issues"
      role="alert"
      class="-mt-1 space-y-0.5 px-1 text-xs text-amber-300"
    >
      <li
        v-for="issue in validationIssues"
        :key="issue.id"
        class="flex items-start gap-1.5"
      >
        <TriangleAlert
          class="mt-px h-3.5 w-3.5 shrink-0"
          aria-hidden="true"
        />
        <span>
          <template
            v-for="(part, index) in issue.parts"
            :key="`${issue.id}-${index}`"
          >
            <span :class="part.className">{{ part.text }}</span>
          </template>
        </span>
      </li>
    </ul>

    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="flex flex-wrap items-start gap-2">
        <div
          v-for="filter in filters.filter(filter => !filter.hidden || filter.primary || filter.control === 'boolean')"
          :key="filter.key"
          class="relative"
        >
          <button
            v-if="filter.control === 'boolean'"
            type="button"
            class="inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-40"
            :class="modelValue[filter.key] === 'true'
              ? filter.tone === 'danger' ? 'border-danger/60 bg-danger/10 text-danger' : 'border-accent/40 bg-accent-muted text-accent'
              : 'border-surface-border bg-surface-raised text-gray-400 hover:text-gray-100'"
            :aria-pressed="modelValue[filter.key] === 'true'"
            :disabled="advancedActive"
            :title="advancedActive ? 'Edit qualifiers directly while the query uses OR or parentheses' : filter.description || filter.label"
            @click="toggleBooleanFilter(filter)"
          >
            <component
              :is="filter.toggleIcon"
              v-if="filter.toggleIcon"
              class="h-3.5 w-3.5"
              aria-hidden="true"
            />
            {{ filter.label }}
          </button>
          <button
            v-else
            class="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition disabled:cursor-not-allowed disabled:opacity-40"
            :class="[
              isFilterMenuOpen(filter.key) || hasFilterSelection(filter.key)
                ? 'border-accent/40 bg-accent-muted text-accent'
                : 'border-surface-border bg-surface-raised text-gray-300 hover:border-surface-border-subtle hover:text-gray-100',
              filter.primary ? 'ring-1 ring-accent/20' : '',
            ]"
            type="button"
            aria-haspopup="true"
            :aria-expanded="isFilterMenuOpen(filter.key)"
            :disabled="advancedActive"
            :title="advancedActive ? 'Dropdowns are disabled while the query uses OR or parentheses — edit the query directly' : undefined"
            @click.stop="toggleFilterMenu(filter.key)"
          >
            <span>{{ filter.label }}</span>
            <span class="text-xs">▾</span>
          </button>

          <Transition
            enter-active-class="transition duration-150 ease-out"
            enter-from-class="translate-y-1 opacity-0"
            enter-to-class="translate-y-0 opacity-100"
            leave-active-class="transition duration-100 ease-in"
            leave-from-class="translate-y-0 opacity-100"
            leave-to-class="translate-y-1 opacity-0"
          >
            <div
              v-if="filter.control !== 'boolean' && isFilterMenuOpen(filter.key)"
              class="absolute left-0 top-[calc(100%+0.5rem)] z-30 w-72 overflow-hidden rounded-lg border border-surface-border bg-surface-raised shadow-lg"
            >
              <div class="border-b border-surface-border-subtle px-3 py-2.5 text-sm font-medium text-gray-100">
                Filter by {{ filter.label }}
              </div>

              <div class="border-b border-surface-border-subtle p-3">
                <input
                  :value="dropdownSearch[filter.key] ?? ''"
                  :placeholder="`Filter ${filter.label.toLowerCase()}s`"
                  type="text"
                  class="w-full rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-sm text-gray-100 placeholder:text-gray-500 focus:border-accent/60 focus:outline-none"
                  @input="setDropdownSearch(filter.key, ($event.target as HTMLInputElement).value)"
                >
              </div>

              <div class="max-h-80 overflow-y-auto px-3 py-3">
                <div class="space-y-2">
                  <div
                    v-if="filteredOptionsFor(filter).length === 0"
                    class="rounded-md border border-dashed border-surface-border-subtle px-3 py-4 text-sm text-gray-500"
                  >
                    No matching options.
                  </div>
                  <button
                    v-for="option in visibleSuggestionsFor(filter)"
                    :key="`option-${filter.key}-${option}`"
                    role="option"
                    :aria-selected="getSelectedValues(filter).includes(option)"
                    class="flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left text-sm transition hover:bg-surface-overlay"
                    :class="getSelectedValues(filter).includes(option) ? 'text-gray-100' : 'text-gray-300 hover:text-gray-100'"
                    type="button"
                    @click="toggleFilterOption(filter, option)"
                  >
                    <span
                      class="flex h-4 w-4 items-center justify-center rounded border text-[10px] font-bold"
                      :class="getSelectedValues(filter).includes(option)
                        ? 'border-accent bg-accent text-surface'
                        : 'border-surface-border text-transparent'"
                    >✓</span>
                    <span class="min-w-0 truncate">{{ option }}</span>
                    <span
                      v-if="optionCount(filter, option) !== undefined"
                      class="ml-auto shrink-0 rounded-full border border-surface-border-subtle px-1.5 py-0.5 text-[10px] font-semibold tabular-nums"
                      :class="optionCount(filter, option) === 0 ? 'text-gray-600' : 'text-gray-400'"
                    >{{ optionCount(filter, option) }}</span>
                  </button>
                  <button
                    v-if="hasMoreSuggestions(filter)"
                    class="mt-2 w-full rounded-md px-2 py-1.5 text-center text-xs text-gray-400 transition hover:bg-surface-overlay hover:text-gray-200"
                    type="button"
                    @click="showMoreSuggestions(filter.key)"
                  >
                    Show {{ showMoreCount(filter) }} more...
                  </button>
                </div>
              </div>
            </div>
          </Transition>
        </div>
      </div>

      <!-- Trailing controls supplied by the host view (e.g. the exploited
           toggle): visually part of the filter row, right of the facet pills. -->
      <slot name="trailing" />

      <div
        v-if="hasSortOptions"
        class="relative ml-auto"
      >
        <button
          class="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition"
          :class="isSortMenuOpen
            ? 'border-accent/40 bg-accent-muted text-accent'
            : 'border-surface-border bg-surface-raised text-gray-300 hover:border-surface-border-subtle hover:text-gray-100'"
          type="button"
          aria-haspopup="true"
          :aria-expanded="isSortMenuOpen"
          @click.stop="toggleSortMenu"
        >
          <span>{{ sortButtonLabel }}</span>
          <span class="text-xs">▾</span>
        </button>

        <Transition
          enter-active-class="transition duration-150 ease-out"
          enter-from-class="translate-y-1 opacity-0"
          enter-to-class="translate-y-0 opacity-100"
          leave-active-class="transition duration-100 ease-in"
          leave-from-class="translate-y-0 opacity-100"
          leave-to-class="translate-y-1 opacity-0"
        >
          <div
            v-if="isSortMenuOpen"
            class="absolute right-0 top-[calc(100%+0.5rem)] z-30 w-56 overflow-hidden rounded-lg border border-surface-border bg-surface-raised shadow-lg"
          >
            <div class="px-3 py-2.5 text-xs font-medium tracking-[0.12em] text-gray-500">
              Sort by
            </div>
            <div
              role="listbox"
              class="py-1"
            >
              <button
                v-for="option in sortOptions"
                :key="option.key"
                role="option"
                :aria-selected="option.key === sortValue"
                class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition"
                :class="option.key === sortValue ? 'bg-accent-muted text-accent' : 'text-gray-300 hover:bg-surface-overlay hover:text-gray-100'"
                type="button"
                @click="selectSort(option.key)"
              >
                <span>{{ option.label }}</span>
                <span v-if="option.key === sortValue">✓</span>
                <span
                  v-else
                  class="text-transparent"
                >✓</span>
              </button>
            </div>

            <template v-if="showSortDirectionControls">
              <div class="mx-3 my-1 border-t border-surface-border-subtle" />
              <div class="px-3 py-2.5 text-xs font-medium tracking-[0.12em] text-gray-500">
                Order
              </div>
              <div
                role="listbox"
                class="py-1"
              >
                <button
                  v-for="option in sortDirectionOptions"
                  :key="option.key"
                  role="option"
                  :aria-selected="option.key === sortDirection"
                  class="flex w-full items-center justify-between px-3 py-2 text-left text-sm transition"
                  :class="option.key === sortDirection ? 'bg-accent-muted text-accent' : 'text-gray-300 hover:bg-surface-overlay hover:text-gray-100'"
                  type="button"
                  :disabled="!hasActiveSort"
                  @click="selectSortDirection(option.key)"
                >
                  <span>{{ option.label }}</span>
                  <span v-if="option.key === sortDirection">✓</span>
                  <span
                    v-else
                    class="text-transparent"
                  >✓</span>
                </button>
              </div>
            </template>
          </div>
        </Transition>
      </div>
    </div>

    <div
      v-if="showCountText"
      class="px-1 text-sm text-gray-400"
    >
      Showing {{ filteredCount }} / {{ totalCount }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch, type Component } from 'vue'
import { TriangleAlert } from 'lucide-vue-next'

import type { DisplaySegment, ValidationIssue } from '@/lib/filterBarQuery'
import {
  buildBarQuery,
  highlightBarQuery,
  isConnectiveWord,
  getCursorContext,
  parseBarQuery,
} from '@/lib/filterBarQuery'

interface FilterDef {
  key: string
  label: string
  options: string[]
  multi?: boolean
  icon?: string
  freeform?: boolean
  hidden?: boolean
  defaultValue?: string
  primary?: boolean
  control?: 'select' | 'boolean'
  toggleIcon?: Component
  tone?: 'accent' | 'danger'
  description?: string
  onToggle?: (enabled: boolean) => void
}

interface SortDef {
  key: string
  label: string
  ascLabel?: string
  descLabel?: string
}

type OpenMenu =
  | { type: 'filter'; key: string }
  | { type: 'sort' }
  | null

type AutocompleteItem =
  | { type: 'key'; key: string; primary: string; secondary: string }
  | { type: 'value'; key: string; value: string; primary: string; secondary: string }
  | { type: 'operator'; value: string; primary: string; secondary: string }

const props = withDefaults(defineProps<{
  filters: FilterDef[]
  searchable?: boolean
  sortOptions?: SortDef[]
  sortDirectionOptions?: SortDef[]
  totalCount?: number
  filteredCount?: number
  // Per-option result counts, keyed by filter key then option value. When
  // provided, each option shows a badge with the number of results it matches.
  counts?: Record<string, Record<string, number>>
  placeholder?: string
}>(), {
  searchable: true,
  sortOptions: undefined,
  sortDirectionOptions: undefined,
  totalCount: undefined,
  filteredCount: undefined,
  counts: undefined,
  placeholder: 'Filter findings...',
})

defineEmits<{
  (event: 'update:modelValue', value: Record<string, string>): void
  (event: 'update:searchQuery', value: string): void
  (event: 'update:sortValue', value: string): void
}>()

const modelValue = defineModel<Record<string, string>>({ default: () => ({}) })
const searchQuery = defineModel<string>('searchQuery', { default: '' })
// Set (and the discrete models left untouched) while the bar holds an OR /
// parenthesised query; empty in plain mode.
const advancedQuery = defineModel<string>('advancedQuery', { default: '' })
function toggleBooleanFilter(filter: FilterDef) {
  const enabled = modelValue.value[filter.key] !== 'true'
  if (filter.onToggle) {
    filter.onToggle(enabled)
    return
  }
  const next = { ...modelValue.value }
  if (enabled) next[filter.key] = 'true'
  else delete next[filter.key]
  modelValue.value = next
}
const sortValue = defineModel<string>('sortValue', { default: '' })
const sortDirection = defineModel<string>('sortDirection', { default: '' })

const rootRef = ref<HTMLElement | null>(null)
const inputRef = ref<HTMLInputElement | null>(null)
const barQuery = ref('')
const inputScrollLeft = ref(0)
const cursorPosition = ref(0)
const inputFocused = ref(false)
const openMenu = ref<OpenMenu>(null)
const dropdownSearch = ref<Record<string, string>>({})
const visibleSuggestionCounts = ref<Record<string, number>>({})
const validationIssues = ref<ValidationIssue[]>([])
const activeAutocompleteIndex = ref(0)
const syncingFromBar = ref(false)

let validationTimer: ReturnType<typeof setTimeout> | null = null

const filterMap = computed(() => {
  return new Map(props.filters.map((filter) => [filter.key.toLowerCase(), filter]))
})

const sortOptions = computed(() => props.sortOptions ?? [])
const sortDirectionOptions = computed(() => props.sortDirectionOptions ?? [])
const hasSortOptions = computed(() => sortOptions.value.length > 0)
const hasSortDirectionOptions = computed(() => sortDirectionOptions.value.length > 0)
const hasActiveSort = computed(() => sortValue.value.length > 0)
const showSortDirectionControls = computed(() => hasSortDirectionOptions.value && hasActiveSort.value)
const placeholderText = computed(() => props.placeholder)
const isSortMenuOpen = computed(() => openMenu.value?.type === 'sort')
const showClearButton = computed(() => barQuery.value.trim().length > 0 || hasActiveSort.value)
const showCountText = computed(() => typeof props.totalCount === 'number' && typeof props.filteredCount === 'number')
const sortButtonLabel = computed(() => {
  if (!hasActiveSort.value) {
    const first = sortOptions.value[0]
    return first ? `↕ ${first.label}` : '↕'
  }
  const activeOption = sortOptions.value.find((o) => o.key === sortValue.value)
  const isAsc = sortDirection.value === 'asc'
  const arrow = isAsc ? '↑' : '↓'
  const label = (isAsc ? activeOption?.ascLabel : activeOption?.descLabel) ?? activeOption?.label ?? sortValue.value
  return `${arrow} ${label}`
})

const parsedBarQuery = computed(() => parseBarQuery(barQuery.value, props.filters, props.searchable))
const cursorContext = computed(() => getCursorContext(barQuery.value, cursorPosition.value))

const autocompleteItems = computed<AutocompleteItem[]>(() => {
  if (!inputFocused.value || isSortMenuOpen.value || openMenu.value?.type === 'filter') {
    return []
  }

  const context = cursorContext.value
  const keyItems = (keyQuery: string): AutocompleteItem[] => props.filters
    .filter((filter) => keyQuery === '' || filter.key.toLowerCase().includes(keyQuery) || filter.label.toLowerCase().includes(keyQuery))
    .map((filter) => ({
      type: 'key' as const,
      key: filter.key,
      primary: `${filter.key}:`,
      secondary: filter.label,
    }))
  // Connectives are offered only where the grammar allows one: after a
  // completed condition or a closing paren, never at the start, after an
  // opening paren, or after another connective.
  const operatorItems = (keyQuery: string): AutocompleteItem[] => {
    const before = barQuery.value.slice(0, context?.start ?? cursorPosition.value).trimEnd()
    const lastWord = before.match(/[^\s()]+$|\)$/)?.[0] ?? ''
    if (!lastWord || lastWord === '(' || isConnectiveWord(lastWord)) {
      return []
    }
    return ['and', 'or']
      .filter((word) => keyQuery === '' || word.startsWith(keyQuery))
      .map((word) => ({
        type: 'operator' as const,
        value: word,
        primary: word,
        secondary: word === 'and' ? 'both conditions' : 'either condition',
      }))
  }

  if (!context || !context.token) {
    return [...operatorItems(''), ...keyItems('')]
  }

  const separatorIndex = context.token.indexOf(':')
  if (separatorIndex === -1) {
    const keyQuery = context.token.toLowerCase()
    return [...operatorItems(keyQuery), ...keyItems(keyQuery)]
  }

  const key = context.token.slice(0, separatorIndex).toLowerCase()
  const filter = filterMap.value.get(key)
  if (!filter) {
    return []
  }

  const rawValue = context.token.slice(separatorIndex + 1)
  const splitValues = filter.multi ? rawValue.split(',') : [rawValue]
  const currentFragment = splitValues[splitValues.length - 1]?.trim().toLowerCase() ?? ''
  const selectedValues = filter.multi
    ? splitValues.slice(0, -1).map((value) => value.trim().toLowerCase()).filter(Boolean)
    : []

  const candidates = filter.options
    .filter((option) => !selectedValues.includes(option.toLowerCase()))
    .filter((option) => currentFragment.length === 0 || option.toLowerCase().includes(currentFragment))

  // For freeform filters with mixed granularity options (e.g. file paths
  // and file:line entries), show coarse options first. Only include fine-
  // grained options (containing ':') when few coarse matches remain or the
  // typed fragment already narrows to a specific coarse match.
  let visibleCandidates = candidates
  if (filter.freeform) {
    const coarse = candidates.filter((o) => !o.includes(':'))
    const fine = candidates.filter((o) => o.includes(':'))
    if (coarse.length > 3 || (coarse.length > 0 && currentFragment.length === 0)) {
      visibleCandidates = coarse
    } else {
      visibleCandidates = [...coarse, ...fine]
    }
  }

  return visibleCandidates
    .slice(0, 20)
    .map((option) => ({
      type: 'value',
      key: filter.key,
      value: option,
      primary: option,
      secondary: filter.label,
    }))
})

const showAutocomplete = computed(() => autocompleteItems.value.length > 0)

// The suggestion list opens under the word being completed, like GitHub's
// search, instead of at the far left of the bar.
const autocompleteLeft = ref(0)
const AUTOCOMPLETE_WIDTH_PX = 288
let measureCanvas: HTMLCanvasElement | null = null

function updateAutocompleteLeft() {
  const input = inputRef.value
  if (!input) return
  measureCanvas ??= document.createElement('canvas')
  const context = measureCanvas.getContext('2d')
  if (!context) return
  const style = getComputedStyle(input)
  context.font = `${style.fontStyle} ${style.fontWeight} ${style.fontSize} ${style.fontFamily}`
  const anchor = cursorContext.value?.start ?? cursorPosition.value
  const textWidth = context.measureText(barQuery.value.slice(0, anchor)).width
  const left = parseFloat(style.paddingLeft) + textWidth - input.scrollLeft
  const maxLeft = Math.max(0, input.clientWidth - AUTOCOMPLETE_WIDTH_PX)
  autocompleteLeft.value = Math.round(Math.min(Math.max(0, left), maxLeft))
}

watch([showAutocomplete, () => cursorContext.value?.start], ([visible]) => {
  if (visible) void nextTick(updateAutocompleteLeft)
})

const displaySegments = computed<DisplaySegment[]>(() => highlightBarQuery(barQuery.value, props.filters))

const advancedActive = computed(() => parsedBarQuery.value.booleanSyntax)

watch(
  [modelValue, searchQuery, advancedQuery],
  () => {
    if (syncingFromBar.value) {
      return
    }
    syncBarFromModels()
  },
  { deep: true, immediate: true },
)

watch(barQuery, () => {
  void nextTick(syncInputScroll)
  syncModelsFromBar()
  scheduleValidation()
})

watch(dropdownSearch, () => {
  visibleSuggestionCounts.value = {}
}, { deep: true })

watch(autocompleteItems, (items) => {
  if (items.length === 0) {
    activeAutocompleteIndex.value = 0
    return
  }

  if (activeAutocompleteIndex.value > items.length - 1) {
    activeAutocompleteIndex.value = 0
  }
})

onMounted(() => {
  document.addEventListener('mousedown', handleDocumentPointer)
  document.addEventListener('selectionchange', handleSelectionChange)
})

onUnmounted(() => {
  document.removeEventListener('mousedown', handleDocumentPointer)
  document.removeEventListener('selectionchange', handleSelectionChange)
  if (validationTimer !== null) {
    clearTimeout(validationTimer)
  }
})

// Dragging a selection past the edge scrolls the input without any key or
// input event; follow it so the colouring stays under the text.
function handleSelectionChange() {
  if (inputRef.value && document.activeElement === inputRef.value) syncInputScroll()
}

function handleDocumentPointer(event: MouseEvent) {
  const target = event.target as Node | null
  if (target && rootRef.value && !rootRef.value.contains(target)) {
    inputFocused.value = false
    openMenu.value = null
    applyValidationNow()
  }
}

function focusInput() {
  openMenu.value = null
  inputRef.value?.focus()
}

function handleInputFocus() {
  inputFocused.value = true
  openMenu.value = null
  updateCursorPosition()
}

function handleInputBlur() {
  inputFocused.value = false
  applyValidationNow()
  void nextTick(syncInputScroll)
}

function handleInputEvent() {
  updateCursorPosition()
}

function handleCursorKeyup() {
  updateCursorPosition()
}

function updateCursorPosition() {
  cursorPosition.value = inputRef.value?.selectionStart ?? barQuery.value.length
  syncInputScroll()
}

// The coloured text is a single line under the transparent input; it must
// scroll with the input or long queries drift away from the caret.
function syncInputScroll() {
  inputScrollLeft.value = inputRef.value?.scrollLeft ?? 0
}

function handleInputKeydown(event: KeyboardEvent) {
  if (event.key === 'Escape') {
    inputFocused.value = false
    openMenu.value = null
    applyValidationNow()
    return
  }

  if (showAutocomplete.value && event.key === 'ArrowDown') {
    event.preventDefault()
    activeAutocompleteIndex.value = (activeAutocompleteIndex.value + 1) % autocompleteItems.value.length
    return
  }

  if (showAutocomplete.value && event.key === 'ArrowUp') {
    event.preventDefault()
    activeAutocompleteIndex.value = (activeAutocompleteIndex.value - 1 + autocompleteItems.value.length) % autocompleteItems.value.length
    return
  }

  if (showAutocomplete.value && event.key === 'Enter') {
    event.preventDefault()
    const item = autocompleteItems.value[activeAutocompleteIndex.value] ?? autocompleteItems.value[0]
    if (item) {
      selectAutocomplete(item)
    }
    return
  }

  if (event.key === 'Enter') {
    inputFocused.value = false
    applyValidationNow()
  }
}

function selectAutocomplete(item: AutocompleteItem) {
  const context = cursorContext.value ?? { token: '', start: barQuery.value.length, end: barQuery.value.length }
  const before = barQuery.value.slice(0, context.start)
  const after = barQuery.value.slice(context.end)
  let replacement = ''
  let nextCursor = 0

  // Right after a closing paren, a new word needs a space to read as one.
  const separator = context.token === '' && before.endsWith(')') ? ' ' : ''

  if (item.type === 'key') {
    replacement = `${separator}${item.key}:`
    nextCursor = (before + replacement).length
  } else if (item.type === 'operator') {
    replacement = `${separator}${item.value}${after.length === 0 ? ' ' : ''}`
    nextCursor = (before + replacement).length
  } else {
    const filter = filterMap.value.get(item.key.toLowerCase())
    if (!filter) {
      return
    }

    if (filter.multi) {
      const separatorIndex = context.token.indexOf(':')
      const rawValues = separatorIndex === -1 ? '' : context.token.slice(separatorIndex + 1)
      const values = rawValues.split(',').map((value) => value.trim())
      values[values.length - 1] = item.value
      replacement = `${item.key}:${values.filter(Boolean).join(',')}`
    } else {
      replacement = `${item.key}:${item.value}`
    }

    if (after.length === 0) {
      replacement = `${replacement} `
    }
    nextCursor = (before + replacement).length
  }

  barQuery.value = `${before}${replacement}${after}`
  activeAutocompleteIndex.value = 0

  void nextTick(() => {
    inputRef.value?.focus()
    inputRef.value?.setSelectionRange(nextCursor, nextCursor)
    cursorPosition.value = nextCursor
  })
}

function autocompleteOptionId(index: number) {
  return `filterbar-autocomplete-option-${index}`
}

function autocompleteItemKey(item: AutocompleteItem, index: number) {
  if (item.type === 'key') {
    return `key-${item.key}-${index}`
  }
  if (item.type === 'operator') {
    return `operator-${item.value}-${index}`
  }
  return `value-${item.key}-${item.value}-${index}`
}

function isFilterMenuOpen(key: string) {
  return openMenu.value?.type === 'filter' && openMenu.value.key === key
}

function toggleFilterMenu(key: string) {
  inputFocused.value = false
  if (isFilterMenuOpen(key)) {
    openMenu.value = null
    return
  }
  visibleSuggestionCounts.value = {}
  openMenu.value = { type: 'filter', key }
}

function toggleSortMenu() {
  inputFocused.value = false
  openMenu.value = isSortMenuOpen.value ? null : { type: 'sort' }
}

function setDropdownSearch(key: string, value: string) {
  dropdownSearch.value = {
    ...dropdownSearch.value,
    [key]: value,
  }
}

function filteredOptionsFor(filter: FilterDef) {
  const search = (dropdownSearch.value[filter.key] ?? '').trim().toLowerCase()
  const selected = new Set(getSelectedValues(filter).map((v) => v.toLowerCase()))
  const matching = filter.options.filter((option) => {
    if (search.length === 0) {
      return true
    }
    return option.toLowerCase().includes(search)
  })

  // Sort selected items first so they're never pushed below the pagination cut
  const selectedItems = matching.filter((o) => selected.has(o.toLowerCase()))
  const unselectedItems = matching.filter((o) => !selected.has(o.toLowerCase()))

  if (!filter.freeform) {
    return [...selectedItems, ...unselectedItems]
  }

  const unselectedCoarse = unselectedItems.filter((o) => !o.includes(':'))
  const unselectedFine = unselectedItems.filter((o) => o.includes(':'))
  if (unselectedCoarse.length > 3 || (unselectedCoarse.length > 0 && search.length === 0)) {
    return [...selectedItems, ...unselectedCoarse]
  }
  return [...selectedItems, ...unselectedCoarse, ...unselectedFine]
}

function visibleSuggestionsFor(filter: FilterDef) {
  const limit = visibleSuggestionCounts.value[filter.key] ?? 20
  return filteredOptionsFor(filter).slice(0, limit)
}

function hasMoreSuggestions(filter: FilterDef) {
  const limit = visibleSuggestionCounts.value[filter.key] ?? 20
  return filteredOptionsFor(filter).length > limit
}

function showMoreSuggestions(filterKey: string) {
  const current = visibleSuggestionCounts.value[filterKey] ?? 20
  visibleSuggestionCounts.value = {
    ...visibleSuggestionCounts.value,
    [filterKey]: current + 20,
  }
}

function showMoreCount(filter: FilterDef) {
  const limit = visibleSuggestionCounts.value[filter.key] ?? 20
  return Math.min(20, filteredOptionsFor(filter).length - limit)
}

function optionCount(filter: FilterDef, option: string): number | undefined {
  return props.counts?.[filter.key]?.[option]
}

function getSelectedValues(filter: FilterDef) {
  const rawValue = modelValue.value?.[filter.key]
  if (!rawValue) {
    return []
  }

  if (!filter.multi) {
    return [rawValue]
  }

  return rawValue.split(',').map((value) => value.trim()).filter(Boolean)
}

function hasFilterSelection(key: string) {
  return Boolean(modelValue.value?.[key])
}

function toggleFilterOption(filter: FilterDef, option: string) {
  const current = getSelectedValues(filter)
  let nextValues: string[] = []

  if (filter.multi) {
    nextValues = current.includes(option)
      ? current.filter((value) => value !== option)
      : [...current, option]
  } else {
    nextValues = current.includes(option) ? [] : [option]
  }

  const nextFilters = { ...(modelValue.value ?? {}) }
  if (nextValues.length === 0) {
    if (filter.defaultValue) {
      nextFilters[filter.key] = filter.defaultValue
    } else {
      delete nextFilters[filter.key]
    }
  } else {
    nextFilters[filter.key] = filter.multi ? nextValues.join(',') : nextValues[0]
  }

  modelValue.value = nextFilters

  if (!filter.multi) {
    openMenu.value = null
  }
}

function selectSort(key: string) {
  sortValue.value = key
}

function selectSortDirection(key: string) {
  if (!sortValue.value) {
    return
  }
  sortDirection.value = key
}

function clearAll() {
  const defaultFilters: Record<string, string> = {}
  for (const filter of props.filters) {
    if (filter.defaultValue) {
      defaultFilters[filter.key] = filter.defaultValue
    }
  }

  modelValue.value = defaultFilters
  searchQuery.value = ''
  if (sortValue.value) {
    sortValue.value = ''
  }
  if (sortDirection.value) {
    sortDirection.value = ''
  }
  barQuery.value = ''
  dropdownSearch.value = {}
  visibleSuggestionCounts.value = {}
  validationIssues.value = []
  activeAutocompleteIndex.value = 0
  inputFocused.value = false
  openMenu.value = null
}

function syncBarFromModels() {
  // While the bar holds a boolean query, it is the source of truth: the
  // discrete models cannot express OR/parens, so rebuilding from them would
  // destroy the query. The dropdown buttons are disabled in this mode.
  if (advancedQuery.value) {
    if (barQuery.value !== advancedQuery.value) {
      barQuery.value = advancedQuery.value
    }
    return
  }
  const nextQuery = buildBarQuery(props.filters, modelValue.value ?? {}, searchQuery.value, props.searchable)
  if (barQuery.value !== nextQuery) {
    barQuery.value = nextQuery
  }
  validationIssues.value = []
}

function syncModelsFromBar() {
  const parsed = parsedBarQuery.value

  // A broken boolean query has no meaning yet: keep the last valid query
  // applied rather than falling back to the discrete filters.
  if (parsed.booleanSyntax && parsed.issues.length > 0) {
    return
  }

  if (advancedQuery.value !== parsed.advancedQuery) {
    advancedQuery.value = parsed.advancedQuery
  }
  // Advanced mode leaves the discrete models untouched — the consumer runs
  // the advanced query verbatim and ignores them while it is set.
  if (parsed.advancedQuery) {
    return
  }

  syncingFromBar.value = true

  try {
    // When there are validation issues, preserve the current model values
    // for filter keys that are being edited (avoids wiping the bar text
    // via the reverse model→bar sync while the user is still typing).
    const mergedFilters = { ...parsed.filters }
    if (parsed.issues.length > 0) {
      const current = modelValue.value ?? {}
      for (const key of Object.keys(current)) {
        if (!(key in mergedFilters)) {
          mergedFilters[key] = current[key]
        }
      }
    }

    if (!sameRecord(modelValue.value ?? {}, mergedFilters)) {
      modelValue.value = mergedFilters
    }

    if (searchQuery.value !== parsed.searchText) {
      searchQuery.value = parsed.searchText
    }
  } finally {
    // Reset on nextTick so Vue's queued watcher for [modelValue, searchQuery]
    // still sees the flag as true and skips the reverse sync.
    nextTick(() => {
      syncingFromBar.value = false
    })
  }
}

function applyValidationNow() {
  validationIssues.value = parsedBarQuery.value.issues
}

function scheduleValidation() {
  if (validationTimer !== null) {
    clearTimeout(validationTimer)
  }

  // While typing, a half-written token is not an error yet: only clear
  // problems the edit fixed. New ones surface on blur or Enter.
  validationTimer = setTimeout(() => {
    const issues = parsedBarQuery.value.issues
    if (inputFocused.value) {
      const current = new Set(issues.map(issue => issue.id))
      validationIssues.value = validationIssues.value.filter(issue => current.has(issue.id))
    } else {
      validationIssues.value = issues
    }
    validationTimer = null
  }, 250)
}

function sameRecord(left: Record<string, string>, right: Record<string, string>) {
  const keys = new Set([...Object.keys(left), ...Object.keys(right)])
  for (const key of keys) {
    if ((left[key] ?? '') !== (right[key] ?? '')) {
      return false
    }
  }
  return true
}

function filterKeyBadge(key: string): string {
  const filter = filterMap.value.get(key.toLowerCase())
  if (filter?.label) {
    return filter.label.slice(0, 2)
  }
  return key.slice(0, 2)
}
</script>
