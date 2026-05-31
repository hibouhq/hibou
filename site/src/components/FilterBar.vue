<template>
  <div
    ref="rootRef"
    class="space-y-3"
  >
    <div class="relative">
      <div
        class="relative rounded-lg border border-surface-border bg-surface-overlay transition focus-within:border-accent/60"
        @click="focusInput"
      >
        <div
          aria-hidden="true"
          class="pointer-events-none absolute inset-0 flex items-center overflow-hidden px-3 py-2.5 pr-10 text-sm"
        >
          <div
            v-if="barQuery"
            class="min-w-0 whitespace-pre-wrap break-all"
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
          class="relative z-10 w-full bg-transparent px-3 py-2.5 pr-10 text-sm text-transparent caret-gray-100 placeholder:text-gray-500 focus:outline-none"
          @focus="handleInputFocus"
          @blur="handleInputBlur"
          @click="updateCursorPosition"
          @input="handleInputEvent"
          @keyup="handleCursorKeyup"
          @keydown="handleInputKeydown"
        >

        <button
          v-if="showClearButton"
          class="group absolute right-2 top-1/2 z-20 inline-flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-full border border-gray-500 text-gray-400 transition hover:border-gray-300 hover:text-gray-100"
          type="button"
          title="Clear filter"
          aria-label="Clear filter"
          @mousedown.prevent
          @click.stop="clearAll"
        >
          <svg class="h-3 w-3" fill="none" viewBox="0 0 12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M2 2l8 8M10 2l-8 8" /></svg>
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
          class="absolute left-0 top-[calc(100%+0.5rem)] z-40 w-full overflow-hidden rounded-lg border border-surface-border bg-surface-raised shadow-lg"
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
                class="flex h-5 w-5 shrink-0 items-center justify-center rounded text-gray-500"
                :class="index === activeAutocompleteIndex ? 'text-accent/70' : ''"
                v-html="filterKeyIcon(item.key)"
              />
              <span class="min-w-0 truncate font-medium">{{ item.primary }}</span>
              <span class="ml-auto shrink-0 text-xs text-gray-500">{{ item.secondary }}</span>
            </button>
          </div>
        </div>
      </Transition>
    </div>

    <div
      v-if="validationIssues.length > 0"
      class="rounded-lg border border-[#d29922]/40 bg-[#9e6a03]/20 px-3 py-2.5 text-sm text-[#d29922]"
    >
      <div class="flex items-start gap-2">
        <span class="mt-0.5 text-base leading-none">⚠</span>
        <div class="space-y-1">
          <div class="font-medium">
            Filter contains {{ validationIssues.length }} issue<span v-if="validationIssues.length !== 1">s</span>:
          </div>
          <ul class="list-disc space-y-1 pl-4 text-[#f0c674]">
            <li
              v-for="issue in validationIssues"
              :key="issue.id"
            >
              <template
                v-for="(part, index) in issue.parts"
                :key="`${issue.id}-${index}`"
              >
                <span :class="part.className">{{ part.text }}</span>
              </template>
            </li>
          </ul>
        </div>
      </div>
    </div>

    <div class="flex flex-wrap items-start justify-between gap-3">
      <div class="flex flex-wrap items-start gap-2">
        <div
          v-for="filter in filters"
          :key="filter.key"
          class="relative"
        >
          <button
            class="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition"
            :class="isFilterMenuOpen(filter.key) || hasFilterSelection(filter.key)
              ? 'border-accent/40 bg-accent-muted text-accent'
              : 'border-surface-border bg-surface-raised text-gray-300 hover:border-surface-border-subtle hover:text-gray-100'"
            type="button"
            aria-haspopup="true"
            :aria-expanded="isFilterMenuOpen(filter.key)"
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
              v-if="isFilterMenuOpen(filter.key)"
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
                <div
                  v-if="selectedOptionsFor(filter).length > 0"
                  class="space-y-2"
                >
                  <div class="text-xs font-medium uppercase tracking-[0.18em] text-gray-500">
                    Selected
                  </div>
                  <button
                    v-for="option in selectedOptionsFor(filter)"
                    :key="`selected-${filter.key}-${option}`"
                    role="option"
                    aria-selected="true"
                    class="flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left text-sm text-gray-100 transition hover:bg-surface-overlay"
                    type="button"
                    @click="toggleFilterOption(filter, option)"
                  >
                    <span class="flex h-4 w-4 items-center justify-center rounded border border-accent bg-accent text-[10px] font-bold text-surface">✓</span>
                    <span class="min-w-0 truncate">{{ option }}</span>
                  </button>
                </div>

                <div
                  v-if="selectedOptionsFor(filter).length > 0 && suggestionOptionsFor(filter).length > 0"
                  class="my-3 border-t border-surface-border-subtle"
                />

                <div class="space-y-2">
                  <div class="text-xs font-medium uppercase tracking-[0.18em] text-gray-500">
                    Suggestions
                  </div>
                  <div
                    v-if="suggestionOptionsFor(filter).length === 0"
                    class="rounded-md border border-dashed border-surface-border-subtle px-3 py-4 text-sm text-gray-500"
                  >
                    No matching options.
                  </div>
                  <button
                    v-for="option in suggestionOptionsFor(filter)"
                    :key="`suggestion-${filter.key}-${option}`"
                    role="option"
                    aria-selected="false"
                    class="flex w-full items-center gap-3 rounded-md px-2 py-1.5 text-left text-sm text-gray-300 transition hover:bg-surface-overlay hover:text-gray-100"
                    type="button"
                    @click="toggleFilterOption(filter, option)"
                  >
                    <span class="flex h-4 w-4 items-center justify-center rounded border border-surface-border text-transparent">✓</span>
                    <span class="min-w-0 truncate">{{ option }}</span>
                  </button>
                </div>
              </div>
            </div>
          </Transition>
        </div>
      </div>

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
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'

interface FilterDef {
  key: string
  label: string
  options: string[]
  multi?: boolean
  icon?: string
  freeform?: boolean
}

interface SortDef {
  key: string
  label: string
  ascLabel?: string
  descLabel?: string
}

interface DisplaySegment {
  text: string
  className: string
}

interface ValidationIssue {
  id: string
  parts: DisplaySegment[]
}

interface ParsedQuery {
  filters: Record<string, string>
  searchText: string
  issues: ValidationIssue[]
}

interface CursorContext {
  token: string
  start: number
  end: number
}

interface BarQueryChunk {
  text: string
  isWhitespace: boolean
}

type OpenMenu =
  | { type: 'filter'; key: string }
  | { type: 'sort' }
  | null

type AutocompleteItem =
  | { type: 'key'; key: string; primary: string; secondary: string }
  | { type: 'value'; key: string; value: string; primary: string; secondary: string }

const props = withDefaults(defineProps<{
  filters: FilterDef[]
  searchable?: boolean
  sortOptions?: SortDef[]
  sortDirectionOptions?: SortDef[]
  totalCount?: number
  filteredCount?: number
  placeholder?: string
}>(), {
  searchable: true,
  sortOptions: undefined,
  sortDirectionOptions: undefined,
  totalCount: undefined,
  filteredCount: undefined,
  placeholder: 'Filter findings...',
})

defineEmits<{
  (event: 'update:modelValue', value: Record<string, string>): void
  (event: 'update:searchQuery', value: string): void
  (event: 'update:sortValue', value: string): void
}>()

const modelValue = defineModel<Record<string, string>>({ default: () => ({}) })
const searchQuery = defineModel<string>('searchQuery', { default: '' })
const sortValue = defineModel<string>('sortValue', { default: '' })
const sortDirection = defineModel<string>('sortDirection', { default: '' })

const rootRef = ref<HTMLElement | null>(null)
const inputRef = ref<HTMLInputElement | null>(null)
const barQuery = ref('')
const cursorPosition = ref(0)
const inputFocused = ref(false)
const openMenu = ref<OpenMenu>(null)
const dropdownSearch = ref<Record<string, string>>({})
const validationIssues = ref<ValidationIssue[]>([])
const activeAutocompleteIndex = ref(0)
const syncingFromBar = ref(false)

let validationTimer: ReturnType<typeof setTimeout> | null = null

const filterMap = computed(() => {
  return new Map(props.filters.map((filter) => [filter.key.toLowerCase(), filter]))
})

const filterOptionMaps = computed(() => {
  return new Map(props.filters.map((filter) => [
    filter.key.toLowerCase(),
    new Map(filter.options.map((option) => [normalizeFilterFragment(option), option])),
  ]))
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

const parsedBarQuery = computed(() => parseBarQuery(barQuery.value))
const cursorContext = computed(() => getCursorContext(barQuery.value, cursorPosition.value))

const autocompleteItems = computed<AutocompleteItem[]>(() => {
  if (!inputFocused.value || isSortMenuOpen.value || openMenu.value?.type === 'filter') {
    return []
  }

  const context = cursorContext.value
  if (!context || !context.token) {
    return props.filters.map((filter) => ({
      type: 'key',
      key: filter.key,
      primary: `${filter.key}:`,
      secondary: filter.label,
    }))
  }

  const separatorIndex = context.token.indexOf(':')
  if (separatorIndex === -1) {
    const keyQuery = context.token.toLowerCase()
    return props.filters
      .filter((filter) => filter.key.toLowerCase().includes(keyQuery) || filter.label.toLowerCase().includes(keyQuery))
      .map((filter) => ({
        type: 'key',
        key: filter.key,
        primary: `${filter.key}:`,
        secondary: filter.label,
      }))
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

const displaySegments = computed<DisplaySegment[]>(() => {
  const chunks = tokenizeBarQuery(barQuery.value)
  return chunks.flatMap((chunk) => {
    if (chunk.isWhitespace) {
      return [{ text: chunk.text, className: 'text-transparent' }]
    }

    const match = chunk.text.match(/^([A-Za-z0-9_-]+):(.*)$/)
    if (!match) {
      return [{ text: chunk.text, className: 'text-gray-100' }]
    }

    return buildFilterDisplaySegments(match[1], match[2])
  })
})

watch(
  [modelValue, searchQuery],
  () => {
    if (syncingFromBar.value) {
      return
    }
    syncBarFromModels()
  },
  { deep: true, immediate: true },
)

watch(barQuery, () => {
  syncModelsFromBar()
  scheduleValidation()
})

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
})

onUnmounted(() => {
  document.removeEventListener('mousedown', handleDocumentPointer)
  if (validationTimer !== null) {
    clearTimeout(validationTimer)
  }
})

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
}

function handleInputEvent() {
  updateCursorPosition()
}

function handleCursorKeyup() {
  updateCursorPosition()
}

function updateCursorPosition() {
  cursorPosition.value = inputRef.value?.selectionStart ?? barQuery.value.length
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

  if (item.type === 'key') {
    replacement = `${item.key}:`
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

function selectedOptionsFor(filter: FilterDef) {
  return getSelectedValues(filter)
}

function suggestionOptionsFor(filter: FilterDef) {
  const search = (dropdownSearch.value[filter.key] ?? '').trim().toLowerCase()
  const selected = new Set(getSelectedValues(filter).map((value) => value.toLowerCase()))
  const matching = filter.options.filter((option) => {
    if (selected.has(option.toLowerCase())) {
      return false
    }
    if (search.length === 0) {
      return true
    }
    return option.toLowerCase().includes(search)
  })

  if (!filter.freeform) {
    return matching
  }

  const coarse = matching.filter((o) => !o.includes(':'))
  const fine = matching.filter((o) => o.includes(':'))
  if (coarse.length > 3 || (coarse.length > 0 && search.length === 0)) {
    return coarse
  }
  return [...coarse, ...fine]
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
    delete nextFilters[filter.key]
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
  modelValue.value = {}
  searchQuery.value = ''
  if (sortValue.value) {
    sortValue.value = ''
  }
  if (sortDirection.value) {
    sortDirection.value = ''
  }
  barQuery.value = ''
  validationIssues.value = []
  activeAutocompleteIndex.value = 0
  inputFocused.value = false
  openMenu.value = null
}

function syncBarFromModels() {
  const nextQuery = buildBarQuery(modelValue.value ?? {}, searchQuery.value)
  if (barQuery.value !== nextQuery) {
    barQuery.value = nextQuery
  }
  validationIssues.value = []
}

function syncModelsFromBar() {
  const parsed = parsedBarQuery.value
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

function buildBarQuery(filters: Record<string, string>, freeText: string) {
  const tokens: string[] = []

  for (const filter of props.filters) {
    const value = filters[filter.key]
    if (value) {
      tokens.push(`${filter.key}:${value}`)
    }
  }

  const trimmedSearch = props.searchable ? freeText.trim() : ''
  if (trimmedSearch.length > 0) {
    tokens.push(trimmedSearch)
  }

  return tokens.join(' ')
}

function parseBarQuery(query: string): ParsedQuery {
  const filters: Record<string, string> = {}
  const searchTerms: string[] = []
  const issues = new Map<string, ValidationIssue>()
  const tokens = tokenizeBarQuery(query)
    .filter((chunk) => !chunk.isWhitespace)
    .map((chunk) => chunk.text)

  for (const token of tokens) {
    const match = token.match(/^([A-Za-z0-9_-]+):(.*)$/)
    if (!match) {
      if (props.searchable && token.length > 0) {
        searchTerms.push(token)
      }
      continue
    }

    const rawKey = match[1]
    const rawValue = match[2]
    const filter = filterMap.value.get(rawKey.toLowerCase())

    if (!filter) {
      addValidationIssue(issues, createUnknownFilterIssue(rawKey))
      continue
    }

    const validated = validateFilterValues(filter, rawValue)

    for (const issue of validated.issues) {
      addValidationIssue(issues, issue)
    }

    if (validated.issues.length === 0 && validated.values.length > 0) {
      filters[filter.key] = filter.multi ? dedupe(validated.values).join(',') : validated.values[0]
    }

    if (filter.multi) {
      continue
    }
  }

  return {
    filters,
    searchText: props.searchable ? searchTerms.join(' ') : '',
    issues: [...issues.values()],
  }
}

function applyValidationNow() {
  validationIssues.value = parsedBarQuery.value.issues
}

function scheduleValidation() {
  if (validationTimer !== null) {
    clearTimeout(validationTimer)
  }

  validationTimer = setTimeout(() => {
    validationIssues.value = parsedBarQuery.value.issues
    validationTimer = null
  }, 250)
}

function getCursorContext(text: string, cursor: number): CursorContext {
  const safeCursor = Math.max(0, Math.min(cursor, text.length))
  const left = text.slice(0, safeCursor)
  const right = text.slice(safeCursor)
  const leftToken = left.match(/\S+$/)?.[0] ?? ''
  const rightToken = right.match(/^\S+/)?.[0] ?? ''
  const token = `${leftToken}${rightToken}`
  const start = safeCursor - leftToken.length
  const end = safeCursor + rightToken.length
  return { token, start, end }
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

function dedupe(values: string[]) {
  return Array.from(new Set(values))
}

function tokenizeBarQuery(query: string): BarQueryChunk[] {
  const chunks: BarQueryChunk[] = []
  let index = 0

  while (index < query.length) {
    if (isWhitespaceChar(query[index])) {
      const whitespaceStart = index
      while (index < query.length && isWhitespaceChar(query[index])) {
        index += 1
      }

      chunks.push({
        text: query.slice(whitespaceStart, index),
        isWhitespace: true,
      })
      continue
    }

    const tokenEnd = findBarTokenEnd(query, index)
    chunks.push({
      text: query.slice(index, tokenEnd),
      isWhitespace: false,
    })
    index = tokenEnd
  }

  return chunks
}

function findBarTokenEnd(query: string, start: number) {
  if (!hasQualifierKeyAt(query, start)) {
    let end = start
    while (end < query.length && !isWhitespaceChar(query[end])) {
      end += 1
    }
    return end
  }

  let end = start
  while (end < query.length) {
    if (!isWhitespaceChar(query[end])) {
      end += 1
      continue
    }

    const whitespaceStart = end
    while (end < query.length && isWhitespaceChar(query[end])) {
      end += 1
    }

    if (hasQualifierKeyAt(query, end)) {
      return whitespaceStart
    }
  }

  return query.length
}

function hasQualifierKeyAt(query: string, start: number) {
  if (start >= query.length) {
    return false
  }

  let end = start
  while (end < query.length && /[A-Za-z0-9_-]/.test(query[end])) {
    end += 1
  }

  return end > start && query[end] === ':'
}

function isWhitespaceChar(char: string) {
  return /\s/.test(char)
}

function normalizeFilterFragment(value: string) {
  return value.trim().toLowerCase()
}

function getCanonicalFilterOption(filter: FilterDef, value: string) {
  const options = filterOptionMaps.value.get(filter.key.toLowerCase())
  const normalized = normalizeFilterFragment(value)

  if (!options || normalized.length === 0) {
    return undefined
  }

  return options.get(normalized)
}

function validateFilterValues(filter: FilterDef, rawValue: string) {
  const values: string[] = []
  const issues: ValidationIssue[] = []

  if (!filter.multi) {
    const trimmed = rawValue.trim()
    if (trimmed.length === 0) {
      issues.push(createEmptyValueIssue(filter.key))
      return { values, issues }
    }

    if (filter.freeform) {
      values.push(trimmed)
      return { values, issues }
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, rawValue)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter.key, trimmed))
        return { values, issues }
      }
      values.push(canonical)
      return { values, issues }
    }

    values.push(trimmed)
    return { values, issues }
  }

  const fragments = rawValue.split(',')
  for (const fragment of fragments) {
    const trimmed = fragment.trim()
    if (trimmed.length === 0) {
      issues.push(createEmptyValueIssue(filter.key))
      continue
    }

    if (filter.freeform) {
      values.push(trimmed)
      continue
    }

    if (filter.options.length > 0) {
      const canonical = getCanonicalFilterOption(filter, fragment)
      if (!canonical) {
        issues.push(createInvalidValueIssue(filter.key, trimmed))
        continue
      }
      values.push(canonical)
      continue
    }

    values.push(trimmed)
  }

  if (issues.length > 0) {
    return { values: [], issues }
  }

  return { values, issues }
}

function buildFilterDisplaySegments(rawKey: string, rawValue: string): DisplaySegment[] {
  const filter = filterMap.value.get(rawKey.toLowerCase())
  const qualifierClass = 'text-gray-400'
  const valueClass = 'text-[#79c0ff]'
  const warningClass = 'text-[#d29922]'

  if (!filter) {
    return [
      { text: rawKey, className: warningClass },
      { text: ':', className: warningClass },
      ...(rawValue.length > 0 ? [{ text: rawValue, className: warningClass }] : []),
    ]
  }

  const segments: DisplaySegment[] = [
    { text: filter.key, className: qualifierClass },
    { text: ':', className: qualifierClass },
  ]

  if (!filter.multi) {
    if (rawValue.length === 0) {
      return segments
    }

    const className = isValidFilterValue(filter, rawValue) ? valueClass : warningClass
    segments.push({ text: rawValue, className })
    return segments
  }

  const fragments = rawValue.split(',')
  for (let index = 0; index < fragments.length; index += 1) {
    const fragment = fragments[index]

    if (index > 0) {
      const prevFragment = fragments[index - 1]
      const hasEmptyNeighbor = prevFragment.trim().length === 0 || fragment.trim().length === 0
      segments.push({ text: ',', className: hasEmptyNeighbor ? warningClass : qualifierClass })
    }

    if (fragment.length === 0) {
      continue
    }

    segments.push({
      text: fragment,
      className: isValidFilterValue(filter, fragment) ? valueClass : warningClass,
    })
  }

  return segments
}

function isValidFilterValue(filter: FilterDef, rawValue: string) {
  const trimmed = rawValue.trim()
  if (trimmed.length === 0) {
    return false
  }

  if (filter.freeform || filter.options.length === 0) {
    return true
  }

  return getCanonicalFilterOption(filter, rawValue) !== undefined
}

function createUnknownFilterIssue(rawKey: string): ValidationIssue {
  return {
    id: `unknown-filter:${rawKey.toLowerCase()}`,
    parts: [
      { text: 'Unknown filter ', className: 'text-[#f0c674]' },
      { text: rawKey, className: 'font-medium text-[#ffcc66]' },
    ],
  }
}

function createEmptyValueIssue(key: string): ValidationIssue {
  return {
    id: `empty-value:${key}`,
    parts: [
      { text: 'Empty value for ', className: 'text-[#f0c674]' },
      { text: key, className: 'font-medium text-[#ffd38a]' },
    ],
  }
}

function createInvalidValueIssue(key: string, value: string): ValidationIssue {
  return {
    id: `invalid-value:${key}:${value.toLowerCase()}`,
    parts: [
      { text: 'Invalid value ', className: 'text-[#f0c674]' },
      { text: value, className: 'font-medium text-[#ffb757]' },
      { text: ' for ', className: 'text-[#f0c674]' },
      { text: key, className: 'font-medium text-[#ffd38a]' },
    ],
  }
}

function addValidationIssue(target: Map<string, ValidationIssue>, issue: ValidationIssue) {
  if (!target.has(issue.id)) {
    target.set(issue.id, issue)
  }
}

const defaultIcons: Record<string, string> = {
  severity: '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm9-3a1 1 0 11-2 0 1 1 0 012 0zM8 7a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 018 7z"/></svg>',
  tool: '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M5.433 2.304A4.494 4.494 0 003.5 6c0 1.598.832 3.002 2.09 3.802.518.329.91.9.91 1.535v.663h3v-.663c0-.635.392-1.206.91-1.535A4.494 4.494 0 0012.5 6a4.494 4.494 0 00-1.933-3.696A4.49 4.49 0 008 1.5a4.49 4.49 0 00-2.567.804zM8 0a6 6 0 013.532 10.856c-.192.122-.282.322-.282.48V12H4.75v-.664c0-.158-.09-.358-.282-.48A6 6 0 018 0zM5.25 13.5h5.5a.75.75 0 010 1.5h-5.5a.75.75 0 010-1.5z"/></svg>',
  status: '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M8 9.5a1.5 1.5 0 100-3 1.5 1.5 0 000 3z"/><path d="M8 0a8 8 0 100 16A8 8 0 008 0zM1.5 8a6.5 6.5 0 1113 0 6.5 6.5 0 01-13 0z"/></svg>',
  ecosystem: '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M1 2.5A2.5 2.5 0 013.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 010-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 011 11.5v-9z"/></svg>',
  search: '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M10.68 11.74a6 6 0 01-7.922-8.982 6 6 0 018.982 7.922l3.04 3.04a.749.749 0 01-.326 1.275.749.749 0 01-.734-.215l-3.04-3.04zM11.5 7a4.499 4.499 0 10-8.997 0A4.499 4.499 0 0011.5 7z"/></svg>',
}

const fallbackIcon = '<svg viewBox="0 0 16 16" fill="currentColor" width="14" height="14"><path d="M0 1.75C0 .784.784 0 1.75 0h12.5C15.216 0 16 .784 16 1.75v12.5A1.75 1.75 0 0114.25 16H1.75A1.75 1.75 0 010 14.25V1.75zM6.5 6.5v8h2v-8h-2zm-5 3v5h2v-5h-2zm10-3v8h2v-8h-2z"/></svg>'

function filterKeyIcon(key: string): string {
  const filter = filterMap.value.get(key.toLowerCase())
  if (filter?.icon) {
    return filter.icon
  }
  return defaultIcons[key.toLowerCase()] ?? fallbackIcon
}
</script>
