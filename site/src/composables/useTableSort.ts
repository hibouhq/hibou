import { computed, ref, type Ref } from 'vue'
import { ArrowUpDown, ChevronDown, ChevronUp } from 'lucide-vue-next'

export type SortDirection = 'asc' | 'desc'

export interface SortColumn<Row> {
  /** Accessor for the sortable value; null sorts last in either direction. */
  value: (row: Row) => string | number | null
  /** Direction used the first time the column is activated. */
  initial?: SortDirection
}

/**
 * Column-driven sort state shared by the file tables (coverage, tests,
 * security). Give it the column accessors; it hands back the sorted rows, a
 * toggle, and the right header icon.
 */
export function useTableSort<Row, Field extends string>(
  rows: Ref<Row[]>,
  columns: Record<Field, SortColumn<Row>>,
  defaultField: Field,
) {
  const field = ref(defaultField) as Ref<Field>
  const direction = ref<SortDirection>(columns[defaultField].initial ?? 'asc')

  const sorted = computed(() => {
    const column = columns[field.value]
    const factor = direction.value === 'asc' ? 1 : -1
    return [...rows.value].sort((left, right) => {
      const a = column.value(left)
      const b = column.value(right)
      if (a === b) return 0
      // Nulls sink to the bottom regardless of direction.
      if (a === null) return 1
      if (b === null) return -1
      if (typeof a === 'string' && typeof b === 'string') return a.localeCompare(b) * factor
      return (Number(a) - Number(b)) * factor
    })
  })

  function toggle(next: Field) {
    if (field.value === next) {
      direction.value = direction.value === 'asc' ? 'desc' : 'asc'
      return
    }
    field.value = next
    direction.value = columns[next].initial ?? 'asc'
  }

  function icon(of: Field) {
    if (field.value !== of) return ArrowUpDown
    return direction.value === 'asc' ? ChevronUp : ChevronDown
  }

  return { field, direction, sorted, toggle, icon }
}
