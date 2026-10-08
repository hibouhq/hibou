// The URL-backed state of a findings list. Two states are equal only when
// every part matches — the advanced `q` included, or switching between two
// boolean queries would never reach the URL.
export interface ListQueryState {
  filters: Record<string, string>
  search: string
  q: string
  sort: string
  order: string
  page: number
}

export function sameFilterValues(keys: readonly string[], left: Record<string, string>, right: Record<string, string>) {
  return keys.every(key => (left[key] || '') === (right[key] || ''))
}

export function sameListQueryState(keys: readonly string[], left: ListQueryState, right: ListQueryState) {
  return sameFilterValues(keys, left.filters, right.filters)
    && left.search === right.search
    && left.q === right.q
    && left.sort === right.sort
    && left.order === right.order
    && left.page === right.page
}
