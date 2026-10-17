import type { RouteLocationRaw } from 'vue-router'

// The fact rows the finding detail views render. Lives outside the SFC because
// `<script setup>` cannot export, and every kind-specific view builds these.
export interface Fact {
  label: string
  value?: string | number | boolean | null
  /** Renders the value in monospace — identifiers, paths, versions. */
  mono?: boolean
  /** Turns the value into an external link. */
  href?: string
  /** Turns the value into an in-app link (vue-router location). */
  to?: RouteLocationRaw
  /** Spans both columns; for long values like a purl. */
  wide?: boolean
  hint?: string
}
