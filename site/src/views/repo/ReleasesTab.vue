<template>
  <section class="px-4 pb-8">
    <!-- The Releases tab brings its own filter bar: it is not scoped to the
         ref/snapshot selector like the analysis tabs (ADR-024 §1). -->
    <div class="flex flex-wrap items-center gap-2">
      <div class="relative">
        <Search class="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-500" />
        <input
          v-model="versionQuery"
          class="h-8 w-56 rounded-md border border-surface-border bg-surface-overlay pl-8 pr-2.5 text-sm text-gray-200 placeholder:text-gray-500 focus:border-accent/50 focus:outline-none"
          type="text"
          placeholder="Filter versions…"
        >
      </div>

      <select
        v-model="clientFilter"
        class="h-8 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
      >
        <option value="">
          All clients
        </option>
        <option
          v-for="client in orgClients"
          :key="client.slug"
          :value="client.slug"
        >
          {{ client.name }}
        </option>
      </select>

      <button
        class="inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-sm transition"
        :class="vulnerableOnly
          ? 'border-danger/50 bg-danger/10 text-danger'
          : 'border-surface-border bg-surface-overlay text-gray-400 hover:text-gray-200'"
        type="button"
        @click="vulnerableOnly = !vulnerableOnly"
      >
        <ShieldAlert class="h-3.5 w-3.5" />
        Vulnerable only
      </button>

      <div class="ml-auto flex items-center gap-2">
        <span
          v-if="!loading"
          class="text-xs text-gray-500"
        >{{ total }} release{{ total === 1 ? '' : 's' }}</span>
        <!-- ADR-045 §4.3: every release without an inventory, newest first. -->
        <button
          v-if="isReleaseManager && !loading && !loadError && canBackfillReleases(inventorySummary)"
          class="inline-flex h-8 items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-400 transition hover:text-gray-200 disabled:opacity-50"
          type="button"
          :disabled="backfilling"
          title="Queue up to 100 missing release inventories across this repository, newest first; existing SBOMs are preserved"
          @click="backfillReleases"
        >
          <PackageSearch class="h-3.5 w-3.5" />
          {{ backfilling ? 'Queuing…' : `Backfill missing inventories (${inventorySummary?.eligible})` }}
        </button>
      </div>
    </div>

    <p
      v-if="releaseInventoryPending(inventorySummary)"
      class="mt-3 text-xs text-gray-400"
      role="status"
    >
      Release inventories: {{ inventorySummary?.queued }} queued · {{ inventorySummary?.processing }} extracting · {{ inventorySummary?.matching }} matching advisories.
      {{ inventoryPolls >= 120 ? 'Automatic refresh paused; reload to check progress.' : 'Progress refreshes automatically.' }}
    </p>
    <p
      v-if="inventorySummary?.enabled === false"
      class="mt-3 text-xs text-gray-500"
    >
      Dependency extraction is disabled on this instance.
    </p>
    <p
      v-if="loadError"
      class="mt-3 text-sm text-danger"
      role="alert"
    >
      {{ loadError }}
    </p>
    <p
      v-if="backfillError"
      class="mt-3 text-sm text-danger"
      role="alert"
    >
      {{ backfillError }}
    </p>

    <!-- List -->
    <div
      v-if="loading"
      class="mt-6 text-sm text-gray-500"
    >
      Loading releases…
    </div>

    <div
      v-else-if="releases.length === 0"
      class="mt-6 rounded-md border border-dashed border-surface-border px-6 py-10 text-center"
    >
      <Rocket class="mx-auto h-8 w-8 text-gray-600" />
      <p class="mt-3 text-sm font-medium text-gray-300">
        {{ hasFilters ? 'No releases match the current filters.' : 'No releases yet' }}
      </p>
      <p
        v-if="!hasFilters"
        class="mx-auto mt-1.5 max-w-xl text-sm text-gray-500"
      >
        Releases are derived automatically — publish a release on the forge, or push a version
        tag (<code class="text-gray-400">v1.2.3</code>) and upload its analysis from your
        pipeline. Nothing is created by hand.
      </p>
    </div>

    <div
      v-else
      class="mt-4 overflow-hidden rounded-md border border-surface-border"
    >
      <div
        v-for="(release, index) in releases"
        :key="release.id"
        :class="index > 0 ? 'border-t border-surface-border' : ''"
      >
        <!-- Row -->
        <div
          class="grid w-full grid-cols-[minmax(16rem,1fr)_minmax(0,2.2fr)_minmax(0,1.2fr)_auto] items-center gap-3 px-4 py-3 text-left transition hover:bg-surface-overlay/50"
          @click="toggleExpanded(release.id)"
        >
          <!-- Version + provenance -->
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <Tag class="h-4 w-4 shrink-0 text-gray-500" />
              <span class="truncate font-mono text-sm font-semibold text-white">{{ release.version }}</span>
              <RouterLink
                v-if="release.snapshot_id"
                :to="{ name: 'repo-remediation', params: route.params, query: { release: release.id } }"
                class="inline-flex shrink-0 rounded-full border border-accent/30 px-2 py-0.5 text-[11px] text-accent transition hover:bg-accent/10"
                title="Prepare a verified dependency patch against this exact shipped source"
                @click.stop
              >
                Remediate
              </RouterLink>
              <span
                v-if="release.diverged_at"
                class="inline-flex shrink-0 items-center gap-1 rounded-full border border-warn/50 bg-warn/10 px-1.5 py-0.5 text-[11px] font-medium text-warn"
                title="The tag was recreated on another commit while clients run this build"
              >
                <TriangleAlert class="h-3 w-3" />
                Tag moved
              </span>
              <a
                v-if="safeHref(release.html_url)"
                :href="safeHref(release.html_url)"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex shrink-0 items-center gap-1 rounded-full border border-surface-border px-1.5 py-0.5 text-[11px] text-gray-400 transition hover:border-accent/50 hover:text-accent"
                title="Open the forge release page"
                @click.stop
              >
                <ExternalLink class="h-3 w-3" />
                Release page
              </a>
            </div>
            <p class="mt-0.5 truncate text-xs text-gray-500">
              {{ release.published_at ? `published ${relativeTime(release.published_at)}` : `created ${relativeTime(release.created_at)}` }}
              <span class="text-gray-600"> · {{ release.source === 'forge' ? 'from forge release' : 'from version tag' }}</span>
            </p>
          </div>

          <!-- Risk -->
          <div class="flex flex-wrap items-center gap-1.5">
            <span
              v-if="!release.snapshot_id"
              class="rounded border border-surface-border px-2 py-0.5 text-xs text-gray-500"
              title="No analysis snapshot is attached to this release yet"
            >Not analyzed</span>
            <template v-else-if="release.open_finding_count === 0 && release.inventory?.has_inventory && release.inventory.state !== 'matching' && release.last_scanned_at">
              <span class="rounded border border-ok/40 px-2 py-0.5 text-xs font-medium text-ok">No open findings</span>
            </template>
            <span
              v-else-if="release.open_finding_count === 0"
              class="text-xs text-gray-500"
            >Not assessed</span>
            <!-- The org overview's labels: malware, exploited, then severities,
                 each opening this release's matching findings. -->
            <template v-else>
              <RouterLink
                v-if="release.malware_open > 0"
                :to="releaseFindings(release, OPEN_RISK_MALWARE_QUERY)"
                class="inline-flex items-center gap-1 rounded border border-malware/60 bg-malware/10 px-2 py-0.5 text-xs font-semibold text-malware hover:underline"
                :title="`Open the ${release.malware_open} malicious packages this release ships`"
              >
                <MalwareIcon size="sm" />
                {{ release.malware_open }} malware
              </RouterLink>
              <RouterLink
                v-if="release.kev_open"
                :to="releaseFindings(release, OPEN_RISK_KEV_QUERY)"
                class="inline-flex items-center gap-1 rounded border border-danger/60 bg-danger/10 px-2 py-0.5 text-xs font-semibold text-danger hover:underline"
                title="Listed on a known-exploited catalog (CISA KEV / ENISA EUVD)"
              >
                <Flame class="h-3 w-3" />
                {{ release.kev_open }} exploited
              </RouterLink>
              <RouterLink
                v-for="item in severityItems(release)"
                :key="item.key"
                :to="releaseFindings(release, openRiskSeverityQuery(item.key))"
                :class="[severityBadgeClass(item.key), 'transition hover:brightness-125']"
                :title="`Open the ${item.value} open ${item.key} findings`"
              >
                {{ item.value }} {{ item.key }}
              </RouterLink>
            </template>
          </div>

          <!-- Clients -->
          <div class="flex min-w-0 flex-wrap items-center gap-1.5">
            <span
              v-for="client in release.clients.slice(0, 3)"
              :key="client.deployment_id"
              class="inline-flex max-w-[10rem] items-center gap-1 truncate rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] text-gray-300"
            >
              <Users class="h-3 w-3 shrink-0 text-gray-500" />
              <span class="truncate">{{ client.name }}</span>
            </span>
            <span
              v-if="release.clients.length > 3"
              class="text-[11px] text-gray-500"
            >+{{ release.clients.length - 3 }}</span>
            <span
              v-if="release.clients.length === 0"
              class="text-[11px] text-gray-600"
            >No clients</span>
          </div>

          <!-- Scanned-at + chevron -->
          <div class="flex items-center gap-3">
            <span
              v-if="release.snapshot_id"
              class="hidden whitespace-nowrap text-xs sm:inline"
              :class="isStale(release) ? 'text-warn' : 'text-gray-500'"
              :title="release.last_scanned_at ? `Last advisory scan ${relativeTime(release.last_scanned_at)}` : 'Never scanned for advisories'"
            >
              {{ release.last_scanned_at ? `scanned ${relativeTime(release.last_scanned_at)}` : 'never scanned' }}
            </span>
            <button
              class="rounded p-1 text-gray-500 transition hover:bg-surface-overlay hover:text-gray-300"
              type="button"
              :aria-label="expandedId === release.id ? `Collapse release ${release.version}` : `Expand release ${release.version}`"
              :aria-expanded="expandedId === release.id"
              @click.stop="toggleExpanded(release.id)"
            >
              <ChevronDown
                class="h-4 w-4 transition-transform"
                :class="expandedId === release.id ? 'rotate-180' : ''"
              />
            </button>
          </div>
        </div>

        <!-- Expanded detail -->
        <div
          v-if="expandedId === release.id"
          class="border-t border-surface-border-subtle bg-surface-overlay/30 px-4 py-4"
        >
          <!-- Re-tag divergence (ADR-024 §5) -->
          <div
            v-if="release.diverged_at"
            class="mb-4 rounded-md border border-warn/40 bg-warn/5 px-4 py-3"
          >
            <div class="flex items-start gap-2.5">
              <TriangleAlert class="mt-0.5 h-4 w-4 shrink-0 text-warn" />
              <div class="min-w-0 flex-1">
                <p class="text-sm font-medium text-warn">
                  Tag {{ release.version }} was recreated on another commit
                </p>
                <p class="mt-1 text-xs text-gray-400">
                  Clients on this release run
                  <code class="text-gray-300">{{ shortSha(release.commit_sha) }}</code>, but the tag now points at
                  <code class="text-gray-300">{{ shortSha(release.pending_commit_sha) }}</code>.
                  Adopt the new build if the previous one was a mistake — or keep tracking what actually shipped.
                </p>
                <div
                  v-if="isReleaseManager"
                  class="mt-2.5 flex flex-wrap items-center gap-2"
                >
                  <button
                    class="rounded-md bg-warn/20 px-3 py-1.5 text-xs font-medium text-warn transition hover:bg-warn/30 disabled:opacity-50"
                    type="button"
                    :disabled="resolvingDivergence"
                    @click="resolveDivergence(release, 'adopt')"
                  >
                    Adopt new build
                  </button>
                  <button
                    class="rounded-md border border-surface-border px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:text-white disabled:opacity-50"
                    type="button"
                    :disabled="resolvingDivergence"
                    @click="resolveDivergence(release, 'keep')"
                  >
                    Keep shipped build
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div class="grid gap-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
            <!-- Analysis -->
            <div>
              <h3 class="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">
                Analysis
              </h3>
              <dl class="mt-2 space-y-1.5 text-sm">
                <div class="flex gap-3">
                  <dt class="w-28 shrink-0 text-gray-500">
                    Source ref
                  </dt>
                  <dd class="font-mono text-gray-200">
                    {{ release.ref_name }}
                  </dd>
                </div>
                <div class="flex gap-3">
                  <dt class="w-28 shrink-0 text-gray-500">
                    Snapshot
                  </dt>
                  <dd>
                    <template v-if="release.snapshot_id">
                      <span class="font-mono text-xs text-gray-400">{{ release.snapshot_id.slice(0, 8) }}</span>
                      <span
                        class="ml-2 text-xs"
                        :class="isStale(release) ? 'text-warn' : 'text-gray-500'"
                      >
                        {{ release.last_scanned_at ? `advisories checked ${relativeTime(release.last_scanned_at)}` : 'advisories never checked' }}
                      </span>
                    </template>
                    <span
                      v-else
                      class="text-gray-500"
                    >none — attaches automatically when the ref's analysis upload completes</span>
                  </dd>
                </div>
                <div
                  v-if="release.published_at"
                  class="flex gap-3"
                >
                  <dt class="w-28 shrink-0 text-gray-500">
                    Published
                  </dt>
                  <dd class="text-gray-200">
                    {{ formatDateTime(release.published_at) }}
                  </dd>
                </div>
              </dl>

              <div class="mt-3 flex flex-wrap items-center gap-2">
                <RouterLink
                  v-if="release.snapshot_id"
                  class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white"
                  :to="{ name: 'repo-vulnerabilities', params: route.params, query: { ref: release.ref_name, snapshot: release.snapshot_id } }"
                >
                  <ShieldAlert class="h-3.5 w-3.5" />
                  View findings ({{ release.open_finding_count }})
                </RouterLink>
                <button
                  v-if="isReleaseManager && release.snapshot_id && release.inventory?.has_inventory"
                  class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                  type="button"
                  :disabled="rescanning === release.id"
                  title="Query advisory providers again for this release's exact dependency set"
                  @click="rescan(release)"
                >
                  <RefreshCw
                    class="h-3.5 w-3.5"
                    :class="rescanning === release.id ? 'animate-spin' : ''"
                  />
                  {{ rescanning === release.id ? 'Re-scanning…' : 'Re-scan' }}
                </button>
                <!-- Built-in inventory for a release tagged before onboarding or
                     without an SBOM (ADR-045 §4.3): extracted from the tag's
                     lockfiles, onto the release's pinned snapshot. -->
                <button
                  v-if="isReleaseManager && !loadError && canExtractReleaseInventory(release.inventory, inventorySummary?.enabled)"
                  class="inline-flex items-center gap-1.5 rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-300 transition hover:border-accent/50 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
                  type="button"
                  :disabled="extractingRelease === release.id"
                  title="Extract this release's dependencies from its tag's lockfiles and manifests"
                  @click="extractRelease(release)"
                >
                  <PackageSearch class="h-3.5 w-3.5" />
                  {{ extractingRelease === release.id ? 'Queuing…' : release.inventory?.state === 'failed' ? 'Retry dependency extraction' : 'Extract dependencies' }}
                </button>
              </div>
              <p
                class="mt-3 text-xs"
                :class="release.inventory?.state === 'failed' ? 'text-danger' : 'text-gray-400'"
                role="status"
              >
                {{ releaseInventoryLabel(release.inventory) }}
                <span v-if="release.inventory?.detail"> · {{ release.inventory.detail }}</span>
              </p>
            </div>

            <!-- Inventory sources (ADR-046 §4): every artifact behind the
                 release's components, with its origin; deliverables are
                 recorded by the CLI, never uploaded through the browser. -->
            <div class="mb-4">
              <div class="flex flex-wrap items-center justify-between gap-2">
                <h3 class="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">
                  Inventory sources
                </h3>
                <button
                  type="button"
                  class="text-xs text-gray-400 transition hover:text-white"
                  @click="toggleSources(release)"
                >
                  {{ sources[release.id] ? 'Hide' : 'Show' }}
                </button>
              </div>
              <div
                v-if="sources[release.id]"
                class="mt-2 space-y-2"
              >
                <ul
                  v-if="sources[release.id]!.sources.length > 0"
                  class="divide-y divide-surface-border-subtle rounded-md border border-surface-border bg-surface-overlay text-xs"
                >
                  <li
                    v-for="source in sources[release.id]!.sources"
                    :key="source.id"
                    class="flex flex-wrap items-center justify-between gap-2 px-3 py-2"
                    :class="source.revoked ? 'opacity-60' : ''"
                  >
                    <span class="flex flex-wrap items-center gap-2">
                      <span class="font-mono text-gray-200">{{ source.filename }}</span>
                      <span class="rounded border border-surface-border px-1 py-px text-[10px] uppercase tracking-wide text-gray-500">{{ source.origin }}</span>
                      <span class="text-gray-500">{{ source.component_count }} components</span>
                      <span
                        v-if="source.extractor_version"
                        class="text-gray-500"
                        :title="sources[release.id]!.current_extractor_version && source.extractor_version !== sources[release.id]!.current_extractor_version ? `current: ${sources[release.id]!.current_extractor_version}` : ''"
                      >extractor {{ source.extractor_version }}{{ sources[release.id]!.current_extractor_version && source.extractor_version !== sources[release.id]!.current_extractor_version ? ' (older)' : '' }}</span>
                      <span
                        v-if="source.after_release"
                        class="text-warn"
                        title="Recorded after the release date, unlike sources recorded by the build itself"
                      >added {{ formatDateTime(source.created_at) }}, after the release</span>
                      <span
                        v-if="source.revoked"
                        class="text-danger"
                      >revoked: {{ source.revoke_reason }}</span>
                    </span>
                    <span
                      v-if="sources[release.id]!.can_revoke && source.origin === 'manual'"
                      class="flex items-center gap-2"
                    >
                      <button
                        v-if="!source.revoked"
                        type="button"
                        class="text-gray-500 transition hover:text-danger"
                        @click="revokeSource(release, source)"
                      >
                        revoke
                      </button>
                      <button
                        v-else
                        type="button"
                        class="text-gray-500 transition hover:text-white"
                        @click="restoreSource(release, source)"
                      >
                        restore
                      </button>
                    </span>
                  </li>
                </ul>
                <p
                  v-else
                  class="text-xs text-gray-500"
                >
                  No inventory source yet: extract the tag, upload an SBOM from CI, or record the deliverables.
                </p>
                <!-- "Add deliverables": the CLI analyses them locally so
                     proprietary binaries never reach Hibou (ADR-046 §4.1). -->
                <div class="rounded-md border border-surface-border bg-surface-overlay px-3 py-2 text-xs text-gray-400">
                  <span class="text-gray-300">Add deliverables</span> (WAR, Go binary, image, zip of everything): analysed on your machine, only the inventory is recorded.
                  <code class="mt-1 block select-all font-mono text-[11px] text-gray-200">{{ sources[release.id]!.record_command }}</code>
                </div>
              </div>
            </div>

            <!-- Clients on this release -->
            <div>
              <h3 class="text-xs font-semibold uppercase tracking-[0.14em] text-gray-500">
                Clients on this release
              </h3>

              <ul
                v-if="release.clients.length > 0"
                class="mt-2 space-y-1.5"
              >
                <li
                  v-for="client in release.clients"
                  :key="client.deployment_id"
                  class="flex items-center justify-between gap-2 rounded-md border border-surface-border bg-surface-overlay px-3 py-2"
                >
                  <div class="min-w-0">
                    <RouterLink
                      class="truncate text-sm font-medium text-gray-200 transition hover:text-accent"
                      :to="`/orgs/${provider}/${orgSlug}/clients/${client.slug}`"
                    >
                      {{ client.name }}
                    </RouterLink>
                    <p class="text-[11px] text-gray-500">
                      {{ client.environment }} · since {{ relativeTime(client.deployed_at) }}
                    </p>
                  </div>
                  <button
                    v-if="isReleaseManager"
                    class="shrink-0 rounded-md p-1 text-gray-500 transition hover:text-danger"
                    type="button"
                    title="Mark as rolled back"
                    @click="removeClient(release, client)"
                  >
                    <X class="h-3.5 w-3.5" />
                  </button>
                </li>
              </ul>
              <p
                v-else
                class="mt-2 text-sm text-gray-500"
              >
                No client is recorded on this release.
              </p>

              <!-- Add client (release managers) -->
              <div
                v-if="isReleaseManager"
                class="mt-3 flex flex-wrap items-center gap-2"
              >
                <select
                  v-model="addClientSlug"
                  class="h-8 min-w-40 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 focus:border-accent/50 focus:outline-none"
                >
                  <option value="">
                    Add a client…
                  </option>
                  <option
                    v-for="client in assignableClients(release)"
                    :key="client.slug"
                    :value="client.slug"
                  >
                    {{ client.name }}
                  </option>
                </select>
                <input
                  v-model="addClientEnvironment"
                  class="h-8 w-32 rounded-md border border-surface-border bg-surface-overlay px-2.5 text-sm text-gray-200 placeholder:text-gray-500 focus:border-accent/50 focus:outline-none"
                  type="text"
                  placeholder="production"
                >
                <button
                  class="h-8 rounded-md bg-accent px-3 text-xs font-medium text-white transition hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50"
                  type="button"
                  :disabled="!addClientSlug || addingClient"
                  @click="addClient(release)"
                >
                  {{ addingClient ? 'Adding…' : 'Add' }}
                </button>
              </div>
              <p
                v-if="isReleaseManager"
                class="mt-1.5 text-[11px] text-gray-600"
              >
                Pipelines can record this automatically:
                <code class="text-gray-500">hibou release deploy --repo {{ repoSlug }} --version {{ release.version }} --client &lt;slug&gt;</code>
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Pagination -->
    <div
      v-if="total > perPage"
      class="mt-4 flex items-center justify-between text-sm text-gray-400"
    >
      <button
        class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
        type="button"
        :disabled="page <= 1"
        @click="page--"
      >
        Previous
      </button>
      <span class="text-xs text-gray-500">Page {{ page }} of {{ Math.ceil(total / perPage) }}</span>
      <button
        class="rounded-md border border-surface-border px-3 py-1.5 text-xs transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
        type="button"
        :disabled="page >= Math.ceil(total / perPage)"
        @click="page++"
      >
        Next
      </button>
    </div>
  </section>
</template>

<script setup lang="ts">
import { safeHref } from '@/lib/safeUrl'
import { ChevronDown, ExternalLink, Flame, PackageSearch, RefreshCw, Rocket, Search, ShieldAlert, Tag, TriangleAlert, Users, X } from 'lucide-vue-next'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api, type Client, type ReleaseClient, type ReleaseInventorySummary, type ReleaseSource, type ReleaseSources, type ReleaseWithRisk } from '@/api/client'
import { useDialog } from '@/composables/useDialog'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { formatDateTime, relativeTime } from '@/lib/datetime'
import MalwareIcon from '@/components/finding/MalwareIcon.vue'
import { severityBadgeClass } from '@/lib/findingDisplay'
import { OPEN_RISK_KEV_QUERY, OPEN_RISK_MALWARE_QUERY, openRiskSeverityQuery } from '@/lib/openRiskPreset'
import { canBackfillReleases, canExtractReleaseInventory, releaseInventoryLabel, releaseInventoryPending } from '@/lib/releaseInventory'

const { confirmDialog } = useDialog()
const route = useRoute()
const { pushToast } = useToast()
const { isReleaseManager } = useOrgRole()

const provider = computed(() => route.params.provider as string)
const orgSlug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const releases = ref<ReleaseWithRisk[]>([])
const orgClients = ref<Client[]>([])
const loading = ref(true)
const loadError = ref('')
const backfillError = ref('')
const inventorySummary = ref<ReleaseInventorySummary | null>(null)
const total = ref(0)
const page = ref(1)
const perPage = 25

const versionQuery = ref('')
const clientFilter = ref('')
const vulnerableOnly = ref(false)
const expandedId = ref<string | null>(null)

const addClientSlug = ref('')
const addClientEnvironment = ref('')
const addingClient = ref(false)
const rescanning = ref<string | null>(null)
const resolvingDivergence = ref(false)

const hasFilters = computed(() => versionQuery.value !== '' || clientFilter.value !== '' || vulnerableOnly.value)

// A released snapshot whose advisory data is older than the staleness window
// deserves a visible nudge, whatever the refresh worker's cadence is.
const STALE_AFTER_MS = 7 * 24 * 60 * 60 * 1000

function isStale(release: ReleaseWithRisk) {
  if (!release.snapshot_id) {
    return false
  }
  if (!release.last_scanned_at) {
    return true
  }
  return Date.now() - new Date(release.last_scanned_at).getTime() > STALE_AFTER_MS
}

function severityItems(release: ReleaseWithRisk) {
  return [
    { key: 'critical', value: release.critical_count },
    { key: 'high', value: release.high_count },
    { key: 'medium', value: release.medium_count },
    { key: 'low', value: release.low_count },
  ].filter((item) => item.value > 0)
}

// This release's findings, narrowed like the org overview's labels.
function releaseFindings(release: ReleaseWithRisk, q: string) {
  return { name: 'repo-vulnerabilities', params: route.params, query: { ref: release.ref_name, snapshot: release.snapshot_id, q } }
}

function assignableClients(release: ReleaseWithRisk) {
  const assigned = new Set(release.clients.map((client) => client.slug))
  return orgClients.value.filter((client) => !assigned.has(client.slug))
}

function toggleExpanded(id: string) {
  expandedId.value = expandedId.value === id ? null : id
  addClientSlug.value = ''
  addClientEnvironment.value = ''
}

let requestToken = 0
let disposed = false
let inventoryPolls = 0
let inventoryTimer: ReturnType<typeof setTimeout> | undefined
const currentScope = () => `${provider.value}/${orgSlug.value}/${repoSlug.value}`

async function loadReleases(background = false) {
  clearTimeout(inventoryTimer)
  const token = ++requestToken
  if (!background) loading.value = true
  try {
    const response = await api.listReleases(provider.value, orgSlug.value, repoSlug.value, {
      page: page.value,
      per_page: perPage,
      q: versionQuery.value || undefined,
      client: clientFilter.value || undefined,
      vulnerable: vulnerableOnly.value || undefined,
    })
    if (disposed || token !== requestToken) {
      return
    }
    releases.value = response.data
    total.value = response.pagination.total
    inventorySummary.value = response.inventory ?? null
    loadError.value = ''
    if (releaseInventoryPending(inventorySummary.value) && inventoryPolls < 120) {
      inventoryTimer = setTimeout(() => {
        inventoryPolls++
        void loadReleases(true)
      }, 5000)
    }
  } catch (err) {
    if (!disposed && token === requestToken) {
      loadError.value = err instanceof Error ? err.message : 'Failed to load release inventory status'
    }
  } finally {
    if (token === requestToken) {
      loading.value = false
    }
  }
}

async function loadClients() {
  try {
    const response = await api.listClients(provider.value, orgSlug.value, { per_page: 100 })
    orgClients.value = response.data
  } catch {
    orgClients.value = []
  }
}

async function addClient(release: ReleaseWithRisk) {
  if (!addClientSlug.value) {
    return
  }
  addingClient.value = true
  try {
    await api.addReleaseClient(provider.value, orgSlug.value, repoSlug.value, release.id, {
      client_slug: addClientSlug.value,
      environment: addClientEnvironment.value.trim() || undefined,
    })
    pushToast({ title: 'Client added to release', tone: 'success' })
    addClientSlug.value = ''
    addClientEnvironment.value = ''
    await loadReleases()
  } catch (err) {
    pushToast({ title: 'Failed to add client', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    addingClient.value = false
  }
}

async function removeClient(release: ReleaseWithRisk, client: ReleaseClient) {
  try {
    await api.removeReleaseClient(provider.value, orgSlug.value, repoSlug.value, release.id, client.deployment_id)
    pushToast({ title: `${client.name} marked as rolled back`, tone: 'success' })
    await loadReleases()
  } catch (err) {
    pushToast({ title: 'Failed to remove client', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  }
}

function shortSha(sha?: string) {
  return sha ? sha.slice(0, 7) : '?'
}

async function resolveDivergence(release: ReleaseWithRisk, action: 'adopt' | 'keep') {
  if (action === 'adopt' && !(await confirmDialog({ title: `Point ${release.version} at ${shortSha(release.pending_commit_sha)}?`, message: 'Its risk posture will be recomputed from the new build; client records stay.', confirmLabel: 'Adopt build' }))) {
    return
  }
  resolvingDivergence.value = true
  try {
    await api.resolveReleaseDivergence(provider.value, orgSlug.value, repoSlug.value, release.id, action)
    pushToast({
      title: action === 'adopt' ? `${release.version} now tracks the new build` : `${release.version} keeps the shipped build`,
      tone: 'success',
    })
    await loadReleases()
  } catch (err) {
    pushToast({ title: 'Failed to resolve divergence', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    resolvingDivergence.value = false
  }
}

const extractingRelease = ref<string | null>(null)

// Inventory sources per release, loaded on demand (ADR-046 §4).
const sources = ref<Record<string, ReleaseSources | undefined>>({})

async function loadSources(release: ReleaseWithRisk) {
  try {
    const response = await api.getReleaseSources(provider.value, orgSlug.value, repoSlug.value, release.id)
    sources.value = { ...sources.value, [release.id]: response.data }
  } catch (err) {
    pushToast({ title: 'Sources could not be loaded', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  }
}

async function toggleSources(release: ReleaseWithRisk) {
  if (sources.value[release.id]) {
    sources.value = { ...sources.value, [release.id]: undefined }
    return
  }
  await loadSources(release)
}

async function revokeSource(release: ReleaseWithRisk, source: ReleaseSource) {
  const reason = window.prompt(`Why revoke ${source.filename}? The reason is audit-logged; its components leave the release unless another source reports them.`)
  if (!reason || !reason.trim()) return
  try {
    await api.revokeReleaseSource(provider.value, orgSlug.value, repoSlug.value, release.id, source.id, reason.trim())
    pushToast({ title: 'Source revoked', description: `${source.filename} no longer counts for ${release.version}.`, tone: 'success' })
    await loadSources(release)
  } catch (err) {
    pushToast({ title: 'Revocation failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  }
}

async function restoreSource(release: ReleaseWithRisk, source: ReleaseSource) {
  try {
    await api.restoreReleaseSource(provider.value, orgSlug.value, repoSlug.value, release.id, source.id)
    pushToast({ title: 'Source restored', description: `${source.filename} counts again for ${release.version}.`, tone: 'success' })
    await loadSources(release)
  } catch (err) {
    pushToast({ title: 'Restore failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  }
}
const backfilling = ref(false)

async function extractRelease(release: ReleaseWithRisk) {
  if (!isReleaseManager.value || extractingRelease.value || !canExtractReleaseInventory(release.inventory, inventorySummary.value?.enabled)) return
  const scope = currentScope()
  extractingRelease.value = release.id
  try {
    await api.extractReleaseDependencies(provider.value, orgSlug.value, repoSlug.value, release.id)
    if (disposed || scope !== currentScope()) return
    if (release.inventory) release.inventory = { ...release.inventory, state: 'queued', can_extract: false }
    inventoryPolls = 0
    pushToast({ title: 'Extraction queued', description: `Dependencies of ${release.version} will be extracted at its pinned commit, or its tag if not yet pinned.`, tone: 'success' })
    await loadReleases(true)
  } catch (err) {
    if (disposed || scope !== currentScope()) return
    pushToast({ title: 'Extraction failed to queue', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    if (scope === currentScope()) extractingRelease.value = null
  }
}

async function backfillReleases() {
  if (!isReleaseManager.value || backfilling.value || !canBackfillReleases(inventorySummary.value)) return
  const scope = currentScope()
  backfilling.value = true
  backfillError.value = ''
  try {
    const response = await api.extractAllReleases(provider.value, orgSlug.value, repoSlug.value)
    if (disposed || scope !== currentScope()) return
    const result = response.data
    backfillError.value = result.errors.map(item => `${item.release_id}: ${item.error}`).join(' ')
    inventoryPolls = 0
    pushToast({
      title: result.failed ? 'Backfill partially queued' : 'Backfill queued',
      description: `${result.queued} queued, ${result.skipped} already covered or queued, ${result.failed} failed. ${result.remaining} still eligible; each request queues up to 100 releases.`,
      tone: result.failed ? 'error' : 'success',
    })
    await loadReleases(true)
  } catch (err) {
    if (disposed || scope !== currentScope()) return
    backfillError.value = err instanceof Error ? err.message : 'Failed to queue release backfill'
    pushToast({ title: 'Backfill failed to queue', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    if (scope === currentScope()) backfilling.value = false
  }
}

async function rescan(release: ReleaseWithRisk) {
  if (!release.snapshot_id) {
    return
  }
  rescanning.value = release.id
  try {
    await api.triggerComponentScan(provider.value, orgSlug.value, repoSlug.value, {
      ref: release.ref_name,
      snapshot: release.snapshot_id,
    })
    pushToast({ title: 'Re-scan started', description: 'Fresh advisory data lands in a moment; reload to see it.', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Re-scan failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    rescanning.value = null
  }
}

let searchDebounce: ReturnType<typeof setTimeout> | undefined
watch(versionQuery, () => {
  clearTimeout(searchDebounce)
  searchDebounce = setTimeout(() => {
    page.value = 1
    void loadReleases()
  }, 250)
})

watch([clientFilter, vulnerableOnly], () => {
  page.value = 1
  void loadReleases()
})

watch(page, () => void loadReleases())

watch([provider, orgSlug, repoSlug], () => {
  clearTimeout(inventoryTimer)
  clearTimeout(searchDebounce)
  inventorySummary.value = null
  releases.value = []
  loadError.value = ''
  backfillError.value = ''
  extractingRelease.value = null
  backfilling.value = false
  inventoryPolls = 0
  page.value = 1
  expandedId.value = null
  void loadReleases()
  void loadClients()
})

onMounted(() => {
  void loadReleases()
  void loadClients()
})

onUnmounted(() => {
  disposed = true
  requestToken++
  clearTimeout(inventoryTimer)
  clearTimeout(searchDebounce)
})
</script>
