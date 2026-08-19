<template>
  <div class="px-4 pt-5">
    <!-- compare-rise's animation makes this a stacking context, so the ref
         picker dropdowns (z-50 inside) are trapped at this block's level: it
         must sit above the z-20 snapshot row or they render underneath it. -->
    <div class="compare-rise relative z-30">
      <p class="mb-1 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-gray-500">
        <span class="compare-beacon" />
        <span class="compare-display">Compare</span>
      </p>
      <!-- The title IS the control: click either side to change head/base. -->
      <div class="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2">
        <div class="flex min-w-0 items-center gap-1.5">
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="headRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            :repo-html-url="repo?.html_url"
            :provider="repo?.provider"
            hero
            @select="selectHead"
          />
          <a
            v-if="headForgeUrl"
            :href="headForgeUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="shrink-0 text-gray-500 transition hover:text-accent"
            :title="`Open ${headLabel} on ${forgeName}`"
          >
            <ExternalLink class="h-3.5 w-3.5" />
          </a>
        </div>
        <button
          type="button"
          class="compare-swap inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/60 hover:text-white"
          :disabled="!baseRef || !headRef"
          title="Swap base and head"
          aria-label="Swap base and head"
          @click="swapRefs"
        >
          <ArrowLeftRight class="h-4 w-4" />
        </button>
        <div class="flex min-w-0 items-center gap-1.5">
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="baseRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            :repo-html-url="repo?.html_url"
            :provider="repo?.provider"
            hero
            align="right"
            @select="selectBase"
          />
          <a
            v-if="baseForgeUrl"
            :href="baseForgeUrl"
            target="_blank"
            rel="noopener noreferrer"
            class="shrink-0 text-gray-500 transition hover:text-accent"
            :title="`Open ${baseLabel} on ${forgeName}`"
          >
            <ExternalLink class="h-3.5 w-3.5" />
          </a>
        </div>
      </div>
      <span
        v-if="gateState"
        class="absolute right-0 top-0 inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium"
        :class="gateState.badgeClass"
        :title="gateSourceTitle"
      >
        <span
          class="h-1.5 w-1.5 rounded-full"
          :class="gateState.dotClass"
        />
        {{ gateState.label }}
      </span>
    </div>

    <div
      class="compare-rise relative z-20 mt-4 border-b border-surface-border pb-3"
    >
      <div class="compare-comparator grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:items-start lg:gap-6">
        <div class="min-w-0 flex-1 space-y-2">
          <div
            v-if="headSnapshots.length > 0"
            class="flex items-center gap-2"
          >
            <button
              v-if="headSnapshotId"
              type="button"
              class="inline-flex shrink-0 items-center rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.2em] text-gray-300 transition hover:border-accent/50 hover:text-white"
              @click="headSnapshotId = ''"
            >
              Snapshot
            </button>
            <div class="relative min-w-0 flex-1">
              <button
                type="button"
                class="compare-snap-select flex w-full items-center gap-2 rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-left text-xs text-gray-300 transition hover:border-accent/50"
                aria-label="Head snapshot"
                @click.stop="headSnapshotOpen = !headSnapshotOpen"
              >
                <span
                  v-if="selectedHeadSnapshot"
                  class="inline-block h-2 w-2 shrink-0 rounded-full"
                  :class="snapshotDotClass(selectedHeadSnapshot)"
                />
                <span class="flex-1 truncate">{{ selectedHeadSnapshot ? snapshotOptionLabel(selectedHeadSnapshot) : 'Snapshot' }}</span>
                <ChevronDown class="h-3 w-3 shrink-0 text-gray-500" />
              </button>
              <div
                v-if="headSnapshotOpen"
                class="absolute left-0 top-[calc(100%+4px)] z-50 max-h-60 w-full overflow-y-auto rounded-lg border border-surface-border bg-surface-overlay py-1 shadow-2xl"
              >
                <button
                  v-for="snapshot in headSnapshots"
                  :key="snapshot.id"
                  type="button"
                  class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-white/5"
                  :class="headSnapshotId === snapshot.id ? 'text-accent font-medium' : 'text-gray-300'"
                  @click="headSnapshotId = snapshot.id; headSnapshotOpen = false"
                >
                  <span
                    class="inline-block h-2 w-2 shrink-0 rounded-full"
                    :class="snapshotDotClass(snapshot)"
                  />
                  <span class="font-mono">{{ snapshot.commit_sha.slice(0, 7) }}</span>
                  <span :class="snapshotStatusTextClass(snapshot)">{{ snapshotStatusLabel(snapshot) }}</span>
                  <span class="text-gray-500">{{ formatDateTime(snapshot.created_at) }}</span>
                  <span
                    v-if="snapshot.run_number"
                    class="text-gray-500"
                  >#{{ snapshot.run_number }}</span>
                  <span
                    v-if="snapshot.tag"
                    class="rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] text-sky-300"
                  >{{ snapshot.tag }}</span>
                </button>
              </div>
            </div>
          </div>

          <div
            v-if="selectedHeadSnapshot"
            class="flex flex-wrap items-center gap-x-2 gap-y-1 px-1 text-[11px] text-gray-500"
          >
            <span
              class="rounded-full px-2 py-0.5 font-medium"
              :class="snapshotBadgeClass(selectedHeadSnapshot)"
            >
              {{ snapshotStatusLabel(selectedHeadSnapshot) }}
            </span>
            <span class="font-mono text-gray-300">{{ snapshotPrimaryLabel(selectedHeadSnapshot) }}</span>
            <span>{{ snapshotSecondaryLine(selectedHeadSnapshot) }}</span>
          </div>
        </div>

        <div class="min-w-0 flex-1 space-y-2">
          <div
            v-if="baseSnapshots.length > 0"
            class="flex items-center gap-2"
          >
            <div class="relative min-w-0 flex-1">
              <button
                type="button"
                class="compare-snap-select flex w-full items-center gap-2 rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-left text-xs text-gray-300 transition hover:border-accent/50"
                aria-label="Base snapshot"
                @click.stop="baseSnapshotOpen = !baseSnapshotOpen"
              >
                <span
                  v-if="selectedBaseSnapshot"
                  class="inline-block h-2 w-2 shrink-0 rounded-full"
                  :class="snapshotDotClass(selectedBaseSnapshot)"
                />
                <span class="flex-1 truncate">{{ selectedBaseSnapshot ? snapshotOptionLabel(selectedBaseSnapshot) : 'Snapshot' }}</span>
                <ChevronDown class="h-3 w-3 shrink-0 text-gray-500" />
              </button>
              <div
                v-if="baseSnapshotOpen"
                class="absolute right-0 top-[calc(100%+4px)] z-50 max-h-60 w-full overflow-y-auto rounded-lg border border-surface-border bg-surface-overlay py-1 shadow-2xl"
              >
                <button
                  v-for="snapshot in baseSnapshots"
                  :key="snapshot.id"
                  type="button"
                  class="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-white/5"
                  :class="baseSnapshotId === snapshot.id ? 'text-accent font-medium' : 'text-gray-300'"
                  @click="baseSnapshotId = snapshot.id; baseSnapshotOpen = false"
                >
                  <span
                    class="inline-block h-2 w-2 shrink-0 rounded-full"
                    :class="snapshotDotClass(snapshot)"
                  />
                  <span class="font-mono">{{ snapshot.commit_sha.slice(0, 7) }}</span>
                  <span :class="snapshotStatusTextClass(snapshot)">{{ snapshotStatusLabel(snapshot) }}</span>
                  <span class="text-gray-500">{{ formatDateTime(snapshot.created_at) }}</span>
                  <span
                    v-if="snapshot.run_number"
                    class="text-gray-500"
                  >#{{ snapshot.run_number }}</span>
                  <span
                    v-if="snapshot.tag"
                    class="rounded bg-sky-500/15 px-1.5 py-0.5 text-[10px] text-sky-300"
                  >{{ snapshot.tag }}</span>
                </button>
              </div>
            </div>
            <button
              v-if="baseSnapshotId"
              type="button"
              class="inline-flex shrink-0 items-center rounded-lg border border-surface-border bg-surface-overlay px-2.5 py-1.5 text-[11px] font-medium uppercase tracking-[0.2em] text-gray-300 transition hover:border-accent/50 hover:text-white"
              @click="baseSnapshotId = ''"
            >
              Snapshot
            </button>
          </div>

          <div
            v-if="selectedBaseSnapshot"
            class="flex flex-wrap items-center justify-end gap-x-2 gap-y-1 px-1 text-[11px] text-gray-500"
          >
            <span>{{ snapshotSecondaryLine(selectedBaseSnapshot) }}</span>
            <span class="font-mono text-gray-300">{{ snapshotPrimaryLabel(selectedBaseSnapshot) }}</span>
            <span
              class="rounded-full px-2 py-0.5 font-medium"
              :class="snapshotBadgeClass(selectedBaseSnapshot)"
            >
              {{ snapshotStatusLabel(selectedBaseSnapshot) }}
            </span>
          </div>
        </div>
      </div>
    </div>

    <div
      v-if="hasFailedSnapshot"
      class="compare-rise mt-3 flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/[0.06] px-4 py-3 text-sm text-amber-200"
    >
      <ShieldAlert class="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
      <div>
        <p class="font-medium">
          Comparing against a failed build
        </p>
        <p class="mt-0.5 text-xs text-amber-300/70">
          {{ failedSnapshotWarning }} Results may be incomplete or misleading.
        </p>
      </div>
    </div>

    <div
      v-if="loading"
      class="compare-rise relative mt-4 overflow-hidden rounded-xl border border-dashed border-surface-border-subtle px-4 py-6 text-sm text-gray-500"
    >
      <span class="compare-scan" />
      Running comparison…
    </div>

    <div
      v-else-if="error"
      class="relative rounded-2xl border border-danger/30 bg-danger/10 px-4 py-5 text-sm text-danger"
    >
      {{ error }}
    </div>

    <template v-else-if="comparison">
      <!-- Tab bar -->
      <nav class="compare-rise mt-3 flex flex-wrap gap-0.5 border-b border-surface-border">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          type="button"
          class="compare-tab inline-flex items-center gap-2 border-b-2 border-transparent px-3 pb-2.5 pt-1.5 text-sm transition"
          :class="activeTab === tab.id ? 'compare-tab-active text-white' : 'text-gray-400 hover:text-gray-200'"
          @click="activeTab = tab.id"
        >
          <component
            :is="tab.icon"
            class="h-4 w-4"
          />
          <span class="compare-display">{{ tab.label }}</span>
          <span
            v-if="tab.badge"
            class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] font-semibold text-gray-300"
          >{{ tab.badge }}</span>
        </button>
      </nav>

      <!-- Overview tab -->
      <div
        v-show="activeTab === 'overview'"
        class="compare-overview space-y-4"
      >
        <div
          class="compare-verdict compare-rise relative flex items-center gap-4 overflow-hidden rounded-2xl border p-5"
          :class="verdict.shellClass"
        >
          <span
            class="compare-verdict-orb"
            :class="verdict.orbClass"
          />
          <div class="relative">
            <p
              class="text-xs uppercase tracking-[0.22em]"
              :class="verdict.eyebrowClass"
            >
              {{ verdict.eyebrow }}
            </p>
            <p class="compare-display mt-1 text-xl font-semibold text-white">
              {{ verdict.headline }}
            </p>
            <p class="mt-1 text-sm text-gray-400">
              {{ verdict.detail }}
            </p>
          </div>
        </div>

        <div
          v-if="gateReasons.length > 0"
          class="rounded-2xl border border-danger/30 bg-danger/10 p-4 text-sm text-danger"
        >
          <p class="font-medium text-white">
            Gate reasons
          </p>
          <ul class="mt-2 space-y-1">
            <li
              v-for="reason in gateReasons"
              :key="reason"
            >
              <button
                type="button"
                class="text-left underline decoration-danger/40 underline-offset-2 transition hover:decoration-danger"
                title="Show exactly the findings behind this reason"
                @click="openSecurityForReason(reason)"
              >
                {{ reason }}
              </button>
            </li>
          </ul>
        </div>

        <div class="compare-grid grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <button
            type="button"
            style="--i: 0"
            class="compare-stat group flex flex-col rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-5 text-left transition hover:border-accent/50"
            @click="activeTab = 'security'"
          >
            <div class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
              <ShieldAlert class="h-4 w-4 text-accent" />
              Security
            </div>
            <div class="mt-4 flex items-baseline gap-2">
              <span class="text-3xl font-semibold text-white">{{ comparison.delta.new_vulnerabilities.length }}</span>
              <span class="text-sm text-gray-500">new</span>
            </div>
            <p class="mt-2 text-sm">
              <span :class="comparison.delta.resolved_vulnerabilities.length > 0 ? 'text-emerald-300' : 'text-gray-400'">
                {{ comparison.delta.resolved_vulnerabilities.length }} resolved
              </span>
            </p>
          </button>

          <button
            type="button"
            style="--i: 1"
            class="compare-stat group flex flex-col rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-5 text-left transition hover:border-accent/50"
            @click="activeTab = 'coverage'"
          >
            <div class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
              <GaugeCircle class="h-4 w-4 text-accent" />
              Coverage
            </div>
            <div
              v-if="coverageDiff"
              class="mt-4 flex items-baseline gap-2"
            >
              <component
                :is="trendIcon(coverageDiff.line_rate_delta)"
                class="h-5 w-5 self-center"
                :style="{ color: deltaColor(coverageDiff.line_rate_delta) }"
              />
              <span
                class="text-3xl font-semibold"
                :style="{ color: deltaColor(coverageDiff.line_rate_delta) }"
              >{{ formatRateDelta(coverageDiff.line_rate_delta) }}</span>
            </div>
            <div
              v-else
              class="mt-4 text-2xl font-semibold text-gray-600"
            >
              —
            </div>
            <p class="mt-2 text-sm text-gray-400">
              <template v-if="coverageDiff">
                {{ formatRate(coverageDiff.base?.line_rate ?? null) }} → {{ formatRate(coverageDiff.head?.line_rate ?? null) }} line
              </template>
              <template v-else>
                No coverage data
              </template>
            </p>
          </button>

          <button
            type="button"
            style="--i: 2"
            class="compare-stat group flex flex-col rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-5 text-left transition hover:border-accent/50"
            @click="activeTab = 'tests'"
          >
            <div class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
              <FlaskConical class="h-4 w-4 text-accent" />
              Tests
            </div>
            <div
              v-if="testDiff"
              class="mt-4 flex items-baseline gap-3"
            >
              <span class="text-3xl font-semibold text-white">{{ testDiff.added.length }}</span>
              <span class="text-sm text-gray-500">added · {{ testDiff.removed.length }} removed</span>
            </div>
            <div
              v-else
              class="mt-4 text-2xl font-semibold text-gray-600"
            >
              —
            </div>
            <p
              v-if="testDiff"
              class="mt-2 text-sm text-gray-400"
            >
              <span
                v-if="testDiff.slower.length > 0"
                class="text-danger"
              >{{ testDiff.slower.length }} slower</span>
              <span v-else>{{ testDiff.status_changed.length }} status changes</span>
              <span class="text-gray-600"> · </span>
              <span :style="{ color: deltaColor(-testDiff.duration_delta_seconds) }">{{ formatDurationDelta(testDiff.duration_delta_seconds) }}</span>
            </p>
            <p
              v-else
              class="mt-2 text-sm text-gray-400"
            >
              No test data
            </p>
          </button>

          <button
            type="button"
            style="--i: 3"
            class="compare-stat group flex flex-col rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-5 text-left transition hover:border-accent/50"
            @click="activeTab = 'components'"
          >
            <div class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
              <Package class="h-4 w-4 text-accent" />
              Components
            </div>
            <div class="mt-4 flex items-baseline gap-2">
              <span class="text-3xl font-semibold text-white">{{ comparison.component_diff.added.length }}</span>
              <span class="text-sm text-gray-500">added</span>
            </div>
            <p class="mt-2 text-sm text-gray-400">
              {{ comparison.component_diff.updated?.length ?? 0 }} updated · {{ comparison.component_diff.removed.length }} removed
            </p>
          </button>
        </div>
      </div>

      <!-- Security tab: delta grouped by CAUSE — one decision per cause. -->
      <div
        v-show="activeTab === 'security'"
        class="space-y-3"
      >
        <TriageDialog
          v-if="groupDialog"
          :kind="groupDialog.kind"
          :count="groupDialog.group.rows.length"
          :error="groupDialogError"
          :submitting="groupDialogSubmitting"
          @cancel="groupDialog = null"
          @confirm="confirmGroupAccept"
        />
        <div
          v-if="headScanRunning"
          class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-2 text-xs text-amber-300"
        >
          Scanning components against advisory providers… this list may still change.
        </div>
        <div
          v-if="securitySeverityFilter"
          class="flex items-center gap-2 text-xs text-gray-400"
        >
          Showing only
          <span :class="severityBadgeClass(securitySeverityFilter)">{{ securitySeverityFilter }}</span>
          findings (from a gate reason)
          <button
            type="button"
            class="underline transition hover:text-white"
            @click="securitySeverityFilter = ''"
          >
            clear
          </button>
        </div>
        <div
          v-if="securityGroups.length === 0"
          class="rounded-2xl border border-surface-border-subtle px-4 py-10 text-sm text-gray-500"
        >
          {{ headScanRunning ? 'No vulnerability changes yet — scan in progress.' : 'No vulnerability changes between these refs.' }}
        </div>
        <div
          v-for="group in securityGroups"
          :key="group.key"
          class="overflow-hidden rounded-2xl border border-surface-border-subtle"
        >
          <div
            class="flex flex-wrap items-center gap-3 bg-surface-overlay/60 px-4 py-2.5"
          >
            <button
              type="button"
              class="flex min-w-0 flex-1 items-center gap-2 text-left"
              @click="toggleGroup(group.key)"
            >
              <ChevronDown
                class="h-4 w-4 shrink-0 text-gray-500 transition"
                :class="expandedGroups.has(group.key) ? '' : '-rotate-90'"
              />
              <span
                v-if="group.kind === 'resolved'"
                :class="changeBadgeClass('resolved')"
              >resolved</span>
              <span
                v-else
                :class="changeBadgeClass('new')"
              >new</span>
              <span class="min-w-0 truncate text-sm font-medium text-white">{{ group.label }}</span>
              <span class="shrink-0 rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] font-semibold text-gray-300">{{ group.rows.length }}</span>
              <span class="hidden truncate text-xs text-gray-500 sm:inline">{{ group.context }}</span>
            </button>
            <span
              v-if="groupAcceptedKeys.has(group.key)"
              class="whitespace-nowrap rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[11px] font-medium text-amber-300"
            >Risk accepted</span>
            <template v-else-if="group.kind === 'dependency' && group.fingerprints.length > 0">
              <button
                type="button"
                class="whitespace-nowrap rounded-lg border border-surface-border px-2 py-1 text-[11px] text-gray-300 transition hover:border-accent/50 hover:text-white"
                :title="`One decision for the whole component: accept all ${group.rows.length} findings with one reason`"
                @click.stop="openGroupAccept('risk_accepted', group)"
              >
                Accept component…
              </button>
            </template>
          </div>
          <div
            v-if="expandedGroups.has(group.key)"
            class="overflow-x-auto"
          >
            <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
              <tbody class="divide-y divide-surface-border-subtle">
                <tr
                  v-for="vuln in group.rows"
                  :key="`${vuln.change}-${vuln.id}`"
                  class="transition hover:bg-white/5"
                >
                  <td class="w-24 px-4 py-3">
                    <span :class="severityBadgeClass(vuln.severity)">{{ vuln.severity }}</span>
                  </td>
                  <td class="px-4 py-3 font-mono text-xs text-accent">
                    {{ vuln.primary_identifier_value || vuln.scanner_name || 'n/a' }}
                  </td>
                  <td class="max-w-md truncate px-4 py-3 text-gray-300">
                    {{ vuln.title }}
                  </td>
                  <!-- Kind-specific cell: a dep vuln is not a SAST hit. -->
                  <td class="px-4 py-3 text-xs text-gray-400">
                    <template v-if="group.kind === 'dependency'">
                      <span
                        v-if="vuln.reachability === 'not_reachable'"
                        class="mr-2 rounded-full border border-surface-border bg-surface-overlay px-1.5 py-0.5 text-[10px] text-gray-500"
                        title="Vulnerable symbol never called (govulncheck)"
                      >unreachable</span>
                      <span
                        v-if="vuln.has_remediation && vuln.remediation_link"
                        class="text-emerald-300"
                      >
                        <a
                          :href="vuln.remediation_link"
                          target="_blank"
                          rel="noopener noreferrer"
                          class="underline"
                        >fix available</a>
                      </span>
                      <span
                        v-else-if="vuln.has_remediation"
                        class="text-emerald-300"
                      >fix available</span>
                      <span v-else>no fix yet</span>
                    </template>
                    <template v-else-if="group.kind === 'secret'">
                      <span class="text-gray-400">{{ vulnerabilityLocation(vuln) }}</span>
                      <span
                        v-if="vuln.change === 'resolved'"
                        class="ml-2 text-amber-300"
                        title="A secret vanishing from the diff says nothing about the credential — the repo finding stays open until revocation is attested"
                      >still needs attestation</span>
                    </template>
                    <template v-else>
                      <a
                        v-if="vuln.file_path && forgeFileLink(vuln.file_path)"
                        :href="forgeFileLink(vuln.file_path)!"
                        target="_blank"
                        rel="noopener noreferrer"
                        class="underline decoration-gray-600 underline-offset-2 transition hover:text-white"
                      >{{ vulnerabilityLocation(vuln) }}</a>
                      <span v-else>{{ vulnerabilityLocation(vuln) }}</span>
                    </template>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
        <p
          v-if="comparison.delta.unchanged_vulnerabilities > 0"
          class="px-1 text-xs text-gray-500"
        >
          {{ comparison.delta.unchanged_vulnerabilities }} unchanged {{ comparison.delta.unchanged_vulnerabilities === 1 ? 'finding' : 'findings' }} carried over —
          <RouterLink
            :to="{ name: 'repo-vulnerabilities', params: { provider, slug, repoSlug }, query: comparison.head.snapshot_id ? { snapshot: comparison.head.snapshot_id } : {} }"
            class="underline transition hover:text-white"
          >
            view them with their triage state
          </RouterLink>
        </p>
      </div>

      <!-- Coverage tab -->
      <div
        v-show="activeTab === 'coverage'"
        class="space-y-4"
      >
        <div
          v-if="!coverageDiff"
          class="rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-sm text-gray-500"
        >
          Neither snapshot has coverage data to compare.
        </div>

        <template v-else>
          <!-- Patch (diff) coverage — the headline PR signal: of the lines this
               change added or modified, which are actually tested. -->
          <div
            v-if="patchCoverage"
            class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4"
          >
            <div class="flex flex-wrap items-end gap-x-6 gap-y-3">
              <div>
                <p class="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-gray-500">
                  <GitPullRequest class="h-4 w-4 text-accent" />
                  Patch coverage
                </p>
                <div class="mt-2 flex items-baseline gap-2">
                  <span
                    class="text-3xl font-semibold"
                    :style="{ color: rateColor(patchCoverage.rate) }"
                  >{{ formatRate(patchCoverage.rate) }}</span>
                  <span class="text-sm text-gray-400">
                    {{ patchCoverage.covered_lines }}/{{ patchTotalLines(patchCoverage) }} new lines covered
                  </span>
                </div>
              </div>
              <div
                v-if="patchCoverage.uncovered_lines > 0"
                class="ml-auto rounded-full border border-danger/40 bg-danger/10 px-3 py-1 text-xs font-medium text-danger"
              >
                {{ patchCoverage.uncovered_lines }} uncovered new {{ patchCoverage.uncovered_lines === 1 ? 'line' : 'lines' }}
              </div>
              <div
                v-else
                class="ml-auto rounded-full border border-emerald-500/40 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-300"
              >
                Every new line covered
              </div>
            </div>

            <div class="mt-3 h-1.5 w-full rounded-full bg-surface-overlay">
              <div
                class="h-1.5 rounded-full transition-all"
                :style="coverageBarStyle(patchCoverage.rate)"
              />
            </div>

            <p
              v-if="patchCoverage.truncated"
              class="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-300"
            >
              The forge truncated the diff; patch coverage reflects the first files only.
            </p>

            <div
              v-if="patchCoverage.files.length"
              class="mt-4 space-y-2"
            >
              <div
                v-for="file in patchCoverage.files"
                :key="file.file_path"
                class="rounded-xl border border-surface-border-subtle bg-surface-base/40 p-3"
              >
                <div class="flex items-center justify-between gap-3">
                  <button
                    v-if="file.hunks"
                    type="button"
                    class="flex min-w-0 items-center gap-1.5 text-left transition hover:text-white"
                    @click="togglePatchFile(file.file_path)"
                  >
                    <ChevronDown
                      class="h-3.5 w-3.5 shrink-0 text-gray-500 transition-transform"
                      :class="expandedPatchFiles.has(file.file_path) ? '' : '-rotate-90'"
                    />
                    <span class="truncate font-mono text-xs text-gray-200">{{ file.file_path }}</span>
                  </button>
                  <span
                    v-else
                    class="truncate font-mono text-xs text-gray-200"
                  >{{ file.file_path }}</span>
                  <span class="flex shrink-0 items-center gap-2">
                    <span
                      class="text-xs font-medium"
                      :style="{ color: rateColor(file.rate) }"
                    >
                      {{ formatRate(file.rate) }} · {{ file.covered_lines }}/{{ patchTotalLines(file) }}
                    </span>
                    <a
                      v-if="forgeFileLink(file.file_path)"
                      :href="forgeFileLink(file.file_path)!"
                      target="_blank"
                      rel="noopener noreferrer"
                      class="rounded p-0.5 text-gray-500 transition hover:text-white"
                      :title="`Open ${file.file_path} on ${forgeName}`"
                      :aria-label="`Open ${file.file_path} on ${forgeName}`"
                    >
                      <ExternalLink class="h-3.5 w-3.5" />
                    </a>
                  </span>
                </div>
                <div
                  v-if="file.uncovered_line_numbers && file.uncovered_line_numbers.length"
                  class="mt-2 flex flex-wrap items-center gap-1.5"
                >
                  <span class="text-[11px] uppercase tracking-wide text-gray-500">Uncovered</span>
                  <span
                    v-for="range in formatLineRanges(file.uncovered_line_numbers)"
                    :key="range"
                    class="rounded bg-danger/15 px-1.5 py-0.5 font-mono text-[11px] text-danger"
                  >L{{ range }}</span>
                </div>
                <div
                  v-else
                  class="mt-2 text-[11px] text-emerald-300"
                >
                  All changed lines covered
                </div>
                <div
                  v-if="file.hunks && expandedPatchFiles.has(file.file_path)"
                  class="mt-3"
                >
                  <PatchDiffFile
                    :hunks="file.hunks"
                    :covered-lines="file.covered_line_numbers ?? []"
                    :uncovered-lines="file.uncovered_line_numbers ?? []"
                    :head-covered-lines="file.head_covered_lines"
                    :head-uncovered-lines="file.head_uncovered_lines"
                    :base-covered-lines="file.base_covered_lines"
                    :base-uncovered-lines="file.base_uncovered_lines"
                  />
                </div>
              </div>
            </div>
          </div>

          <!-- New code first: "is what this change introduced tested?" is the
               question reviewers actually ask; the absolute rate is history. -->
          <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                New code coverage
              </p>
              <span class="text-xs text-gray-500">lines this comparison changed</span>
            </div>
            <div
              v-if="coverageDiff.new_line_rate !== null"
              class="mt-3 flex flex-wrap items-center gap-3"
            >
              <span
                class="text-2xl font-semibold"
                :style="{ color: rateColor(coverageDiff.new_line_rate) }"
              >{{ formatRate(coverageDiff.new_line_rate) }}</span>
              <span class="text-sm text-gray-400">
                {{ coverageDiff.new_covered }}/{{ coverageDiff.new_lines }} changed lines covered
              </span>
              <span
                v-if="coverageDiff.new_code_truncated"
                class="rounded border border-warning/40 bg-warning/10 px-2 py-0.5 text-[11px] text-warning"
                title="The forge capped the compared file list, so this covers only the first files."
              >partial — forge truncated the file list</span>
            </div>
            <p
              v-else
              class="mt-3 text-sm text-gray-500"
            >
              No measurable new code in this comparison — the changed lines are not instrumented (docs, comments, or files without coverage).
            </p>
          </div>

          <div class="grid gap-3 sm:grid-cols-2">
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Line coverage
              </p>
              <div class="mt-3 flex items-center gap-3">
                <span :style="{ color: rateColor(coverageDiff.base?.line_rate ?? null) }">{{ formatRate(coverageDiff.base?.line_rate ?? null) }}</span>
                <ArrowRight class="h-4 w-4 text-gray-600" />
                <span
                  class="text-lg font-semibold"
                  :style="{ color: rateColor(coverageDiff.head?.line_rate ?? null) }"
                >{{ formatRate(coverageDiff.head?.line_rate ?? null) }}</span>
                <span
                  class="ml-auto text-sm font-semibold"
                  :style="{ color: deltaColor(coverageDiff.line_rate_delta) }"
                >{{ formatRateDelta(coverageDiff.line_rate_delta) }}</span>
              </div>
            </div>
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Branch coverage
              </p>
              <div class="mt-3 flex items-center gap-3">
                <span :style="{ color: rateColor(coverageDiff.base?.branch_rate ?? null) }">{{ formatRate(coverageDiff.base?.branch_rate ?? null) }}</span>
                <ArrowRight class="h-4 w-4 text-gray-600" />
                <span
                  class="text-lg font-semibold"
                  :style="{ color: rateColor(coverageDiff.head?.branch_rate ?? null) }"
                >{{ formatRate(coverageDiff.head?.branch_rate ?? null) }}</span>
                <span
                  class="ml-auto text-sm font-semibold"
                  :style="{ color: deltaColor(coverageDiff.branch_rate_delta) }"
                >{{ formatRateDelta(coverageDiff.branch_rate_delta) }}</span>
              </div>
            </div>
          </div>

          <div class="overflow-hidden rounded-2xl border border-surface-border-subtle">
            <div class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
              <h3 class="text-sm font-semibold text-white">
                Per-file changes
              </h3>
              <div class="flex flex-wrap items-center gap-3">
                <label
                  class="flex cursor-pointer items-center gap-1.5 text-xs"
                  :class="newCodeOnly ? 'text-white' : 'text-gray-400'"
                  title="Show only files with lines this comparison changed"
                >
                  <input
                    v-model="newCodeOnly"
                    type="checkbox"
                    class="h-3.5 w-3.5 rounded border-surface-border bg-surface-overlay accent-[--color-accent]"
                  >
                  new code only
                </label>
                <label
                  v-if="!newCodeOnly"
                  class="flex cursor-pointer items-center gap-1.5 text-xs text-gray-400"
                >
                  <input
                    v-model="showUnchangedCoverage"
                    type="checkbox"
                    class="h-3.5 w-3.5 rounded border-surface-border bg-surface-overlay accent-[--color-accent]"
                  >
                  show unchanged files
                </label>
                <div class="flex overflow-hidden rounded-lg border border-surface-border">
                  <button
                    type="button"
                    class="px-2.5 py-1 text-xs transition"
                    :class="coverageFilesView === 'list' ? 'bg-accent/15 text-white' : 'bg-surface-overlay text-gray-400 hover:text-white'"
                    @click="coverageFilesView = 'list'"
                  >
                    List
                  </button>
                  <button
                    type="button"
                    class="px-2.5 py-1 text-xs transition"
                    :class="coverageFilesView === 'tree' ? 'bg-accent/15 text-white' : 'bg-surface-overlay text-gray-400 hover:text-white'"
                    @click="coverageFilesView = 'tree'"
                  >
                    Tree
                  </button>
                </div>
                <span class="text-xs text-gray-500">{{ coverageDiff.unchanged_files }} unchanged</span>
              </div>
            </div>
            <CoverageTreeView
              v-if="coverageFilesView === 'tree' && compareTreeFiles.length > 0"
              :files="compareTreeFiles"
              @select-file="openCompareSource"
            />
            <div
              v-else-if="coverageFilesView === 'tree'"
              class="px-4 py-8 text-sm text-gray-500"
            >
              {{ newCodeOnly ? 'No files with measurable new code in this comparison — the changed lines are not instrumented.' : `No coverage files to show${showUnchangedCoverage ? '' : ' — try "show unchanged files"'}.` }}
            </div>
            <div
              v-else-if="compareListRows.length === 0"
              class="px-4 py-8 text-sm text-gray-500"
            >
              {{ newCodeOnly ? 'No files with measurable new code in this comparison — the changed lines are not instrumented.' : `No per-file coverage changes between these refs${showUnchangedCoverage ? '' : ' — "show unchanged files" lists the rest'}.` }}
            </div>
            <div
              v-else
              class="overflow-x-auto"
            >
              <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
                <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
                  <tr>
                    <th class="px-4 py-3 font-medium">
                      Change
                    </th>
                    <th class="px-4 py-3 font-medium">
                      File
                    </th>
                    <th class="px-4 py-3 font-medium">
                      Base → Head
                    </th>
                    <th class="px-4 py-3 font-medium">
                      Δ
                    </th>
                    <th class="px-4 py-3 font-medium">
                      New lines
                    </th>
                    <th class="px-4 py-3 font-medium">
                      Lines
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-border-subtle">
                  <tr
                    v-for="file in compareListRows"
                    :key="`${file.change}-${file.file_path}`"
                    class="cursor-pointer transition hover:bg-white/5"
                    @click="openCompareSource(file.file_path)"
                  >
                    <td class="px-4 py-3 align-top">
                      <span :class="coverageChangeBadgeClass(file.change)">{{ file.change }}</span>
                    </td>
                    <td class="px-4 py-3 align-top font-mono text-xs text-gray-200">
                      {{ file.file_path }}
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="flex items-center gap-2">
                        <span :style="{ color: rateColor(file.base_line_rate) }">{{ formatRate(file.base_line_rate) }}</span>
                        <ArrowRight class="h-3.5 w-3.5 text-gray-600" />
                        <span
                          class="font-medium"
                          :style="{ color: rateColor(file.head_line_rate) }"
                        >{{ formatRate(file.head_line_rate) }}</span>
                      </div>
                      <div class="mt-2 h-1.5 w-40 rounded-full bg-surface-overlay">
                        <div
                          class="h-1.5 rounded-full"
                          :style="coverageBarStyle(file.head_line_rate ?? file.base_line_rate)"
                        />
                      </div>
                    </td>
                    <td
                      class="px-4 py-3 align-top text-sm font-semibold"
                      :style="{ color: deltaColor(file.line_rate_delta) }"
                    >
                      {{ formatRateDelta(file.line_rate_delta) }}
                    </td>
                    <td class="px-4 py-3 align-top text-xs">
                      <template v-if="patchFileByPath.has(file.file_path)">
                        <span class="font-medium text-blue-300">+{{ patchFileByPath.get(file.file_path)!.covered_lines }} covered</span>
                        <span
                          v-if="patchFileByPath.get(file.file_path)!.uncovered_lines > 0"
                          class="ml-2 font-medium text-orange-300"
                        >+{{ patchFileByPath.get(file.file_path)!.uncovered_lines }} uncovered</span>
                      </template>
                      <template v-else-if="file.new_lines > 0">
                        <span class="font-medium text-blue-300">{{ file.new_covered }} covered</span>
                        <span
                          v-if="file.new_lines - file.new_covered > 0"
                          class="ml-2 font-medium text-orange-300"
                        >{{ file.new_lines - file.new_covered }} uncovered</span>
                      </template>
                      <span
                        v-else
                        class="text-gray-600"
                        title="No instrumented line changed in this file"
                      >—</span>
                    </td>
                    <td class="px-4 py-3 align-top text-gray-300">
                      {{ file.base_lines_covered }}/{{ file.base_lines_valid }} → {{ file.head_lines_covered }}/{{ file.head_lines_valid }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </template>

        <CoverageSourceModal
          v-if="compareSourceFile && headCoverage"
          :provider="provider"
          :slug="slug"
          :repo-slug="repoSlug"
          :snapshot-id="headCoverage.snapshot_id"
          :path="compareSourceFile"
          :repo-html-url="repo?.html_url"
          @close="compareSourceFile = null"
        />
      </div>

      <!-- Tests tab -->
      <div
        v-show="activeTab === 'tests'"
        class="space-y-4"
      >
        <div
          v-if="!testDiff"
          class="rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-sm text-gray-500"
        >
          Neither snapshot has test results to compare.
        </div>

        <template v-else>
          <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Total
              </p>
              <p class="mt-2 text-lg font-semibold text-white">
                {{ testDiff.base?.total ?? 0 }} → {{ testDiff.head?.total ?? 0 }}
              </p>
            </div>
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Failed
              </p>
              <p
                class="mt-2 text-lg font-semibold"
                :class="(testDiff.head?.failed ?? 0) > (testDiff.base?.failed ?? 0) ? 'text-danger' : 'text-white'"
              >
                {{ testDiff.base?.failed ?? 0 }} → {{ testDiff.head?.failed ?? 0 }}
              </p>
            </div>
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Skipped
              </p>
              <p class="mt-2 text-lg font-semibold text-white">
                {{ testDiff.base?.skipped ?? 0 }} → {{ testDiff.head?.skipped ?? 0 }}
              </p>
            </div>
            <div class="rounded-2xl border border-surface-border-subtle bg-surface-overlay/70 p-4">
              <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
                Duration
              </p>
              <p class="mt-2 flex items-baseline gap-2">
                <span class="text-lg font-semibold text-white">{{ formatDuration(testDiff.head?.duration_seconds ?? 0) }}</span>
                <span
                  class="text-sm font-semibold"
                  :style="{ color: deltaColor(-testDiff.duration_delta_seconds) }"
                >{{ formatDurationDelta(testDiff.duration_delta_seconds) }}</span>
              </p>
            </div>
          </div>

          <div
            v-for="group in visibleTestGroups"
            :key="group.key"
            class="overflow-hidden rounded-2xl border border-surface-border-subtle"
          >
            <div class="flex items-center gap-2 border-b border-surface-border-subtle bg-surface-overlay/60 px-4 py-3">
              <span :class="group.badgeClass">{{ group.label }}</span>
              <span class="text-xs text-gray-500">{{ group.items.length }}</span>
              <span class="ml-2 text-xs text-gray-500">{{ group.hint }}</span>
            </div>
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
                <thead class="bg-surface-overlay/40 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
                  <tr>
                    <th class="px-4 py-2.5 font-medium">
                      Test
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Suite
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Status
                    </th>
                    <th class="px-4 py-2.5 font-medium">
                      Duration
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-border-subtle">
                  <tr
                    v-for="testCase in group.items"
                    :key="`${group.key}-${testCase.suite}-${testCase.classname}-${testCase.name}`"
                    class="transition hover:bg-white/5"
                  >
                    <td class="px-4 py-3 align-top">
                      <div class="font-medium text-gray-100">
                        {{ testCase.name }}
                      </div>
                      <div
                        v-if="testCase.file_path"
                        class="text-xs text-gray-500"
                      >
                        {{ testCase.file_path }}
                      </div>
                    </td>
                    <td class="px-4 py-3 align-top text-gray-400">
                      {{ testCase.suite || testCase.classname || '—' }}
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div
                        v-if="group.key === 'status_changed'"
                        class="flex items-center gap-2"
                      >
                        <span :class="statusBadgeClass(testCase.base_status)">{{ testCase.base_status || 'n/a' }}</span>
                        <ArrowRight class="h-3.5 w-3.5 text-gray-600" />
                        <span :class="statusBadgeClass(testCase.head_status)">{{ testCase.head_status || 'n/a' }}</span>
                      </div>
                      <span
                        v-else
                        :class="statusBadgeClass(group.key === 'removed' ? testCase.base_status : testCase.head_status)"
                      >{{ (group.key === 'removed' ? testCase.base_status : testCase.head_status) || 'n/a' }}</span>
                    </td>
                    <td class="px-4 py-3 align-top">
                      <div class="text-gray-300">
                        <template v-if="group.key === 'added'">
                          {{ formatDuration(testCase.head_duration_seconds) }}
                        </template>
                        <template v-else-if="group.key === 'removed'">
                          {{ formatDuration(testCase.base_duration_seconds) }}
                        </template>
                        <template v-else>
                          {{ formatDuration(testCase.base_duration_seconds) }} → {{ formatDuration(testCase.head_duration_seconds) }}
                        </template>
                      </div>
                      <div
                        v-if="group.key === 'slower' || group.key === 'faster'"
                        class="text-xs font-semibold"
                        :style="{ color: deltaColor(-testCase.duration_delta_seconds) }"
                      >
                        {{ formatDurationDelta(testCase.duration_delta_seconds) }}
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <div
            v-if="testChangeCount === 0"
            class="rounded-2xl border border-dashed border-surface-border-subtle px-4 py-8 text-sm text-gray-500"
          >
            No test additions, removals, status changes, or significant timing changes.
          </div>
        </template>
      </div>

      <!-- Components tab -->
      <div
        v-show="activeTab === 'components'"
        class="overflow-hidden rounded-2xl border border-surface-border-subtle"
      >
        <div
          v-if="headScanRunning"
          class="border-b border-surface-border-subtle bg-surface-overlay/40 px-4 py-2 text-xs text-amber-300"
        >
          Scanning components against advisory providers… vulnerability counts may still change.
        </div>
        <div
          v-if="newLicenses.length > 0"
          class="border-b border-surface-border-subtle px-4 py-3"
        >
          <div class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-500">
            New licenses introduced by this change
          </div>
          <div class="mt-2 flex flex-wrap gap-2">
            <button
              v-for="[licenseId, count] in newLicenses"
              :key="licenseId"
              type="button"
              class="rounded-full border border-amber-400/40 bg-amber-400/10 px-2.5 py-1 text-xs text-amber-200 transition hover:bg-amber-400/20"
              :title="`${count} component(s) — click to filter`"
              @click="componentSearch = licenseId"
            >
              {{ licenseId }} <span class="text-amber-400/70">×{{ count }}</span>
            </button>
          </div>
        </div>
        <div
          v-if="componentRows.length > 0"
          class="flex flex-wrap items-center gap-2 border-b border-surface-border-subtle px-4 py-2.5"
        >
          <input
            v-model="componentSearch"
            type="text"
            placeholder="Filter by name, purl, license…"
            class="w-64 rounded-lg border border-surface-border bg-surface-overlay/40 px-2.5 py-1.5 text-xs text-gray-200 placeholder:text-gray-600 focus:border-accent/50 focus:outline-none"
          >
          <select
            v-model="componentChangeFilter"
            class="rounded-lg border border-surface-border bg-surface-overlay/40 px-2 py-1.5 text-xs text-gray-300"
          >
            <option value="">
              all changes
            </option>
            <option value="added">
              added
            </option>
            <option value="updated">
              updated
            </option>
            <option value="removed">
              removed
            </option>
          </select>
          <select
            v-model="componentEcosystemFilter"
            class="rounded-lg border border-surface-border bg-surface-overlay/40 px-2 py-1.5 text-xs text-gray-300"
          >
            <option value="">
              all ecosystems
            </option>
            <option
              v-for="eco in componentEcosystems"
              :key="eco"
              :value="eco"
            >
              {{ eco }}
            </option>
          </select>
          <span class="ml-auto text-xs text-gray-500">{{ filteredComponentRows.length }} / {{ componentRows.length }}</span>
        </div>
        <div
          v-if="componentRows.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No component changes between these refs.
        </div>
        <div
          v-else
          class="overflow-x-auto"
        >
          <table class="min-w-full divide-y divide-surface-border-subtle text-sm">
            <thead class="bg-surface-overlay/60 text-left text-xs uppercase tracking-[0.18em] text-gray-500">
              <tr>
                <th class="px-4 py-3 font-medium">
                  Change
                </th>
                <th class="px-4 py-3 font-medium">
                  Package
                </th>
                <th class="px-4 py-3 font-medium">
                  Version
                </th>
                <th class="px-4 py-3 font-medium">
                  Ecosystem
                </th>
                <th class="px-4 py-3 font-medium">
                  License
                </th>
                <th class="px-4 py-3 font-medium">
                  Vulns
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="component in filteredComponentRows"
                :key="`${component.change}-${component.purl || `${component.name}-${component.version}`}`"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="changeBadgeClass(component.change)">{{ component.change }}</span>
                </td>
                <td class="px-4 py-4 text-gray-200">
                  <div class="font-medium">
                    {{ component.name }}
                  </div>
                  <div class="text-xs text-gray-500">
                    {{ component.purl }}
                  </div>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ component.version }}
                </td>
                <td class="px-4 py-4">
                  <span class="rounded-full border border-surface-border px-2.5 py-1 text-xs uppercase tracking-[0.14em] text-gray-300">
                    {{ component.ecosystem }}
                  </span>
                </td>
                <td class="px-4 py-4 text-xs">
                  <div
                    v-if="component.licenses?.length"
                    class="flex flex-wrap gap-1"
                  >
                    <span
                      v-for="licenseId in component.licenses.slice(0, 2)"
                      :key="licenseId"
                      class="rounded border border-surface-border px-1.5 py-0.5 font-mono text-[11px] text-gray-300"
                    >{{ licenseId }}</span>
                    <span
                      v-if="component.licenses.length > 2"
                      class="text-gray-500"
                      :title="component.licenses.join(', ')"
                    >+{{ component.licenses.length - 2 }}</span>
                  </div>
                  <span
                    v-else
                    class="rounded border border-amber-400/40 px-1.5 py-0.5 text-[11px] text-amber-300"
                    title="No license metadata — fails the gate when deny_unknown is on"
                  >unknown</span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ component.vuln_count }}
                  <span
                    v-if="component.vuln_delta !== null && component.vuln_delta !== 0"
                    :class="component.vuln_delta < 0 ? 'text-emerald-400' : 'text-danger'"
                    class="ml-1 text-xs"
                  >({{ component.vuln_delta > 0 ? '+' : '' }}{{ component.vuln_delta }})</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ArrowLeftRight, ArrowRight, ArrowDownRight, ArrowUpRight, ChevronDown, ExternalLink, FlaskConical, GaugeCircle, GitPullRequest, LayoutDashboard, Minus, Package, ShieldAlert } from 'lucide-vue-next'
import { useRoute, useRouter } from 'vue-router'

import { api, type AcceptanceReasonKind, type CompareResult, type ComponentEntry, type CoverageFileDelta, type CoverageReport, type EnhancedRef, type PatchFileCoverage, type Repository, type Snapshot, type TestCaseDelta, type Vulnerability } from '@/api/client'
import BranchPRSelector from '@/components/BranchPRSelector.vue'
import TriageDialog from '@/components/TriageDialog.vue'
import CoverageSourceModal from '@/components/CoverageSourceModal.vue'
import CoverageTreeView from '@/components/CoverageTreeView.vue'
import PatchDiffFile from '@/components/PatchDiffFile.vue'
import { forgeFileUrl, forgeLabel, forgeRefUrl } from '@/lib/forgeLinks'

type VulnRow = Vulnerability & { change: 'new' | 'resolved' }
type ComponentRow = Omit<ComponentEntry, 'version'> & {
  version: string
  vuln_delta: number | null
  change: 'added' | 'removed' | 'updated'
}
type TabId = 'overview' | 'security' | 'coverage' | 'tests' | 'components'

const route = useRoute()
const router = useRouter()

// ─── Core state ───────────────────────────────────────────────────────────────
const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const comparison = ref<CompareResult | null>(null)
const headCoverage = ref<CoverageReport | null>(null)
const coverageFilesView = ref<'list' | 'tree'>('tree')
const showUnchangedCoverage = ref(false)
// New-code lens (ADR-019). Default on for PR comparisons — reviewing a PR is
// exactly when only the changed lines matter — off for branch comparisons.
const newCodeOnly = ref(false)
const compareSourceFile = ref<string | null>(null)

watch(
  () => comparison.value?.head,
  async (head) => {
    headCoverage.value = null
    showUnchangedCoverage.value = false
    newCodeOnly.value = comparison.value?.pr != null
    if (!head?.ref_name) return
    try {
      const res = await api.getCoverage(provider.value, slug.value, repoSlug.value, { ref: head.ref_name })
      headCoverage.value = res.data ?? null
    } catch {
      headCoverage.value = null
    }
  },
  { immediate: true },
)

const compareTreeFiles = computed(() => {
  const deltas = new Map((comparison.value?.coverage_diff?.files ?? []).map((f) => [f.file_path, f.line_rate_delta]))
  const files = (headCoverage.value?.files ?? []).map((file) => {
    const key = file.canonical_path || file.file_path
    return {
      path: key,
      valid: file.lines_valid,
      covered: file.lines_covered,
      rate: file.line_rate,
      delta: deltas.get(key) ?? null,
    }
  })
  if (newCodeOnly.value) {
    const withNewCode = newCodeFilePaths.value
    return files.filter((file) => withNewCode.has(file.path))
  }
  if (showUnchangedCoverage.value) return files
  return files.filter((file) => deltas.has(file.path))
})

// Files carrying measurable new code, i.e. the comparison changed at least one
// instrumented line in them.
const newCodeFilePaths = computed(() => {
  const paths = new Set<string>()
  for (const file of comparison.value?.coverage_diff?.files ?? []) {
    if (file.new_lines > 0) paths.add(file.file_path)
  }
  return paths
})

type CompareListRow = Omit<CoverageFileDelta, 'change'> & { change: CoverageFileDelta['change'] | 'unchanged' }

// The list mirrors the tree's "show unchanged files" toggle: diff rows first,
// then synthetic unchanged rows built from the head snapshot's file set.
const compareListRows = computed<CompareListRow[]>(() => {
  const diffRows: CompareListRow[] = comparison.value?.coverage_diff?.files ?? []
  if (newCodeOnly.value) return diffRows.filter((row) => (row.new_lines ?? 0) > 0)
  if (!showUnchangedCoverage.value) return diffRows
  const changed = new Set(diffRows.map((row) => row.file_path))
  const unchanged: CompareListRow[] = (headCoverage.value?.files ?? [])
    .filter((file) => !changed.has(file.canonical_path || file.file_path))
    .map((file) => ({
      file_path: file.canonical_path || file.file_path,
      change: 'unchanged',
      base_line_rate: file.line_rate,
      head_line_rate: file.line_rate,
      line_rate_delta: null,
      base_lines_covered: file.lines_covered,
      head_lines_covered: file.lines_covered,
      // Unchanged by definition means no changed lines, so no new code.
      new_lines: 0,
      new_covered: 0,
      new_line_rate: null,
      base_lines_valid: file.lines_valid,
      head_lines_valid: file.lines_valid,
    }))
  return [...diffRows, ...unchanged]
})

// Per-file "new lines" counts come from patch coverage (changed, instrumented
// lines by outcome); only PR compares carry it.
const patchFileByPath = computed(() => {
  const map = new Map<string, PatchFileCoverage>()
  for (const file of comparison.value?.patch_coverage?.files ?? []) {
    map.set(file.file_path, file)
  }
  return map
})

function openCompareSource(path: string) {
  compareSourceFile.value = path
}
const loading = ref(false)
const loadingRefs = ref(true)
const error = ref('')
const baseRef = ref('')
const headRef = ref('')
const baseSnapshots = ref<Snapshot[]>([])
const headSnapshots = ref<Snapshot[]>([])
const baseSnapshotId = ref('')
const headSnapshotId = ref('')
const baseSnapshotOpen = ref(false)
const headSnapshotOpen = ref(false)
const activeTab = ref<TabId>('overview')
const expandedPatchFiles = ref<Set<string>>(new Set())

// Auto-expand files with uncovered lines so the gaps are visible at a glance —
// but cap it. A large PR would otherwise mount every diff at once and jank the
// page; past the cap we start collapsed and let the reviewer open on demand.
const MAX_AUTO_EXPANDED_FILES = 10
watch(
  () => comparison.value?.patch_coverage,
  (patch) => {
    const withGaps = (patch?.files ?? [])
      .filter((file) => file.hunks && (file.uncovered_line_numbers?.length ?? 0) > 0)
      .map((file) => file.file_path)
    expandedPatchFiles.value = new Set(
      withGaps.length > MAX_AUTO_EXPANDED_FILES ? [] : withGaps,
    )
  },
)

function togglePatchFile(path: string) {
  const next = new Set(expandedPatchFiles.value)
  if (next.has(path)) next.delete(path)
  else next.add(path)
  expandedPatchFiles.value = next
}

function closeSnapshotDropdowns() {
  baseSnapshotOpen.value = false
  headSnapshotOpen.value = false
}
onMounted(() => document.addEventListener('click', closeSnapshotDropdowns))
onUnmounted(() => document.removeEventListener('click', closeSnapshotDropdowns))

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)


function refLabel(refObj: EnhancedRef | undefined, refName: string | undefined): string {
  if (refObj?.ref_type === 'pull_request') {
    const num = refObj.pr_number || ''
    const title = refObj.pr_title?.trim() || ''
    return num ? (title ? `#${num} ${title}` : `#${num}`) : title || refObj.name
  }
  return refObj?.name || refName || ''
}


const headRefObj = computed(() => refs.value.find(r => r.name === headRef.value))
const baseRefObj = computed(() => refs.value.find(r => r.name === baseRef.value))
const headLabel = computed(() => refLabel(headRefObj.value, headRef.value) || 'Head')
const baseLabel = computed(() => refLabel(baseRefObj.value, baseRef.value) || 'Base')
const forgeProvider = computed(() => repo.value?.provider || provider.value)
const forgeName = computed(() => forgeLabel(forgeProvider.value))
const headForgeUrl = computed(() => forgeRefUrl(repo.value?.html_url, forgeProvider.value, headRef.value, headRefObj.value?.ref_type))
const baseForgeUrl = computed(() => forgeRefUrl(repo.value?.html_url, forgeProvider.value, baseRef.value, baseRefObj.value?.ref_type))

function forgeFileLink(filePath: string): string | null {
  return forgeFileUrl(repo.value?.html_url, forgeProvider.value, headRef.value, filePath)
}
const selectedBaseSnapshot = computed(() => resolveSelectedSnapshot(baseSnapshots.value, baseSnapshotId.value))
const selectedHeadSnapshot = computed(() => resolveSelectedSnapshot(headSnapshots.value, headSnapshotId.value))

const coverageDiff = computed(() => comparison.value?.coverage_diff ?? null)
const patchCoverage = computed(() => comparison.value?.patch_coverage ?? null)
const testDiff = computed(() => comparison.value?.test_diff ?? null)
const gateReasons = computed(() => comparison.value?.gate?.reasons ?? [])

// The QG badge explains where its verdict comes from — the page/forge
// disagreement (dogfood bug #5) must never be silent again.
const gateSourceTitle = computed(() => {
  if (!comparison.value?.gate) return undefined
  if (comparison.value.gate_source === 'persisted') {
    const commit = comparison.value.gate_commit ? ` (commit ${comparison.value.gate_commit.slice(0, 7)})` : ''
    return `Same verdict as the forge check${commit}`
  }
  return 'Evaluated live for this comparison — no published check for it'
})
const isPRAgainstTarget = computed(() => {
  const head = headRefObj.value
  if (!head || head.ref_type !== 'pull_request') return false
  return baseRef.value === head.merge_target_ref_name
})

const gateState = computed(() => {
  if (!isPRAgainstTarget.value) return null
  if (!comparison.value?.gate) return null
  if (!comparison.value.gate.passed) {
    return {
      label: 'QG Failed',
      badgeClass: 'border-danger/40 bg-danger/10 text-danger',
      dotClass: 'bg-danger',
    }
  }
  if (!comparison.value.gate.configured) {
    return {
      label: 'QG — no thresholds configured',
      badgeClass: 'border-surface-border bg-surface-overlay text-gray-400',
      dotClass: 'bg-gray-500',
    }
  }
  return {
    label: 'QG Passed',
    badgeClass: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    dotClass: 'bg-emerald-400',
  }
})

const hasFailedSnapshot = computed(() => {
  return selectedBaseSnapshot.value?.status === 'failed' || selectedHeadSnapshot.value?.status === 'failed'
})

const failedSnapshotWarning = computed(() => {
  const baseFailed = selectedBaseSnapshot.value?.status === 'failed'
  const headFailed = selectedHeadSnapshot.value?.status === 'failed'
  if (baseFailed && headFailed) return 'Both base and head snapshots have failed builds.'
  if (baseFailed) return 'The base snapshot has a failed build.'
  return 'The head snapshot has a failed build.'
})

// ─── Derived data ─────────────────────────────────────────────────────────────
const vulnRows = computed<VulnRow[]>(() => {
  if (!comparison.value) return []
  return [
    ...comparison.value.delta.new_vulnerabilities.map((vuln) => ({ ...vuln, change: 'new' as const })),
    ...comparison.value.delta.resolved_vulnerabilities.map((vuln) => ({ ...vuln, change: 'resolved' as const })),
  ]
})

// ─── Security delta, grouped by CAUSE (ADR: the unit of action is the cause,
// not the finding — 436 findings from one added base image is ONE decision).
interface SecurityGroup {
  key: string
  kind: 'dependency' | 'code' | 'secret' | 'resolved'
  label: string
  // Why this group exists in the delta — e.g. the component was added by
  // this change vs a finding in changed code.
  context: string
  rows: VulnRow[]
  worst: number
  fingerprints: string[]
}

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
const securitySeverityFilter = ref('')

const securityGroups = computed<SecurityGroup[]>(() => {
  if (!comparison.value) return []
  const addedPurls = new Set((comparison.value.component_diff.added ?? []).map((c) => c.purl).filter(Boolean))
  const groups = new Map<string, SecurityGroup>()
  const push = (key: string, kind: SecurityGroup['kind'], label: string, context: string, row: VulnRow) => {
    let group = groups.get(key)
    if (!group) {
      group = { key, kind, label, context, rows: [], worst: 0, fingerprints: [] }
      groups.set(key, group)
    }
    group.rows.push(row)
    group.worst = Math.max(group.worst, SEVERITY_RANK[String(row.severity)] ?? 0)
    if (row.fingerprint) group.fingerprints.push(row.fingerprint)
  }

  for (const row of vulnRows.value) {
    if (securitySeverityFilter.value && String(row.severity) !== securitySeverityFilter.value) continue
    if (row.change === 'resolved') {
      push('resolved', 'resolved', 'Resolved', 'No longer reported by the head snapshot', row)
      continue
    }
    if (row.type === 'dependency' || row.type === 'container' || row.type === 'malware') {
      const component = row.component_name
        ? `${row.component_name}${row.component_version ? '@' + row.component_version : ''}`
        : 'unknown component'
      const introduced = row.component_purl && addedPurls.has(row.component_purl)
      push(`dep:${row.component_purl || component}`, 'dependency', component,
        introduced ? 'Component added by this change' : 'Existing component', row)
    } else if (row.type === 'secret') {
      // Never grouped away — each leaked secret is its own incident.
      push(`secret:${row.fingerprint || row.id}`, 'secret', row.secret_type || 'Secret', 'Leaked credential', row)
    } else {
      const rule = row.primary_identifier_value || row.scanner_name || 'rule'
      push(`code:${row.scanner_name}:${rule}`, 'code', rule, `${row.scanner_name || 'scanner'} finding in changed code`, row)
    }
  }

  return [...groups.values()].sort((a, b) => {
    if ((a.kind === 'resolved') !== (b.kind === 'resolved')) return a.kind === 'resolved' ? 1 : -1
    if (a.worst !== b.worst) return b.worst - a.worst
    return b.rows.length - a.rows.length
  })
})

const expandedGroups = ref<Set<string>>(new Set())
function toggleGroup(key: string) {
  const next = new Set(expandedGroups.value)
  if (next.has(key)) {
    next.delete(key)
  } else {
    next.add(key)
  }
  expandedGroups.value = next
}

// Blocking-first: small groups and every non-resolved group with critical/high
// findings start expanded; the long tail stays behind its header.
watch(securityGroups, (groups) => {
  const next = new Set<string>()
  for (const group of groups) {
    if (group.kind !== 'resolved' && (group.worst >= 4 || group.rows.length <= 3)) next.add(group.key)
  }
  expandedGroups.value = next
}, { immediate: true })

// Gate reasons deep-link into the blocking subset: severity parsed from the
// reason text pre-filters the security tab.
function openSecurityForReason(reason: string) {
  const match = reason.toLowerCase().match(/critical|high|medium|low/)
  securitySeverityFilter.value = match ? match[0] : ''
  activeTab.value = 'security'
}

// ─── Accept a whole cause (ADR §6): one decision for one component ──────────
const groupDialog = ref<{ kind: AcceptanceReasonKind; group: SecurityGroup } | null>(null)
const groupDialogError = ref('')
const groupDialogSubmitting = ref(false)
const groupAcceptedKeys = ref<Set<string>>(new Set())

function openGroupAccept(kind: AcceptanceReasonKind, group: SecurityGroup) {
  groupDialogError.value = ''
  groupDialog.value = { kind, group }
}

async function confirmGroupAccept(payload: { reason: string; labels: string[]; expiresAt?: string }) {
  if (!groupDialog.value) return
  const { kind, group } = groupDialog.value
  groupDialogSubmitting.value = true
  groupDialogError.value = ''
  try {
    await api.batchFindingAcceptance(provider.value, slug.value, repoSlug.value, {
      fingerprints: [...new Set(group.fingerprints)],
      status: 'accepted',
      reason_kind: kind,
      reason: payload.reason || undefined,
      labels: payload.labels,
      expires_at: payload.expiresAt,
    })
    groupAcceptedKeys.value = new Set([...groupAcceptedKeys.value, group.key])
    groupDialog.value = null
  } catch (err) {
    groupDialogError.value = err instanceof Error ? err.message : 'Failed to accept the findings'
  } finally {
    groupDialogSubmitting.value = false
  }
}

const componentRows = computed<ComponentRow[]>(() => {
  if (!comparison.value) return []
  const diff = comparison.value.component_diff
  return [
    ...(diff.updated ?? []).map((c) => ({
      name: c.name,
      ecosystem: c.ecosystem,
      purl: c.purl,
      version: `${c.base_version} → ${c.head_version}`,
      vuln_count: c.head_vuln_count,
      vuln_delta: c.head_vuln_count - c.base_vuln_count,
      licenses: c.licenses ?? [],
      change: 'updated' as const,
    })),
    ...diff.added.map((c) => ({ ...c, licenses: c.licenses ?? [], vuln_delta: null, change: 'added' as const })),
    ...diff.removed.map((c) => ({ ...c, licenses: c.licenses ?? [], vuln_delta: null, change: 'removed' as const })),
  ]
})

// Component-tab filters: free text + change kind + ecosystem.
const componentSearch = ref('')
const componentChangeFilter = ref('')
const componentEcosystemFilter = ref('')

const componentEcosystems = computed(() =>
  Array.from(new Set(componentRows.value.map((c) => c.ecosystem || 'unknown'))).sort())

const filteredComponentRows = computed(() => {
  const query = componentSearch.value.trim().toLowerCase()
  return componentRows.value.filter((row) => {
    if (componentChangeFilter.value && row.change !== componentChangeFilter.value) return false
    if (componentEcosystemFilter.value && (row.ecosystem || 'unknown') !== componentEcosystemFilter.value) return false
    if (!query) return true
    const haystack = [row.name, row.purl, row.version, ...(row.licenses ?? [])]
    return haystack.some((value) => value?.toLowerCase().includes(query))
  })
})

// Licenses this PR introduces that main does not have anywhere — the
// reviewable event for license policy.
const newLicenses = computed(() => {
  const diff = comparison.value?.component_diff
  if (!diff) return []
  const baseLicenses = new Set<string>()
  for (const c of diff.removed) for (const l of c.licenses ?? []) baseLicenses.add(l)
  // removed = base-only; unchanged components exist on both sides so their
  // licenses cannot be new. Added + updated carry the head side.
  const introduced = new Map<string, number>()
  for (const c of [...diff.added, ...(diff.updated ?? [])]) {
    for (const l of c.licenses ?? []) {
      if (!baseLicenses.has(l)) introduced.set(l, (introduced.get(l) ?? 0) + 1)
    }
  }
  return Array.from(introduced.entries()).sort((a, b) => b[1] - a[1])
})

const headScanRunning = computed(() => {
  const status = comparison.value?.head?.scan_status
  return status === 'running' || status === 'pending'
})

const testChangeCount = computed(() => {
  const diff = testDiff.value
  if (!diff) return 0
  return diff.added.length + diff.removed.length + diff.status_changed.length + diff.slower.length + diff.faster.length
})

type TestGroup = { key: TestCaseDelta['change']; label: string; hint: string; badgeClass: string; items: TestCaseDelta[] }

const testGroups = computed<TestGroup[]>(() => {
  const diff = testDiff.value
  if (!diff) return []
  return [
    { key: 'status_changed', label: 'Status changed', hint: 'e.g. skipped or newly failing', badgeClass: pillClass('amber'), items: diff.status_changed },
    { key: 'slower', label: 'Slower', hint: 'significant execution-time increase', badgeClass: pillClass('red'), items: diff.slower },
    { key: 'faster', label: 'Faster', hint: 'significant execution-time drop', badgeClass: pillClass('emerald'), items: diff.faster },
    { key: 'added', label: 'Added', hint: 'new tests in head', badgeClass: pillClass('emerald'), items: diff.added },
    { key: 'removed', label: 'Removed', hint: 'tests dropped from head', badgeClass: pillClass('red'), items: diff.removed },
  ]
})

const visibleTestGroups = computed(() => testGroups.value.filter((g) => g.items.length > 0))

const verdict = computed(() => {
  const c = comparison.value
  if (!c) {
    return { eyebrow: 'No data', headline: 'Nothing to compare', detail: 'Select two refs to run a comparison.', shellClass: 'border-surface-border-subtle bg-surface-overlay/40', orbClass: 'compare-orb-neutral', eyebrowClass: 'text-gray-500' }
  }

  const newVuln = c.delta.new_vulnerabilities.length
  const resolved = c.delta.resolved_vulnerabilities.length
  const cov = coverageDiff.value?.line_rate_delta ?? 0
  const slower = testDiff.value?.slower.length ?? 0
  const removedTests = testDiff.value?.removed.length ?? 0

  const wins: string[] = []
  const risks: string[] = []
  if (newVuln > 0) risks.push(`${newVuln} new ${newVuln === 1 ? 'vulnerability' : 'vulnerabilities'}`)
  if (resolved > 0) wins.push(`${resolved} resolved`)
  if (cov > 0.0001) wins.push(`coverage ${formatRateDelta(cov)}`)
  else if (cov < -0.0001) risks.push(`coverage ${formatRateDelta(cov)}`)
  if (slower > 0) risks.push(`${slower} slower ${slower === 1 ? 'test' : 'tests'}`)
  if (removedTests > 0) risks.push(`${removedTests} ${removedTests === 1 ? 'test' : 'tests'} removed`)

  const detail = [...wins, ...risks].join(' · ') || 'No meaningful changes detected between these refs.'

  if (risks.length > 0 && wins.length > 0) return { eyebrow: 'Mixed signals', headline: 'Improvements with regressions', detail, shellClass: 'border-amber-500/30 bg-amber-500/[0.06]', orbClass: 'compare-orb-amber', eyebrowClass: 'text-amber-300' }
  if (risks.length > 0) return { eyebrow: 'Regression detected', headline: 'Quality dropped on head', detail, shellClass: 'border-danger/30 bg-danger/[0.06]', orbClass: 'compare-orb-red', eyebrowClass: 'text-danger' }
  if (wins.length > 0) return { eyebrow: 'Net improvement', headline: 'Head looks healthier', detail, shellClass: 'border-emerald-500/30 bg-emerald-500/[0.06]', orbClass: 'compare-orb-emerald', eyebrowClass: 'text-emerald-300' }
  return { eyebrow: 'Steady', headline: 'No meaningful change', detail, shellClass: 'border-surface-border-subtle bg-surface-overlay/40', orbClass: 'compare-orb-neutral', eyebrowClass: 'text-gray-500' }
})

const coverageBadge = computed(() => {
  const rate = coverageDiff.value?.head?.line_rate
  return typeof rate === 'number' ? `${(rate * 100).toFixed(1)}%` : ''
})

const tabs = computed(() => [
  { id: 'overview' as const, label: 'Overview', icon: LayoutDashboard, badge: '' },
  { id: 'security' as const, label: 'Security', icon: ShieldAlert, badge: vulnRows.value.length > 0 ? String(vulnRows.value.length) : '' },
  { id: 'coverage' as const, label: 'Coverage', icon: GaugeCircle, badge: coverageBadge.value },
  { id: 'tests' as const, label: 'Tests', icon: FlaskConical, badge: testChangeCount.value > 0 ? String(testChangeCount.value) : '' },
  { id: 'components' as const, label: 'Components', icon: Package, badge: componentRows.value.length > 0 ? String(componentRows.value.length) : '' },
])

// ─── URL ↔ State sync ────────────────────────────────────────────────────────
function routeQuery(): Record<string, string> {
  const q: Record<string, string> = {}
  for (const [k, v] of Object.entries(route.query)) {
    if (typeof v === 'string') q[k] = v
  }
  return q
}

// URL → local state
watch(
  () => [route.query.base, route.query.head, route.query.base_snapshot, route.query.head_snapshot],
  ([base, head, baseSn, headSn]) => {
    const nextBase = typeof base === 'string' ? base : ''
    const nextHead = typeof head === 'string' ? head : ''
    if (nextBase !== baseRef.value) baseSnapshots.value = []
    if (nextHead !== headRef.value) headSnapshots.value = []
    baseRef.value = nextBase
    headRef.value = nextHead
    baseSnapshotId.value = typeof baseSn === 'string' ? baseSn : ''
    headSnapshotId.value = typeof headSn === 'string' ? headSn : ''
  },
  { immediate: true },
)

// Local state → URL
watch([baseRef, headRef, baseSnapshotId, headSnapshotId], ([base, head, baseSn, headSn]) => {
  const q = routeQuery()
  if (base === (q.base || '') && head === (q.head || '') && baseSn === (q.base_snapshot || '') && headSn === (q.head_snapshot || '')) return

  const next: Record<string, string> = { ...q }
  if (base) next.base = base; else delete next.base
  if (head) next.head = head; else delete next.head
  if (baseSn) next.base_snapshot = baseSn; else delete next.base_snapshot
  if (headSn) next.head_snapshot = headSn; else delete next.head_snapshot
  void router.replace({ query: next })
})

// ─── User actions ─────────────────────────────────────────────────────────────
function selectBase(name: string) {
  baseRef.value = name
  baseSnapshotId.value = ''
  baseSnapshots.value = []
}

function selectHead(name: string) {
  headRef.value = name
  headSnapshotId.value = ''
  headSnapshots.value = []
}

function swapRefs() {
  if (!baseRef.value || !headRef.value) return
  // Swap refs, selected snapshot ids, AND the loaded snapshot lists together.
  // Clearing the lists would break same-branch compares: the snapshot-loading
  // watchers are keyed on ref name, so they don't refire when base === head,
  // leaving the dropdowns permanently empty (hidden by v-if on list length).
  const prevRef = baseRef.value
  baseRef.value = headRef.value
  headRef.value = prevRef
  const prevSnapshotId = baseSnapshotId.value
  baseSnapshotId.value = headSnapshotId.value
  headSnapshotId.value = prevSnapshotId
  const prevSnapshots = baseSnapshots.value
  baseSnapshots.value = headSnapshots.value
  headSnapshots.value = prevSnapshots
}

// ─── Data loading (reactive with onCleanup) ──────────────────────────────────
// Load refs when route params change
watch(
  () => [provider.value, slug.value, repoSlug.value] as const,
  async ([p, s, r], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    loadingRefs.value = true
    try {
      const [repoRes, refsRes] = await Promise.all([
        api.getRepo(p, s, r),
        api.listRefsEnhanced(p, s, r),
      ])
      if (cancelled) return
      repo.value = repoRes.data
      refs.value = refsRes.data

      // Set defaults if URL has no base/head
      if (!baseRef.value || !headRef.value) {
        const defaultBase = refsRes.data.find((ref) => ref.name === repoRes.data.default_branch)?.name || refsRes.data[0]?.name || ''
        const defaultHead = refsRes.data.find((ref) => ref.name !== defaultBase)?.name || defaultBase
        if (!baseRef.value) baseRef.value = defaultBase
        if (!headRef.value) headRef.value = defaultHead
      }
    } catch {
      if (cancelled) return
      repo.value = null
      refs.value = []
      error.value = 'Failed to load refs for comparison.'
    } finally {
      if (!cancelled) loadingRefs.value = false
    }
  },
  { immediate: true },
)

// Load base snapshots
watch(
  () => [baseRef.value, loadingRefs.value, provider.value, slug.value, repoSlug.value] as const,
  async ([refName, refsLoading, p, s, r], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (refsLoading || !refName || !p || !s || !r) {
      baseSnapshots.value = []
      return
    }
    try {
      const res = await api.listSnapshots(p, s, r, { ref: refName, per_page: 50 })
      if (!cancelled) baseSnapshots.value = res.data
    } catch {
      if (!cancelled) baseSnapshots.value = []
    }
  },
  { immediate: true },
)

// Load head snapshots
watch(
  () => [headRef.value, loadingRefs.value, provider.value, slug.value, repoSlug.value] as const,
  async ([refName, refsLoading, p, s, r], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (refsLoading || !refName || !p || !s || !r) {
      headSnapshots.value = []
      return
    }
    try {
      const res = await api.listSnapshots(p, s, r, { ref: refName, per_page: 50 })
      if (!cancelled) headSnapshots.value = res.data
    } catch {
      if (!cancelled) headSnapshots.value = []
    }
  },
  { immediate: true },
)

// Load comparison
watch(
  () => [baseRef.value, headRef.value, selectedBaseSnapshot.value?.id, selectedHeadSnapshot.value?.id, loadingRefs.value, provider.value, slug.value, repoSlug.value] as const,
  async ([base, head, baseSn, headSn, refsLoading, p, s, r], _, onCleanup) => {
    let cancelled = false
    onCleanup(() => { cancelled = true })

    if (refsLoading || !p || !s || !r || !base || !head) {
      comparison.value = null
      loading.value = false
      return
    }

    loading.value = true
    error.value = ''
    try {
      const res = await api.compareRefs(p, s, r, base, head, {
        baseSnapshot: baseSn || undefined,
        headSnapshot: headSn || undefined,
      })
      if (cancelled) return
      comparison.value = res.data
    } catch (err) {
      if (cancelled) return
      comparison.value = null
      error.value = err instanceof Error ? err.message : 'Failed to compare refs.'
    } finally {
      if (!cancelled) loading.value = false
    }
  },
  { immediate: true },
)

// ─── Snapshot helpers ─────────────────────────────────────────────────────────
function snapshotOptionLabel(snapshot: Snapshot) {
  const parts: string[] = []

  // Status prefix for non-complete snapshots
  if (snapshot.status === 'failed') parts.push('✗')
  else if (snapshot.status === 'pending') parts.push('⏳')

  // Commit SHA (always)
  parts.push(snapshot.commit_sha.slice(0, 7))

  // Tag if present
  if (snapshot.tag) parts.push(`[${snapshot.tag}]`)

  // Status label
  parts.push(snapshotStatusLabel(snapshot))

  // Date
  parts.push(formatDateTime(snapshot.created_at))

  // PR info
  if (snapshot.pr_number) parts.push(`PR #${snapshot.pr_number}`)

  // Run number
  if (snapshot.run_number) parts.push(`#${snapshot.run_number}`)

  return parts.join(' · ')
}

function snapshotPrimaryLabel(snapshot: Snapshot) {
  return snapshot.tag || snapshot.commit_sha.slice(0, 7)
}

function snapshotStatusLabel(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'Build failed'
  if (snapshot.status === 'pending') return 'Build running'
  if (snapshot.status === 'processing') return 'Processing'
  if (snapshot.status === 'active') return 'Build active'
  return 'Build passed'
}

function snapshotBadgeClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'bg-danger/15 text-danger'
  if (snapshot.status === 'pending' || snapshot.status === 'processing') return 'bg-amber-500/15 text-amber-300'
  if (snapshot.tag) return 'bg-sky-500/15 text-sky-300'
  return 'bg-emerald-500/15 text-emerald-300'
}

function snapshotDotClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'bg-danger'
  if (snapshot.status === 'pending' || snapshot.status === 'processing') return 'bg-amber-400 animate-pulse'
  return 'bg-emerald-400'
}

function snapshotStatusTextClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'text-danger'
  if (snapshot.status === 'pending' || snapshot.status === 'processing') return 'text-amber-300'
  return 'text-emerald-300'
}

function snapshotSecondaryLine(snapshot: Snapshot) {
  const details = [`Commit ${snapshot.commit_sha.slice(0, 12)}`, formatDateTime(snapshot.created_at)]
  if (snapshot.tag) details.push(`Tag ${snapshot.tag}`)
  if (snapshot.run_number) details.push(`Run #${snapshot.run_number}`)
  else if (snapshot.run_id) details.push(`Run ${snapshot.run_id}`)
  if (snapshot.pr_number) {
    const suffix = snapshot.pr_target_branch ? ` -> ${snapshot.pr_target_branch}` : ''
    details.push(`PR #${snapshot.pr_number}${suffix}`)
  }
  return details.join(' · ')
}

function resolveSelectedSnapshot(snapshots: Snapshot[], id: string) {
  if (id) {
    const found = snapshots.find((s) => s.id === id)
    if (found) return found
  }
  return snapshots.find((s) => s.status === 'complete' || s.status === 'active') ?? snapshots[0] ?? null
}

// ─── Display helpers ──────────────────────────────────────────────────────────
function severityBadgeClass(severity: string) {
  return `sev-${severity.toLowerCase()} rounded-full px-2.5 py-1 text-xs font-medium`
}

function changeBadgeClass(change: string) {
  if (change === 'new' || change === 'added') {
    return 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-emerald-300'
  }
  if (change === 'updated') {
    return 'rounded-full bg-blue-500/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-blue-300'
  }
  return 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-danger'
}

function pillClass(color: 'emerald' | 'red' | 'amber') {
  const palette = { emerald: 'bg-emerald-500/15 text-emerald-300', red: 'bg-danger/15 text-danger', amber: 'bg-amber-500/15 text-amber-300' }
  return `rounded-full px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] ${palette[color]}`
}

function coverageChangeBadgeClass(change: CompareListRow['change']) {
  if (change === 'improved' || change === 'added') return pillClass('emerald')
  if (change === 'regressed' || change === 'removed') return pillClass('red')
  if (change === 'unchanged') return 'rounded-full bg-surface-overlay px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wide text-gray-400'
  return pillClass('amber')
}

function statusBadgeClass(status: string) {
  switch (status) {
    case 'passed': return 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium text-emerald-300'
    case 'failed': case 'error': return 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium text-danger'
    case 'skipped': return 'rounded-full bg-amber-500/15 px-2.5 py-1 text-xs font-medium text-amber-300'
    default: return 'rounded-full bg-surface-overlay px-2.5 py-1 text-xs font-medium text-gray-300'
  }
}

function vulnerabilityLocation(vuln: Vulnerability) {
  if (vuln.file_path) return vuln.start_line ? `${vuln.file_path}:${vuln.start_line}` : vuln.file_path
  if (vuln.component_name) return vuln.component_version ? `${vuln.component_name}@${vuln.component_version}` : vuln.component_name
  return 'n/a'
}

// ─── Formatting ───────────────────────────────────────────────────────────────
function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function formatRate(rate: number | null) {
  if (rate === null || rate === undefined) return 'n/a'
  return `${(rate * 100).toFixed(1)}%`
}

// formatLineRanges compresses a sorted list of line numbers into human-readable
// ranges, e.g. [11, 45, 46, 47] -> ["11", "45–47"], for the uncovered-line chips.
function formatLineRanges(numbers: number[] | null | undefined): string[] {
  if (!numbers || numbers.length === 0) return []
  const sorted = [...numbers].sort((a, b) => a - b)
  const ranges: string[] = []
  let start = sorted[0]
  let prev = sorted[0]
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i] === prev + 1) {
      prev = sorted[i]
      continue
    }
    ranges.push(start === prev ? `${start}` : `${start}–${prev}`)
    start = sorted[i]
    prev = sorted[i]
  }
  ranges.push(start === prev ? `${start}` : `${start}–${prev}`)
  return ranges
}

function patchTotalLines(cov: { covered_lines: number; uncovered_lines: number }) {
  return cov.covered_lines + cov.uncovered_lines
}

function formatRateDelta(delta: number | null) {
  if (delta === null || delta === undefined) return 'n/a'
  const points = delta * 100
  if (Math.abs(points) < 0.05) return '0.0%'
  return `${points > 0 ? '+' : ''}${points.toFixed(1)}%`
}

function formatDuration(seconds: number) {
  return seconds >= 1 ? `${seconds.toFixed(2)}s` : `${(seconds * 1000).toFixed(0)}ms`
}

function formatDurationDelta(seconds: number) {
  if (Math.abs(seconds) < 0.0005) return '±0ms'
  const sign = seconds > 0 ? '+' : '-'
  const abs = Math.abs(seconds)
  return `${sign}${abs >= 1 ? `${abs.toFixed(2)}s` : `${(abs * 1000).toFixed(0)}ms`}`
}

function rateColor(rate: number | null) {
  if (rate === null || rate === undefined) return 'var(--color-text-muted, #6b7280)'
  const pct = rate * 100
  if (pct >= 80) return 'var(--color-ok, #3fb950)'
  if (pct >= 60) return 'var(--color-warn, #d29922)'
  return 'var(--color-danger, #f85149)'
}

function deltaColor(delta: number | null) {
  if (delta === null || delta === undefined || Math.abs(delta) < 1e-9) return 'var(--color-text-muted, #6b7280)'
  return delta > 0 ? 'var(--color-ok, #3fb950)' : 'var(--color-danger, #f85149)'
}

function trendIcon(delta: number | null) {
  if (delta === null || delta === undefined || Math.abs(delta) < 1e-9) return Minus
  return delta > 0 ? ArrowUpRight : ArrowDownRight
}

function coverageBarStyle(rate: number | null) {
  return { width: `${Math.max(0, Math.min(100, (rate ?? 0) * 100))}%`, backgroundColor: rateColor(rate) }
}
</script>

<style scoped>
.compare-display {
  font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace;
}

.compare-beacon {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 9999px;
  background: #58a6ff;
}

.compare-ref {
  color: #e6edf3;
}

.compare-ref-head {
  color: #79c0ff;
}

.compare-arrow {
  margin: 0 0.35rem;
  color: #58a6ff;
  text-shadow: 0 0 12px rgb(88 166 255 / 0.5);
}

.compare-dot {
  width: 0.45rem;
  height: 0.45rem;
  border-radius: 9999px;
}
.compare-dot-base { background: #8b949e; box-shadow: 0 0 8px rgb(139 148 158 / 0.6); }
.compare-dot-head { background: #58a6ff; box-shadow: 0 0 8px rgb(88 166 255 / 0.7); }

.compare-swap:not(:disabled):hover {
  box-shadow: 0 0 0 1px rgb(88 166 255 / 0.3);
  transform: rotate(180deg);
}
.compare-swap {
  transition: transform 0.3s cubic-bezier(0.22, 1, 0.36, 1), border-color 0.2s ease, color 0.2s ease, box-shadow 0.2s ease;
}
.compare-swap:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.compare-select {
  transition: border-color 0.18s ease, box-shadow 0.18s ease;
}
.compare-select:hover,
.compare-select:focus {
  border-color: rgb(88 166 255 / 0.6);
  box-shadow: 0 0 0 1px rgb(88 166 255 / 0.25);
}

.compare-tab-active {
  border-bottom-color: rgb(88 166 255 / 1);
  font-weight: 600;
}

/* Instrument stat cards. */
.compare-stat {
  position: relative;
  overflow: hidden;
  opacity: 0;
  animation: compare-rise 0.5s cubic-bezier(0.22, 1, 0.36, 1) forwards;
  animation-delay: calc(var(--i, 0) * 70ms + 60ms);
}
.compare-stat::before {
  content: '';
  position: absolute;
  inset: 0 0 auto 0;
  height: 2px;
  background: linear-gradient(90deg, transparent, rgb(88 166 255 / 0.7), transparent);
  opacity: 0;
  transition: opacity 0.25s ease;
}
.compare-stat:hover {
  transform: translateY(-3px);
  box-shadow: 0 18px 40px -24px rgb(88 166 255 / 0.55);
}
.compare-stat:hover::before { opacity: 1; }

.compare-verdict { position: relative; }
.compare-verdict-orb {
  position: absolute;
  right: -2.5rem;
  top: 50%;
  width: 9rem;
  height: 9rem;
  transform: translateY(-50%);
  border-radius: 9999px;
  filter: blur(36px);
  opacity: 0.55;
  pointer-events: none;
}
.compare-orb-emerald { background: radial-gradient(circle, rgb(63 185 80 / 0.7), transparent 70%); }
.compare-orb-red { background: radial-gradient(circle, rgb(248 81 73 / 0.7), transparent 70%); }
.compare-orb-amber { background: radial-gradient(circle, rgb(210 153 34 / 0.7), transparent 70%); }
.compare-orb-neutral { background: radial-gradient(circle, rgb(88 166 255 / 0.4), transparent 70%); }

/* Scanning shimmer on the loading state. */
.compare-scan {
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgb(88 166 255 / 0.08), transparent);
  background-size: 40% 100%;
  background-repeat: no-repeat;
  animation: compare-sweep 1.3s ease-in-out infinite;
}

@keyframes compare-sweep {
  0% { background-position: -40% 0; }
  100% { background-position: 140% 0; }
}

.compare-rise {
  opacity: 0;
  animation: compare-rise 0.55s cubic-bezier(0.22, 1, 0.36, 1) forwards;
}

@keyframes compare-rise {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

@media (prefers-reduced-motion: reduce) {
  .compare-stat,
  .compare-rise {
    opacity: 1;
    animation: none;
  }
  .compare-scan {
    animation: none;
  }
}
</style>
