<template>
  <div class="px-4 pt-5">
    <div class="compare-rise relative">
      <p class="mb-1 flex items-center gap-2 text-xs uppercase tracking-[0.24em] text-gray-500">
        <span class="compare-beacon" />
        <span class="compare-display">Compare</span>
      </p>
      <div class="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-3 lg:gap-2">
        <span class="flex min-w-0 items-center gap-2 text-xl font-semibold tracking-tight sm:text-2xl">
          <component
            :is="headRefIcon"
            class="h-5 w-5 shrink-0 text-gray-400"
          />
          <span class="compare-ref min-w-0 truncate">{{ headLabel }}</span>
        </span>
        <span class="compare-arrow flex h-10 w-10 items-center justify-center text-2xl">→</span>
        <span class="flex min-w-0 items-center gap-2 text-xl font-semibold tracking-tight sm:text-2xl">
          <component
            :is="baseRefIcon"
            class="h-5 w-5 shrink-0 text-gray-400"
          />
          <span class="compare-ref compare-ref-head min-w-0 truncate">{{ baseLabel }}</span>
        </span>
      </div>
      <span
        v-if="gateState"
        class="absolute right-0 top-1/2 inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium"
        :class="gateState.badgeClass"
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
      <div class="compare-comparator grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] lg:items-start lg:gap-2">
        <div class="min-w-0 flex-1 space-y-2">
          <span class="flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-gray-500">
            <span class="compare-dot compare-dot-head" />
            Head <span class="text-gray-600">(from)</span>
          </span>
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="headRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            compact
            block
            @select="selectHead"
          />
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

        <button
          type="button"
          class="compare-swap mx-auto my-1 inline-flex h-10 w-10 shrink-0 self-center items-center justify-center rounded-xl border border-surface-border bg-surface-overlay text-gray-300 transition hover:border-accent/60 hover:text-white"
          :disabled="!baseRef || !headRef"
          title="Swap base and head"
          aria-label="Swap base and head"
          @click="swapRefs"
        >
          <ArrowLeftRight class="h-4 w-4" />
        </button>

        <div class="min-w-0 flex-1 space-y-2">
          <span class="flex items-center justify-end gap-2 text-xs uppercase tracking-[0.2em] text-gray-500">
            Base <span class="text-gray-600">(to)</span>
            <span class="compare-dot compare-dot-base" />
          </span>
          <BranchPRSelector
            :refs="refs"
            :selected-ref-name="baseRef"
            :default-branch="repo?.default_branch"
            :loading="loadingRefs"
            compact
            block
            align="right"
            @select="selectBase"
          />
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
            v-if="tab.count > 0"
            class="rounded-full bg-surface-overlay px-2 py-0.5 text-[11px] font-semibold text-gray-300"
          >{{ tab.count }}</span>
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
              {{ reason }}
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
              {{ comparison.component_diff.removed.length }} removed
            </p>
          </button>
        </div>
      </div>

      <!-- Security tab -->
      <div
        v-show="activeTab === 'security'"
        class="overflow-hidden rounded-2xl border border-surface-border-subtle"
      >
        <div
          v-if="vulnRows.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No vulnerability changes between these refs.
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
                  Severity
                </th>
                <th class="px-4 py-3 font-medium">
                  Type
                </th>
                <th class="px-4 py-3 font-medium">
                  Identifier
                </th>
                <th class="px-4 py-3 font-medium">
                  Title
                </th>
                <th class="px-4 py-3 font-medium">
                  Location
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="vuln in vulnRows"
                :key="`${vuln.change}-${vuln.advisory_id}-${vuln.component_name}`"
                class="transition hover:bg-white/5"
              >
                <td class="px-4 py-4">
                  <span :class="changeBadgeClass(vuln.change)">{{ vuln.change }}</span>
                </td>
                <td class="px-4 py-4">
                  <span :class="severityBadgeClass(vuln.severity)">{{ vuln.severity }}</span>
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vuln.type }}
                </td>
                <td class="px-4 py-4 font-mono text-xs text-accent">
                  {{ vuln.primary_identifier_value || vuln.scanner_name || 'n/a' }}
                </td>
                <td class="px-4 py-4 text-gray-300">
                  {{ vuln.title }}
                </td>
                <td class="px-4 py-4 text-gray-400">
                  {{ vulnerabilityLocation(vuln) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
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
                  <span
                    class="shrink-0 text-xs font-medium"
                    :style="{ color: rateColor(file.rate) }"
                  >
                    {{ formatRate(file.rate) }} · {{ file.covered_lines }}/{{ patchTotalLines(file) }}
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
                  />
                </div>
              </div>
            </div>
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
            <div class="flex items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
              <h3 class="text-sm font-semibold text-white">
                Per-file changes
              </h3>
              <span class="text-xs text-gray-500">{{ coverageDiff.unchanged_files }} unchanged</span>
            </div>
            <div
              v-if="coverageDiff.files.length === 0"
              class="px-4 py-8 text-sm text-gray-500"
            >
              No per-file coverage changes between these refs.
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
                      Lines
                    </th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-surface-border-subtle">
                  <tr
                    v-for="file in coverageDiff.files"
                    :key="`${file.change}-${file.file_path}`"
                    class="transition hover:bg-white/5"
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
                    <td class="px-4 py-3 align-top text-gray-300">
                      {{ file.base_lines_covered }}/{{ file.base_lines_valid }} → {{ file.head_lines_covered }}/{{ file.head_lines_valid }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </template>
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
          v-if="componentRows.length === 0"
          class="px-4 py-10 text-sm text-gray-500"
        >
          No component additions or removals between these refs.
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
                  Vulns
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-surface-border-subtle">
              <tr
                v-for="component in componentRows"
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
                <td class="px-4 py-4 text-gray-300">
                  {{ component.vuln_count }}
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
import { ArrowLeftRight, ArrowRight, ArrowDownRight, ArrowUpRight, ChevronDown, FlaskConical, GaugeCircle, GitBranch, GitPullRequest, LayoutDashboard, Minus, Package, ShieldAlert, Tag } from 'lucide-vue-next'
import { useRoute, useRouter } from 'vue-router'

import { api, type CompareResult, type ComponentEntry, type CoverageFileDelta, type EnhancedRef, type Repository, type Snapshot, type TestCaseDelta, type Vulnerability } from '@/api/client'
import BranchPRSelector from '@/components/BranchPRSelector.vue'
import PatchDiffFile from '@/components/PatchDiffFile.vue'

type VulnRow = Vulnerability & { change: 'new' | 'resolved' }
type ComponentRow = ComponentEntry & { change: 'added' | 'removed' }
type TabId = 'overview' | 'security' | 'coverage' | 'tests' | 'components'

const route = useRoute()
const router = useRouter()

// ─── Core state ───────────────────────────────────────────────────────────────
const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const comparison = ref<CompareResult | null>(null)
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

function refIconFor(refObj: EnhancedRef | undefined) {
  if (refObj?.ref_type === 'pull_request') return GitPullRequest
  if (refObj?.ref_type === 'tag') return Tag
  return GitBranch
}

const headRefObj = computed(() => refs.value.find(r => r.name === headRef.value))
const baseRefObj = computed(() => refs.value.find(r => r.name === baseRef.value))
const headLabel = computed(() => refLabel(headRefObj.value, headRef.value) || 'Head')
const baseLabel = computed(() => refLabel(baseRefObj.value, baseRef.value) || 'Base')
const headRefIcon = computed(() => refIconFor(headRefObj.value))
const baseRefIcon = computed(() => refIconFor(baseRefObj.value))
const selectedBaseSnapshot = computed(() => resolveSelectedSnapshot(baseSnapshots.value, baseSnapshotId.value))
const selectedHeadSnapshot = computed(() => resolveSelectedSnapshot(headSnapshots.value, headSnapshotId.value))

const coverageDiff = computed(() => comparison.value?.coverage_diff ?? null)
const patchCoverage = computed(() => comparison.value?.patch_coverage ?? null)
const testDiff = computed(() => comparison.value?.test_diff ?? null)
const gateReasons = computed(() => comparison.value?.gate?.reasons ?? [])
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

const componentRows = computed<ComponentRow[]>(() => {
  if (!comparison.value) return []
  return [
    ...comparison.value.component_diff.added.map((c) => ({ ...c, change: 'added' as const })),
    ...comparison.value.component_diff.removed.map((c) => ({ ...c, change: 'removed' as const })),
  ]
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

const tabs = computed(() => [
  { id: 'overview' as const, label: 'Overview', icon: LayoutDashboard, count: 0 },
  { id: 'security' as const, label: 'Security', icon: ShieldAlert, count: vulnRows.value.length },
  { id: 'coverage' as const, label: 'Coverage', icon: GaugeCircle, count: coverageDiff.value?.files.length ?? 0 },
  { id: 'tests' as const, label: 'Tests', icon: FlaskConical, count: testChangeCount.value },
  { id: 'components' as const, label: 'Components', icon: Package, count: componentRows.value.length },
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
  if (snapshot.status === 'active') return 'Build active'
  return 'Build passed'
}

function snapshotBadgeClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'bg-danger/15 text-danger'
  if (snapshot.status === 'pending') return 'bg-amber-500/15 text-amber-300'
  if (snapshot.tag) return 'bg-sky-500/15 text-sky-300'
  return 'bg-emerald-500/15 text-emerald-300'
}

function snapshotDotClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'bg-danger'
  if (snapshot.status === 'pending') return 'bg-amber-400 animate-pulse'
  return 'bg-emerald-400'
}

function snapshotStatusTextClass(snapshot: Snapshot) {
  if (snapshot.status === 'failed') return 'text-danger'
  if (snapshot.status === 'pending') return 'text-amber-300'
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
  return change === 'new' || change === 'added'
    ? 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-emerald-300'
    : 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-danger'
}

function pillClass(color: 'emerald' | 'red' | 'amber') {
  const palette = { emerald: 'bg-emerald-500/15 text-emerald-300', red: 'bg-danger/15 text-danger', amber: 'bg-amber-500/15 text-amber-300' }
  return `rounded-full px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] ${palette[color]}`
}

function coverageChangeBadgeClass(change: CoverageFileDelta['change']) {
  if (change === 'improved' || change === 'added') return pillClass('emerald')
  if (change === 'regressed' || change === 'removed') return pillClass('red')
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
