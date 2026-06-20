<template>
  <section class="compare-root relative space-y-6 overflow-hidden rounded-3xl border border-surface-border bg-surface-raised p-6 sm:p-7">
    <div
      class="compare-aurora pointer-events-none absolute inset-0"
      aria-hidden="true"
    />
    <div
      class="compare-grain pointer-events-none absolute inset-0"
      aria-hidden="true"
    />

    <div class="compare-rise relative flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
      <div>
        <p class="flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-gray-500">
          <span class="compare-beacon" />
          <span class="compare-display">Snapshot comparison</span>
        </p>
        <h1 class="compare-display mt-3 text-3xl font-semibold tracking-tight text-white sm:text-[2.1rem]">
          <span class="text-gray-500">compare</span>
          <span class="compare-ref">{{ baseLabel }}</span>
          <span class="compare-arrow">→</span>
          <span class="compare-ref compare-ref-head">{{ headLabel }}</span>
        </h1>
        <p class="mt-3 max-w-xl text-sm text-gray-400">
          Security, coverage, tests, and SBOM components — diffed across any two scanned refs.
        </p>
      </div>
    </div>

    <div class="compare-rise relative grid gap-4 lg:grid-cols-2">
      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Base ref</span>
        <select
          v-model="baseRef"
          class="compare-select w-full rounded-2xl border border-surface-border bg-surface-overlay/80 px-4 py-3 text-sm text-gray-100"
        >
          <option
            v-for="refItem in refs"
            :key="`base-${refItem.id}`"
            :value="refItem.name"
          >
            {{ formatRefOption(refItem) }}
          </option>
        </select>
      </label>

      <label class="space-y-2 text-sm text-gray-300">
        <span class="block text-xs uppercase tracking-[0.2em] text-gray-500">Head ref</span>
        <select
          v-model="headRef"
          class="compare-select w-full rounded-2xl border border-surface-border bg-surface-overlay/80 px-4 py-3 text-sm text-gray-100"
        >
          <option
            v-for="refItem in refs"
            :key="`head-${refItem.id}`"
            :value="refItem.name"
          >
            {{ formatRefOption(refItem) }}
          </option>
        </select>
      </label>
    </div>

    <div
      v-if="comparison"
      class="compare-rise relative grid gap-4 lg:grid-cols-2"
    >
      <div class="compare-snapcard rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4">
        <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
          Base snapshot
        </p>
        <p class="mt-2 text-lg font-medium text-white">
          {{ comparison.base.ref_name }}
        </p>
        <p class="mt-1 text-sm text-gray-400">
          <a
            v-if="commitUrl(comparison.base.commit_sha)"
            :href="commitUrl(comparison.base.commit_sha) || undefined"
            target="_blank"
            rel="noopener"
            class="font-mono hover:text-accent hover:underline"
          >{{ comparison.base.commit_sha.slice(0, 12) }}</a>
          <span
            v-else
            class="font-mono"
          >{{ comparison.base.commit_sha.slice(0, 12) }}</span>
          · {{ formatDateTime(comparison.base.date) }}
        </p>
      </div>

      <div class="compare-snapcard rounded-2xl border border-surface-border-subtle bg-surface-overlay/60 p-4">
        <p class="text-xs uppercase tracking-[0.18em] text-gray-500">
          Head snapshot
        </p>
        <p class="mt-2 text-lg font-medium text-white">
          {{ comparison.head.ref_name }}
        </p>
        <p class="mt-1 text-sm text-gray-400">
          <a
            v-if="commitUrl(comparison.head.commit_sha)"
            :href="commitUrl(comparison.head.commit_sha) || undefined"
            target="_blank"
            rel="noopener"
            class="font-mono hover:text-accent hover:underline"
          >{{ comparison.head.commit_sha.slice(0, 12) }}</a>
          <span
            v-else
            class="font-mono"
          >{{ comparison.head.commit_sha.slice(0, 12) }}</span>
          · {{ formatDateTime(comparison.head.date) }}
        </p>
      </div>
    </div>

    <div
      v-if="loading"
      class="compare-rise relative overflow-hidden rounded-2xl border border-dashed border-surface-border-subtle px-4 py-10 text-sm text-gray-500"
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
      <nav class="compare-rise relative flex flex-wrap gap-1 border-b border-surface-border-subtle">
        <button
          v-for="tab in tabs"
          :key="tab.id"
          type="button"
          class="compare-tab inline-flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition"
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
                  {{ vuln.primary_identifier?.value || vuln.scanner_name || 'n/a' }}
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
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ArrowRight, ArrowDownRight, ArrowUpRight, FlaskConical, GaugeCircle, LayoutDashboard, Minus, Package, ShieldAlert } from 'lucide-vue-next'
import { useRoute, useRouter } from 'vue-router'

import { api, forgeCommitUrl, type CompareResult, type ComponentEntry, type CoverageFileDelta, type EnhancedRef, type Repository, type TestCaseDelta, type Vulnerability } from '@/api/client'
import { useOrgStore } from '@/stores/org'

type VulnRow = Vulnerability & { change: 'new' | 'resolved' }
type ComponentRow = ComponentEntry & { change: 'added' | 'removed' }
type TabId = 'overview' | 'security' | 'coverage' | 'tests' | 'components'

const route = useRoute()
const router = useRouter()
const orgStore = useOrgStore()

const repo = ref<Repository | null>(null)
const refs = ref<EnhancedRef[]>([])
const comparison = ref<CompareResult | null>(null)
const loading = ref(false)
const loadingRefs = ref(true)
const error = ref('')
const baseRef = ref('')
const headRef = ref('')
const activeTab = ref<TabId>('overview')
const forgeUrl = computed(() => orgStore.currentOrg?.forge_url ?? '')
const repoProviderID = computed(() => repo.value?.provider_id ?? '')

const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)
const repoSlug = computed(() => route.params.repoSlug as string)

const baseLabel = computed(() => baseRef.value || 'Base')
const headLabel = computed(() => headRef.value || 'Head')

const coverageDiff = computed(() => comparison.value?.coverage_diff ?? null)
const testDiff = computed(() => comparison.value?.test_diff ?? null)

const vulnRows = computed<VulnRow[]>(() => {
  if (!comparison.value) {
    return []
  }

  return [
    ...comparison.value.delta.new_vulnerabilities.map((vuln) => ({ ...vuln, change: 'new' as const })),
    ...comparison.value.delta.resolved_vulnerabilities.map((vuln) => ({ ...vuln, change: 'resolved' as const })),
  ]
})

const componentRows = computed<ComponentRow[]>(() => {
  if (!comparison.value) {
    return []
  }

  return [
    ...comparison.value.component_diff.added.map((component) => ({ ...component, change: 'added' as const })),
    ...comparison.value.component_diff.removed.map((component) => ({ ...component, change: 'removed' as const })),
  ]
})

const testChangeCount = computed(() => {
  const diff = testDiff.value
  if (!diff) {
    return 0
  }
  return diff.added.length + diff.removed.length + diff.status_changed.length + diff.slower.length + diff.faster.length
})

type TestGroup = { key: TestCaseDelta['change']; label: string; hint: string; badgeClass: string; items: TestCaseDelta[] }

const testGroups = computed<TestGroup[]>(() => {
  const diff = testDiff.value
  if (!diff) {
    return []
  }
  return [
    { key: 'status_changed', label: 'Status changed', hint: 'e.g. skipped or newly failing', badgeClass: pillClass('amber'), items: diff.status_changed },
    { key: 'slower', label: 'Slower', hint: 'significant execution-time increase', badgeClass: pillClass('red'), items: diff.slower },
    { key: 'faster', label: 'Faster', hint: 'significant execution-time drop', badgeClass: pillClass('emerald'), items: diff.faster },
    { key: 'added', label: 'Added', hint: 'new tests in head', badgeClass: pillClass('emerald'), items: diff.added },
    { key: 'removed', label: 'Removed', hint: 'tests dropped from head', badgeClass: pillClass('red'), items: diff.removed },
  ]
})

const visibleTestGroups = computed(() => testGroups.value.filter((group) => group.items.length > 0))

const verdict = computed(() => {
  const c = comparison.value
  if (!c) {
    return {
      eyebrow: 'No data',
      headline: 'Nothing to compare',
      detail: 'Select two refs to run a comparison.',
      shellClass: 'border-surface-border-subtle bg-surface-overlay/40',
      orbClass: 'compare-orb-neutral',
      eyebrowClass: 'text-gray-500',
    }
  }

  const newVuln = c.delta.new_vulnerabilities.length
  const resolved = c.delta.resolved_vulnerabilities.length
  const cov = coverageDiff.value?.line_rate_delta ?? 0
  const slower = testDiff.value?.slower.length ?? 0
  const removedTests = testDiff.value?.removed.length ?? 0
  const eps = 0.0001

  const wins: string[] = []
  const risks: string[] = []

  if (newVuln > 0) {
    risks.push(`${newVuln} new ${newVuln === 1 ? 'vulnerability' : 'vulnerabilities'}`)
  }
  if (resolved > 0) {
    wins.push(`${resolved} resolved`)
  }
  if (cov > eps) {
    wins.push(`coverage ${formatRateDelta(cov)}`)
  } else if (cov < -eps) {
    risks.push(`coverage ${formatRateDelta(cov)}`)
  }
  if (slower > 0) {
    risks.push(`${slower} slower ${slower === 1 ? 'test' : 'tests'}`)
  }
  if (removedTests > 0) {
    risks.push(`${removedTests} ${removedTests === 1 ? 'test' : 'tests'} removed`)
  }

  const detail = [...wins, ...risks].join(' · ') || 'No meaningful changes detected between these refs.'

  if (risks.length > 0 && wins.length > 0) {
    return {
      eyebrow: 'Mixed signals',
      headline: 'Improvements with regressions',
      detail,
      shellClass: 'border-amber-500/30 bg-amber-500/[0.06]',
      orbClass: 'compare-orb-amber',
      eyebrowClass: 'text-amber-300',
    }
  }
  if (risks.length > 0) {
    return {
      eyebrow: 'Regression detected',
      headline: 'Quality dropped on head',
      detail,
      shellClass: 'border-danger/30 bg-danger/[0.06]',
      orbClass: 'compare-orb-red',
      eyebrowClass: 'text-danger',
    }
  }
  if (wins.length > 0) {
    return {
      eyebrow: 'Net improvement',
      headline: 'Head looks healthier',
      detail,
      shellClass: 'border-emerald-500/30 bg-emerald-500/[0.06]',
      orbClass: 'compare-orb-emerald',
      eyebrowClass: 'text-emerald-300',
    }
  }
  return {
    eyebrow: 'Steady',
    headline: 'No meaningful change',
    detail,
    shellClass: 'border-surface-border-subtle bg-surface-overlay/40',
    orbClass: 'compare-orb-neutral',
    eyebrowClass: 'text-gray-500',
  }
})

const tabs = computed(() => [
  { id: 'overview' as const, label: 'Overview', icon: LayoutDashboard, count: 0 },
  { id: 'security' as const, label: 'Security', icon: ShieldAlert, count: vulnRows.value.length },
  { id: 'coverage' as const, label: 'Coverage', icon: GaugeCircle, count: coverageDiff.value?.files.length ?? 0 },
  { id: 'tests' as const, label: 'Tests', icon: FlaskConical, count: testChangeCount.value },
  { id: 'components' as const, label: 'Components', icon: Package, count: componentRows.value.length },
])

watch(
  () => [route.params.provider, route.params.slug, route.params.repoSlug],
  () => {
    void loadRefs()
  },
  { immediate: true },
)

watch(
  () => [route.query.base, route.query.head],
  () => {
    baseRef.value = typeof route.query.base === 'string' ? route.query.base : ''
    headRef.value = typeof route.query.head === 'string' ? route.query.head : ''
    void loadComparison()
  },
  { immediate: true },
)

watch([baseRef, headRef], ([base, head]) => {
  const nextBase = typeof route.query.base === 'string' ? route.query.base : ''
  const nextHead = typeof route.query.head === 'string' ? route.query.head : ''
  if (!base || !head || (base === nextBase && head === nextHead)) {
    return
  }

  void router.replace({ query: { ...route.query, base, head } })
})

async function loadRefs() {
  loadingRefs.value = true

  try {
    const [repoRes, refsRes] = await Promise.all([
      api.getRepo(provider.value, slug.value, repoSlug.value),
      api.listRefsEnhanced(provider.value, slug.value, repoSlug.value),
    ])

    repo.value = repoRes.data
    refs.value = refsRes.data
    ensureSelections()
  } catch {
    repo.value = null
    refs.value = []
    error.value = 'Failed to load refs for comparison.'
  } finally {
    loadingRefs.value = false

    if (typeof route.query.base === 'string' && typeof route.query.head === 'string') {
      void loadComparison()
    }
  }
}

function ensureSelections() {
  if (refs.value.length === 0 || !repo.value) {
    return
  }

  const routeBase = typeof route.query.base === 'string' ? route.query.base : ''
  const routeHead = typeof route.query.head === 'string' ? route.query.head : ''
  const defaultBase = refs.value.find((refItem) => refItem.name === repo.value?.default_branch)?.name || refs.value[0]?.name || ''
  const defaultHead = refs.value.find((refItem) => refItem.name !== defaultBase)?.name || defaultBase

  baseRef.value = routeBase || defaultBase
  headRef.value = routeHead || defaultHead

  if (!routeBase || !routeHead) {
    void router.replace({
      query: {
        ...route.query,
        base: baseRef.value,
        head: headRef.value,
      },
    })
  }
}

async function loadComparison() {
  if (loadingRefs.value || !baseRef.value || !headRef.value) {
    return
  }

  loading.value = true
  error.value = ''

  try {
    const response = await api.compareRefs(
      provider.value,
      slug.value,
      repoSlug.value,
      baseRef.value,
      headRef.value,
    )
    comparison.value = response.data
  } catch (err) {
    comparison.value = null
    error.value = err instanceof Error ? err.message : 'Failed to compare refs.'
  } finally {
    loading.value = false
  }
}

function formatRefOption(refItem: EnhancedRef) {
  if (refItem.ref_type === 'pull_request') {
    return `${refItem.pr_title || refItem.name} (${refItem.pr_source_branch || 'source'} → ${refItem.merge_target_ref_name || 'target'})`
  }
  return refItem.name
}

function commitUrl(sha: string): string | null {
  return forgeCommitUrl(forgeUrl.value, repoProviderID.value, sha)
}

function severityBadgeClass(severity: string) {
  return `sev-${severity.toLowerCase()} rounded-full px-2.5 py-1 text-xs font-medium`
}

function changeBadgeClass(change: string) {
  if (change === 'new' || change === 'added') {
    return 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-emerald-300'
  }

  return 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] text-danger'
}

function pillClass(color: 'emerald' | 'red' | 'amber') {
  const palette = {
    emerald: 'bg-emerald-500/15 text-emerald-300',
    red: 'bg-danger/15 text-danger',
    amber: 'bg-amber-500/15 text-amber-300',
  }
  return `rounded-full px-2.5 py-1 text-xs font-medium uppercase tracking-[0.14em] ${palette[color]}`
}

function coverageChangeBadgeClass(change: CoverageFileDelta['change']) {
  switch (change) {
    case 'improved':
    case 'added':
      return pillClass('emerald')
    case 'regressed':
    case 'removed':
      return pillClass('red')
    default:
      return pillClass('amber')
  }
}

function statusBadgeClass(status: string) {
  switch (status) {
    case 'passed':
      return 'rounded-full bg-emerald-500/15 px-2.5 py-1 text-xs font-medium text-emerald-300'
    case 'failed':
    case 'error':
      return 'rounded-full bg-danger/15 px-2.5 py-1 text-xs font-medium text-danger'
    case 'skipped':
      return 'rounded-full bg-amber-500/15 px-2.5 py-1 text-xs font-medium text-amber-300'
    default:
      return 'rounded-full bg-surface-overlay px-2.5 py-1 text-xs font-medium text-gray-300'
  }
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value))
}

function vulnerabilityLocation(vuln: Vulnerability) {
  if (vuln.file_path) {
    return vuln.start_line ? `${vuln.file_path}:${vuln.start_line}` : vuln.file_path
  }

  if (vuln.component_name) {
    return vuln.component_version ? `${vuln.component_name}@${vuln.component_version}` : vuln.component_name
  }

  return 'n/a'
}

function formatRate(rate: number | null) {
  if (rate === null || rate === undefined) {
    return 'n/a'
  }
  return `${(rate * 100).toFixed(1)}%`
}

function formatRateDelta(delta: number | null) {
  if (delta === null || delta === undefined) {
    return 'n/a'
  }
  const points = delta * 100
  if (Math.abs(points) < 0.05) {
    return '0.0 pp'
  }
  return `${points > 0 ? '+' : ''}${points.toFixed(1)} pp`
}

function formatDuration(seconds: number) {
  if (seconds >= 1) {
    return `${seconds.toFixed(2)}s`
  }
  return `${(seconds * 1000).toFixed(0)}ms`
}

function formatDurationDelta(seconds: number) {
  if (Math.abs(seconds) < 0.0005) {
    return '±0ms'
  }
  const sign = seconds > 0 ? '+' : '-'
  const abs = Math.abs(seconds)
  return `${sign}${abs >= 1 ? `${abs.toFixed(2)}s` : `${(abs * 1000).toFixed(0)}ms`}`
}

function rateColor(rate: number | null) {
  if (rate === null || rate === undefined) {
    return 'var(--color-text-muted, #6b7280)'
  }
  const percent = rate * 100
  if (percent >= 80) {
    return 'var(--color-ok, #3fb950)'
  }
  if (percent >= 60) {
    return 'var(--color-warn, #d29922)'
  }
  return 'var(--color-danger, #f85149)'
}

function deltaColor(delta: number | null) {
  if (delta === null || delta === undefined || Math.abs(delta) < 1e-9) {
    return 'var(--color-text-muted, #6b7280)'
  }
  return delta > 0 ? 'var(--color-ok, #3fb950)' : 'var(--color-danger, #f85149)'
}

function trendIcon(delta: number | null) {
  if (delta === null || delta === undefined || Math.abs(delta) < 1e-9) {
    return Minus
  }
  return delta > 0 ? ArrowUpRight : ArrowDownRight
}

function coverageBarStyle(rate: number | null) {
  return {
    width: `${Math.max(0, Math.min(100, (rate ?? 0) * 100))}%`,
    backgroundColor: rateColor(rate),
  }
}
</script>

<style scoped>
.compare-display {
  font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace;
}

/* Lift every real child above the decorative aurora/grain layers. */
.compare-root > :not(.compare-aurora):not(.compare-grain) {
  position: relative;
}

/* Atmospheric mesh — a quiet night sky for an owl. */
.compare-aurora {
  background:
    radial-gradient(120% 80% at 8% -10%, rgb(88 166 255 / 0.16), transparent 55%),
    radial-gradient(90% 70% at 100% 0%, rgb(63 185 80 / 0.10), transparent 50%),
    radial-gradient(80% 90% at 60% 120%, rgb(188 140 255 / 0.08), transparent 60%);
  opacity: 0.9;
}

.compare-grain {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.5'/%3E%3C/svg%3E");
  opacity: 0.025;
  mix-blend-mode: overlay;
}

/* Pulsing signal beacon in the eyebrow. */
.compare-beacon {
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 9999px;
  background: #58a6ff;
  box-shadow: 0 0 0 0 rgb(88 166 255 / 0.55);
  animation: compare-pulse 2.4s ease-out infinite;
}

@keyframes compare-pulse {
  0% { box-shadow: 0 0 0 0 rgb(88 166 255 / 0.5); }
  70% { box-shadow: 0 0 0 8px rgb(88 166 255 / 0); }
  100% { box-shadow: 0 0 0 0 rgb(88 166 255 / 0); }
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

.compare-select {
  transition: border-color 0.18s ease, box-shadow 0.18s ease;
}
.compare-select:hover,
.compare-select:focus {
  border-color: rgb(88 166 255 / 0.6);
  box-shadow: 0 0 0 1px rgb(88 166 255 / 0.25);
}

.compare-snapcard {
  transition: border-color 0.2s ease, transform 0.2s ease;
}
.compare-snapcard:hover {
  border-color: rgb(88 166 255 / 0.35);
  transform: translateY(-1px);
}

/* Underline-glide tabs. */
.compare-tab {
  position: relative;
}
.compare-tab::after {
  content: '';
  position: absolute;
  left: 0.6rem;
  right: 0.6rem;
  bottom: -1px;
  height: 2px;
  border-radius: 2px;
  background: linear-gradient(90deg, #58a6ff, #79c0ff);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 0.22s ease;
}
.compare-tab:hover::after { transform: scaleX(0.4); }
.compare-tab-active::after { transform: scaleX(1); }
.compare-tab-active { text-shadow: 0 0 16px rgb(88 166 255 / 0.25); }

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
  .compare-beacon,
  .compare-scan {
    animation: none;
  }
}
</style>
