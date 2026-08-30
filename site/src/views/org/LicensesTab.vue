<template>
  <div class="space-y-5">
    <!-- Coverage first, deliberately. Every number below is drawn only from
         repos that produced a usable snapshot, and "no copyleft found" is
         worthless without knowing how much was actually looked at. -->
    <section class="rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Coverage
        </h2>
        <span class="text-xs text-gray-500">
          License exposure across each repository's current default-branch snapshot
        </span>
      </div>

      <div
        v-if="loading"
        class="py-10 text-center text-sm text-gray-500"
      >
        Loading licenses...
      </div>
      <div
        v-else-if="error"
        class="py-10 text-center text-sm text-danger"
      >
        {{ error }}
      </div>
      <template v-else>
        <div class="grid grid-cols-2 gap-3 px-4 py-4 lg:grid-cols-5">
          <div
            v-for="tile in coverageTiles"
            :key="tile.label"
            class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3"
            :class="tile.accent"
          >
            <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              {{ tile.label }}
            </div>
            <div
              class="mt-1.5 text-2xl font-semibold"
              :class="tile.valueClass"
            >
              {{ tile.value }}
            </div>
            <div class="mt-1 text-[11px] leading-snug text-gray-500">
              {{ tile.hint }}
            </div>
          </div>
        </div>

        <!-- The two caveats that decide whether this page is trustworthy. -->
        <div class="space-y-1.5 border-t border-surface-border-subtle px-4 py-3 text-[11px] leading-relaxed text-gray-500">
          <p v-if="unscannedRepos > 0">
            <span class="font-medium text-warn">{{ unscannedRepos }}</span>
            {{ unscannedRepos === 1 ? 'enrolled repository has' : 'enrolled repositories have' }}
            no snapshot with components, so nothing here covers them.
          </p>
          <p>
            This is <span class="text-gray-400">exposure, not enforcement</span> — a component listed
            under a restrictive category does not mean any repository's quality gate denies it.
          </p>
          <p>
            Scope is every component in the ingested SBOMs. Dependency scanners typically omit
            dev-only dependencies, so a build- or test-only package may be absent rather than clean.
          </p>
        </div>
      </template>
    </section>

    <!-- Policy compliance. Separate from the exposure numbers above: this is
         what the org enforces and who has departed from it, not what is present.
         Deliberately not loaded with the page — see loadPolicy. -->
    <section class="rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b border-surface-border-subtle px-4 py-3">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          Policy compliance
        </h2>
        <button
          v-if="policyRequested && !policyLoading"
          type="button"
          class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
          @click="loadPolicy"
        >
          Re-check
        </button>
      </div>

      <!-- The override rule is stated whether or not the check has run: a reader
           looking at the org policy after a re-check still needs to know that any
           repository's own block discards all of it. -->
      <p class="border-b border-surface-border-subtle px-4 py-3 text-xs leading-relaxed text-gray-500">
        The organization holds <span class="text-gray-400">one</span> license policy and every
        repository inherits it, unless the repository's own
        <code class="text-gray-400">.hibou.yaml</code> declares a
        <code class="text-gray-400">licenses:</code> block — which
        <span class="text-gray-400">replaces</span> the org policy entirely rather than merging
        with it.
      </p>

      <!-- The check fans out to one forge request per repository, so the wait is
           expected; saying so up front keeps it from reading as a hang. -->
      <div
        v-if="!policyRequested"
        class="flex flex-wrap items-center justify-between gap-4 px-4 py-4"
      >
        <p class="max-w-2xl text-xs leading-relaxed text-gray-500">
          Which repositories have departed from it is not shown automatically: finding out reads
          each enrolled repository's configuration from the forge, one request per repository.
        </p>
        <button
          type="button"
          class="rounded-md border border-surface-border bg-surface-overlay px-3 py-1.5 text-xs font-medium text-gray-200 transition hover:border-accent/50 hover:text-white"
          @click="loadPolicy"
        >
          Check repository overrides
        </button>
      </div>
      <div
        v-else-if="policyLoading"
        class="py-10 text-center text-sm text-gray-500"
      >
        Reading each repository's configuration...
      </div>
      <!-- An error is an unknown, not a clean bill of health. -->
      <div
        v-else-if="policyError"
        class="py-10 text-center text-sm text-danger"
      >
        {{ policyError }}
      </div>
      <!-- A response whose repository scan did not run must not be rendered as a
           result. An empty list is an unknown here, not an all-clear. -->
      <div
        v-else-if="policy && !policy.repos_scanned"
        class="px-4 py-6 text-center text-sm text-warn"
      >
        Repositories were not checked, so whether any has departed from this policy is unknown.
      </div>
      <template v-else-if="policy">
        <div class="grid grid-cols-2 gap-3 px-4 py-4 lg:grid-cols-6">
          <!-- Departures leads and is the only tile sized to be read from across
               the room; the rest is denominator. -->
          <div
            class="col-span-2 rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3"
            :class="policy.departures > 0 ? 'border-l-2 border-l-danger/70' : ''"
          >
            <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              Departures
            </div>
            <!-- With no org policy there is nothing to depart from, so a green
                 zero would be reassurance about a rule that does not exist. -->
            <div
              class="mt-1.5 text-3xl font-semibold"
              :class="departureTone"
            >
              {{ policy.configured ? policy.departures : '—' }}
            </div>
            <div class="mt-1 text-[11px] leading-snug text-gray-500">
              {{ departureHint }}
            </div>
          </div>
          <div
            v-for="tile in policyTiles"
            :key="tile.label"
            class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-4 py-3"
            :class="tile.accent"
          >
            <div class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              {{ tile.label }}
            </div>
            <div
              class="mt-1.5 text-2xl font-semibold"
              :class="tile.valueClass"
            >
              {{ tile.value }}
            </div>
            <div class="mt-1 text-[11px] leading-snug text-gray-500">
              {{ tile.hint }}
            </div>
          </div>
        </div>

        <dl
          v-if="policySpec"
          class="grid gap-x-6 gap-y-3 border-t border-surface-border-subtle px-4 py-4 sm:grid-cols-2"
        >
          <div>
            <dt class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              Denied categories
            </dt>
            <dd class="mt-1 flex flex-wrap gap-1">
              <span
                v-for="category in policySpec.deny_categories"
                :key="category"
                class="rounded border border-surface-border-subtle px-1.5 py-0.5 text-[11px]"
                :class="deniedChipClass(category)"
              >{{ categoryLabel(category) }}</span>
              <span
                v-if="policySpec.deny_categories.length === 0"
                class="text-[11px] text-gray-500"
              >none</span>
            </dd>
          </div>
          <div
            v-for="list in policyLists"
            :key="list.label"
          >
            <dt class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              {{ list.label }}
            </dt>
            <dd class="mt-1 flex flex-wrap gap-1">
              <span
                v-for="value in list.values"
                :key="value"
                class="max-w-full truncate rounded border border-surface-border-subtle px-1.5 py-0.5 font-mono text-[11px] text-gray-300"
                :title="value"
              >{{ value }}</span>
              <span
                v-if="list.values.length === 0"
                class="text-[11px] text-gray-500"
              >none</span>
            </dd>
          </div>
          <div>
            <dt class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              Unrecognized or missing license
            </dt>
            <dd
              class="mt-1 text-[11px] leading-relaxed"
              :class="policySpec.deny_unknown ? 'text-gray-300' : 'text-warn'"
            >
              {{ policySpec.deny_unknown
                ? 'Denied — a component whose license the catalog cannot place fails the gate'
                : 'Allowed — a component whose license the catalog cannot place passes the gate' }}
            </dd>
          </div>
          <div>
            <dt class="text-[11px] font-medium uppercase tracking-[0.16em] text-gray-500">
              Scope
            </dt>
            <dd class="mt-1 text-[11px] leading-relaxed text-gray-300">
              {{ policySpec.evaluate === 'all'
                ? 'Every component in the dependency tree'
                : 'Only the components a change introduces' }}
            </dd>
          </div>
        </dl>
        <p
          v-else
          class="border-t border-surface-border-subtle px-4 py-3 text-[11px] leading-relaxed text-gray-500"
        >
          No organization license policy is set, so no repository inherits anything — each one is
          governed only by the <code class="text-gray-400">licenses:</code> block in its own
          <code class="text-gray-400">.hibou.yaml</code>, or by nothing at all.
        </p>

        <div
          v-if="policy.repos.length === 0"
          class="border-t border-surface-border-subtle py-10 text-center text-sm text-gray-500"
        >
          No repository in this organization is enrolled.
        </div>
        <!-- Row order is the API's: departures, then unreadable, then the rest.
             Re-sorting here would bury what the endpoint ranked. -->
        <div
          v-else
          class="overflow-x-auto border-t border-surface-border-subtle"
        >
          <table class="w-full text-left text-sm">
            <thead class="border-b border-surface-border-subtle text-[11px] uppercase tracking-[0.12em] text-gray-500">
              <tr>
                <th class="px-4 py-2 font-medium">
                  Repository
                </th>
                <th class="px-4 py-2 font-medium">
                  Policy source
                </th>
                <th class="px-4 py-2 font-medium">
                  Against org
                </th>
                <th class="px-4 py-2 font-medium">
                  What differs
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="repo in policy.repos"
                :key="repo.slug"
                class="border-b border-surface-border-subtle/50 last:border-0"
                :class="policyRowAccent(repo)"
              >
                <td class="px-4 py-2">
                  <RouterLink
                    :to="{ name: 'repo-dependencies', params: { provider, slug, repoSlug: repo.slug } }"
                    class="text-gray-200 hover:text-white hover:underline"
                  >
                    {{ repo.name || repo.slug }}
                  </RouterLink>
                </td>
                <td class="px-4 py-2 text-xs">
                  <span
                    v-if="repo.unreadable"
                    class="text-warn"
                    title="The repository's .hibou.yaml could not be fetched, so its policy is unknown — not assumed compliant"
                  >Unreadable</span>
                  <span
                    v-else
                    class="text-gray-400"
                  >{{ sourceLabel(repo.source) }}</span>
                </td>
                <td class="px-4 py-2 text-xs">
                  <span
                    v-if="repo.unreadable"
                    class="text-warn"
                  >unknown</span>
                  <span
                    v-else-if="repo.relation"
                    :class="relationText(repo.relation)"
                  >{{ relationLabel(repo.relation) }}</span>
                  <span
                    v-else
                    class="text-gray-600"
                  >—</span>
                </td>
                <td class="px-4 py-2">
                  <ul
                    v-if="repo.differences?.length"
                    class="space-y-0.5"
                  >
                    <li
                      v-for="difference in repo.differences"
                      :key="difference.field"
                      class="font-mono text-[11px] leading-relaxed"
                    >
                      <span :class="relationText(difference.direction)">{{ difference.field }}</span>
                      <!-- The delta, not both whole sets: on a real policy the
                           full lists are too long to diff by eye. The sets stay
                           on the tooltip for anyone who wants them. -->
                      <span
                        class="text-gray-300"
                        :title="`${diffValue(difference.base)} → ${diffValue(difference.override)}`"
                      >: {{ diffSummary(difference) }}</span>
                    </li>
                  </ul>
                  <span
                    v-else
                    class="text-[11px] text-gray-600"
                  >—</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </template>
    </section>

    <template v-if="!loading && !error && overview">
      <!-- Category partition, most restrictive first: the categories that force
           a decision lead, rather than the ones with the biggest counts. -->
      <section class="space-y-3">
        <div class="flex items-center justify-between">
          <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
            Categories
          </h2>
          <span class="text-xs text-gray-500">{{ overview.coverage.components_total }} components</span>
        </div>
        <div class="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <button
            v-for="stat in orderedCategories"
            :key="stat.category"
            type="button"
            :disabled="stat.components === 0"
            class="rounded-xl border border-surface-border-subtle bg-surface-overlay/40 px-3 py-2.5 text-left transition enabled:hover:border-gray-600 enabled:hover:bg-surface-overlay/70 disabled:cursor-default"
            :class="[stat.components > 0 ? categoryAccent(stat.category) : 'opacity-60', isActiveDrilldown({ category: stat.category }) ? 'ring-1 ring-gray-500' : '']"
            @click="openDrilldown({ category: stat.category })"
          >
            <div class="text-[11px] font-medium uppercase tracking-[0.12em] text-gray-500">
              {{ categoryLabel(stat.category) }}
            </div>
            <div
              class="mt-1 text-xl font-semibold"
              :class="stat.components > 0 ? categoryText(stat.category) : 'text-gray-600'"
            >
              {{ stat.components }}
            </div>
            <div class="text-[11px] text-gray-500">
              {{ stat.repos }} {{ stat.repos === 1 ? 'repo' : 'repos' }}
            </div>
          </button>
        </div>
      </section>

      <!-- Unknown splits into two problems with different owners. Merging them
           sends the whole bucket to whoever shouts loudest. -->
      <section
        v-if="overview.coverage.undeclared > 0 || overview.coverage.unrecognized > 0"
        class="grid gap-3 md:grid-cols-2"
      >
        <div class="rounded-2xl border border-surface-border-subtle bg-surface-raised/40 px-4 py-3">
          <div class="flex items-baseline justify-between">
            <h3 class="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-400">
              No license metadata
            </h3>
            <button
              type="button"
              class="text-lg font-semibold text-warn hover:underline"
              @click="openDrilldown({ undeclared: true })"
            >
              {{ overview.coverage.undeclared }}
            </button>
          </div>
          <p class="mt-1 text-[11px] leading-relaxed text-gray-500">
            The SBOM carried no license for these components. Fix the generator — a missing
            license is not a permissive one, and <code class="text-gray-400">deny_unknown</code>
            defaults to true.
          </p>
        </div>
        <div class="rounded-2xl border border-surface-border-subtle bg-surface-raised/40 px-4 py-3">
          <div class="flex items-baseline justify-between">
            <h3 class="text-[11px] font-semibold uppercase tracking-[0.16em] text-gray-400">
              Unrecognized identifier
            </h3>
            <span class="text-lg font-semibold text-warn">{{ overview.coverage.unrecognized }}</span>
          </div>
          <p class="mt-1 text-[11px] leading-relaxed text-gray-500">
            A license was declared but does not map to a category, so it is treated as the most
            restrictive. These are catalog gaps — see the unknown rows below.
          </p>
        </div>
      </section>

      <!-- Licenses in use -->
      <section class="space-y-3">
        <div class="flex flex-wrap items-center justify-between gap-3">
          <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
            Licenses in use
          </h2>
          <div class="flex items-center gap-3">
            <input
              v-model="licenseSearch"
              type="text"
              placeholder="Filter licenses…"
              class="w-48 rounded-lg border border-surface-border-subtle bg-surface-overlay/40 px-2.5 py-1 text-xs text-gray-200 placeholder:text-gray-600 focus:border-gray-600 focus:outline-none"
            >
            <span class="text-xs text-gray-500">{{ filteredLicenses.length }} distinct</span>
          </div>
        </div>

        <div class="overflow-hidden rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
          <div
            v-if="filteredLicenses.length === 0"
            class="py-10 text-center text-sm text-gray-500"
          >
            {{ overview.licenses.length === 0 ? 'No license metadata across this organization.' : 'No licenses match that filter.' }}
          </div>
          <div
            v-else
            class="overflow-x-auto"
          >
            <table class="w-full text-left text-sm">
              <thead class="border-b border-surface-border-subtle text-[11px] uppercase tracking-[0.12em] text-gray-500">
                <tr>
                  <th class="px-4 py-2 font-medium">
                    License
                  </th>
                  <th class="px-4 py-2 font-medium">
                    Category
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Components
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Repos
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="stat in filteredLicenses"
                  :key="stat.license"
                  class="cursor-pointer border-b border-surface-border-subtle/50 transition last:border-0 hover:bg-white/5"
                  :class="isActiveDrilldown({ license: stat.license }) ? 'bg-white/5' : ''"
                  @click="openDrilldown({ license: stat.license })"
                >
                  <td class="px-4 py-2">
                    <span class="font-mono text-xs text-gray-200">{{ stat.license }}</span>
                    <!-- AND vs OR is not cosmetic: the gate resolves them
                         differently, so an unflagged table looks like it
                         disagrees with the check that ran. -->
                    <span
                      v-if="stat.has_and"
                      class="ml-2 rounded border border-surface-border-subtle px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-warn"
                      title="Conjunctive: every operand's obligations apply at once"
                    >and</span>
                    <span
                      v-if="stat.has_or"
                      class="ml-2 rounded border border-surface-border-subtle px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-gray-400"
                      title="Elective: the category shown is the alternative a consumer would pick"
                    >or</span>
                  </td>
                  <td class="px-4 py-2">
                    <span
                      class="rounded border border-surface-border-subtle px-1.5 py-0.5 text-[11px]"
                      :class="categoryText(stat.category)"
                    >{{ categoryLabel(stat.category) }}</span>
                  </td>
                  <td class="px-4 py-2 text-right tabular-nums text-gray-300">
                    {{ stat.components }}
                  </td>
                  <td class="px-4 py-2 text-right tabular-nums text-gray-400">
                    {{ stat.repos }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <!-- Drilldown: opened by any count above. Rendered above the per-repo
           table so the answer appears next to the question that was clicked. -->
      <section
        v-if="drilldown"
        class="space-y-3"
      >
        <div class="flex flex-wrap items-center justify-between gap-3">
          <!-- The count is omitted while loading or after an error: showing a
               stale or zeroed total beside a failure reads as "there are none". -->
          <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
            <template v-if="drilldownLoading || drilldownError">
              {{ drilldownLabel }}
            </template>
            <template v-else>
              {{ drilldownTotal }} {{ drilldownLabel }}
            </template>
          </h2>
          <button
            type="button"
            class="rounded-lg border border-surface-border-subtle px-2.5 py-1 text-xs text-gray-400 transition hover:border-gray-600 hover:text-gray-200"
            @click="closeDrilldown"
          >
            Clear
          </button>
        </div>

        <div class="overflow-hidden rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
          <div
            v-if="drilldownLoading"
            class="py-10 text-center text-sm text-gray-500"
          >
            Loading components...
          </div>
          <div
            v-else-if="drilldownError"
            class="py-10 text-center text-sm text-danger"
          >
            {{ drilldownError }}
          </div>
          <div
            v-else-if="drilldownRows.length === 0"
            class="py-10 text-center text-sm text-gray-500"
          >
            No components match.
          </div>
          <div
            v-else
            class="overflow-x-auto"
          >
            <table class="w-full text-left text-sm">
              <thead class="border-b border-surface-border-subtle text-[11px] uppercase tracking-[0.12em] text-gray-500">
                <tr>
                  <th class="px-4 py-2 font-medium">
                    Component
                  </th>
                  <th class="px-4 py-2 font-medium">
                    Ecosystem
                  </th>
                  <th class="px-4 py-2 font-medium">
                    License
                  </th>
                  <th class="px-4 py-2 font-medium">
                    Category
                  </th>
                  <th class="px-4 py-2 font-medium">
                    Repositories
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="row in drilldownRows"
                  :key="row.purl + '@' + row.version"
                  class="border-b border-surface-border-subtle/50 last:border-0"
                >
                  <td class="px-4 py-2">
                    <div class="font-medium text-gray-200">
                      {{ row.name }}
                    </div>
                    <div
                      class="truncate font-mono text-[11px] text-gray-500"
                      :title="row.purl"
                    >
                      {{ row.version }}
                    </div>
                  </td>
                  <td class="px-4 py-2 text-xs text-gray-400">
                    {{ row.ecosystem || 'unknown' }}
                  </td>
                  <td class="px-4 py-2">
                    <div
                      v-if="row.licenses.length"
                      class="flex flex-wrap gap-1"
                    >
                      <span
                        v-for="licenseId in row.licenses"
                        :key="licenseId"
                        class="font-mono text-[11px] text-gray-300"
                      >{{ licenseId }}</span>
                    </div>
                    <span
                      v-else
                      class="text-[11px] text-warn"
                      title="No license metadata in the SBOM"
                    >none declared</span>
                  </td>
                  <td class="px-4 py-2">
                    <span
                      class="rounded border border-surface-border-subtle px-1.5 py-0.5 text-[11px]"
                      :class="categoryText(row.category)"
                    >{{ categoryLabel(row.category) }}</span>
                  </td>
                  <td class="px-4 py-2">
                    <div class="flex flex-wrap gap-1">
                      <RouterLink
                        v-for="repoSlug in row.repos.slice(0, 3)"
                        :key="repoSlug"
                        :to="{ name: 'repo-dependencies', params: { provider, slug, repoSlug } }"
                        class="rounded-full border border-surface-border px-2 py-0.5 text-[11px] text-gray-300 hover:text-white"
                      >
                        {{ repoSlug }}
                      </RouterLink>
                      <span
                        v-if="row.repos.length > 3"
                        class="text-[11px] text-gray-500"
                        :title="row.repos.join(', ')"
                      >+{{ row.repos.length - 3 }}</span>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div
            v-if="drilldownPages > 1"
            class="flex items-center justify-between border-t border-surface-border-subtle px-4 py-2 text-xs text-gray-500"
          >
            <button
              type="button"
              :disabled="drilldownPage <= 1"
              class="rounded px-2 py-1 transition enabled:hover:text-gray-200 disabled:opacity-40"
              @click="goToDrilldownPage(drilldownPage - 1)"
            >
              ← Previous
            </button>
            <span>Page {{ drilldownPage }} of {{ drilldownPages }}</span>
            <button
              type="button"
              :disabled="drilldownPage >= drilldownPages"
              class="rounded px-2 py-1 transition enabled:hover:text-gray-200 disabled:opacity-40"
              @click="goToDrilldownPage(drilldownPage + 1)"
            >
              Next →
            </button>
          </div>
        </div>
      </section>

      <!-- Per-repo posture -->
      <section class="space-y-3">
        <h2 class="text-[11px] font-semibold uppercase tracking-[0.18em] text-gray-400">
          By repository
        </h2>
        <div class="overflow-hidden rounded-2xl border border-surface-border-subtle bg-surface-raised/40">
          <div
            v-if="overview.repos.length === 0"
            class="py-10 text-center text-sm text-gray-500"
          >
            No repository in this organization has a snapshot with components.
          </div>
          <div
            v-else
            class="overflow-x-auto"
          >
            <table class="w-full text-left text-sm">
              <thead class="border-b border-surface-border-subtle text-[11px] uppercase tracking-[0.12em] text-gray-500">
                <tr>
                  <th class="px-4 py-2 font-medium">
                    Repository
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Components
                  </th>
                  <th
                    v-for="category in repoColumnCategories"
                    :key="category"
                    class="px-4 py-2 text-right font-medium"
                  >
                    {{ categoryLabel(category) }}
                  </th>
                  <th class="px-4 py-2 text-right font-medium">
                    Snapshot
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="repo in overview.repos"
                  :key="repo.slug"
                  class="border-b border-surface-border-subtle/50 last:border-0"
                >
                  <td class="px-4 py-2">
                    <RouterLink
                      :to="{ name: 'repo-dependencies', params: { provider, slug, repoSlug: repo.slug } }"
                      class="text-gray-200 hover:text-white hover:underline"
                    >
                      {{ repo.name || repo.slug }}
                    </RouterLink>
                  </td>
                  <td class="px-4 py-2 text-right tabular-nums">
                    <button
                      type="button"
                      class="text-gray-400 hover:text-white hover:underline"
                      @click="openDrilldown({ repo: repo.slug })"
                    >
                      {{ repo.components }}
                    </button>
                  </td>
                  <td
                    v-for="category in repoColumnCategories"
                    :key="category"
                    class="px-4 py-2 text-right tabular-nums"
                    :class="(repo.by_category[category] ?? 0) > 0 ? categoryText(category) : 'text-gray-600'"
                  >
                    {{ repo.by_category[category] ?? 0 }}
                  </td>
                  <td class="px-4 py-2 text-right text-xs text-gray-500">
                    {{ formatSnapshot(repo) }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import {
  api,
  type LicenseCategory,
  type OrgLicenseComponent,
  type OrgLicenseComponentQuery,
  type OrgLicenseOverview,
  type OrgLicensePolicyOverview,
  type OrgLicensePolicyDiff,
  type OrgLicensePolicyRepo,
  type OrgLicenseRelation,
  type OrgLicenseRepoStat,
} from '@/api/client'
import { LICENSE_CATEGORY_LABELS, LICENSE_CATEGORY_ORDER } from '@/lib/licenses'

const route = useRoute()
const provider = computed(() => route.params.provider as string)
const slug = computed(() => route.params.slug as string)

const overview = ref<OrgLicenseOverview | null>(null)
const loading = ref(true)
const error = ref('')
const licenseSearch = ref('')

// Most restrictive first. The backend returns categories least-to-most
// restrictive because that is the natural partition order; the page inverts it
// because the reader is looking for problems, not for a taxonomy.
// The shared taxonomy already lists categories most-restrictive-first, which is
// the order a reader hunting for problems wants, so this is a reference rather
// than a second copy that could drift from it.
const CATEGORY_DISPLAY_ORDER = LICENSE_CATEGORY_ORDER

// Per-repo columns stay narrow: the categories that actually drive a decision.
const repoColumnCategories: LicenseCategory[] = [
  'unknown',
  'source-available',
  'network-copyleft',
  'copyleft',
]

// Shared with the policy settings form; see lib/licenses.
const CATEGORY_LABELS = LICENSE_CATEGORY_LABELS

const orderedCategories = computed(() => {
  const byCategory = new Map(overview.value?.categories.map((stat) => [stat.category, stat]) ?? [])
  return CATEGORY_DISPLAY_ORDER.map(
    (category) => byCategory.get(category) ?? { category, components: 0, repos: 0 },
  )
})

const unscannedRepos = computed(() => {
  const coverage = overview.value?.coverage
  if (!coverage) return 0
  return Math.max(0, coverage.repos_enrolled - coverage.repos_with_components)
})

const coverageTiles = computed(() => {
  const coverage = overview.value?.coverage
  if (!coverage) return []
  const undeclared = coverage.undeclared
  return [
    {
      label: 'Repos enrolled',
      value: coverage.repos_enrolled,
      hint: 'watched by hibou',
      accent: '',
      valueClass: 'text-white',
    },
    {
      label: 'With a snapshot',
      value: coverage.repos_with_snapshot,
      hint: 'resolved a current snapshot',
      accent: '',
      valueClass: 'text-white',
    },
    {
      label: 'With components',
      value: coverage.repos_with_components,
      hint: 'actually contributed data',
      accent: unscannedRepos.value > 0 ? 'border-l-2 border-l-warn/70' : '',
      valueClass: unscannedRepos.value > 0 ? 'text-warn' : 'text-ok',
    },
    {
      label: 'Components',
      value: coverage.components_total,
      hint: 'distinct package versions',
      accent: '',
      valueClass: 'text-white',
    },
    {
      label: 'Unlicensed',
      value: undeclared,
      hint: 'no license metadata',
      accent: undeclared > 0 ? 'border-l-2 border-l-warn/70' : '',
      valueClass: undeclared > 0 ? 'text-warn' : 'text-ok',
    },
  ]
})

const filteredLicenses = computed(() => {
  const licenses = overview.value?.licenses ?? []
  const query = licenseSearch.value.trim().toLowerCase()
  if (!query) return licenses
  return licenses.filter(
    (stat) => stat.license.toLowerCase().includes(query) || stat.category.includes(query),
  )
})

function categoryLabel(category: LicenseCategory | string): string {
  return CATEGORY_LABELS[category as LicenseCategory] ?? category
}

function categoryText(category: LicenseCategory | string): string {
  switch (category) {
    case 'source-available':
    case 'network-copyleft':
      return 'text-danger'
    case 'copyleft':
      return 'text-orange-400'
    case 'unknown':
    case 'weak-copyleft':
      return 'text-warn'
    default:
      return 'text-ok'
  }
}

function categoryAccent(category: LicenseCategory | string): string {
  switch (category) {
    case 'source-available':
    case 'network-copyleft':
      return 'border-l-2 border-l-danger/70'
    case 'copyleft':
      return 'border-l-2 border-l-orange-400/70'
    case 'unknown':
      return 'border-l-2 border-l-warn/70'
    default:
      return ''
  }
}

function formatSnapshot(repo: OrgLicenseRepoStat): string {
  if (!repo.snapshot_at) return repo.snapshot_status || '—'
  const days = Math.floor((Date.now() - new Date(repo.snapshot_at).getTime()) / 86_400_000)
  if (days <= 0) return 'today'
  if (days === 1) return 'yesterday'
  return `${days}d ago`
}

// Policy compliance. This endpoint fetches every repository's .hibou.yaml from
// the forge, so it stays behind an explicit click instead of loading with the
// tab — including the one free fact it carries, whether an org policy exists.
const policy = ref<OrgLicensePolicyOverview | null>(null)
const policyRequested = ref(false)
const policyLoading = ref(false)
const policyError = ref('')

// configured is false for both a missing and an emptied-out policy; the spec is
// only worth rendering when it actually governs something.
const policySpec = computed(() => (policy.value?.configured ? policy.value.policy ?? null : null))

const RELATION_LABELS: Record<OrgLicenseRelation, string> = {
  equivalent: 'Equivalent',
  stricter: 'Stricter',
  looser: 'Looser',
  mixed: 'Mixed',
}

const SOURCE_LABELS: Record<OrgLicensePolicyRepo['source'], string> = {
  organization: 'Inherited',
  repository: 'Own .hibou.yaml',
  none: 'No policy',
}

const policyTiles = computed(() => {
  const current = policy.value
  if (!current) return []
  return [
    {
      label: 'Overriding',
      value: current.overriding,
      hint: 'declare their own policy',
      accent: '',
      valueClass: 'text-white',
    },
    {
      label: 'Inheriting',
      value: current.inheriting,
      hint: 'use the org policy as-is',
      accent: '',
      valueClass: 'text-white',
    },
    {
      // An unreadable config is an unknown, so it never gets the ok colour.
      label: 'Unreadable',
      value: current.unreadable,
      hint: 'config could not be fetched',
      accent: current.unreadable > 0 ? 'border-l-2 border-l-warn/70' : '',
      valueClass: current.unreadable > 0 ? 'text-warn' : 'text-gray-500',
    },
    {
      label: 'Enrolled',
      value: current.total,
      hint: 'repositories checked',
      accent: '',
      valueClass: 'text-white',
    },
  ]
})

const policyLists = computed(() => {
  const spec = policySpec.value
  if (!spec) return []
  return [
    { label: 'Denied licenses', values: spec.deny },
    { label: 'Allowed licenses', values: spec.allow },
    { label: 'Exempt packages', values: spec.exempt_purls },
  ]
})

function relationLabel(relation: string): string {
  return RELATION_LABELS[relation as OrgLicenseRelation] ?? relation
}

// Only looser and mixed are compliance departures; a repository that tightened
// its own policy is not a finding, so it must not read like one.
function relationText(relation: string): string {
  switch (relation) {
    case 'looser':
    case 'mixed':
      return 'text-danger'
    case 'stricter':
      return 'text-ok'
    default:
      return 'text-gray-400'
  }
}

function sourceLabel(source: OrgLicensePolicyRepo['source']): string {
  return SOURCE_LABELS[source] ?? source
}

function policyRowAccent(repo: OrgLicensePolicyRepo): string {
  if (repo.relation === 'looser' || repo.relation === 'mixed') {
    return 'border-l-2 border-l-danger/70'
  }
  if (repo.unreadable) return 'border-l-2 border-l-warn/70'
  return ''
}

// The backend already renders set axes as comma-joined text; an empty axis means
// the list was empty, not that nothing changed.
function diffValue(value: string): string {
  return value.trim() === '' ? 'none' : value
}

// diffSummary renders what actually changed on one axis. Set axes get
// gained/dropped lists; scalar axes (deny_unknown, evaluate) have no delta and
// fall back to the before → after pair, which is short enough to read.
function diffSummary(difference: OrgLicensePolicyDiff): string {
  const parts: string[] = []
  if (difference.added?.length) parts.push(`+${difference.added.join(' +')}`)
  if (difference.removed?.length) parts.push(`−${difference.removed.join(' −')}`)
  if (parts.length > 0) return parts.join(' ')
  return `${diffValue(difference.base)} → ${diffValue(difference.override)}`
}

// With no org policy configured there is nothing to depart from, so the count is
// not a reassurance — it is not applicable.
const departureTone = computed(() => {
  const current = policy.value
  if (!current?.configured) return 'text-gray-500'
  return current.departures > 0 ? 'text-danger' : 'text-ok'
})

const departureHint = computed(() => {
  const current = policy.value
  if (!current) return ''
  if (!current.configured) {
    return 'no organization policy is set, so repositories are governed only by their own .hibou.yaml'
  }
  return current.departures > 0
    ? 'repositories loosened the org policy, or changed it in both directions'
    : 'no repository has loosened the org policy'
})

// In the exposure tables a category's colour means "how restrictive is this
// license". In a list of DENIED categories that mapping inverts — denying
// `permissive` would render a reassuring green — so denials are styled by the
// fact of denial, not by the category.
function deniedChipClass(category: string): string {
  return CATEGORY_LABELS[category as LicenseCategory] ? 'text-gray-200' : 'text-warn'
}

async function loadPolicy() {
  if (!provider.value || !slug.value) return
  policyRequested.value = true
  policyLoading.value = true
  policyError.value = ''
  try {
    // The repository fan-out is opt-in server-side; without this the check
      // returns an unscanned response that would read as zero departures.
      const res = await api.getOrgLicensePolicy(provider.value, slug.value, true)
    policy.value = res.data
  } catch {
    // Dropping the previous result matters: a stale zero would read as "no
    // departures" when the truth is that nothing could be checked.
    policy.value = null
    policyError.value = 'Failed to read repository configurations. No compliance answer for now — retry the check.'
  } finally {
    policyLoading.value = false
  }
}

function resetPolicy() {
  policy.value = null
  policyRequested.value = false
  policyError.value = ''
}

// Drilldown. A rollup nobody can open is only half an answer: every count on
// this page is a question ("which components?") that has to be answerable.
type DrilldownFilter = Pick<OrgLicenseComponentQuery, 'license' | 'category' | 'repo' | 'undeclared'>

const drilldown = ref<DrilldownFilter | null>(null)
const drilldownRows = ref<OrgLicenseComponent[]>([])
const drilldownTotal = ref(0)
const drilldownPage = ref(1)
const drilldownLoading = ref(false)
const drilldownError = ref('')
const DRILLDOWN_PER_PAGE = 20

const drilldownPages = computed(() => Math.max(1, Math.ceil(drilldownTotal.value / DRILLDOWN_PER_PAGE)))

const drilldownLabel = computed(() => {
  const filter = drilldown.value
  if (!filter) return ''
  if (filter.undeclared) return 'components with no license metadata'
  if (filter.license) return `components licensed ${filter.license}`
  if (filter.category) return `${categoryLabel(filter.category).toLowerCase()} components`
  if (filter.repo) return `components in ${filter.repo}`
  return 'components'
})

function sameFilter(a: DrilldownFilter | null, b: DrilldownFilter): boolean {
  if (!a) return false
  return a.license === b.license && a.category === b.category && a.repo === b.repo && !!a.undeclared === !!b.undeclared
}

function isActiveDrilldown(filter: DrilldownFilter): boolean {
  return sameFilter(drilldown.value, filter)
}

function openDrilldown(filter: DrilldownFilter) {
  // Clicking the open filter again closes it, so the tiles behave as toggles
  // rather than accumulating panels.
  if (isActiveDrilldown(filter)) {
    closeDrilldown()
    return
  }
  drilldown.value = filter
  drilldownPage.value = 1
  void loadDrilldown()
}

function closeDrilldown() {
  // Invalidate anything in flight so a late response cannot repopulate a panel
  // the user just closed.
  drilldownRequest += 1
  drilldown.value = null
  drilldownRows.value = []
  drilldownTotal.value = 0
  drilldownError.value = ''
}

function goToDrilldownPage(page: number) {
  if (page < 1 || page > drilldownPages.value) return
  drilldownPage.value = page
  void loadDrilldown()
}

// Requests are sequenced: clicking through filters faster than the server
// answers means an earlier response can arrive last, and writing it would show
// one filter's components under another filter's heading.
let drilldownRequest = 0

async function loadDrilldown() {
  const filter = drilldown.value
  if (!filter || !provider.value || !slug.value) return
  const request = ++drilldownRequest
  drilldownLoading.value = true
  drilldownError.value = ''
  try {
    const res = await api.listOrgLicenseComponents(provider.value, slug.value, {
      ...filter,
      page: drilldownPage.value,
      per_page: DRILLDOWN_PER_PAGE,
    })
    if (request !== drilldownRequest) return
    drilldownRows.value = res.data
    drilldownTotal.value = res.pagination?.total ?? res.data.length
  } catch {
    if (request !== drilldownRequest) return
    drilldownRows.value = []
    drilldownTotal.value = 0
    drilldownError.value = 'Failed to load components.'
  } finally {
    if (request === drilldownRequest) {
      drilldownLoading.value = false
    }
  }
}

watch(
  [provider, slug],
  async () => {
    closeDrilldown()
    resetPolicy()
    if (!provider.value || !slug.value) {
      overview.value = null
      return
    }
    loading.value = true
    error.value = ''
    try {
      const res = await api.getOrgLicenses(provider.value, slug.value)
      overview.value = res.data
    } catch {
      overview.value = null
      error.value = 'Failed to load license data.'
    } finally {
      loading.value = false
    }
  },
  { immediate: true },
)
</script>
