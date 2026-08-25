<template>
  <div class="space-y-5">
    <div>
      <h2 class="text-lg font-semibold text-white">
        People across every org
      </h2>
      <p class="mt-1 max-w-[70ch] text-sm leading-relaxed text-gray-400">
        Every organization page answers what someone can do <em>there</em>. This answers what they can
        do everywhere — which is the question worth asking before granting anything that reaches
        across orgs.
      </p>
    </div>

    <div
      v-if="error"
      class="rounded-md border border-danger/30 bg-danger/10 px-4 py-3 text-sm text-red-200"
    >
      {{ error }}
    </div>

    <div class="relative flex items-center gap-2 rounded-lg border border-surface-border bg-surface-overlay px-3 py-2">
      <Search class="h-3.5 w-3.5 shrink-0 text-gray-600" />
      <input
        v-model="filter"
        type="text"
        placeholder="Filter by person, org, or role…"
        class="w-full bg-transparent text-sm text-gray-100 outline-none placeholder:text-gray-600"
      >
      <button
        v-for="role in GRANTABLE"
        :key="role.value"
        type="button"
        class="shrink-0 rounded-full border px-2 py-0.5 text-[11px] transition"
        :class="roleFilter === role.value
          ? 'border-accent/50 bg-accent-muted/30 text-accent'
          : 'border-surface-border text-gray-500 hover:text-gray-300'"
        @click="roleFilter = roleFilter === role.value ? '' : role.value"
      >
        {{ role.label }}
      </button>
    </div>

    <div
      v-if="loading"
      class="py-8 text-sm text-gray-500"
    >
      Loading people…
    </div>

    <div
      v-else-if="visible.length === 0"
      class="rounded-md border border-dashed border-surface-border px-6 py-10 text-center text-sm text-gray-500"
    >
      {{ members.length ? 'Nobody matches that filter.' : 'No members yet.' }}
    </div>

    <div
      v-else
      class="overflow-hidden rounded-md border border-surface-border"
    >
      <div
        v-for="member in visible"
        :key="member.user_id"
        class="border-b border-surface-border-subtle last:border-b-0"
      >
        <div class="flex items-start gap-4 px-4 py-3">
          <div class="min-w-0 flex-1">
            <div class="flex items-center gap-2">
              <span class="text-sm font-medium text-gray-200">{{ member.display_name || member.email }}</span>
              <span class="font-mono text-[11px] text-gray-500">{{ member.email }}</span>
            </div>

            <!-- Forge-derived, read-only. Showing these as editable would invite
                 operators to fight the sync that owns them. -->
            <div class="mt-2 flex flex-wrap items-center gap-1.5">
              <span
                v-for="membership in member.memberships"
                :key="`${membership.provider}-${membership.org_id}`"
                class="inline-flex items-center gap-1.5 rounded border border-surface-border-subtle bg-surface-overlay px-1.5 py-0.5 text-[11px] text-gray-400"
                :title="`${membership.role} in ${membership.org_slug} — synced from ${membership.provider}`"
              >
                <Lock class="h-2.5 w-2.5 text-gray-600" />
                <span class="text-gray-500">{{ membership.provider }}/</span>{{ membership.org_slug }}
                <span class="text-gray-300">{{ membership.role }}</span>
              </span>
              <span
                v-if="!member.memberships.length"
                class="text-[11px] italic text-gray-600"
              >no org membership</span>
            </div>
          </div>

          <!-- Operator-owned grants. These exist outside every forge's
               vocabulary, so this is the only place they can be given. -->
          <div class="w-[340px] shrink-0">
            <div class="text-[10px] font-semibold uppercase tracking-[0.14em] text-gray-600">
              Additional grants
            </div>
            <div class="mt-1.5 flex flex-wrap items-center gap-1.5">
              <span
                v-for="held in member.grants"
                :key="`${held.role}-${held.org_id ?? 'instance'}`"
                class="inline-flex items-center gap-1.5 rounded-full border py-0.5 pl-2 pr-1 text-[11px]"
                :class="held.suspended
                  ? 'border-warn/40 bg-warn/10 text-warn'
                  : 'border-ok/30 bg-ok/10 text-ok'"
                :title="held.suspended ? held.reason : (held.org_id ? 'this org only' : 'every org')"
              >
                {{ held.role }}
                <span
                  v-if="!held.org_id"
                  class="text-[9px] uppercase opacity-70"
                >all</span>
                <button
                  type="button"
                  class="opacity-60 transition hover:opacity-100"
                  :aria-label="`Revoke ${held.role}`"
                  @click="revoke(member, held)"
                ><X class="h-3 w-3" /></button>
              </span>

              <select
                class="rounded-md border border-surface-border bg-surface-overlay px-2 py-1 text-[11px] text-gray-400 outline-none"
                @change="grant(member, ($event.target as HTMLSelectElement).value); ($event.target as HTMLSelectElement).value = ''"
              >
                <option value="">
                  + grant…
                </option>
                <option
                  v-for="role in GRANTABLE"
                  :key="role.value"
                  :value="role.value"
                >
                  {{ role.label }}
                </option>
              </select>
            </div>
            <p
              v-for="held in member.grants.filter(g => g.suspended)"
              :key="`why-${held.role}`"
              class="mt-1.5 text-[10px] leading-relaxed text-warn"
            >
              {{ held.role }} suspended — {{ held.reason }}
            </p>
          </div>
        </div>
      </div>
    </div>

    <p class="px-1 text-[11px] leading-relaxed text-gray-500">
      Org roles are synced from the forge and cannot be edited here. Grants are separate on purpose:
      no forge has an opinion about who may author advisory data, so it is not a thing a forge role
      can confer.
    </p>
  </div>
</template>

<script setup lang="ts">
import { Lock, Search, X } from 'lucide-vue-next'
import { computed, onMounted, ref } from 'vue'

import { api, type InstanceGrant, type InstanceMember } from '@/api/client'

const GRANTABLE = [
  { value: 'cve-triager', label: 'cve-triager' },
  { value: 'subscription-writer', label: 'subscription-writer' },
  { value: 'advisory-promoter', label: 'advisory-promoter' },
]

const members = ref<InstanceMember[]>([])
const loading = ref(true)
const error = ref('')
const filter = ref('')
const roleFilter = ref('')

const visible = computed(() => {
  const needle = filter.value.trim().toLowerCase()
  return members.value.filter(member => {
    if (roleFilter.value && !member.grants.some(g => g.role === roleFilter.value)) return false
    if (!needle) return true
    const haystack = [
      member.email,
      member.display_name,
      ...member.memberships.map(m => `${m.provider}/${m.org_slug} ${m.role}`),
      ...member.grants.map(g => g.role),
    ].join(' ').toLowerCase()
    return haystack.includes(needle)
  })
})

async function grant(member: InstanceMember, role: string) {
  if (!role) return
  try {
    await api.grantLocalRole({ user_id: member.user_id, role })
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to grant the role'
  }
}

async function revoke(member: InstanceMember, target: InstanceGrant) {
  try {
    await api.revokeLocalRole({
      user_id: member.user_id,
      role: target.role,
      org_id: target.org_id ?? undefined,
    })
    await load()
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to revoke the role'
  }
}

async function load() {
  try {
    const response = await api.listInstanceMembers()
    members.value = response.data ?? []
  } catch (e) {
    error.value = e instanceof Error ? e.message : 'Failed to load members'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>
