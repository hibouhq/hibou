<template>
  <div class="space-y-4">
    <div class="flex items-center justify-between border-b border-surface-border pb-2">
      <h2 class="text-base font-semibold text-white">
        Members
      </h2>
      <span class="text-xs text-gray-500">
        {{ isOrgAdmin ? 'Members are synced from the forge; manage roles here' : 'Read-only — org admins can change roles' }}
      </span>
    </div>

    <div
      v-if="loading"
      class="text-sm text-gray-500"
    >
      Loading members…
    </div>
    <div
      v-else-if="loadFailed"
      class="text-sm text-gray-500"
    >
      Members could not be loaded.
    </div>

    <ul
      v-else
      class="divide-y divide-surface-border-subtle rounded-lg border border-surface-border"
    >
      <li
        v-for="member in members"
        :key="member.user_id"
        class="flex items-center gap-3 px-4 py-3"
      >
        <img
          v-if="member.user?.avatar_url"
          :src="member.user.avatar_url"
          :alt="member.user.display_name"
          class="h-8 w-8 rounded-full border border-surface-border object-cover"
        >
        <span
          v-else
          class="flex h-8 w-8 items-center justify-center rounded-full border border-surface-border bg-surface-raised text-xs font-semibold uppercase text-gray-200"
        >
          {{ initials(member) }}
        </span>

        <div class="min-w-0 flex-1">
          <div class="truncate text-sm font-medium text-gray-100">
            {{ member.user?.display_name || member.user_id }}
            <span
              v-if="member.user_id === authStore.user?.id"
              class="ml-1 rounded-full border border-surface-border px-1.5 text-[10px] text-gray-500"
            >you</span>
          </div>
          <div class="truncate text-xs text-gray-500">
            {{ member.user?.email }} · joined {{ relativeTime(member.created_at) }}
          </div>
        </div>

        <template v-if="isOrgAdmin">
          <select
            :value="member.role"
            class="rounded-md border border-surface-border bg-surface-raised px-2 py-1 text-xs text-gray-200 focus:border-accent/50 focus:outline-none"
            :disabled="busyUserID === member.user_id"
            @change="changeRole(member, ($event.target as HTMLSelectElement).value)"
          >
            <option
              v-for="roleOption in ORG_MEMBER_ROLES"
              :key="roleOption"
              :value="roleOption"
            >
              {{ roleLabel(roleOption) }}
            </option>
          </select>
          <button
            type="button"
            class="rounded-md border border-surface-border px-2 py-1 text-xs text-gray-400 transition hover:border-danger/50 hover:text-danger disabled:opacity-50"
            :disabled="busyUserID === member.user_id"
            @click="removeMember(member)"
          >
            Remove
          </button>
        </template>
        <span
          v-else
          class="rounded-full border border-surface-border px-2 py-0.5 text-xs capitalize text-gray-300"
        >
          {{ roleLabel(member.role) }}
        </span>
      </li>
      <li
        v-if="members.length === 0"
        class="px-4 py-6 text-center text-sm text-gray-500"
      >
        No members yet — they appear on first login or forge permission sync.
      </li>
    </ul>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'

import { api, ORG_MEMBER_ROLES, type OrgMember } from '@/api/client'
import { useDialog } from '@/composables/useDialog'
import { useOrgRole } from '@/composables/useOrgRole'
import { useToast } from '@/composables/useToast'
import { relativeTime } from '@/lib/datetime'
import { useAuthStore } from '@/stores/auth'

const { confirmDialog } = useDialog()
const route = useRoute()
const authStore = useAuthStore()
const { isOrgAdmin } = useOrgRole()
const { pushToast } = useToast()

const provider = route.params.provider as string
const slug = route.params.slug as string

const members = ref<OrgMember[]>([])
const loading = ref(true)
const loadFailed = ref(false)
const busyUserID = ref('')

function roleLabel(role: string) {
  return role.replace('_', ' ')
}

function initials(member: OrgMember) {
  const name = member.user?.display_name?.trim() || ''
  if (!name) {
    return '?'
  }
  return name.split(/\s+/).slice(0, 2).map((part) => part[0]?.toUpperCase() || '').join('')
}

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const res = await api.listOrgMembers(provider, slug)
    members.value = res.data
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}

async function changeRole(member: OrgMember, role: string) {
  if (role === member.role) {
    return
  }
  busyUserID.value = member.user_id
  try {
    await api.updateOrgMemberRole(provider, slug, member.user_id, role)
    member.role = role
    pushToast({ title: 'Role updated', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Role change failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
    await load()
  } finally {
    busyUserID.value = ''
  }
}

async function removeMember(member: OrgMember) {
  const name = member.user?.display_name || member.user?.email || 'this member'
  if (!(await confirmDialog({ title: `Remove ${name} from the organization?`, message: 'They lose access immediately; they can be invited again later.', confirmLabel: 'Remove member', tone: 'danger' }))) {
    return
  }
  busyUserID.value = member.user_id
  try {
    await api.removeOrgMember(provider, slug, member.user_id)
    members.value = members.value.filter((entry) => entry.user_id !== member.user_id)
    pushToast({ title: 'Member removed', tone: 'success' })
  } catch (err) {
    pushToast({ title: 'Removal failed', description: err instanceof Error ? err.message : undefined, tone: 'error' })
  } finally {
    busyUserID.value = ''
  }
}

onMounted(load)
</script>
