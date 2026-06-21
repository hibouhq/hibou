<template>
  <Teleport to="body">
    <div
      class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 px-4 py-10 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Install the Hibou CLI"
      @click.self="$emit('close')"
      @keydown.esc="$emit('close')"
    >
      <div class="w-full max-w-2xl rounded-2xl border border-surface-border bg-surface-raised p-5 shadow-2xl">
        <!-- Header -->
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <h2 class="text-lg font-bold text-gray-100">
              Install the Hibou CLI
            </h2>
            <p class="mt-1 text-sm text-gray-400">
              Download the binary for your platform, then add it to your <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-xs text-gray-300">PATH</code>.
            </p>
          </div>
          <button
            type="button"
            class="-mr-1 -mt-1 rounded-lg p-1 text-gray-500 transition hover:text-gray-200"
            title="Close"
            aria-label="Close"
            @click="$emit('close')"
          >
            <svg
              class="h-5 w-5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              stroke-width="2"
            >
              <path
                stroke-linecap="round"
                stroke-linejoin="round"
                d="M6 18L18 6M6 6l12 12"
              />
            </svg>
          </button>
        </div>

        <!-- Detected platform -->
        <div class="mt-5 rounded-xl border border-accent/40 bg-accent-muted/40 p-4">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div class="min-w-0">
              <div class="text-[11px] font-semibold uppercase tracking-[0.14em] text-accent">
                Detected platform
              </div>
              <div class="mt-1 flex items-center gap-2 text-sm text-gray-200">
                <span class="font-medium">{{ osLabel(selectedOs) }}</span>
                <span class="text-gray-500">·</span>
                <!-- Architecture toggle: browsers can't reliably report CPU arch -->
                <span class="inline-flex overflow-hidden rounded-lg border border-surface-border text-xs">
                  <button
                    v-for="arch in archOptions"
                    :key="arch"
                    type="button"
                    class="px-2 py-0.5 font-mono transition"
                    :class="arch === selectedArch ? 'bg-accent text-white' : 'text-gray-400 hover:text-gray-200'"
                    @click="selectedArch = arch"
                  >
                    {{ arch }}
                  </button>
                </span>
              </div>
            </div>
            <a
              :href="downloadUrl"
              :download="binaryName"
              class="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-accent/90"
            >
              <svg
                class="h-4 w-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                stroke-width="2"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M7 10l5 5 5-5M12 15V3"
                />
              </svg>
              Download {{ binaryName }}
            </a>
          </div>
        </div>

        <!-- Post-download steps -->
        <div class="mt-5">
          <h3 class="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            Then run
          </h3>
          <div class="group relative overflow-x-auto rounded-xl border border-surface-border-subtle bg-surface-overlay">
            <pre class="px-4 py-3 font-mono text-xs leading-relaxed text-gray-300"><code>{{ installSnippet }}</code></pre>
            <button
              type="button"
              class="absolute right-2 top-2 rounded-lg border border-surface-border bg-surface-raised px-2 py-1 text-[11px] text-gray-400 transition hover:text-gray-100"
              @click="copySnippet"
            >
              {{ copied ? 'Copied' : 'Copy' }}
            </button>
          </div>
          <p class="mt-2 text-xs text-gray-500">
            Verify with <code class="rounded bg-surface-overlay px-1 py-0.5 font-mono text-gray-300">hibou version</code>.
          </p>
        </div>

        <!-- Other platforms -->
        <div class="mt-5">
          <h3 class="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            All platforms
          </h3>
          <div class="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <a
              v-for="t in allTargets"
              :key="`${t.os}-${t.arch}`"
              :href="api.cliDownloadUrl(t.os, t.arch)"
              :download="targetName(t.os, t.arch)"
              class="flex items-center justify-between gap-2 rounded-xl border border-surface-border bg-surface-overlay px-3 py-2 text-xs transition hover:border-accent/50 hover:text-white"
              :class="t.os === selectedOs && t.arch === selectedArch ? 'text-white' : 'text-gray-400'"
            >
              <span>{{ osLabel(t.os) }}</span>
              <span class="font-mono text-gray-500">{{ t.arch }}</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { api, type CliArch, type CliOS } from '@/api/client'

defineEmits<{ close: [] }>()

const OS_LABELS: Record<CliOS, string> = {
  darwin: 'macOS',
  windows: 'Windows',
  linux: 'Linux',
}

// Must match the platforms the server actually ships (see Makefile PLATFORMS /
// Dockerfile staging). darwin is arm64-only — no Intel build is published.
const allTargets: { os: CliOS; arch: CliArch }[] = [
  { os: 'linux', arch: 'amd64' },
  { os: 'linux', arch: 'arm64' },
  { os: 'darwin', arch: 'arm64' },
  { os: 'windows', arch: 'amd64' },
  { os: 'windows', arch: 'arm64' },
]

// Arches available for the currently selected OS.
const archOptions = computed<CliArch[]>(() =>
  allTargets.filter((t) => t.os === selectedOs.value).map((t) => t.arch),
)

const ua = typeof navigator !== 'undefined' ? navigator.userAgent : ''

function detectOs(): CliOS {
  if (/Win/i.test(ua)) return 'windows'
  if (/Mac/i.test(ua)) return 'darwin'
  return 'linux'
}

function detectArch(os: CliOS): CliArch {
  // darwin ships arm64 only; for the rest, infer from the UA string.
  if (os === 'darwin') return 'arm64'
  if (/arm64|aarch64/i.test(ua)) return 'arm64'
  return 'amd64'
}

const selectedOs = ref<CliOS>(detectOs())
const selectedArch = ref<CliArch>(detectArch(selectedOs.value))

// Keep the arch valid when the OS changes (e.g. darwin has no amd64 build).
watch(selectedOs, (os) => {
  if (!archOptions.value.includes(selectedArch.value)) {
    selectedArch.value = detectArch(os)
  }
})

function osLabel(os: CliOS) {
  return OS_LABELS[os]
}

function targetName(os: CliOS, arch: CliArch) {
  const ext = os === 'windows' ? '.exe' : ''
  return `hibou-${os}-${arch}${ext}`
}

const binaryName = computed(() => targetName(selectedOs.value, selectedArch.value))
const downloadUrl = computed(() => api.cliDownloadUrl(selectedOs.value, selectedArch.value))

const installSnippet = computed(() => {
  if (selectedOs.value === 'windows') {
    return [
      `# Move the downloaded ${binaryName.value} to a folder on your PATH, e.g.`,
      `Move-Item .\\${binaryName.value} "$Env:USERPROFILE\\bin\\hibou.exe"`,
    ].join('\n')
  }
  return [
    `chmod +x ~/Downloads/${binaryName.value}`,
    `sudo mv ~/Downloads/${binaryName.value} /usr/local/bin/hibou`,
  ].join('\n')
})

const copied = ref(false)
async function copySnippet() {
  try {
    await navigator.clipboard.writeText(installSnippet.value)
    copied.value = true
    globalThis.setTimeout(() => { copied.value = false }, 1500)
  } catch {
    // Clipboard unavailable; the snippet is still visible to copy manually.
  }
}
</script>
