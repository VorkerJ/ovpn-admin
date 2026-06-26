<!-- frontend/src/components/TrafficView.vue
     Cumulative per-user traffic (lifetime totals). Data from GET /api/traffic.
     rx_bytes = bytes the server received from the client (client upload);
     tx_bytes = bytes the server sent to the client (client download). -->
<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { fetchTraffic } from '@/api.js'
import Button from '@/components/ui/Button.vue'
import { RefreshCw, ArrowDownToLine, ArrowUpFromLine, Search } from 'lucide-vue-next'

const rows = ref([])
const loading = ref(false)
const error = ref('')
const search = ref('')
const sortKey = ref('total_bytes')
const sortDir = ref('desc')
let timer = null

function fmtBytes(n) {
  n = Number(n) || 0
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let i = -1
  do { n /= 1024; i++ } while (n >= 1024 && i < units.length - 1)
  return `${n.toFixed(n >= 100 ? 0 : 1)} ${units[i]}`
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    rows.value = await fetchTraffic()
  } catch (e) {
    error.value = e?.response?.data?.error || e.message || 'Не удалось загрузить трафик'
  } finally {
    loading.value = false
  }
}

function setSort(key) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'desc' ? 'asc' : 'desc'
  } else {
    sortKey.value = key
    sortDir.value = key === 'user' ? 'asc' : 'desc'
  }
}

const filtered = computed(() => {
  const q = search.value.trim().toLowerCase()
  let r = q ? rows.value.filter((x) => x.user.toLowerCase().includes(q)) : rows.value.slice()
  const k = sortKey.value
  const dir = sortDir.value === 'asc' ? 1 : -1
  r.sort((a, b) => {
    let av = a[k], bv = b[k]
    if (k === 'user') return a.user.localeCompare(b.user) * dir
    return ((Number(av) || 0) - (Number(bv) || 0)) * dir
  })
  return r
})

const totals = computed(() => {
  let rx = 0, tx = 0, online = 0
  for (const x of rows.value) { rx += Number(x.rx_bytes) || 0; tx += Number(x.tx_bytes) || 0; if (x.connected) online++ }
  return { rx, tx, total: rx + tx, online, users: rows.value.length }
})

onMounted(() => {
  load()
  timer = setInterval(load, 30000) // mgmt polls every ~28s; refresh roughly in step
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <div class="space-y-4">
    <!-- summary cards -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div class="rounded-lg border border-border bg-card px-4 py-3">
        <p class="text-xs uppercase tracking-wider text-muted-foreground">
          Всего трафика
        </p>
        <p class="text-lg font-semibold mt-1">
          {{ fmtBytes(totals.total) }}
        </p>
      </div>
      <div class="rounded-lg border border-border bg-card px-4 py-3">
        <p class="text-xs uppercase tracking-wider text-muted-foreground">
          ↓ Скачано
        </p>
        <p class="text-lg font-semibold mt-1">
          {{ fmtBytes(totals.tx) }}
        </p>
      </div>
      <div class="rounded-lg border border-border bg-card px-4 py-3">
        <p class="text-xs uppercase tracking-wider text-muted-foreground">
          ↑ Загружено
        </p>
        <p class="text-lg font-semibold mt-1">
          {{ fmtBytes(totals.rx) }}
        </p>
      </div>
      <div class="rounded-lg border border-border bg-card px-4 py-3">
        <p class="text-xs uppercase tracking-wider text-muted-foreground">
          Онлайн / всего
        </p>
        <p class="text-lg font-semibold mt-1">
          {{ totals.online }} / {{ totals.users }}
        </p>
      </div>
    </div>

    <div class="flex justify-between items-center gap-2 flex-wrap">
      <div class="relative">
        <Search
          :size="16"
          class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
        />
        <input
          v-model="search"
          placeholder="Поиск по пользователю"
          class="h-9 w-60 rounded-md border border-border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
        >
      </div>
      <Button
        variant="ghost"
        size="sm"
        :disabled="loading"
        @click="load"
      >
        <RefreshCw
          :size="16"
          :class="loading ? 'animate-spin' : ''"
        />
        Обновить
      </Button>
    </div>

    <div
      v-if="error"
      class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
    >
      {{ error }}
    </div>

    <div class="rounded-lg border border-border bg-card overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/95">
            <th
              class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('user')"
            >
              Пользователь
            </th>
            <th class="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Статус
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('tx_bytes')"
            >
              <span class="inline-flex items-center gap-1"><ArrowDownToLine :size="13" /> Скачано</span>
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('rx_bytes')"
            >
              <span class="inline-flex items-center gap-1"><ArrowUpFromLine :size="13" /> Загружено</span>
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('total_bytes')"
            >
              Всего
            </th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Подключён
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="filtered.length === 0">
            <td
              colspan="6"
              class="px-4 py-12 text-center text-sm text-muted-foreground"
            >
              {{ loading ? 'Загрузка…' : 'Пока нет данных о трафике' }}
            </td>
          </tr>
          <tr
            v-for="row in filtered"
            :key="row.user"
            class="border-b border-border last:border-0 transition-colors hover:bg-muted/30"
          >
            <td class="px-4 py-3 font-medium">
              {{ row.user }}
            </td>
            <td class="px-4 py-3 text-center">
              <span
                :class="['inline-block h-2 w-2 rounded-full align-middle', row.connected ? 'bg-green-500' : 'bg-muted-foreground/40']"
                :title="row.connected ? 'онлайн' : 'офлайн'"
              />
            </td>
            <td class="px-4 py-3 text-right font-mono tabular-nums">
              {{ fmtBytes(row.tx_bytes) }}
            </td>
            <td class="px-4 py-3 text-right font-mono tabular-nums">
              {{ fmtBytes(row.rx_bytes) }}
            </td>
            <td class="px-4 py-3 text-right font-mono tabular-nums font-semibold">
              {{ fmtBytes(row.total_bytes) }}
            </td>
            <td class="px-4 py-3 text-muted-foreground text-xs">
              <span v-if="row.connected">{{ row.connected_since }}<span v-if="row.real_address"> · {{ row.real_address }}</span></span>
              <span v-else>—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="text-xs text-muted-foreground">
      Накопительно за всё время. «Скачано» — отправлено клиенту, «Загружено» — получено от клиента. Счётчики продолжаются после реконнектов и переживают рестарт (при включённом PVC).
    </p>
  </div>
</template>
