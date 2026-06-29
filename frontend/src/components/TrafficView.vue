<!-- frontend/src/components/TrafficView.vue
     Per-user traffic for a calendar month (data from GET /api/traffic?month=).
     rx_bytes = bytes the server received from the client (client upload);
     tx_bytes = bytes the server sent to the client (client download).
     Buckets are monthly; a fresh bucket starts automatically each 1st. -->
<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { fetchTraffic } from '@/api.js'
import Button from '@/components/ui/Button.vue'
import { RefreshCw, ArrowDownToLine, ArrowUpFromLine, Search, ChevronDown, ChevronUp, Calendar,
  ChevronsLeft, ChevronLeft, ChevronRight, ChevronsRight } from 'lucide-vue-next'

const rows = ref([])
const months = ref([])
const month = ref('') // '' = current month (server decides)
const loading = ref(false)
const error = ref('')
const search = ref('')
const sortKey = ref('total_bytes')
const sortDir = ref('desc')
let timer = null

const MONTH_NOM = ['Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь',
  'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']

function monthLabel(m) {
  const [y, mm] = (m || '').split('-')
  const i = Number(mm) - 1
  return i >= 0 && i < 12 ? `${MONTH_NOM[i]} ${y}` : m
}

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
    const data = await fetchTraffic(month.value)
    rows.value = data.rows
    months.value = data.months
    // adopt the month the server resolved (so the picker shows the real current month)
    if (!month.value && data.month) month.value = data.month
    // make sure the resolved month is selectable even if it has no data yet
    if (month.value && !months.value.includes(month.value)) {
      months.value = [month.value, ...months.value]
    }
  } catch (e) {
    error.value = e?.response?.data?.error || e.message || 'Не удалось загрузить трафик'
  } finally {
    loading.value = false
  }
}

function onMonthChange() {
  load()
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
    if (k === 'user') return a.user.localeCompare(b.user) * dir
    return ((Number(a[k]) || 0) - (Number(b[k]) || 0)) * dir
  })
  return r
})

const totals = computed(() => {
  let rx = 0, tx = 0, online = 0
  for (const x of rows.value) { rx += Number(x.rx_bytes) || 0; tx += Number(x.tx_bytes) || 0; if (x.connected) online++ }
  return { rx, tx, total: rx + tx, online, users: rows.value.length }
})

// Pagination — mirrors the users table (per-page selector persists in
// localStorage, page range + first/prev/next/last controls).
const pageSize = ref(parseInt(localStorage.getItem('trafficPageSize')) || 25)
const currentPage = ref(1)

watch(pageSize, (v) => {
  localStorage.setItem('trafficPageSize', String(v))
  currentPage.value = 1
})
// Reset to page 1 when the visible set changes (search or month switch).
watch([search, month], () => { currentPage.value = 1 })

const totalPages = computed(() =>
  Math.max(1, Math.ceil(filtered.value.length / pageSize.value))
)
watch(totalPages, (tp) => {
  if (currentPage.value > tp) currentPage.value = tp
})

const paginated = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filtered.value.slice(start, start + pageSize.value)
})

const visibleRange = computed(() => {
  const total = filtered.value.length
  if (total === 0) return { start: 0, end: 0, total: 0 }
  const start = (currentPage.value - 1) * pageSize.value + 1
  const end = Math.min(start + pageSize.value - 1, total)
  return { start, end, total }
})

onMounted(() => {
  load()
  timer = setInterval(load, 30000) // mgmt polls every ~28s; refresh roughly in step
})
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <div class="space-y-4">
    <!-- summary cards (for the selected month) -->
    <div class="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <div class="rounded-lg border border-border bg-card px-4 py-3">
        <p class="text-xs uppercase tracking-wider text-muted-foreground">
          Трафик за месяц
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

    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-3">
        <!-- month picker -->
        <div class="relative">
          <Calendar
            :size="16"
            class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
          <select
            v-model="month"
            class="h-9 min-w-[170px] appearance-none rounded-md border border-border bg-background pl-9 pr-9 text-sm font-medium focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
            @change="onMonthChange"
          >
            <option
              v-for="m in months"
              :key="m"
              :value="m"
            >
              {{ monthLabel(m) }}
            </option>
          </select>
          <ChevronDown
            :size="16"
            class="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
        </div>
        <!-- search -->
        <div class="relative">
          <Search
            :size="16"
            class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
          <input
            v-model="search"
            placeholder="Поиск по пользователю"
            class="h-9 w-56 rounded-md border border-border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
          >
        </div>
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
              <span class="inline-flex items-center gap-1">Пользователь <ChevronUp
                v-if="sortKey === 'user' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'user'"
                :size="12"
              /></span>
            </th>
            <th class="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Статус
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('tx_bytes')"
            >
              <span class="inline-flex items-center gap-1"><ArrowDownToLine :size="13" /> Скачано <ChevronUp
                v-if="sortKey === 'tx_bytes' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'tx_bytes'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('rx_bytes')"
            >
              <span class="inline-flex items-center gap-1"><ArrowUpFromLine :size="13" /> Загружено <ChevronUp
                v-if="sortKey === 'rx_bytes' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'rx_bytes'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('total_bytes')"
            >
              <span class="inline-flex items-center gap-1">За месяц <ChevronUp
                v-if="sortKey === 'total_bytes' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'total_bytes'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none"
              @click="setSort('all_time_bytes')"
            >
              <span class="inline-flex items-center gap-1">За всё время <ChevronUp
                v-if="sortKey === 'all_time_bytes' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'all_time_bytes'"
                :size="12"
              /></span>
            </th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Подключён
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="paginated.length === 0">
            <td
              colspan="7"
              class="px-4 py-12 text-center text-sm text-muted-foreground"
            >
              {{ loading ? 'Загрузка…' : 'Пока нет данных о трафике' }}
            </td>
          </tr>
          <tr
            v-for="row in paginated"
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
            <td class="px-4 py-3 text-right font-mono tabular-nums text-muted-foreground">
              {{ fmtBytes(row.all_time_bytes) }}
            </td>
            <td class="px-4 py-3 text-muted-foreground text-xs">
              <span v-if="row.connected">{{ row.connected_since }}<span v-if="row.real_address"> · {{ row.real_address }}</span></span>
              <span v-else>—</span>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination bar -->
    <div class="flex items-center justify-between gap-3 mt-3 flex-wrap">
      <div class="flex items-center gap-3 text-xs text-muted-foreground tabular">
        <div class="inline-flex items-center gap-2">
          <span>На странице:</span>
          <select
            v-model.number="pageSize"
            class="h-8 rounded-md border border-border bg-background px-2 text-xs focus:outline-none focus:ring-1 focus:ring-ring"
          >
            <option :value="10">
              10
            </option>
            <option :value="25">
              25
            </option>
            <option :value="50">
              50
            </option>
            <option :value="100">
              100
            </option>
          </select>
        </div>
        <span class="text-muted-foreground/60">·</span>
        <span>
          Показано <span class="font-medium text-foreground">{{ visibleRange.start }}–{{ visibleRange.end }}</span>
          из <span class="font-medium text-foreground">{{ visibleRange.total }}</span>
        </span>
      </div>
      <div class="flex items-center gap-1">
        <button
          type="button"
          class="h-8 w-8 inline-flex items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-background"
          :disabled="currentPage === 1"
          title="Первая страница"
          @click="currentPage = 1"
        >
          <ChevronsLeft :size="14" />
        </button>
        <button
          type="button"
          class="h-8 w-8 inline-flex items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-background"
          :disabled="currentPage === 1"
          title="Предыдущая страница"
          @click="currentPage--"
        >
          <ChevronLeft :size="14" />
        </button>
        <span class="px-3 text-xs text-muted-foreground tabular">
          Стр. <span class="font-medium text-foreground">{{ currentPage }}</span> из <span class="font-medium text-foreground">{{ totalPages }}</span>
        </span>
        <button
          type="button"
          class="h-8 w-8 inline-flex items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-background"
          :disabled="currentPage >= totalPages"
          title="Следующая страница"
          @click="currentPage++"
        >
          <ChevronRight :size="14" />
        </button>
        <button
          type="button"
          class="h-8 w-8 inline-flex items-center justify-center rounded-md border border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-background"
          :disabled="currentPage >= totalPages"
          title="Последняя страница"
          @click="currentPage = totalPages"
        >
          <ChevronsRight :size="14" />
        </button>
      </div>
    </div>

    <p class="text-xs text-muted-foreground">
      «За месяц» — выбранный календарный месяц; новый месяц начинается автоматически 1-го числа. «За всё время» — сумма по всем месяцам. «Скачано» — отправлено клиенту, «Загружено» — получено от клиента.
    </p>
  </div>
</template>
