<!-- frontend/src/components/UsersTable.vue -->
<script setup>
import { ref, computed, watch } from 'vue'
import Badge from '@/components/ui/Badge.vue'
import ActionsMenu from '@/components/ActionsMenu.vue'
import { Search, Eye, EyeOff, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, ChevronUp, ChevronDown } from 'lucide-vue-next'

const props = defineProps({
  users: { type: Array, default: () => [] },
  modulesEnabled: { type: Array, default: () => [] },
  // serverInitialized — пробрасывается ниже в ActionsMenu чтобы при необходимости
  // визуально приглушить «Ротация» (бэкенд всё равно вернёт 412).
  serverInitialized: { type: Boolean, default: true },
})

const emit = defineEmits([
  'revoke', 'unrevoke', 'rotate', 'delete',
  'download-config', 'edit-ccd', 'change-password'
])

const search = ref('')
const hideRevoked = ref(
  localStorage.getItem('hideRevoked') === 'true'
)

function toggleHideRevoked() {
  hideRevoked.value = !hideRevoked.value
  localStorage.setItem('hideRevoked', hideRevoked.value)
}

const filteredUsers = computed(() => {
  let list = props.users
  if (hideRevoked.value) {
    list = list.filter(u => u.AccountStatus === 'Active')
  }
  if (search.value.trim()) {
    const q = search.value.toLowerCase()
    list = list.filter(u => u.Identity.toLowerCase().includes(q))
  }
  return list
})

// Column sorting. '' = server/default order. Numeric columns compare as
// numbers; the rest as strings with empty/'—' pushed to the end.
const sortKey = ref('')
const sortDir = ref('asc')
const NUMERIC_KEYS = new Set(['Connections'])

function setSort(key) {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc'
  } else {
    sortKey.value = key
    sortDir.value = 'asc'
  }
}

const sortedUsers = computed(() => {
  if (!sortKey.value) return filteredUsers.value
  const k = sortKey.value
  const dir = sortDir.value === 'asc' ? 1 : -1
  const arr = filteredUsers.value.slice()
  arr.sort((a, b) => {
    if (NUMERIC_KEYS.has(k)) return ((Number(a[k]) || 0) - (Number(b[k]) || 0)) * dir
    const av = (a[k] ?? '').toString()
    const bv = (b[k] ?? '').toString()
    const ae = av === '' || av === '—'
    const be = bv === '' || bv === '—'
    if (ae && !be) return 1 // empties always last
    if (!ae && be) return -1
    return av.localeCompare(bv) * dir
  })
  return arr
})

// Pagination. Page size is persisted so the operator's preferred density
// survives reload; 25 is a sensible default for an admin desktop table.
const pageSize = ref(parseInt(localStorage.getItem('usersPageSize')) || 25)
const currentPage = ref(1)

watch(pageSize, (v) => {
  localStorage.setItem('usersPageSize', String(v))
  currentPage.value = 1
})

// Reset page when the filter changes — otherwise a search that returns
// 3 results while the operator was on page 5 shows an empty table.
watch([search, hideRevoked, sortKey, sortDir], () => { currentPage.value = 1 })

const totalPages = computed(() =>
  Math.max(1, Math.ceil(filteredUsers.value.length / pageSize.value))
)

// Guard: list shrinks (e.g. after revoke), page > totalPages would leave
// the user on an empty page until they click pagination manually.
watch(totalPages, (tp) => {
  if (currentPage.value > tp) currentPage.value = tp
})

const paginatedUsers = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return sortedUsers.value.slice(start, start + pageSize.value)
})

const visibleRange = computed(() => {
  const total = filteredUsers.value.length
  if (total === 0) return { start: 0, end: 0, total: 0 }
  const start = (currentPage.value - 1) * pageSize.value + 1
  const end = Math.min(start + pageSize.value - 1, total)
  return { start, end, total }
})

function rowClass(user) {
  if (user.ConnectionStatus === 'Connected') return 'bg-green-500/[0.03]'
  if (user.AccountStatus === 'Revoked') return 'opacity-60'
  if (user.AccountStatus === 'Expired') return 'bg-yellow-500/[0.03]'
  return ''
}

function badgeVariant(status) {
  if (status === 'Active') return 'active'
  if (status === 'Revoked') return 'revoked'
  return 'expired'
}

function badgeLabel(status) {
  if (status === 'Active') return 'Активен'
  if (status === 'Revoked') return 'Отозван'
  return 'Истёк'
}
</script>

<template>
  <div>
    <!-- Toolbar -->
    <div class="flex justify-end items-center gap-2 mb-3 flex-wrap">
      <div class="flex items-center gap-2">
        <div class="relative">
          <Search
            :size="14"
            class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
          />
          <input
            v-model="search"
            placeholder="Поиск пользователя…"
            class="h-9 w-60 rounded-md border border-border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
          >
        </div>
        <button
          type="button"
          :class="[
            'h-9 inline-flex items-center gap-2 rounded-md border px-3 text-xs font-medium transition-colors',
            hideRevoked
              ? 'border-primary/40 bg-primary/10 text-primary'
              : 'border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground'
          ]"
          @click="toggleHideRevoked"
        >
          <component
            :is="hideRevoked ? EyeOff : Eye"
            :size="14"
          />
          {{ hideRevoked ? 'Показать отозванных' : 'Скрыть отозванных' }}
        </button>
      </div>
    </div>

    <!-- Table — sticky thead. top-14 = AppHeader (h-14) height; the entire
         users page scrolls in the window context, so the thead pins directly
         under the global app header rather than under the page-internal toolbar. -->
    <!-- Desktop table (md+). On phones a 7-column table can't fit, so it is
         hidden and replaced by the card list below. -->
    <div class="hidden md:block rounded-lg border border-border bg-card overflow-visible">
      <!-- Auto-sized columns. The fix here is alignment-only: each header's
           text-* class matches the same text-* on its body cells, so an
           operator's eye reads "label above its values" instead of catching
           the prior left-aligned numbers under wide left-aligned headers. -->
      <table class="w-full text-sm">
        <thead class="sticky top-14 z-10">
          <tr class="border-b border-border bg-muted/95 backdrop-blur-sm">
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground w-12">
              #
            </th>
            <th
              class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none hover:text-foreground"
              @click="setSort('Identity')"
            >
              <span class="inline-flex items-center gap-1">Имя <ChevronUp
                v-if="sortKey === 'Identity' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'Identity'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none hover:text-foreground"
              @click="setSort('AccountStatus')"
            >
              <span class="inline-flex items-center gap-1">Статус <ChevronUp
                v-if="sortKey === 'AccountStatus' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'AccountStatus'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none hover:text-foreground"
              @click="setSort('Connections')"
            >
              <span class="inline-flex items-center gap-1">Подключений <ChevronUp
                v-if="sortKey === 'Connections' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'Connections'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none hover:text-foreground"
              @click="setSort('ExpirationDate')"
            >
              <span class="inline-flex items-center gap-1">Дата истечения <ChevronUp
                v-if="sortKey === 'ExpirationDate' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'ExpirationDate'"
                :size="12"
              /></span>
            </th>
            <th
              class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground cursor-pointer select-none hover:text-foreground"
              @click="setSort('RevocationDate')"
            >
              <span class="inline-flex items-center gap-1">Дата отзыва <ChevronUp
                v-if="sortKey === 'RevocationDate' && sortDir === 'asc'"
                :size="12"
              /><ChevronDown
                v-else-if="sortKey === 'RevocationDate'"
                :size="12"
              /></span>
            </th>
            <th class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Действия
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="paginatedUsers.length === 0">
            <td
              colspan="7"
              class="px-4 py-12 text-center text-sm text-muted-foreground"
            >
              Пользователи не найдены
            </td>
          </tr>
          <tr
            v-for="(user, index) in paginatedUsers"
            :key="user.Identity"
            :class="['border-b border-border last:border-0 transition-colors hover:bg-muted/30', rowClass(user)]"
          >
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">
              {{ (currentPage - 1) * pageSize + index + 1 }}
            </td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-2">
                <span class="font-medium text-[15px]">{{ user.Identity }}</span>
                <span
                  v-if="user.ConnectionStatus === 'Connected'"
                  class="inline-block w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_theme(colors.green.500)]"
                  title="Подключён"
                />
              </div>
            </td>
            <td class="px-4 py-3 text-center">
              <Badge :variant="badgeVariant(user.AccountStatus)">
                {{ badgeLabel(user.AccountStatus) }}
              </Badge>
            </td>
            <td class="px-4 py-3 text-center text-muted-foreground font-mono text-sm tabular">
              {{ user.Connections || 0 }}
            </td>
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">
              {{ user.ExpirationDate || '—' }}
            </td>
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">
              {{ user.RevocationDate || '—' }}
            </td>
            <td class="px-4 py-3">
              <div class="flex justify-end">
                <ActionsMenu
                  :user="user"
                  :modules-enabled="modulesEnabled"
                  @revoke="emit('revoke', $event)"
                  @unrevoke="emit('unrevoke', $event)"
                  @rotate="emit('rotate', $event)"
                  @delete="emit('delete', $event)"
                  @download-config="emit('download-config', $event)"
                  @edit-ccd="emit('edit-ccd', $event)"
                  @change-password="emit('change-password', $event)"
                />
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Mobile card list (below md) — one card per user, fields stacked, so
         nothing is clipped and the whole page scrolls normally. -->
    <div class="md:hidden space-y-3">
      <div
        v-if="paginatedUsers.length === 0"
        class="rounded-lg border border-border bg-card px-4 py-12 text-center text-sm text-muted-foreground"
      >
        Пользователи не найдены
      </div>
      <div
        v-for="(user, index) in paginatedUsers"
        :key="user.Identity"
        :class="['rounded-lg border border-border bg-card p-4 space-y-3', rowClass(user)]"
      >
        <!-- header: # + name + connected dot + status -->
        <div class="flex items-start justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-muted-foreground font-mono text-xs tabular shrink-0">#{{ (currentPage - 1) * pageSize + index + 1 }}</span>
            <span class="font-medium text-[15px] truncate">{{ user.Identity }}</span>
            <span
              v-if="user.ConnectionStatus === 'Connected'"
              class="inline-block w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_theme(colors.green.500)] shrink-0"
              title="Подключён"
            />
          </div>
          <Badge :variant="badgeVariant(user.AccountStatus)">
            {{ badgeLabel(user.AccountStatus) }}
          </Badge>
        </div>

        <!-- fields -->
        <dl class="grid grid-cols-3 gap-x-4 gap-y-2">
          <div>
            <dt class="text-[11px] uppercase tracking-wider text-muted-foreground">
              Подключений
            </dt>
            <dd class="font-mono text-sm tabular">
              {{ user.Connections || 0 }}
            </dd>
          </div>
          <div>
            <dt class="text-[11px] uppercase tracking-wider text-muted-foreground">
              Истечение
            </dt>
            <dd class="font-mono text-sm tabular text-muted-foreground">
              {{ user.ExpirationDate || '—' }}
            </dd>
          </div>
          <div>
            <dt class="text-[11px] uppercase tracking-wider text-muted-foreground">
              Отзыв
            </dt>
            <dd class="font-mono text-sm tabular text-muted-foreground">
              {{ user.RevocationDate || '—' }}
            </dd>
          </div>
        </dl>

        <!-- actions -->
        <div class="flex justify-end pt-3 border-t border-border/60">
          <ActionsMenu
            :user="user"
            :modules-enabled="modulesEnabled"
            @revoke="emit('revoke', $event)"
            @unrevoke="emit('unrevoke', $event)"
            @rotate="emit('rotate', $event)"
            @delete="emit('delete', $event)"
            @download-config="emit('download-config', $event)"
            @edit-ccd="emit('edit-ccd', $event)"
            @change-password="emit('change-password', $event)"
          />
        </div>
      </div>
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

    <!-- Legend -->
    <div class="flex justify-center gap-6 mt-4 text-xs text-muted-foreground">
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_6px_theme(colors.green.500)]" />Подключён</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-foreground/40" />Активен</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-red-500" />Отозван</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-yellow-500" />Истёк</span>
    </div>
  </div>
</template>
