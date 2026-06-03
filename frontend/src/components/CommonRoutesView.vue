<!-- frontend/src/components/CommonRoutesView.vue -->
<script setup>
import { ref, computed, watch, onMounted } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import CommonRouteModal from '@/components/modals/CommonRouteModal.vue'
import { useToast } from '@/composables/useToast'
import {
  fetchCommonRoutes, createCommonRoute, updateCommonRoute,
  deleteCommonRoute, refreshCommonRoutesDns, importCommonRoutes,
} from '@/api.js'
import {
  Globe, Network, RefreshCw, Plus, Pencil, Trash2,
  CheckCircle2, AlertTriangle, CornerDownRight,
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  Search, X,
} from 'lucide-vue-next'

const emit = defineEmits(['mfa-required'])

const routes = ref([])
const refreshIntervalHours = ref(24)
const loading = ref(false)
const refreshing = ref(false)
const showImport = ref(false)
const importText = ref('')
const importing = ref(false)
const importReport = ref(null)
function onImportFile(e) {
  const f = e.target.files?.[0]
  if (!f) return
  const reader = new FileReader()
  reader.onload = (ev) => { importText.value = ev.target.result || '' }
  reader.readAsText(f)
}
async function doImport() {
  importing.value = true
  try {
    const r = await importCommonRoutes(importText.value)
    importReport.value = r
    await reload()
  } catch (e) {
    importReport.value = { errors: [{ reason: e.response?.data?.error || e.message }] }
  } finally {
    importing.value = false
  }
}
const submitting = ref(false)
const editSubmitting = ref(false)

const newKind = ref('ip')
const newRoute = ref({ address: '', mask: '', domain: '', description: '' })
const formError = ref('')

const editing = ref(null) // route obj or null

// Search filter — matches against domain, address/mask, and description so
// the operator can find a route by whatever they remember.
const search = ref('')
const filteredRoutes = computed(() => {
  const q = search.value.trim().toLowerCase()
  if (!q) return routes.value
  return routes.value.filter(r => {
    if (r.domain && r.domain.toLowerCase().includes(q)) return true
    if (r.address && r.address.toLowerCase().includes(q)) return true
    if (r.mask && r.mask.toLowerCase().includes(q)) return true
    if (r.description && r.description.toLowerCase().includes(q)) return true
    if (r.resolved_ips && r.resolved_ips.some(ip => ip.includes(q))) return true
    return false
  })
})

watch(search, () => { currentPage.value = 1 })

// Pagination — same shape as the users table for visual consistency.
// Page size lives in localStorage so the operator's preferred density
// survives a reload. 25 rows is a sane desktop default.
const pageSize = ref(parseInt(localStorage.getItem('commonRoutesPageSize')) || 25)
const currentPage = ref(1)

watch(pageSize, (v) => {
  localStorage.setItem('commonRoutesPageSize', String(v))
  currentPage.value = 1
})

const totalPages = computed(() =>
  Math.max(1, Math.ceil(filteredRoutes.value.length / pageSize.value))
)

watch(totalPages, (tp) => {
  if (currentPage.value > tp) currentPage.value = tp
})

const paginatedRoutes = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value
  return filteredRoutes.value.slice(start, start + pageSize.value)
})

const visibleRange = computed(() => {
  const total = filteredRoutes.value.length
  if (total === 0) return { start: 0, end: 0, total: 0 }
  const start = (currentPage.value - 1) * pageSize.value + 1
  const end = Math.min(start + pageSize.value - 1, total)
  return { start, end, total }
})

const { toast: _toast } = useToast()
function notify(title, variant = 'default') {
  _toast({ title, variant })
}

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

function isValidIp(v) { return ipPattern.test(v) }
function isValidDomain(v) { return domainPattern.test(v) }

async function reload() {
  loading.value = true
  try {
    const data = await fetchCommonRoutes()
    routes.value = data.routes || []
    refreshIntervalHours.value = data.refreshIntervalHours || 24
  } finally {
    loading.value = false
  }
}

function resetForm() {
  newRoute.value = { address: '', mask: '', domain: '', description: '' }
  formError.value = ''
}

async function addRoute() {
  if (submitting.value) return
  formError.value = ''
  const payload = { kind: newKind.value, description: newRoute.value.description || '' }
  if (newKind.value === 'ip') {
    if (!isValidIp(newRoute.value.address)) { formError.value = `Неверный формат IP: "${newRoute.value.address}"`; return }
    if (!isValidIp(newRoute.value.mask)) { formError.value = `Неверный формат маски: "${newRoute.value.mask}"`; return }
    payload.address = newRoute.value.address
    payload.mask = newRoute.value.mask
  } else {
    if (!isValidDomain(newRoute.value.domain)) { formError.value = `Неверный домен: "${newRoute.value.domain}"`; return }
    payload.domain = newRoute.value.domain
  }
  submitting.value = true
  try {
    const created = await createCommonRoute(payload)
    routes.value.push(created)
    notify('Маршрут добавлен', 'success')
    if (created.last_resolve_err) {
      notify(`Резолв ${created.domain} не удался: ${created.last_resolve_err}`, 'destructive')
    }
    resetForm()
  } catch (e) {
    const msg = e.response?.data?.error || e.response?.data?.message || e.message || 'Неизвестная ошибка'
    if (e.response?.status === 412 && msg.includes('MFA')) {
      notify('Сначала включите 2FA в правом верхнем углу', 'destructive')
      emit('mfa-required')
      resetForm()
    } else {
      formError.value = translateError(msg)
    }
  } finally {
    submitting.value = false
  }
}

// translateError maps known English backend error strings to Russian for
// the form-level inline message. Anything not in the map falls through
// unchanged so we don't accidentally hide useful detail from new errors.
function translateError(msg) {
  const m = String(msg).toLowerCase()
  if (m.includes('duplicate')) return 'Такой маршрут уже есть'
  if (m.includes('invalid ip')) return 'Неверный формат IP'
  if (m.includes('invalid mask')) return 'Неверный формат маски'
  if (m.includes('invalid domain') || m.includes('not a valid hostname')) return 'Неверный формат домена'
  if (m.includes('resolve')) return `Не удалось зарезолвить домен: ${msg}`
  return msg
}

async function removeRoute(id) {
  try {
    await deleteCommonRoute(id)
    routes.value = routes.value.filter(r => r.id !== id)
    notify('Маршрут удалён')
  } catch (e) {
    const msg = e.response?.data?.error || e.response?.data?.message || e.message || 'Неизвестная ошибка'
    if (e.response?.status === 412 && msg.includes('MFA')) {
      notify('Сначала включите 2FA в правом верхнем углу', 'destructive')
      emit('mfa-required')
    } else {
      notify(`Ошибка удаления: ${msg}`, 'destructive')
    }
  }
}

async function refreshDns() {
  refreshing.value = true
  try {
    const r = await refreshCommonRoutesDns()
    notify(`DNS обновлён: резолвлено ${r.resolved}, ошибок ${r.failed}`, r.failed > 0 ? 'destructive' : 'success')
    await reload()
  } catch (e) {
    const msg = e.response?.data?.error || e.response?.data?.message || e.message || 'Неизвестная ошибка'
    if (e.response?.status === 412 && msg.includes('MFA')) {
      notify('Сначала включите 2FA в правом верхнем углу', 'destructive')
      emit('mfa-required')
    } else {
      notify(`Ошибка обновления DNS: ${msg}`, 'destructive')
    }
  } finally {
    refreshing.value = false
  }
}

function openEdit(route) { editing.value = { ...route } }
function closeEdit() {
  if (editSubmitting.value) return
  editing.value = null
}
async function submitEdit(payload) {
  editSubmitting.value = true
  try {
    const updated = await updateCommonRoute(payload.id, payload)
    const idx = routes.value.findIndex(r => r.id === updated.id)
    if (idx !== -1) routes.value[idx] = updated
    notify('Маршрут обновлён', 'success')
    editing.value = null
  } catch (e) {
    const msg = e.response?.data?.error || e.response?.data?.message || e.message || 'Неизвестная ошибка'
    if (e.response?.status === 412 && msg.includes('MFA')) {
      notify('Сначала включите 2FA в правом верхнем углу', 'destructive')
      emit('mfa-required')
      editing.value = null
    } else {
      notify(`Ошибка: ${msg}`, 'destructive')
    }
  } finally {
    editSubmitting.value = false
  }
}

function formatRelativeTime(iso) {
  if (!iso) return ''
  const diffMs = Date.now() - new Date(iso).getTime()
  const h = Math.floor(diffMs / 3600000)
  if (h < 1) return 'менее часа назад'
  if (h < 24) return `${h} ч назад`
  return `${Math.floor(h / 24)} дн назад`
}

onMounted(reload)
</script>

<template>
  <div class="space-y-4">
    <!-- Header -->
    <div class="flex items-start justify-between gap-4">
      <div>
        <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">
          Общие маршруты
        </p>
        <p class="text-sm text-muted-foreground max-w-xl">
          Применяются ко всем активным пользователям. Изменения вступают в силу после переподключения клиента.
        </p>
      </div>
      <div class="flex gap-2">
        <Button
          variant="secondary"
          size="sm"
          :disabled="refreshing || importing"
          @click="showImport = !showImport"
        >
          Импорт
        </Button>
        <Button
          variant="secondary"
          size="sm"
          :loading="refreshing"
          :disabled="refreshing"
          @click="refreshDns"
        >
          <RefreshCw
            v-if="!refreshing"
            :size="14"
          />
          {{ refreshing ? 'Обновляем' : 'Обновить DNS' }}
        </Button>
      </div>
    </div>

    <!-- Bulk import block -->
    <div
      v-if="showImport"
      class="rounded-lg border border-border bg-muted/20 p-3 space-y-2"
    >
      <div class="text-sm font-medium">
        Импорт общих маршрутов
      </div>
      <textarea
        v-model="importText"
        rows="6"
        placeholder="example.com&#10;10.0.0.0/24&#10;1.2.3.4 255.255.255.255&#10;1.1.1.1"
        class="w-full font-mono text-xs rounded-md border border-border bg-background px-2 py-1.5"
      />
      <div class="flex gap-2 items-center">
        <input
          type="file"
          accept=".txt,.csv,.list,text/plain"
          class="text-xs"
          @change="onImportFile"
        >
        <Button
          size="sm"
          variant="secondary"
          :loading="importing"
          :disabled="!importText.trim() || importing"
          @click="doImport"
        >
          Импортировать
        </Button>
      </div>
      <div
        v-if="importReport"
        class="text-xs space-y-1"
      >
        <div class="text-green-600">
          Добавлено: {{ importReport.added?.length || 0 }}
        </div>
        <div
          v-if="importReport.skipped?.length"
          class="text-yellow-600"
        >
          Пропущено (дубль): {{ importReport.skipped.length }}
        </div>
        <div
          v-if="importReport.errors?.length"
          class="text-destructive"
        >
          Ошибки: {{ importReport.errors.length }}
          <ul class="ml-3 list-disc">
            <li
              v-for="(e, idx) in importReport.errors.slice(0, 10)"
              :key="idx"
              class="font-mono"
            >
              {{ e.line ? `строка ${e.line}: ` : '' }}{{ e.source || '?' }} — {{ e.reason }}
            </li>
          </ul>
        </div>
      </div>
    </div>

    <!-- Add form -->
    <div class="rounded-lg border border-border bg-card p-4 space-y-3">
      <div class="flex items-center gap-3">
        <span class="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Тип:</span>
        <div class="inline-flex border border-border rounded-md overflow-hidden bg-background">
          <button
            type="button"
            :class="[
              'inline-flex items-center gap-1.5 h-7 px-2.5 text-xs font-medium transition-colors',
              newKind === 'ip'
                ? 'bg-primary text-primary-foreground'
                : 'text-foreground hover:bg-accent'
            ]"
            @click="newKind = 'ip'"
          >
            <Network :size="12" /> IP / маска
          </button>
          <button
            type="button"
            :class="[
              'inline-flex items-center gap-1.5 h-7 px-2.5 text-xs font-medium border-l border-border transition-colors',
              newKind === 'domain'
                ? 'bg-primary text-primary-foreground'
                : 'text-foreground hover:bg-accent'
            ]"
            @click="newKind = 'domain'"
          >
            <Globe :size="12" /> Домен
          </button>
        </div>
      </div>
      <!-- items-center so the Add button baseline aligns with the input row
           (items-start left the button visually "drifting" higher because the
           inputs have an internal label-line offset). -->
      <!-- @submit.prevent on the form so pressing Enter in any input commits
           the add action without reloading the page. Native form submission
           is also the cleanest accessibility story (keyboard-only operators). -->
      <form
        class="flex gap-2 flex-wrap items-center"
        @submit.prevent="addRoute"
      >
        <template v-if="newKind === 'ip'">
          <Input
            v-model="newRoute.address"
            placeholder="10.0.0.0"
            class="w-40 font-mono"
          />
          <Input
            v-model="newRoute.mask"
            placeholder="255.255.255.0"
            class="w-40 font-mono"
          />
        </template>
        <Input
          v-else
          v-model="newRoute.domain"
          placeholder="youtube.com"
          class="w-60 font-mono"
        />
        <Input
          v-model="newRoute.description"
          placeholder="Описание (опционально)"
          class="flex-1 min-w-[200px]"
        />
        <!-- size="sm" maps to h-8; combined with the inputs (default h-9)
             would still mismatch. The Button component honours an explicit
             class override, so we pin h-9 + matching padding directly here. -->
        <Button
          type="submit"
          :loading="submitting"
          :disabled="submitting"
          class="h-9 px-4 shrink-0"
        >
          <Plus
            v-if="!submitting"
            :size="14"
          />
          {{ submitting ? 'Добавляем' : 'Добавить' }}
        </Button>
      </form>
      <div
        v-if="formError"
        class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      >
        {{ formError }}
      </div>
    </div>

    <!-- Search bar — filters by domain, address/mask, description, and any
         resolved IP so the operator finds a route by whatever they recall. -->
    <div class="flex justify-end">
      <div class="relative">
        <Search
          :size="14"
          class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none"
        />
        <input
          v-model="search"
          placeholder="Поиск (домен, IP, описание)…"
          class="h-9 w-72 rounded-md border border-border bg-background pl-9 pr-8 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
        >
        <button
          v-if="search"
          type="button"
          class="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
          title="Очистить"
          @click="search = ''"
        >
          <X :size="14" />
        </button>
      </div>
    </div>

    <!-- Table — sticky thead. top-14 matches the global AppHeader height so
         the column headers pin directly under it during page scroll, the
         same pattern used by UsersTable. -->
    <div class="rounded-lg border border-border bg-card overflow-visible">
      <table class="w-full text-sm">
        <thead class="sticky top-14 z-10">
          <tr class="bg-muted/95 backdrop-blur-sm border-b border-border">
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground w-28">
              Тип
            </th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Значение
            </th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Описание
            </th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground w-56">
              DNS
            </th>
            <th class="px-4 py-3 w-24" />
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td
              colspan="5"
              class="px-4 py-8 text-center text-sm text-muted-foreground"
            >
              Загрузка…
            </td>
          </tr>
          <tr v-else-if="routes.length === 0">
            <td
              colspan="5"
              class="px-4 py-12 text-center text-sm text-muted-foreground"
            >
              Пока нет общих маршрутов. Добавьте первый, чтобы все пользователи могли к нему попасть.
            </td>
          </tr>
          <tr v-else-if="filteredRoutes.length === 0">
            <td
              colspan="5"
              class="px-4 py-12 text-center text-sm text-muted-foreground"
            >
              По запросу «{{ search }}» ничего не найдено
            </td>
          </tr>
          <tr
            v-for="r in paginatedRoutes"
            :key="r.id"
            class="border-b border-border last:border-0 align-top hover:bg-muted/30 transition-colors"
          >
            <td class="px-4 py-3">
              <Badge :variant="r.kind === 'ip' ? 'neutral' : 'info'">
                <Network
                  v-if="r.kind === 'ip'"
                  :size="11"
                  class="mr-1"
                />
                <Globe
                  v-else
                  :size="11"
                  class="mr-1"
                />
                {{ r.kind === 'ip' ? 'IP' : 'Domain' }}
              </Badge>
            </td>
            <td class="px-4 py-3 font-mono text-sm">
              <template v-if="r.kind === 'ip'">
                <span>{{ r.address }}</span>
                <span class="text-muted-foreground">/</span>
                <span>{{ r.mask }}</span>
              </template>
              <template v-else>
                <div class="font-medium">
                  {{ r.domain }}
                </div>
                <div
                  v-if="r.resolved_ips && r.resolved_ips.length"
                  class="flex items-start gap-1 text-muted-foreground mt-1"
                >
                  <CornerDownRight
                    :size="11"
                    class="mt-0.5 shrink-0"
                  />
                  <span class="break-all">{{ r.resolved_ips.join(', ') }}</span>
                </div>
              </template>
            </td>
            <td class="px-4 py-3 text-muted-foreground">
              {{ r.description || '—' }}
            </td>
            <td class="px-4 py-3 text-sm">
              <template v-if="r.kind === 'domain'">
                <span
                  v-if="r.last_resolve_err"
                  class="inline-flex items-center gap-1.5 text-yellow-600 dark:text-yellow-400"
                  :title="r.last_resolve_err"
                >
                  <AlertTriangle :size="14" /> DNS error · {{ formatRelativeTime(r.last_resolve_at) }}
                </span>
                <span
                  v-else
                  class="inline-flex items-center gap-1.5 text-green-600 dark:text-green-400"
                >
                  <CheckCircle2 :size="14" /> OK · {{ formatRelativeTime(r.last_resolve_at) }}
                </span>
              </template>
              <span
                v-else
                class="text-muted-foreground"
              >—</span>
            </td>
            <td class="px-4 py-3">
              <div class="flex items-center justify-end gap-1">
                <button
                  type="button"
                  class="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
                  title="Редактировать"
                  @click="openEdit(r)"
                >
                  <Pencil :size="15" />
                </button>
                <button
                  type="button"
                  class="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                  title="Удалить"
                  @click="removeRoute(r.id)"
                >
                  <Trash2 :size="15" />
                </button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Pagination — page-size selector + visible-range counter on the left,
         page navigation on the right. Same layout as the users table. -->
    <div
      v-if="routes.length > 0"
      class="flex items-center justify-between gap-3 mt-3 flex-wrap"
    >
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

    <CommonRouteModal
      v-if="editing"
      :open="!!editing"
      :route="editing"
      :submitting="editSubmitting"
      @close="closeEdit"
      @submit="submitEdit"
    />
  </div>
</template>
