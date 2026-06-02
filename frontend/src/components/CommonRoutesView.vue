<!-- frontend/src/components/CommonRoutesView.vue -->
<script setup>
import { ref, onMounted } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import CommonRouteModal from '@/components/modals/CommonRouteModal.vue'
import { useToast } from '@/composables/useToast'
import {
  fetchCommonRoutes, createCommonRoute, updateCommonRoute,
  deleteCommonRoute, refreshCommonRoutesDns,
} from '@/api.js'
import {
  Globe, Network, RefreshCw, Plus, Pencil, Trash2,
  CheckCircle2, AlertTriangle, CornerDownRight,
} from 'lucide-vue-next'

const emit = defineEmits(['mfa-required'])

const routes = ref([])
const refreshIntervalHours = ref(24)
const loading = ref(false)
const refreshing = ref(false)
const submitting = ref(false)
const editSubmitting = ref(false)

const newKind = ref('ip')
const newRoute = ref({ address: '', mask: '', domain: '', description: '' })
const formError = ref('')

const editing = ref(null) // route obj or null

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
      formError.value = msg
    }
  } finally {
    submitting.value = false
  }
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

    <!-- Add form -->
    <div class="rounded-lg border border-border bg-card p-4 space-y-3">
      <div class="flex items-center gap-3">
        <span class="text-xs font-medium text-muted-foreground uppercase tracking-wider">Тип маршрута:</span>
        <div class="inline-flex border border-border rounded-md overflow-hidden bg-background">
          <button
            type="button"
            :class="[
              'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium transition-colors',
              newKind === 'ip'
                ? 'bg-primary text-primary-foreground'
                : 'text-foreground hover:bg-accent'
            ]"
            @click="newKind = 'ip'"
          >
            <Network :size="14" /> IP / маска
          </button>
          <button
            type="button"
            :class="[
              'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium border-l border-border transition-colors',
              newKind === 'domain'
                ? 'bg-primary text-primary-foreground'
                : 'text-foreground hover:bg-accent'
            ]"
            @click="newKind = 'domain'"
          >
            <Globe :size="14" /> Домен
          </button>
        </div>
      </div>
      <div class="flex gap-2 flex-wrap items-start">
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
        <Button
          :loading="submitting"
          :disabled="submitting"
          @click="addRoute"
        >
          <Plus
            v-if="!submitting"
            :size="14"
          />
          {{ submitting ? 'Добавляем' : 'Добавить' }}
        </Button>
      </div>
      <div
        v-if="formError"
        class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      >
        {{ formError }}
      </div>
    </div>

    <!-- Table -->
    <div class="rounded-lg border border-border bg-card overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="bg-muted/40 border-b border-border">
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
          <tr
            v-for="r in routes"
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
