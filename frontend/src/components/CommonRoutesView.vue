<!-- frontend/src/components/CommonRoutesView.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import CommonRouteModal from '@/components/modals/CommonRouteModal.vue'
import { useToast } from '@/composables/useToast'
import {
  fetchCommonRoutes, createCommonRoute, updateCommonRoute,
  deleteCommonRoute, refreshCommonRoutesDns,
} from '@/api.js'

const props = defineProps({
  serverRole: { type: String, default: 'master' },
})

const routes = ref([])
const refreshIntervalHours = ref(24)
const loading = ref(false)
const refreshing = ref(false)

const newKind = ref('ip')
const newRoute = ref({ address: '', mask: '', domain: '', description: '' })
const formError = ref('')

const editing = ref(null) // route obj or null

const { toast: _toast } = useToast()
function notify(title, variant = 'default') {
  _toast({ title, variant })
}

const isMaster = computed(() => props.serverRole === 'master')

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
  try {
    const created = await createCommonRoute(payload)
    routes.value.push(created)
    notify('Маршрут добавлен', 'success')
    if (created.last_resolve_err) {
      notify(`Резолв ${created.domain} не удался: ${created.last_resolve_err}`, 'destructive')
    }
    resetForm()
  } catch (e) {
    formError.value = e.response?.data || e.message
  }
}

async function removeRoute(id) {
  try {
    await deleteCommonRoute(id)
    routes.value = routes.value.filter(r => r.id !== id)
    notify('Маршрут удалён')
  } catch (e) {
    notify(`Ошибка удаления: ${e.message}`, 'destructive')
  }
}

async function refreshDns() {
  refreshing.value = true
  try {
    const r = await refreshCommonRoutesDns()
    notify(`DNS обновлён: резолвлено ${r.resolved}, ошибок ${r.failed}`, r.failed > 0 ? 'destructive' : 'success')
    await reload()
  } catch (e) {
    notify(`Ошибка обновления DNS: ${e.message}`, 'destructive')
  } finally {
    refreshing.value = false
  }
}

function openEdit(route) { editing.value = { ...route } }
function closeEdit() { editing.value = null }
async function submitEdit(payload) {
  try {
    const updated = await updateCommonRoute(payload.id, payload)
    const idx = routes.value.findIndex(r => r.id === updated.id)
    if (idx !== -1) routes.value[idx] = updated
    notify('Маршрут обновлён', 'success')
    closeEdit()
  } catch (e) {
    notify(`Ошибка: ${e.response?.data || e.message}`, 'destructive')
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
    <div class="flex items-center justify-between">
      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-1">Общие маршруты</p>
        <p class="text-xs text-muted-foreground">Применяются ко всем активным пользователям. Изменения вступают в силу после переподключения клиента.</p>
      </div>
      <Button v-if="isMaster" :disabled="refreshing" @click="refreshDns">
        {{ refreshing ? 'Обновляем…' : 'Обновить DNS' }}
      </Button>
    </div>

    <div v-if="isMaster" class="rounded-md border border-border p-3 space-y-2 bg-card">
      <div class="flex items-center gap-2">
        <label class="text-sm">
          <input type="radio" value="ip" v-model="newKind" /> IP / маска
        </label>
        <label class="text-sm">
          <input type="radio" value="domain" v-model="newKind" /> Домен
        </label>
      </div>
      <div class="flex gap-2 flex-wrap">
        <template v-if="newKind === 'ip'">
          <Input v-model="newRoute.address" placeholder="10.0.0.0" class="w-40" />
          <Input v-model="newRoute.mask" placeholder="255.255.255.0" class="w-40" />
        </template>
        <Input v-else v-model="newRoute.domain" placeholder="youtube.com" class="w-60" />
        <Input v-model="newRoute.description" placeholder="Описание (опционально)" class="flex-1 min-w-[200px]" />
        <Button variant="success" @click="addRoute">+ Добавить</Button>
      </div>
      <div v-if="formError" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ formError }}
      </div>
    </div>

    <div class="rounded-md border border-border overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-muted/50">
          <tr>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground w-20">Тип</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Значение</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Описание</th>
            <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground w-48">DNS</th>
            <th v-if="isMaster" class="px-3 py-2 w-28" />
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="5" class="px-3 py-4 text-center text-muted-foreground">Загрузка…</td>
          </tr>
          <tr v-else-if="routes.length === 0">
            <td colspan="5" class="px-3 py-4 text-center text-muted-foreground">Нет общих маршрутов. Добавьте первый.</td>
          </tr>
          <tr v-for="r in routes" :key="r.id" class="border-t border-border align-top">
            <td class="px-3 py-2">
              <Badge :variant="r.kind === 'ip' ? 'secondary' : 'default'">{{ r.kind === 'ip' ? 'IP' : '🌐 Domain' }}</Badge>
            </td>
            <td class="px-3 py-2 font-mono text-xs">
              <template v-if="r.kind === 'ip'">{{ r.address }} / {{ r.mask }}</template>
              <template v-else>
                <div>{{ r.domain }}</div>
                <div v-if="r.resolved_ips && r.resolved_ips.length" class="text-muted-foreground mt-1">
                  → {{ r.resolved_ips.join(', ') }}
                </div>
              </template>
            </td>
            <td class="px-3 py-2">{{ r.description }}</td>
            <td class="px-3 py-2 text-xs">
              <template v-if="r.kind === 'domain'">
                <span v-if="r.last_resolve_err" class="text-yellow-500" :title="r.last_resolve_err">
                  ⚠ DNS error · {{ formatRelativeTime(r.last_resolve_at) }}
                </span>
                <span v-else class="text-green-600">OK · {{ formatRelativeTime(r.last_resolve_at) }}</span>
              </template>
              <span v-else class="text-muted-foreground">—</span>
            </td>
            <td v-if="isMaster" class="px-3 py-2 text-right">
              <Button size="sm" variant="ghost" @click="openEdit(r)">✏</Button>
              <Button size="sm" variant="destructive" @click="removeRoute(r.id)">✕</Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <CommonRouteModal
      v-if="editing"
      :open="!!editing"
      :route="editing"
      @close="closeEdit"
      @submit="submitEdit"
    />
  </div>
</template>
