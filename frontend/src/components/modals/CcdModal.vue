<!-- frontend/src/components/modals/CcdModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import {
  Network, Globe, Plus, Trash2, CornerDownRight,
  CheckCircle2, AlertTriangle,
} from 'lucide-vue-next'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  serverRole: { type: String, default: 'master' },
  ccd: { type: Object, default: () => ({ Name: '', ClientAddress: '', CustomRoutes: [] }) },
  error: { type: String, default: '' },
  submitting: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'submit'])

let routeId = 0
function withIds(routes) {
  return (routes || []).map(r => ({ ...r, _id: ++routeId, Kind: r.Kind || 'ip' }))
}

const localCcd = ref({ ...props.ccd, CustomRoutes: withIds(props.ccd?.CustomRoutes) })
const newKind = ref('ip')
const newRoute = ref({ Address: '', Mask: '', Domain: '', Description: '' })
const validationError = ref('')

watch(() => props.ccd, (val) => {
  localCcd.value = { ...val, CustomRoutes: withIds(val?.CustomRoutes) }
  validationError.value = ''
}, { deep: true })

const isMaster = () => props.serverRole === 'master'
const isDynamic = () => localCcd.value.ClientAddress === 'dynamic'

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/
function isValidIp(v) { return ipPattern.test(v) }
function isValidDomain(v) { return domainPattern.test(v) }

function addRoute() {
  validationError.value = ''
  if (newKind.value === 'ip') {
    if (!isValidIp(newRoute.value.Address)) {
      validationError.value = `Неверный IP: "${newRoute.value.Address}"`; return
    }
    if (!isValidIp(newRoute.value.Mask)) {
      validationError.value = `Неверная маска: "${newRoute.value.Mask}"`; return
    }
    localCcd.value.CustomRoutes.push({
      _id: ++routeId,
      Kind: 'ip',
      Address: newRoute.value.Address,
      Mask: newRoute.value.Mask,
      Description: newRoute.value.Description,
    })
  } else {
    if (!isValidDomain(newRoute.value.Domain)) {
      validationError.value = `Неверный домен: "${newRoute.value.Domain}"`; return
    }
    // Avoid duplicate domains
    if (localCcd.value.CustomRoutes.some(r => r.Kind === 'domain' && r.Domain === newRoute.value.Domain)) {
      validationError.value = `Домен уже добавлен: "${newRoute.value.Domain}"`; return
    }
    localCcd.value.CustomRoutes.push({
      _id: ++routeId,
      Kind: 'domain',
      Domain: newRoute.value.Domain,
      Description: newRoute.value.Description,
      ResolvedIPs: [], // backend will resolve synchronously on save
    })
  }
  newRoute.value = { Address: '', Mask: '', Domain: '', Description: '' }
}

function removeRoute(index) {
  localCcd.value.CustomRoutes.splice(index, 1)
  validationError.value = ''
}

function onClose() {
  if (props.submitting) return
  validationError.value = ''
  emit('close')
}

function submitCcd() {
  if (props.submitting) return
  validationError.value = ''
  // Re-validate each route (safety net)
  for (const r of localCcd.value.CustomRoutes) {
    if (r.Kind === 'domain') {
      if (!isValidDomain(r.Domain)) { validationError.value = `Неверный домен: "${r.Domain}"`; return }
    } else {
      if (!isValidIp(r.Address)) { validationError.value = `Неверный IP: "${r.Address}"`; return }
      if (!isValidIp(r.Mask)) { validationError.value = `Неверная маска: "${r.Mask}"`; return }
    }
  }
  const payload = {
    ...localCcd.value,
    CustomRoutes: localCcd.value.CustomRoutes.map(({ _id, ...r }) => r),
  }
  emit('submit', payload)
}

function formatRelativeTime(iso) {
  if (!iso) return ''
  const diffMs = Date.now() - new Date(iso).getTime()
  const h = Math.floor(diffMs / 3600000)
  if (h < 1) return 'менее часа назад'
  if (h < 24) return `${h} ч назад`
  return `${Math.floor(h / 24)} дн назад`
}
</script>

<template>
  <Dialog
    :open="open"
    size="lg"
    :title="`Маршруты: ${username}`"
    @close="onClose"
  >
    <div class="space-y-4">
      <!-- Static address -->
      <div class="flex gap-2 items-center">
        <label class="text-sm text-muted-foreground w-36 shrink-0">Статический адрес:</label>
        <Input
          v-model="localCcd.ClientAddress"
          placeholder="dynamic"
          :disabled="!isMaster()"
          class="flex-1 font-mono"
        />
        <Button
          v-if="isMaster()"
          size="sm"
          variant="ghost"
          :disabled="isDynamic()"
          @click="localCcd.ClientAddress = 'dynamic'"
        >
          Сбросить
        </Button>
      </div>

      <!-- Add form -->
      <div v-if="isMaster()" class="rounded-lg border border-border bg-muted/30 p-3 space-y-3">
        <div class="flex items-center gap-3">
          <span class="text-xs font-medium text-muted-foreground uppercase tracking-wider">Тип маршрута:</span>
          <div class="inline-flex border border-border rounded-md overflow-hidden bg-background">
            <button
              type="button"
              @click="newKind = 'ip'"
              :class="[
                'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium transition-colors',
                newKind === 'ip'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
            >
              <Network :size="14" /> IP / маска
            </button>
            <button
              type="button"
              @click="newKind = 'domain'"
              :class="[
                'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium border-l border-border transition-colors',
                newKind === 'domain'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
            >
              <Globe :size="14" /> Домен
            </button>
          </div>
        </div>
        <div class="flex gap-2 flex-wrap items-start">
          <template v-if="newKind === 'ip'">
            <Input v-model="newRoute.Address" placeholder="10.0.0.0" class="w-40 font-mono" />
            <Input v-model="newRoute.Mask" placeholder="255.255.255.0" class="w-40 font-mono" />
          </template>
          <Input v-else v-model="newRoute.Domain" placeholder="youtube.com" class="w-60 font-mono" />
          <Input v-model="newRoute.Description" placeholder="Описание (опционально)" class="flex-1 min-w-[160px]" />
          <Button size="sm" @click="addRoute">
            <Plus :size="13" /> Добавить
          </Button>
        </div>
      </div>

      <!-- Routes table -->
      <div class="rounded-lg border border-border overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/40 border-b border-border">
            <tr>
              <th class="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground w-24">Тип</th>
              <th class="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Значение</th>
              <th class="px-3 py-2.5 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Описание</th>
              <th v-if="isMaster()" class="px-3 py-2.5 w-12" />
            </tr>
          </thead>
          <tbody>
            <tr v-if="!localCcd.CustomRoutes || localCcd.CustomRoutes.length === 0">
              <td colspan="4" class="px-3 py-6 text-center text-sm text-muted-foreground">
                Нет персональных маршрутов
              </td>
            </tr>
            <tr
              v-for="(route, i) in localCcd.CustomRoutes"
              :key="route._id"
              class="border-t border-border align-top hover:bg-muted/20 transition-colors"
            >
              <td class="px-3 py-2.5">
                <Badge :variant="route.Kind === 'domain' ? 'info' : 'neutral'">
                  <component :is="route.Kind === 'domain' ? Globe : Network" :size="11" class="mr-1" />
                  {{ route.Kind === 'domain' ? 'Domain' : 'IP' }}
                </Badge>
              </td>
              <td class="px-3 py-2.5 font-mono text-sm">
                <template v-if="route.Kind === 'domain'">
                  <div class="font-medium">{{ route.Domain }}</div>
                  <div v-if="route.ResolvedIPs && route.ResolvedIPs.length" class="flex items-start gap-1 text-muted-foreground mt-1 text-xs">
                    <CornerDownRight :size="11" class="mt-0.5 shrink-0" />
                    <span class="break-all">{{ route.ResolvedIPs.join(', ') }}</span>
                  </div>
                  <div v-if="route.LastResolveErr" class="text-yellow-600 dark:text-yellow-400 mt-1 text-xs inline-flex items-center gap-1" :title="route.LastResolveErr">
                    <AlertTriangle :size="11" /> DNS error · {{ formatRelativeTime(route.LastResolveAt) }}
                  </div>
                  <div v-else-if="route.LastResolveAt" class="text-green-600 dark:text-green-400 mt-1 text-xs inline-flex items-center gap-1">
                    <CheckCircle2 :size="11" /> {{ formatRelativeTime(route.LastResolveAt) }}
                  </div>
                </template>
                <template v-else>
                  <Input v-if="isMaster()" v-model="route.Address" placeholder="10.0.0.0" class="w-36 inline-block font-mono" />
                  <span v-else class="font-mono">{{ route.Address }}</span>
                  <span class="text-muted-foreground mx-1">/</span>
                  <Input v-if="isMaster()" v-model="route.Mask" placeholder="255.255.255.0" class="w-36 inline-block font-mono" />
                  <span v-else class="font-mono">{{ route.Mask }}</span>
                </template>
              </td>
              <td class="px-3 py-2.5">
                <Input v-if="isMaster()" v-model="route.Description" placeholder="Описание" class="text-sm" />
                <span v-else>{{ route.Description }}</span>
              </td>
              <td v-if="isMaster()" class="px-3 py-2.5">
                <button
                  type="button"
                  class="h-8 w-8 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                  title="Удалить"
                  @click="removeRoute(i)"
                >
                  <Trash2 :size="15" />
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="validationError" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ validationError }}
      </div>
      <div v-else-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" :disabled="submitting" @click="onClose">Закрыть</Button>
      <Button v-if="isMaster()" :loading="submitting" :disabled="submitting" @click="submitCcd">
        Сохранить
      </Button>
    </template>
  </Dialog>
</template>
