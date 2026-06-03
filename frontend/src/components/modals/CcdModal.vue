<!-- frontend/src/components/modals/CcdModal.vue -->
<script setup>
import { ref, watch, computed } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import Badge from '@/components/ui/Badge.vue'
import DataTable from '@/components/ui/DataTable.vue'
import {
  Network, Globe, Plus, Trash2, CornerDownRight,
  CheckCircle2, AlertTriangle, Shield, ChevronDown, Upload,
} from 'lucide-vue-next'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  ccd: { type: Object, default: () => ({ Name: '', ClientAddress: '', CustomRoutes: [] }) },
  error: { type: String, default: '' },
  submitting: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'submit', 'refresh-dns', 'import-routes'])

const importText = ref('')
const importFileRef = ref(null)
const importFileName = ref('')
const importReport = ref(null)
function onImportFile(e) {
  const f = e.target.files?.[0]
  if (!f) return
  importFileName.value = f.name
  const reader = new FileReader()
  reader.onload = (ev) => {
    importText.value = ev.target.result || ''
  }
  reader.readAsText(f)
}
function setImportReport(r) {
  importReport.value = r
}
defineExpose({ setImportReport })

let routeId = 0
function withIds(routes) {
  return (routes || []).map(r => ({ ...r, _id: ++routeId, Kind: r.Kind || 'ip' }))
}

function withFullTunnelDefaults(c) {
  return {
    ...c,
    CustomRoutes: withIds(c?.CustomRoutes),
    RedirectGateway: c?.RedirectGateway || false,
    // Copy each exclusion into a NEW object, not just slice the outer array.
    // Sharing references with props.ccd would let our user-side mutations
    // (push, splice on description) bubble through the deep watch below and
    // reset localCcd — silently clearing the operator's RedirectGateway
    // toggle the instant they add their first per-user exclusion.
    RedirectGatewayExclusions: Array.isArray(c?.RedirectGatewayExclusions)
      ? c.RedirectGatewayExclusions.map(e => ({ ...e }))
      : [],
  }
}

const localCcd = ref(withFullTunnelDefaults(props.ccd))
const newKind = ref('ip')
const newRoute = ref({ Address: '', Mask: '', Domain: '', Description: '' })
const newUserExclusion = ref({ address: '', mask: '', description: '' })
const validationError = ref('')
const userExclusionError = ref('')
// Сворачиваем секцию исключений по умолчанию — у большинства юзеров она
// будет пустая и достаточно глобальных. Раскрывается кликом на чип со
// счётчиком; авто-раскрывается если у юзера уже есть свои исключения,
// чтобы он сразу их видел.
const showExclusions = ref(false)
// Активная вкладка модалки. Маршруты по умолчанию — это основной экшен,
// ради которого открывают окно. Подключение и Исключения — реже.
const activeTab = ref('routes')
// Импорт спрятан под кнопкой внутри Маршрутов — нужен редко (массовая заливка),
// и видеть пустую textarea на каждом открытии модалки не хочется.
const showImport = ref(false)

watch(() => props.ccd, (val) => {
  localCcd.value = withFullTunnelDefaults(val)
  validationError.value = ''
  userExclusionError.value = ''
  // Если у юзера уже есть персональные исключения — раскрываем сразу,
  // чтобы оператор не искал их за свёрнутым «+N».
  showExclusions.value = (localCcd.value.RedirectGatewayExclusions || []).length > 0
}, { deep: true })

// True when the user has at least one domain-typed route — Refresh DNS
// button only makes sense for those (IP/CIDR routes don't need resolving).
const hasDomainRoutes = computed(() =>
  (localCcd.value.CustomRoutes || []).some(r => r.Kind === 'domain')
)

// VPN-IP режим: 'dynamic' = выдать из пула, 'static' = пин на конкретный адрес.
// Когда переключают на static — очищаем поле (если там было "dynamic"), чтобы юзер ввёл IP.
const ipMode = computed({
  get: () => localCcd.value.ClientAddress === 'dynamic' ? 'dynamic' : 'static',
  set: (m) => {
    if (m === 'dynamic') {
      localCcd.value.ClientAddress = 'dynamic'
    } else if (localCcd.value.ClientAddress === 'dynamic') {
      localCcd.value.ClientAddress = ''
    }
  },
})

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

function addUserExclusion() {
  userExclusionError.value = ''
  const a = (newUserExclusion.value.address || '').trim()
  const m = (newUserExclusion.value.mask || '').trim()
  if (!isValidIp(a)) { userExclusionError.value = `Неверный IP: "${a}"`; return }
  if (!isValidIp(m)) { userExclusionError.value = `Неверная маска: "${m}"`; return }
  const list = localCcd.value.RedirectGatewayExclusions
  if (list.some(e => e.address === a && e.mask === m)) {
    userExclusionError.value = 'Уже добавлено'
    return
  }
  list.push({
    address: a,
    mask: m,
    description: (newUserExclusion.value.description || '').trim(),
  })
  newUserExclusion.value = { address: '', mask: '', description: '' }
}

function removeUserExclusion(i) {
  localCcd.value.RedirectGatewayExclusions.splice(i, 1)
  userExclusionError.value = ''
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
    RedirectGateway: !!localCcd.value.RedirectGateway,
    RedirectGatewayExclusions: localCcd.value.RedirectGatewayExclusions || [],
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
    :title="`Настройки: ${username}`"
    @close="onClose"
  >
    <div class="space-y-4">
      <!-- Tab strip: 3 concerns. Routes is the primary action and default tab. -->
      <div class="flex items-center gap-1 border-b border-border">
        <button
          v-for="tab in [
            { id: 'connection', label: 'Подключение' },
            { id: 'routes', label: 'Маршруты', count: localCcd.CustomRoutes?.length },
            { id: 'exclusions', label: 'Исключения', count: localCcd.RedirectGatewayExclusions?.length, hint: 'Подсети, идущие НАПРЯМУЮ (без VPN) при полном туннеле' },
          ]"
          :key="tab.id"
          type="button"
          :title="tab.hint"
          :class="[
            'inline-flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
            activeTab === tab.id
              ? 'border-primary text-foreground'
              : 'border-transparent text-muted-foreground hover:text-foreground'
          ]"
          @click="activeTab = tab.id"
        >
          {{ tab.label }}
          <span
            v-if="tab.count"
            :class="[
              'inline-flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-semibold leading-none',
              activeTab === tab.id
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted text-muted-foreground'
            ]"
          >{{ tab.count }}</span>
        </button>
      </div>

      <!-- TAB: Подключение -->
      <div
        v-show="activeTab === 'connection'"
        class="space-y-3"
      >
        <div class="flex items-center gap-3 flex-wrap">
          <span class="text-xs text-muted-foreground w-24">VPN-адрес</span>
          <div class="inline-flex border border-border rounded-md overflow-hidden bg-background">
            <button
              type="button"
              :class="[
                'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium transition-colors',
                ipMode === 'dynamic'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
              @click="ipMode = 'dynamic'"
            >
              Из пула
            </button>
            <button
              type="button"
              :class="[
                'inline-flex items-center gap-2 h-8 px-3 text-sm font-medium border-l border-border transition-colors',
                ipMode === 'static'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
              @click="ipMode = 'static'"
            >
              Фиксированный
            </button>
          </div>
          <Input
            v-if="ipMode === 'static'"
            v-model="localCcd.ClientAddress"
            placeholder="10.0.0.5"
            class="w-40 font-mono h-8 text-sm"
          />
          <span
            v-else
            class="text-xs text-muted-foreground"
          >
            OpenVPN выдаст любой свободный адрес
          </span>
        </div>

        <div class="flex items-center gap-3 flex-wrap">
          <span class="text-xs text-muted-foreground w-24">Режим</span>
          <label class="inline-flex items-center gap-2 text-sm cursor-pointer">
            <input
              v-model="localCcd.RedirectGateway"
              type="checkbox"
            >
            <Shield
              :size="14"
              class="text-muted-foreground"
            />
            <span class="font-medium">Полный туннель</span>
            <span class="text-xs text-muted-foreground">— весь трафик через VPN</span>
          </label>
        </div>
      </div>

      <!-- TAB: Исключения -->
      <div
        v-show="activeTab === 'exclusions'"
        class="space-y-3"
      >
        <div
          v-if="!localCcd.RedirectGateway"
          class="rounded-md bg-muted/50 border border-border px-3 py-2 text-xs text-muted-foreground"
        >
          <AlertTriangle
            :size="12"
            class="inline -mt-0.5 mr-1"
          />
          Исключения применяются только при включённом «Полном туннеле». Включи его на вкладке «Подключение» — иначе эти подсети ни на что не влияют.
        </div>
        <p class="text-xs text-muted-foreground">
          Подсети, которые идут МИМО VPN. Глобальные LAN-исключения уже применяются из настроек сервера — здесь добавь специфичные для этого юзера (рабочая VPN, домашний NAS на нетипичной подсети и т.п.).
        </p>

        <!-- Add form (same shape as routes Add to keep visual rhythm) -->
        <div class="flex gap-2 flex-wrap items-start">
          <Input
            v-model="newUserExclusion.address"
            placeholder="10.42.0.0"
            class="w-40 font-mono"
          />
          <Input
            v-model="newUserExclusion.mask"
            placeholder="255.255.255.0"
            class="w-40 font-mono"
          />
          <Input
            v-model="newUserExclusion.description"
            placeholder="Описание (опционально)"
            class="flex-1 min-w-[160px]"
          />
          <Button
            size="sm"
            @click="addUserExclusion"
          >
            <Plus :size="13" /> Добавить
          </Button>
        </div>
        <p
          v-if="userExclusionError"
          class="text-xs text-destructive flex items-center gap-1"
        >
          <AlertTriangle :size="12" /> {{ userExclusionError }}
        </p>

        <DataTable
          :empty="!localCcd.RedirectGatewayExclusions?.length"
          empty-text="Нет персональных исключений"
          :colspan="4"
        >
          <template #colgroup>
            <col class="w-[28%]">
            <col class="w-[28%]">
            <col>
            <col class="w-10">
          </template>
          <template #header>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              IP
            </th>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Маска
            </th>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Описание
            </th>
            <th class="px-2 py-2" />
          </template>
          <template #body>
            <tr
              v-for="(e, i) in localCcd.RedirectGatewayExclusions"
              :key="`${e.address}/${e.mask}/${i}`"
              class="border-t border-border hover:bg-muted/20 transition-colors"
            >
              <td class="px-2 py-2 font-mono text-sm">
                {{ e.address }}
              </td>
              <td class="px-2 py-2 font-mono text-sm">
                {{ e.mask }}
              </td>
              <td class="px-2 py-2 text-sm text-muted-foreground truncate">
                {{ e.description || '—' }}
              </td>
              <td class="px-2 py-2">
                <button
                  type="button"
                  class="h-7 w-7 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                  :title="`Удалить ${e.address}/${e.mask}`"
                  @click="removeUserExclusion(i)"
                >
                  <Trash2 :size="13" />
                </button>
              </td>
            </tr>
          </template>
        </DataTable>
      </div>

      <!-- TAB: Маршруты -->
      <div
        v-show="activeTab === 'routes'"
        class="space-y-3"
      >
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <!-- Compact segmented switcher (auto-width to its content) so it
               doesn't visually dominate the smaller inputs row below it. -->
          <div class="inline-flex border border-border rounded-md overflow-hidden bg-background">
            <button
              type="button"
              :class="[
                'inline-flex items-center gap-1.5 h-8 px-3 text-xs font-medium transition-colors',
                newKind === 'ip'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
              @click="newKind = 'ip'"
            >
              <Network :size="13" /> IP / маска
            </button>
            <button
              type="button"
              :class="[
                'inline-flex items-center gap-1.5 h-8 px-3 text-xs font-medium border-l border-border transition-colors',
                newKind === 'domain'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-foreground hover:bg-accent'
              ]"
              @click="newKind = 'domain'"
            >
              <Globe :size="13" /> Домен
            </button>
          </div>
          <button
            type="button"
            class="text-xs text-muted-foreground hover:text-foreground transition-colors inline-flex items-center gap-1 shrink-0"
            @click="showImport = !showImport"
          >
            Импорт
            <ChevronDown
              :size="12"
              :class="['transition-transform', showImport ? 'rotate-180' : '']"
            />
          </button>
        </div>
        <div class="flex gap-2 flex-wrap items-start">
          <template v-if="newKind === 'ip'">
            <Input
              v-model="newRoute.Address"
              placeholder="10.0.0.0"
              class="w-40 font-mono"
            />
            <Input
              v-model="newRoute.Mask"
              placeholder="255.255.255.0"
              class="w-40 font-mono"
            />
          </template>
          <Input
            v-else
            v-model="newRoute.Domain"
            placeholder="youtube.com"
            class="w-60 font-mono"
          />
          <Input
            v-model="newRoute.Description"
            placeholder="Описание (опционально)"
            class="flex-1 min-w-[160px]"
          />
          <Button
            size="sm"
            @click="addRoute"
          >
            <Plus :size="13" /> Добавить
          </Button>
        </div>

        <DataTable
          :empty="!localCcd.CustomRoutes?.length"
          empty-text="Нет персональных маршрутов"
          :colspan="4"
        >
          <template #colgroup>
            <col class="w-20">
            <col class="w-[44%]">
            <col>
            <col class="w-10">
          </template>
          <template #header>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Тип
            </th>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Значение
            </th>
            <th class="px-2 py-2 text-left text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Описание
            </th>
            <th class="px-2 py-2" />
          </template>
          <template #body>
            <tr
              v-for="(route, i) in localCcd.CustomRoutes"
              :key="route._id"
              class="border-t border-border align-top hover:bg-muted/20 transition-colors"
            >
              <td class="px-2 py-2">
                <Badge :variant="route.Kind === 'domain' ? 'info' : 'neutral'">
                  <component
                    :is="route.Kind === 'domain' ? Globe : Network"
                    :size="11"
                    class="mr-1"
                  />
                  {{ route.Kind === 'domain' ? 'Domain' : 'IP' }}
                </Badge>
              </td>
              <td class="px-2 py-2 font-mono text-sm">
                <template v-if="route.Kind === 'domain'">
                  <div class="font-medium">
                    {{ route.Domain }}
                  </div>
                  <div
                    v-if="route.ResolvedIPs && route.ResolvedIPs.length"
                    class="flex items-start gap-1 text-muted-foreground mt-1 text-xs"
                  >
                    <CornerDownRight
                      :size="11"
                      class="mt-0.5 shrink-0"
                    />
                    <span class="break-all">{{ route.ResolvedIPs.join(', ') }}</span>
                  </div>
                  <div
                    v-if="route.LastResolveErr"
                    class="text-yellow-600 dark:text-yellow-400 mt-1 text-xs inline-flex items-center gap-1"
                    :title="route.LastResolveErr"
                  >
                    <AlertTriangle :size="11" /> DNS error · {{ formatRelativeTime(route.LastResolveAt) }}
                  </div>
                  <div
                    v-else-if="route.LastResolveAt"
                    class="text-green-600 dark:text-green-400 mt-1 text-xs inline-flex items-center gap-1"
                  >
                    <CheckCircle2 :size="11" /> {{ formatRelativeTime(route.LastResolveAt) }}
                  </div>
                </template>
                <div
                  v-else
                  class="flex items-center gap-1"
                >
                  <Input
                    v-model="route.Address"
                    placeholder="10.0.0.0"
                    class="h-8 text-xs font-mono flex-1 min-w-0"
                  />
                  <span class="text-muted-foreground text-xs shrink-0">/</span>
                  <Input
                    v-model="route.Mask"
                    placeholder="255.255.255.0"
                    class="h-8 text-xs font-mono flex-1 min-w-0"
                  />
                </div>
              </td>
              <td class="px-2 py-2">
                <Input
                  v-model="route.Description"
                  placeholder="Описание"
                  class="h-8 text-xs"
                />
              </td>
              <td class="px-2 py-2">
                <button
                  type="button"
                  class="h-7 w-7 inline-flex items-center justify-center rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors"
                  title="Удалить"
                  @click="removeRoute(i)"
                >
                  <Trash2 :size="13" />
                </button>
              </td>
            </tr>
          </template>
        </DataTable>

        <!-- Inline bulk import: hidden by default, toggled by the "Импорт ▾" button above. -->
        <div
          v-if="showImport"
          class="space-y-2 pt-3 border-t border-border"
        >
          <p class="text-xs text-muted-foreground">
            По строке на запись. Комментарии (#) и пустые строки игнорируются. Поддерживаются: домены, IP/CIDR, IP+маска.
          </p>
          <textarea
            v-model="importText"
            rows="5"
            placeholder="example.com&#10;10.0.0.0/24&#10;1.2.3.4 255.255.255.255&#10;1.1.1.1"
            class="w-full font-mono text-xs rounded-md border border-border bg-background px-2 py-1.5"
          />
          <div class="flex gap-2 items-center flex-wrap">
            <!-- Native file input is hidden; click bubbles from the styled label.
                 importFileName is set in onImportFile so the operator sees what
                 they selected (otherwise the chosen file is invisible). -->
            <label class="inline-flex items-center gap-2 h-8 px-3 text-xs font-medium rounded-md border border-border bg-background hover:bg-accent cursor-pointer transition-colors">
              <Upload :size="12" />
              <span>{{ importFileName || 'Выбрать файл' }}</span>
              <input
                ref="importFileRef"
                type="file"
                accept=".txt,.csv,.list,text/plain"
                class="sr-only"
                @change="onImportFile"
              >
            </label>
            <Button
              size="sm"
              variant="secondary"
              :disabled="!importText.trim() || submitting"
              @click="emit('import-routes', { username, text: importText })"
            >
              Импортировать
            </Button>
          </div>
          <div
            v-if="importReport"
            class="text-xs space-y-1 pt-1"
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
      </div>

      <div
        v-if="validationError"
        class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      >
        {{ validationError }}
      </div>
      <div
        v-else-if="error"
        class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      >
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button
        size="sm"
        variant="ghost"
        :disabled="submitting"
        @click="onClose"
      >
        Закрыть
      </Button>
      <Button
        v-if="hasDomainRoutes"
        size="sm"
        variant="secondary"
        :disabled="submitting"
        @click="emit('refresh-dns', username)"
      >
        Обновить DNS
      </Button>
      <Button
        size="sm"
        :loading="submitting"
        :disabled="submitting"
        @click="submitCcd"
      >
        Сохранить
      </Button>
    </template>
  </Dialog>
</template>
