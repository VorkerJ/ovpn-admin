<!-- frontend/src/components/ServerConfigView.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import SectionCard from '@/components/server-config/SectionCard.vue'
import ChipInput from '@/components/server-config/ChipInput.vue'
import { useToast } from '@/composables/useToast'
import { useConfirm } from '@/composables/useConfirm'
import {
  fetchServerConfig, updateServerConfig, fetchServerConfigDefaults,
} from '@/api.js'
import { Save, RotateCcw, AlertTriangle, CheckCircle2, Plus, X } from 'lucide-vue-next'

// saved — успешное сохранение конфига; App.vue использует это чтобы
// перечитать /api/server/settings и убрать баннер "сервер не настроен".
const emit = defineEmits(['saved', 'mfa-required'])

const cfg = ref(null)
const dcoAvailable = ref(false)
const loading = ref(false)
const submitting = ref(false)

const { toast: _toast } = useToast()
function notify(title, variant = 'default') { _toast({ title, variant }) }
const { confirm } = useConfirm()

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/

const dataCipherChoices = ['AES-256-GCM', 'AES-128-GCM', 'CHACHA20-POLY1305', 'AES-256-CBC', 'AES-128-CBC']

const pushExtraText = computed({
  get: () => (cfg.value?.push_extra || []).join('\n'),
  set: (v) => { cfg.value.push_extra = v.split('\n').map(s => s.trim()).filter(Boolean) },
})

const customDirectivesText = computed({
  get: () => (cfg.value?.custom_directives || []).join('\n'),
  set: (v) => { cfg.value.custom_directives = v.split('\n').map(s => s.trim()).filter(Boolean) },
})

async function reload() {
  loading.value = true
  try {
    const data = await fetchServerConfig()
    cfg.value = data.config
    dcoAvailable.value = data.dco_available
  } finally { loading.value = false }
}

async function save() {
  if (submitting.value) return
  submitting.value = true
  try {
    const r = await updateServerConfig(cfg.value)
    cfg.value = r.config
    emit('saved')
    if (r.reload_kind === 'hard') {
      notify('Сохранено. OpenVPN перезапущен — клиенты переподключатся.', 'success')
    } else if (r.reload_kind === 'soft') {
      notify('Сохранено. Изменения применены без рестарта.', 'success')
    } else {
      notify('Настройки сохранены.', 'success')
    }
  } catch (e) {
    const msg = e.response?.data?.error || e.response?.data?.message || e.message || 'Неизвестная ошибка'
    if (e.response?.status === 412 && msg.includes('MFA')) {
      notify('Сначала включите 2FA в правом верхнем углу', 'destructive')
      emit('mfa-required')
    } else {
      notify(`Ошибка: ${msg}`, 'destructive')
    }
  } finally { submitting.value = false }
}

async function resetToDefaults() {
  const ok = await confirm({
    title: 'Сбросить настройки сервера?',
    message: 'Все настройки сервера вернутся к значениям по умолчанию. Изменения не сохранятся, пока вы не нажмёте «Сохранить».',
    confirmText: 'Сбросить',
    variant: 'destructive',
  })
  if (!ok) return
  const def = await fetchServerConfigDefaults()
  cfg.value = def
}

function toggleCipher(c) {
  const idx = cfg.value.data_ciphers.indexOf(c)
  if (idx === -1) cfg.value.data_ciphers.push(c)
  else cfg.value.data_ciphers.splice(idx, 1)
}

const newExclusion = ref({ address: '', mask: '', description: '' })
const exclusionError = ref('')

function exclusions() {
  if (!cfg.value) return []
  if (!Array.isArray(cfg.value.redirect_gateway_exclusions)) {
    cfg.value.redirect_gateway_exclusions = []
  }
  return cfg.value.redirect_gateway_exclusions
}

function addExclusion() {
  exclusionError.value = ''
  const a = (newExclusion.value.address || '').trim()
  const m = (newExclusion.value.mask || '').trim()
  if (!ipPattern.test(a)) { exclusionError.value = `Неверный IP: "${a}"`; return }
  if (!ipPattern.test(m)) { exclusionError.value = `Неверная маска: "${m}"`; return }
  const list = exclusions()
  if (list.some(e => e.address === a && e.mask === m)) {
    exclusionError.value = 'Такая подсеть уже есть'
    return
  }
  list.push({
    address: a,
    mask: m,
    description: (newExclusion.value.description || '').trim(),
  })
  newExclusion.value = { address: '', mask: '', description: '' }
}

function removeExclusion(i) {
  exclusions().splice(i, 1)
}

onMounted(reload)
</script>

<template>
  <div class="space-y-4 pb-16">
    <!--
      Sticky header keeps Save + Reset visible regardless of how far the
      operator has scrolled down through the form sections. Previously the
      buttons sat at the top only, so editing "Дополнительно" (which is at
      the bottom of a long page) left the operator searching for how to
      commit their edits.
    -->
    <div class="sticky top-14 z-20 -mx-6 px-6 py-3 bg-background/95 backdrop-blur-sm border-b border-border flex items-start justify-between gap-3">
      <div class="min-w-0">
        <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-1">
          Сервер
        </p>
        <p class="text-sm text-muted-foreground max-w-2xl">
          Параметры OpenVPN-сервера. Изменения часть применяются hot (push routes, verb, keepalive),
          часть требует перезапуска openvpn-процесса (port, proto, MTU, шифр, DCO).
        </p>
      </div>
      <div class="flex gap-2 shrink-0">
        <Button
          variant="secondary"
          size="sm"
          data-testid="server-config-reset"
          @click="resetToDefaults"
        >
          <RotateCcw :size="14" /> Сбросить
        </Button>
        <Button
          size="sm"
          :loading="submitting"
          :disabled="!cfg"
          data-testid="server-config-save"
          @click="save"
        >
          <Save :size="14" /> Сохранить
        </Button>
      </div>
    </div>

    <div
      v-if="loading"
      class="text-sm text-muted-foreground"
    >
      Загрузка…
    </div>
    <div
      v-else-if="cfg"
      class="space-y-3"
    >
      <div
        :class="[
          'rounded-md border px-3 py-2 text-sm flex items-center gap-2',
          dcoAvailable
            ? 'border-green-500/30 bg-green-500/5 text-green-700 dark:text-green-300'
            : 'border-yellow-500/30 bg-yellow-500/5 text-yellow-700 dark:text-yellow-300'
        ]"
      >
        <CheckCircle2
          v-if="dcoAvailable"
          :size="16"
        />
        <AlertTriangle
          v-else
          :size="16"
        />
        <span>
          <strong>DCO (kernel offload):</strong>
          {{ dcoAvailable ? 'доступен на этой ноде' : 'не загружен kernel-модуль ovpn — toggle ниже неактивен' }}
        </span>
      </div>

      <SectionCard
        title="Сеть и транспорт"
        description="Протокол, порт, MTU, подсеть VPN"
      >
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Proto</span>
            <select
              v-model="cfg.proto"
              class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono"
            >
              <option value="udp">UDP (быстрее, рекомендуется)</option>
              <option value="tcp">TCP</option>
            </select>
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Port</span>
            <Input
              v-model.number="cfg.port"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Network</span>
            <Input
              v-model="cfg.network"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Network mask</span>
            <Input
              v-model="cfg.network_mask"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">tun-mtu (576–9000)</span>
            <Input
              v-model.number="cfg.tun_mtu"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">mssfix (0=выкл, 100–9000)</span>
            <Input
              v-model.number="cfg.mss_fix"
              type="number"
              class="font-mono mt-1"
            />
          </label>
        </div>
      </SectionCard>

      <SectionCard
        title="Публичный endpoint"
        description="Что попадает в .ovpn клиентам (по умолчанию — из --ovpn.server)"
        :default-open="false"
      >
        <div class="grid grid-cols-3 gap-3">
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Hostname / IP</span>
            <Input
              v-model="cfg.public_hostname"
              placeholder="vpn.example.com"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Port</span>
            <Input
              v-model.number="cfg.public_port"
              type="number"
              placeholder="1194"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Protocol</span>
            <select
              v-model="cfg.public_proto"
              class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono"
            >
              <option value="">(default)</option>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </select>
          </label>
        </div>
        <p class="text-xs text-muted-foreground mt-2">
          Оставьте пустым чтобы использовать значение из --ovpn.server CLI флага
        </p>
      </SectionCard>

      <SectionCard
        title="Шифрование"
        description="Cipher, TLS, DCO"
      >
        <div class="space-y-3">
          <div>
            <span class="text-xs text-muted-foreground">Data ciphers (порядок = приоритет NCP)</span>
            <div class="flex flex-wrap gap-1.5 mt-1">
              <button
                v-for="c in dataCipherChoices"
                :key="c"
                type="button"
                :class="[
                  'inline-flex items-center gap-1 rounded-md border px-2.5 h-7 text-xs font-mono transition-colors',
                  cfg.data_ciphers.includes(c)
                    ? 'border-primary bg-primary text-primary-foreground'
                    : 'border-border bg-background text-muted-foreground hover:bg-accent'
                ]"
                @click="toggleCipher(c)"
              >
                {{ c }}
              </button>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <label class="block text-sm">
              <span class="text-xs text-muted-foreground">TLS version min</span>
              <select
                v-model="cfg.tls_version_min"
                class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono"
              >
                <option value="1.2">1.2</option>
                <option value="1.3">1.3 (рекомендуется)</option>
              </select>
            </label>
            <label class="block text-sm">
              <span class="text-xs text-muted-foreground">TLS auth mode</span>
              <select
                v-model="cfg.tls_auth_mode"
                class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono"
              >
                <option value="tls-auth">tls-auth (HMAC)</option>
                <option value="tls-crypt">tls-crypt (encrypted, рекомендуется)</option>
              </select>
            </label>
          </div>
          <label class="flex items-center gap-2 text-sm">
            <input
              v-model="cfg.dco_enabled"
              type="checkbox"
              :disabled="!dcoAvailable"
            >
            DCO (kernel offload) {{ !dcoAvailable ? '— недоступен на этой ноде' : '' }}
          </label>
          <label class="flex items-center gap-2 text-sm">
            <input
              v-model="cfg.password_auth"
              type="checkbox"
            >
            Парольная аутентификация (доп. пароль для избранных)
          </label>
          <p
            v-if="cfg.password_auth"
            class="text-xs text-muted-foreground -mt-1"
          >
            Кому на вкладке «Пользователи» задан пароль (🔑) — заходит по сертификату + паролю; остальные — только по сертификату, без запроса пароля.
          </p>
        </div>
      </SectionCard>

      <SectionCard
        title="Поведение"
        description="Keepalive, лимиты, логи"
      >
        <div class="grid grid-cols-2 gap-3">
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Keepalive interval (sec)</span>
            <Input
              v-model.number="cfg.keepalive_interval"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Keepalive timeout (sec)</span>
            <Input
              v-model.number="cfg.keepalive_timeout"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Max clients (0 = unlimited)</span>
            <Input
              v-model.number="cfg.max_clients"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Compression</span>
            <select
              v-model="cfg.compression"
              class="w-full h-9 mt-1 rounded-md border border-border bg-background px-2 text-sm font-mono"
            >
              <option value="">отключено (рекомендуется — VORACLE)</option>
              <option value="lz4-v2">lz4-v2</option>
              <option value="lzo">lzo</option>
            </select>
          </label>
          <label class="block text-sm">
            <span class="text-xs text-muted-foreground">Verb (log level 0–11)</span>
            <Input
              v-model.number="cfg.verb"
              type="number"
              class="font-mono mt-1"
            />
          </label>
          <label class="block text-sm">
            <span
              class="text-xs text-muted-foreground"
              title="Background-резолв доменных маршрутов (Common Routes + per-user). 0 = выключено, новые IP подхватятся только при ручном Refresh."
            >Domain refresh interval (ч)</span>
            <Input
              v-model.number="cfg.domain_refresh_interval_hours"
              type="number"
              min="0"
              class="font-mono mt-1"
            />
          </label>
        </div>
        <div class="flex gap-4 pt-2">
          <label class="inline-flex items-center gap-2 text-sm">
            <input
              v-model="cfg.client_to_client"
              type="checkbox"
            >
            client-to-client
          </label>
          <label class="inline-flex items-center gap-2 text-sm">
            <input
              v-model="cfg.duplicate_cn"
              type="checkbox"
            >
            duplicate-cn
          </label>
        </div>
      </SectionCard>

      <SectionCard
        title="Пуш клиентам"
        description="Маршруты, DNS, gateway"
      >
        <label class="inline-flex items-center gap-2 text-sm">
          <input
            v-model="cfg.redirect_gateway"
            type="checkbox"
          >
          redirect-gateway def1 (весь трафик через VPN)
        </label>
        <div>
          <span class="text-xs text-muted-foreground">DNS-серверы (push клиентам)</span>
          <ChipInput
            v-model="cfg.dns_servers"
            placeholder="1.1.1.1 (Enter / запятая)"
            :validator="(v) => ipPattern.test(v)"
          />
        </div>
        <div>
          <span class="text-xs text-muted-foreground">Push extra (одна строка = одна push-директива; whitelist)</span>
          <textarea
            v-model="pushExtraText"
            rows="3"
            class="w-full mt-1 rounded-md border border-border bg-background px-2 py-1 text-sm font-mono"
            placeholder="route 10.0.0.0 255.0.0.0"
          />
        </div>
      </SectionCard>

      <SectionCard
        title="Исключения для full-tunnel"
        description="Подсети, которые идут МИМО VPN при включённом full-tunnel (домашняя LAN, корп. сети)."
        :default-open="false"
      >
        <div
          v-if="exclusions().length > 0"
          class="flex flex-wrap gap-1.5"
        >
          <span
            v-for="(e, i) in exclusions()"
            :key="`${e.address}/${e.mask}/${i}`"
            class="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-background border border-border text-xs"
          >
            <span class="font-mono">{{ e.address }}/{{ e.mask }}</span>
            <span
              v-if="e.description"
              class="text-muted-foreground"
            >· {{ e.description }}</span>
            <button
              type="button"
              class="text-muted-foreground hover:text-foreground transition-colors"
              :title="`Удалить ${e.address}/${e.mask}`"
              @click="removeExclusion(i)"
            >
              <X :size="11" />
            </button>
          </span>
        </div>
        <div class="flex gap-1.5 flex-wrap items-center pt-2 border-t border-border">
          <Input
            v-model="newExclusion.address"
            placeholder="192.168.0.0"
            class="w-32 font-mono h-8 text-xs"
          />
          <Input
            v-model="newExclusion.mask"
            placeholder="255.255.0.0"
            class="w-32 font-mono h-8 text-xs"
          />
          <Input
            v-model="newExclusion.description"
            placeholder="Описание"
            class="flex-1 min-w-[120px] h-8 text-xs"
          />
          <Button
            class="h-8"
            @click="addExclusion"
          >
            <Plus :size="12" />
          </Button>
        </div>
        <p
          v-if="exclusionError"
          class="text-xs text-destructive flex items-center gap-1"
        >
          <AlertTriangle :size="12" /> {{ exclusionError }}
        </p>
      </SectionCard>

      <SectionCard
        title="Дополнительно"
        description="Custom OpenVPN directives (whitelist)"
        :default-open="false"
      >
        <textarea
          v-model="customDirectivesText"
          rows="5"
          class="w-full rounded-md border border-border bg-background px-2 py-1 text-sm font-mono"
          placeholder="explicit-exit-notify
route 192.168.0.0 255.255.0.0"
        />
        <p class="text-xs text-muted-foreground">
          Разрешены: <span class="font-mono">route, route-nopull, topology, mtu-test, fragment, tx-queue-len, fast-io, explicit-exit-notify, sndbuf, rcvbuf</span>.
        </p>
      </SectionCard>
    </div>
  </div>
</template>
