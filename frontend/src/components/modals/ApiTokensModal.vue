<!-- frontend/src/components/modals/ApiTokensModal.vue
     Manage service-account API tokens for non-interactive integrations.
     A token may only manage VPN users and routes (scope enforced server-side)
     and is shown in full exactly once, at creation. -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'
import Tooltip from '@/components/ui/Tooltip.vue'
import { fetchApiTokens, createApiToken, revokeApiToken, fetchMfaStatus } from '@/api.js'
import { KeyRound, Copy, Check, Trash2, ShieldAlert, FileDown } from 'lucide-vue-next'

const props = defineProps({ open: Boolean })
const emit = defineEmits(['close'])

const tokens = ref([])
const loading = ref(false)
const error = ref('')
const newName = ref('')
// Grant the token the extra capability of exporting user configs *with the
// private key* (/api/user/config/show). Off by default — most integrations only
// create users and routes and must not be able to exfiltrate private keys.
const allowConfigExport = ref(false)
const creating = ref(false)
// Creating a token requires an MFA-enabled admin session (server returns 412
// otherwise). Mirror that in the UI so the button is disabled with an
// explanation instead of failing on click.
const mfaEnabled = ref(true)
const created = ref(null) // { name, token } — shown once
const copied = ref(false)

// Map backend errors to friendly Russian text. Creating/revoking a token needs
// an MFA-enabled admin session; the backend returns an English 412 — translate
// it and point the operator at the 2FA toggle.
function friendlyErr(e, fallback) {
  const msg = e?.response?.data?.error || ''
  if (e?.response?.status === 412 && msg.includes('MFA')) {
    return 'Сначала включите двухфакторную аутентификацию (значок-щит в шапке) — без неё управлять токенами нельзя.'
  }
  return msg || fallback
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    tokens.value = await fetchApiTokens()
  } catch (e) {
    error.value = friendlyErr(e, 'Не удалось загрузить токены')
  } finally {
    loading.value = false
  }
}

watch(() => props.open, (o) => {
  if (o) {
    created.value = null
    newName.value = ''
    allowConfigExport.value = false
    error.value = ''
    load()
    fetchMfaStatus().then(s => { mfaEnabled.value = !!s?.enabled }).catch(() => {})
  }
})

async function create() {
  if (creating.value || !newName.value.trim()) return
  creating.value = true
  error.value = ''
  try {
    created.value = await createApiToken(newName.value.trim(), allowConfigExport.value)
    newName.value = ''
    allowConfigExport.value = false
    copied.value = false
    await load()
  } catch (e) {
    error.value = friendlyErr(e, 'Не удалось создать токен')
  } finally {
    creating.value = false
  }
}

async function revoke(id) {
  try {
    await revokeApiToken(id)
    await load()
  } catch (e) {
    error.value = friendlyErr(e, 'Не удалось отозвать токен')
  }
}

async function copyToken() {
  try {
    await navigator.clipboard.writeText(created.value.token)
    copied.value = true
    setTimeout(() => (copied.value = false), 2000)
  } catch {
    // clipboard may be unavailable over plain HTTP — user can select manually
  }
}

function onClose() {
  created.value = null
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
    title="API-токены (сервис-аккаунты)"
    description="Для интеграций, которые создают пользователей и маршруты по API. Токен ограничен управлением пользователями и маршрутами — без доступа к настройкам сервера, MFA и паролю."
    size="lg"
    @close="onClose"
  >
    <!-- one-time reveal of a freshly created token -->
    <div
      v-if="created"
      class="mb-4 rounded-md border-2 border-green-500/40 bg-green-500/10 p-3"
    >
      <p class="text-sm font-medium mb-2">
        Токен «{{ created.name }}» создан. Скопируйте его сейчас — больше он не будет показан.
      </p>
      <div class="flex items-center gap-2">
        <code class="flex-1 rounded bg-background px-2 py-1.5 text-xs font-mono break-all border border-border">{{ created.token }}</code>
        <Button
          size="icon-sm"
          variant="ghost"
          :title="copied ? 'Скопировано' : 'Копировать'"
          @click="copyToken"
        >
          <Check
            v-if="copied"
            :size="16"
            class="text-green-600"
          />
          <Copy
            v-else
            :size="16"
          />
        </Button>
      </div>
      <p class="mt-2 text-xs text-muted-foreground">
        Использование: <code class="font-mono">Authorization: Bearer &lt;токен&gt;</code>
      </p>
    </div>

    <!-- create form -->
    <div class="flex items-end gap-2 mb-4">
      <div class="flex-1">
        <label class="text-xs text-muted-foreground">Название нового токена</label>
        <input
          v-model="newName"
          placeholder="например, teleport-prod"
          class="mt-1 h-9 w-full rounded-md border border-border bg-background px-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
          @keyup.enter="create"
        >
      </div>
      <Tooltip :text="!mfaEnabled ? 'Нужна включённая 2FA: Профиль → MFA Setup. Токены может создавать только админ с MFA.' : ''">
        <Button
          :loading="creating"
          :disabled="creating || !newName.trim() || !mfaEnabled"
          @click="create"
        >
          <KeyRound :size="14" />
          Создать
        </Button>
      </Tooltip>
    </div>

    <!-- optional capability: allow this token to export user configs with private key -->
    <label class="mb-4 flex items-start gap-2 text-xs text-muted-foreground cursor-pointer select-none">
      <input
        v-model="allowConfigExport"
        type="checkbox"
        class="mt-0.5 h-3.5 w-3.5 shrink-0 rounded border-border"
      >
      <span>
        Разрешить экспорт конфигов с приватным ключом
        (<code class="font-mono">/api/user/config/show</code>).
        По умолчанию выключено — без него токен может лишь создавать пользователей и маршруты,
        но не выгружать приватные ключи.
      </span>
    </label>

    <!-- MFA requirement notice — visible without hovering the disabled button -->
    <div
      v-if="!mfaEnabled"
      class="mb-4 flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-600 dark:text-yellow-400"
    >
      <ShieldAlert
        :size="14"
        class="mt-0.5 shrink-0"
      />
      <span>Создание токенов доступно только админу с включённой 2FA. Включите её: <b>Профиль → MFA Setup</b>.</span>
    </div>

    <div
      v-if="error"
      class="mb-3 rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
    >
      {{ error }}
    </div>

    <!-- token list -->
    <div class="rounded-lg border border-border overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/60 text-xs uppercase tracking-wider text-muted-foreground">
            <th class="px-3 py-2 text-left">
              Название
            </th>
            <th class="px-3 py-2 text-left">
              Токен
            </th>
            <th class="px-3 py-2 text-left">
              Создан
            </th>
            <th class="px-3 py-2 text-left">
              Последнее использование
            </th>
            <th class="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          <tr v-if="tokens.length === 0">
            <td
              colspan="5"
              class="px-3 py-8 text-center text-sm text-muted-foreground"
            >
              {{ loading ? 'Загрузка…' : 'Токенов пока нет' }}
            </td>
          </tr>
          <tr
            v-for="t in tokens"
            :key="t.id"
            class="border-b border-border last:border-0 hover:bg-muted/30"
          >
            <td class="px-3 py-2 font-medium">
              <span class="inline-flex items-center gap-1.5">
                {{ t.name }}
                <Tooltip
                  v-if="t.allow_config_export"
                  text="Может экспортировать конфиги с приватным ключом (/api/user/config/show)"
                >
                  <span class="inline-flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400">
                    <FileDown :size="11" />
                    export
                  </span>
                </Tooltip>
              </span>
            </td>
            <td class="px-3 py-2 font-mono text-xs text-muted-foreground">
              {{ t.hint }}
            </td>
            <td class="px-3 py-2 text-xs text-muted-foreground">
              {{ (t.created_at || '').slice(0, 10) }}
            </td>
            <td class="px-3 py-2 text-xs text-muted-foreground">
              {{ t.last_used_at ? t.last_used_at.replace('T', ' ').slice(0, 16) : '—' }}
            </td>
            <td class="px-3 py-2 text-right">
              <Button
                size="icon-sm"
                variant="ghost"
                title="Отозвать"
                @click="revoke(t.id)"
              >
                <Trash2
                  :size="15"
                  class="text-destructive"
                />
              </Button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <template #footer>
      <Button
        variant="ghost"
        @click="onClose"
      >
        Закрыть
      </Button>
    </template>
  </Dialog>
</template>
