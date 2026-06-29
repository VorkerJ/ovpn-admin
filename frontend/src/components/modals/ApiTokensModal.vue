<!-- frontend/src/components/modals/ApiTokensModal.vue
     Manage service-account API tokens for non-interactive integrations.
     A token may only manage VPN users and routes (scope enforced server-side)
     and is shown in full exactly once, at creation. -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'
import { fetchApiTokens, createApiToken, revokeApiToken } from '@/api.js'
import { KeyRound, Copy, Check, Trash2 } from 'lucide-vue-next'

const props = defineProps({ open: Boolean })
const emit = defineEmits(['close'])

const tokens = ref([])
const loading = ref(false)
const error = ref('')
const newName = ref('')
const creating = ref(false)
const created = ref(null) // { name, token } — shown once
const copied = ref(false)

async function load() {
  loading.value = true
  error.value = ''
  try {
    tokens.value = await fetchApiTokens()
  } catch (e) {
    error.value = e?.response?.data?.error || 'Не удалось загрузить токены'
  } finally {
    loading.value = false
  }
}

watch(() => props.open, (o) => {
  if (o) {
    created.value = null
    newName.value = ''
    error.value = ''
    load()
  }
})

async function create() {
  if (creating.value || !newName.value.trim()) return
  creating.value = true
  error.value = ''
  try {
    created.value = await createApiToken(newName.value.trim())
    newName.value = ''
    copied.value = false
    await load()
  } catch (e) {
    error.value = e?.response?.data?.error || 'Не удалось создать токен'
  } finally {
    creating.value = false
  }
}

async function revoke(id) {
  try {
    await revokeApiToken(id)
    await load()
  } catch (e) {
    error.value = e?.response?.data?.error || 'Не удалось отозвать токен'
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
      <Button
        :loading="creating"
        :disabled="creating || !newName.trim()"
        @click="create"
      >
        <KeyRound :size="14" />
        Создать
      </Button>
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
              {{ t.name }}
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
