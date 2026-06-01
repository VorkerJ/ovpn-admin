<!-- frontend/src/components/modals/MfaSetupModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import QRCode from 'qrcode'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import { ShieldCheck, ShieldOff, Copy, AlertTriangle } from 'lucide-vue-next'
import { fetchMfaStatus, setupMfa, confirmMfa, disableMfa } from '@/api.js'

const props = defineProps({
  open: Boolean,
})

const emit = defineEmits(['close', 'status-change'])

// step: 'loading' | 'off' | 'setup' | 'backup' | 'on'
const step = ref('loading')
const error = ref('')
const submitting = ref(false)

// setup state
const secret = ref('')
const qrUrl = ref('')
const qrDataUrl = ref('')
const confirmCode = ref('')

// backup codes
const backupCodes = ref([])
const copied = ref(false)

// disable state
const disablePassword = ref('')
const disableCode = ref('')

watch(() => props.open, async (val) => {
  if (val) {
    step.value = 'loading'
    error.value = ''
    confirmCode.value = ''
    disableCode.value = ''
    disablePassword.value = ''
    secret.value = ''
    qrUrl.value = ''
    qrDataUrl.value = ''
    backupCodes.value = []
    copied.value = false
    try {
      const status = await fetchMfaStatus()
      step.value = status.enabled ? 'on' : 'off'
    } catch {
      error.value = 'Не удалось получить статус 2FA'
      step.value = 'off'
    }
  }
})

async function startSetup() {
  error.value = ''
  submitting.value = true
  try {
    const data = await setupMfa()
    secret.value = data.secret
    qrUrl.value = data.qr_url
    // Render QR client-side to avoid leaking the TOTP secret to any third-party.
    qrDataUrl.value = await QRCode.toDataURL(data.qr_url, { width: 200, margin: 1 })
    step.value = 'setup'
  } catch (e) {
    error.value = e.response?.data?.error || 'Ошибка настройки 2FA'
  } finally {
    submitting.value = false
  }
}

async function confirm() {
  error.value = ''
  if (!confirmCode.value) {
    error.value = 'Введите код из приложения'
    return
  }
  submitting.value = true
  try {
    const data = await confirmMfa(confirmCode.value)
    backupCodes.value = data.backup_codes || []
    step.value = 'backup'
    emit('status-change', true)
  } catch (e) {
    error.value = e.response?.data?.error || 'Неверный код'
  } finally {
    submitting.value = false
  }
}

async function disable() {
  error.value = ''
  if (!disablePassword.value) {
    error.value = 'Введите пароль для подтверждения'
    return
  }
  if (!disableCode.value) {
    error.value = 'Введите код для отключения'
    return
  }
  submitting.value = true
  try {
    await disableMfa(disablePassword.value, disableCode.value)
    step.value = 'off'
    disablePassword.value = ''
    disableCode.value = ''
    emit('status-change', false)
  } catch (e) {
    error.value = e.response?.data?.error || 'Неверный код'
  } finally {
    submitting.value = false
  }
}

function copyBackupCodes() {
  const text = backupCodes.value.join('\n')
  navigator.clipboard.writeText(text)
  copied.value = true
  setTimeout(() => { copied.value = false }, 2000)
}

function onClose() {
  if (submitting.value) return
  emit('close')
}
</script>

<template>
  <Dialog :open="open" title="Двухфакторная аутентификация" @close="onClose">
    <!-- Loading -->
    <div v-if="step === 'loading'" class="flex items-center justify-center py-8">
      <span class="text-sm text-muted-foreground">Загрузка...</span>
    </div>

    <!-- Step: OFF — 2FA disabled -->
    <div v-else-if="step === 'off'" class="space-y-4">
      <div class="flex items-start gap-3">
        <ShieldOff :size="20" class="text-muted-foreground mt-0.5 shrink-0" />
        <div>
          <p class="text-sm font-medium">2FA отключена</p>
          <p class="text-sm text-muted-foreground">
            Включите двухфакторную аутентификацию для дополнительной защиты аккаунта.
          </p>
        </div>
      </div>

      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>

      <Button :loading="submitting" :disabled="submitting" class="w-full" @click="startSetup">
        <ShieldCheck :size="14" />
        {{ submitting ? 'Настройка...' : 'Включить 2FA' }}
      </Button>
    </div>

    <!-- Step: SETUP — QR + code input -->
    <div v-else-if="step === 'setup'" class="space-y-4">
      <p class="text-sm text-muted-foreground">
        Отсканируйте QR-код в приложении аутентификации (Google Authenticator, Authy и др.)
        и введите полученный код для подтверждения.
      </p>

      <div class="flex justify-center">
        <img
          :src="qrDataUrl"
          alt="QR code"
          width="200"
          height="200"
          class="rounded-md border border-border"
        />
      </div>

      <div class="space-y-1">
        <label class="text-xs font-medium text-muted-foreground">Или введите ключ вручную:</label>
        <div class="rounded-md bg-muted px-3 py-2 text-sm font-mono break-all select-all">
          {{ secret }}
        </div>
      </div>

      <div class="space-y-1.5">
        <label class="text-sm font-medium">Код подтверждения</label>
        <Input
          v-model="confirmCode"
          placeholder="000000"
          class="text-center text-lg font-mono tracking-widest"
          maxlength="6"
          autocomplete="one-time-code"
        />
      </div>

      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>

    <!-- Step: BACKUP — show backup codes -->
    <div v-else-if="step === 'backup'" class="space-y-4">
      <div class="flex items-start gap-3">
        <AlertTriangle :size="20" class="text-yellow-500 mt-0.5 shrink-0" />
        <div>
          <p class="text-sm font-medium">Сохраните резервные коды</p>
          <p class="text-sm text-muted-foreground">
            Эти коды можно использовать для входа, если вы потеряете доступ к приложению аутентификации.
            Каждый код можно использовать только один раз.
          </p>
        </div>
      </div>

      <div class="grid grid-cols-2 gap-2">
        <div
          v-for="code in backupCodes"
          :key="code"
          class="rounded-md bg-muted px-3 py-2 text-sm font-mono text-center select-all"
        >
          {{ code }}
        </div>
      </div>

      <Button variant="secondary" class="w-full" @click="copyBackupCodes">
        <Copy :size="14" />
        {{ copied ? 'Скопировано!' : 'Скопировать коды' }}
      </Button>
    </div>

    <!-- Step: ON — 2FA enabled -->
    <div v-else-if="step === 'on'" class="space-y-4">
      <div class="flex items-start gap-3">
        <ShieldCheck :size="20" class="text-green-500 mt-0.5 shrink-0" />
        <div>
          <p class="text-sm font-medium">2FA включена</p>
          <p class="text-sm text-muted-foreground">
            Ваш аккаунт защищён двухфакторной аутентификацией.
          </p>
        </div>
      </div>

      <div class="border-t border-border pt-4 space-y-3">
        <p class="text-sm font-medium text-destructive">Отключить 2FA</p>
        <div class="space-y-1.5">
          <label class="text-sm text-muted-foreground">Текущий пароль</label>
          <Input
            v-model="disablePassword"
            type="password"
            placeholder="••••••••"
            autocomplete="current-password"
          />
        </div>
        <div class="space-y-1.5">
          <label class="text-sm text-muted-foreground">Введите код из приложения для отключения</label>
          <Input
            v-model="disableCode"
            placeholder="000000"
            class="text-center text-lg font-mono tracking-widest"
            maxlength="10"
            autocomplete="one-time-code"
          />
        </div>

        <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
          {{ error }}
        </div>

        <Button variant="destructive" :loading="submitting" :disabled="submitting" class="w-full" @click="disable">
          <ShieldOff :size="14" />
          {{ submitting ? 'Отключение...' : 'Отключить 2FA' }}
        </Button>
      </div>
    </div>

    <template #footer>
      <template v-if="step === 'setup'">
        <Button variant="ghost" :disabled="submitting" @click="onClose">Отмена</Button>
        <Button :loading="submitting" :disabled="submitting" @click="confirm">
          {{ submitting ? 'Проверка...' : 'Подтвердить' }}
        </Button>
      </template>
      <template v-else-if="step === 'backup'">
        <Button @click="onClose">Готово</Button>
      </template>
      <template v-else>
        <Button variant="ghost" @click="onClose">Закрыть</Button>
      </template>
    </template>
  </Dialog>
</template>
