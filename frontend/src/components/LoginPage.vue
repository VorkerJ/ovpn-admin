<!-- frontend/src/components/LoginPage.vue -->
<script setup>
import { ref } from 'vue'
import Input from '@/components/ui/Input.vue'
import OtpInput from '@/components/ui/OtpInput.vue'
import Button from '@/components/ui/Button.vue'
import { loginMfa } from '@/api.js'

const emit = defineEmits(['login'])

const username = ref('')
const password = ref('')
const error = ref('')
const loading = ref(false)

const mfaStep = ref(false)
const mfaToken = ref('')
const mfaCode = ref('')
const useBackupCode = ref(false)

function toggleBackupMode() {
  useBackupCode.value = !useBackupCode.value
  mfaCode.value = ''
  error.value = ''
}

async function submit() {
  error.value = ''
  if (!password.value) {
    error.value = 'Введите пароль'
    return
  }
  loading.value = true
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.value, password: password.value }),
    })
    const data = await res.json().catch(() => ({}))
    if (res.ok) {
      if (data.mfa_required) {
        mfaToken.value = data.mfa_token
        mfaStep.value = true
      } else {
        emit('login')
      }
    } else {
      error.value = data.error || 'Неверный логин или пароль'
    }
  } catch {
    error.value = 'Ошибка подключения к серверу'
  } finally {
    loading.value = false
  }
}

async function submitMfa() {
  error.value = ''
  if (!mfaCode.value) {
    error.value = 'Введите код'
    return
  }
  loading.value = true
  try {
    const code = useBackupCode.value ? mfaCode.value.toUpperCase().trim() : mfaCode.value
    await loginMfa(mfaToken.value, code)
    emit('login')
  } catch (e) {
    error.value = e.response?.data?.error || 'Неверный код'
  } finally {
    loading.value = false
  }
}

function backToPassword() {
  mfaStep.value = false
  mfaToken.value = ''
  mfaCode.value = ''
  useBackupCode.value = false
  error.value = ''
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background">
    <div class="w-full max-w-sm space-y-6 p-8 rounded-lg border border-border bg-card shadow-lg">
      <div class="space-y-1">
        <h1 class="text-2xl font-semibold">
          ovpn-admin
        </h1>
        <p class="text-sm text-muted-foreground">
          {{ mfaStep ? 'Введите код двухфакторной аутентификации' : 'Войдите для продолжения' }}
        </p>
      </div>

      <!-- Password step -->
      <form
        v-if="!mfaStep"
        class="space-y-4"
        @submit.prevent="submit"
      >
        <div class="space-y-1.5">
          <label class="text-sm font-medium">Логин</label>
          <Input
            v-model="username"
            placeholder="admin"
          />
        </div>
        <div class="space-y-1.5">
          <label class="text-sm font-medium">Пароль</label>
          <Input
            v-model="password"
            type="password"
            placeholder="••••••••"
            autofocus
          />
        </div>

        <div
          v-if="error"
          class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
        >
          {{ error }}
        </div>

        <Button
          type="submit"
          class="w-full"
          :disabled="loading"
        >
          {{ loading ? 'Вход...' : 'Войти' }}
        </Button>
      </form>

      <!-- MFA step -->
      <form
        v-else
        class="space-y-4"
        @submit.prevent="submitMfa"
      >
        <div class="space-y-1.5">
          <label class="text-sm font-medium">
            {{ useBackupCode ? 'Резервный код' : 'Код из приложения' }}
          </label>

          <OtpInput
            v-if="!useBackupCode"
            v-model="mfaCode"
          />
          <Input
            v-else
            v-model="mfaCode"
            placeholder="XXXX-XXXX"
            class="text-center text-lg font-mono tracking-widest uppercase"
            maxlength="10"
            autocomplete="off"
            autofocus
          />

          <button
            type="button"
            class="text-xs text-muted-foreground hover:text-foreground transition-colors mt-2"
            @click="toggleBackupMode"
          >
            {{ useBackupCode ? '← Использовать код из приложения' : 'Использовать резервный код →' }}
          </button>
        </div>

        <div
          v-if="error"
          class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
        >
          {{ error }}
        </div>

        <Button
          type="submit"
          class="w-full"
          :disabled="loading"
        >
          {{ loading ? 'Проверка...' : 'Подтвердить' }}
        </Button>

        <button
          type="button"
          class="w-full text-sm text-muted-foreground hover:text-foreground transition-colors"
          @click="backToPassword"
        >
          &larr; Назад
        </button>
      </form>
    </div>
  </div>
</template>
