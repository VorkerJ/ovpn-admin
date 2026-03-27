<!-- frontend/src/components/LoginPage.vue -->
<script setup>
import { ref } from 'vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const emit = defineEmits(['login'])

const username = ref('admin')
const password = ref('')
const error = ref('')
const loading = ref(false)

async function submit() {
  error.value = ''
  if (!password.value) {
    error.value = 'Введите пароль'
    return
  }
  loading.value = true
  try {
    const body = new URLSearchParams({ username: username.value, password: password.value })
    const res = await fetch('/api/login', { method: 'POST', body })
    if (res.ok) {
      emit('login')
    } else {
      const data = await res.json().catch(() => ({}))
      error.value = data.error || 'Неверный логин или пароль'
    }
  } catch {
    error.value = 'Ошибка подключения к серверу'
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-background">
    <div class="w-full max-w-sm space-y-6 p-8 rounded-lg border border-border bg-card shadow-lg">
      <div class="space-y-1">
        <h1 class="text-2xl font-semibold">ovpn-admin</h1>
        <p class="text-sm text-muted-foreground">Войдите для продолжения</p>
      </div>

      <form class="space-y-4" @submit.prevent="submit">
        <div class="space-y-1.5">
          <label class="text-sm font-medium">Логин</label>
          <Input v-model="username" placeholder="admin" />
        </div>
        <div class="space-y-1.5">
          <label class="text-sm font-medium">Пароль</label>
          <Input v-model="password" type="password" placeholder="••••••••" autofocus />
        </div>

        <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
          {{ error }}
        </div>

        <Button type="submit" class="w-full" :disabled="loading">
          {{ loading ? 'Вход...' : 'Войти' }}
        </Button>
      </form>
    </div>
  </div>
</template>
