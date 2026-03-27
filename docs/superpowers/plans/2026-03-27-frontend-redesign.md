# Frontend Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Переписать фронтенд ovpn-admin с Vue 2 + Bootstrap + Webpack на Vue 3 + shadcn-vue + Tailwind CSS + Vite, сохранив всю функциональность и добавив тёмную/светлую тему с переключателем, русский интерфейс и App Shell layout.

**Architecture:** Монолитный `main.js` + HTML-шаблон разбивается на отдельные `.vue` компоненты. Все API-вызовы выносятся в `api.js`. Go-бэкенд не меняется — Vite конфигурируется так, чтобы собранные файлы попадали в `frontend/static/`, откуда `packr` их раздаёт.

**Tech Stack:** Vue 3 (Composition API + `<script setup>`), Vite, Tailwind CSS v3, shadcn-vue, axios, TypeScript НЕ используем (остаёмся на JS для минимальных изменений).

---

## Структура файлов

```
frontend/
├── index.html                      ← НОВЫЙ (Vite entry, заменяет static/index.html)
├── package.json                    ← ЗАМЕНИТЬ полностью
├── vite.config.js                  ← НОВЫЙ (заменяет webpack.config.js)
├── tailwind.config.js              ← НОВЫЙ
├── postcss.config.js               ← НОВЫЙ
├── components.json                 ← НОВЫЙ (shadcn-vue config)
├── src/
│   ├── main.js                     ← ПЕРЕПИСАТЬ (Vue 3 init)
│   ├── App.vue                     ← НОВЫЙ (корневой компонент)
│   ├── api.js                      ← НОВЫЙ (все axios-вызовы)
│   ├── composables/
│   │   └── useTheme.js             ← НОВЫЙ (dark/light toggle)
│   ├── components/
│   │   ├── AppHeader.vue           ← НОВЫЙ
│   │   ├── StatCards.vue           ← НОВЫЙ
│   │   ├── UsersTable.vue          ← НОВЫЙ
│   │   ├── ActionsMenu.vue         ← НОВЫЙ (главная кнопка + ··· dropdown)
│   │   └── modals/
│   │       ├── AddUserModal.vue    ← НОВЫЙ
│   │       ├── DeleteUserModal.vue ← НОВЫЙ
│   │       ├── RotateUserModal.vue ← НОВЫЙ
│   │       ├── ChangePasswordModal.vue ← НОВЫЙ
│   │       └── CcdModal.vue        ← НОВЫЙ
│   ├── components/ui/              ← ГЕНЕРИРУЕТСЯ shadcn-vue CLI
│   └── lib/
│       └── utils.js                ← ГЕНЕРИРУЕТСЯ shadcn-vue (cn helper)
│   └── style.css                   ← ПЕРЕПИСАТЬ (Tailwind directives + CSS vars)
└── static/                         ← Vite будет писать сборку сюда
    └── (старые файлы dist/ можно удалить после успешной сборки)
```

**Данные от API (shape неизменен):**
```js
// GET api/users/list
[{ Identity, AccountStatus, Connections, ExpirationDate, RevocationDate, ConnectionStatus }]
// AccountStatus: "Active" | "Revoked" | "Expired"
// ConnectionStatus: "Connected" | ""

// GET api/server/settings
{ serverRole: "master" | "slave", modules: ["core", "ccd", "passwdAuth"] }

// GET api/sync/last/successful  (только slave)
"2024-01-01 12:00:00"

// GET/POST api/user/ccd
{ Name, ClientAddress, CustomRoutes: [{ Address, Mask, Description }] }
```

---

## Task 1: Инициализация Vite + Vue 3 + Tailwind

**Files:**
- Replace: `frontend/package.json`
- Create: `frontend/vite.config.js`
- Create: `frontend/tailwind.config.js`
- Create: `frontend/postcss.config.js`
- Create: `frontend/index.html`

- [ ] **Step 1: Заменить package.json**

```json
{
  "name": "ovpn-admin",
  "version": "2.0.0",
  "private": true,
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "axios": "^1.6.0",
    "vue": "^3.4.0",
    "@vueuse/core": "^10.7.0",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.1.0",
    "tailwind-merge": "^2.2.0",
    "lucide-vue-next": "^0.323.0",
    "radix-vue": "^1.7.0"
  },
  "devDependencies": {
    "@vitejs/plugin-vue": "^5.0.0",
    "autoprefixer": "^10.4.17",
    "postcss": "^8.4.33",
    "tailwindcss": "^3.4.1",
    "vite": "^5.1.0"
  }
}
```

- [ ] **Step 2: Создать vite.config.js**

```js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'static',
    emptyOutDir: false,
    rollupOptions: {
      input: path.resolve(__dirname, 'index.html'),
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})
```

- [ ] **Step 3: Создать tailwind.config.js**

```js
/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    './index.html',
    './src/**/*.{vue,js}',
  ],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
  plugins: [],
}
```

- [ ] **Step 4: Создать postcss.config.js**

```js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
```

- [ ] **Step 5: Создать frontend/index.html (Vite entry)**

```html
<!DOCTYPE html>
<html lang="ru" class="">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OVPN Admin</title>
</head>
<body>
  <div id="app"></div>
  <script type="module" src="/src/main.js"></script>
</body>
</html>
```

- [ ] **Step 6: Установить зависимости**

```bash
cd frontend && npm install
```

Ожидаемый результат: `node_modules/` создан без ошибок.

- [ ] **Step 7: Проверить что Vite стартует**

```bash
cd frontend && npx vite --version
```

Ожидаемый результат: `vite/5.x.x`

- [ ] **Step 8: Commit**

```bash
git add frontend/package.json frontend/vite.config.js frontend/tailwind.config.js frontend/postcss.config.js frontend/index.html
git commit -m "build: migrate from webpack to vite, add vue3 + tailwind deps"
```

---

## Task 2: CSS переменные + тема

**Files:**
- Create: `frontend/src/style.css`
- Create: `frontend/src/lib/utils.js`
- Create: `frontend/src/composables/useTheme.js`

- [ ] **Step 1: Создать src/style.css с Tailwind директивами и CSS переменными**

```css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    --background: 210 40% 98%;
    --foreground: 222 47% 11%;
    --card: 0 0% 100%;
    --card-foreground: 222 47% 11%;
    --border: 214 32% 91%;
    --input: 214 32% 91%;
    --primary: 239 84% 67%;
    --primary-foreground: 0 0% 100%;
    --secondary: 210 40% 96%;
    --secondary-foreground: 222 47% 11%;
    --muted: 210 40% 96%;
    --muted-foreground: 215 16% 47%;
    --accent: 210 40% 96%;
    --accent-foreground: 222 47% 11%;
    --destructive: 0 84% 60%;
    --destructive-foreground: 0 0% 100%;
    --ring: 239 84% 67%;
    --radius: 0.5rem;
  }

  .dark {
    --background: 222 47% 5%;
    --foreground: 213 31% 91%;
    --card: 222 47% 9%;
    --card-foreground: 213 31% 91%;
    --border: 226 24% 17%;
    --input: 226 24% 17%;
    --primary: 239 84% 67%;
    --primary-foreground: 0 0% 100%;
    --secondary: 226 24% 14%;
    --secondary-foreground: 213 31% 91%;
    --muted: 223 47% 11%;
    --muted-foreground: 215 16% 47%;
    --accent: 226 24% 14%;
    --accent-foreground: 213 31% 91%;
    --destructive: 0 63% 31%;
    --destructive-foreground: 0 84% 80%;
    --ring: 239 84% 67%;
    --radius: 0.5rem;
  }

  * {
    @apply border-border;
  }

  body {
    @apply bg-background text-foreground font-sans;
  }
}
```

- [ ] **Step 2: Создать src/lib/utils.js**

```js
import { clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs) {
  return twMerge(clsx(inputs))
}
```

- [ ] **Step 3: Создать src/composables/useTheme.js**

```js
import { ref, watchEffect } from 'vue'

const isDark = ref(
  localStorage.getItem('theme') === 'dark' ||
  (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)
)

watchEffect(() => {
  const html = document.documentElement
  if (isDark.value) {
    html.classList.add('dark')
    localStorage.setItem('theme', 'dark')
  } else {
    html.classList.remove('dark')
    localStorage.setItem('theme', 'light')
  }
})

export function useTheme() {
  function toggle() {
    isDark.value = !isDark.value
  }
  return { isDark, toggle }
}
```

- [ ] **Step 4: Commit**

```bash
git add frontend/src/style.css frontend/src/lib/utils.js frontend/src/composables/useTheme.js
git commit -m "feat: add tailwind css vars, dark/light theme composable"
```

---

## Task 3: Базовые UI компоненты (shadcn-вручную)

Вместо CLI shadcn-vue добавляем нужные компоненты вручную — это надёжнее при кастомных конфигурациях.

**Files:**
- Create: `frontend/src/components/ui/Button.vue`
- Create: `frontend/src/components/ui/Badge.vue`
- Create: `frontend/src/components/ui/Input.vue`
- Create: `frontend/src/components/ui/Dialog.vue`
- Create: `frontend/src/components/ui/DropdownMenu.vue`
- Create: `frontend/src/components/ui/Toast.vue`

- [ ] **Step 1: Создать Button.vue**

```vue
<!-- frontend/src/components/ui/Button.vue -->
<script setup>
import { cn } from '@/lib/utils'

const props = defineProps({
  variant: { type: String, default: 'default' },
  size: { type: String, default: 'default' },
  class: { type: String, default: '' },
})

const variants = {
  default: 'bg-primary text-primary-foreground hover:bg-primary/90',
  destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
  outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
  ghost: 'hover:bg-accent hover:text-accent-foreground',
  warning: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 hover:bg-yellow-500/20',
  success: 'bg-green-500/10 text-green-600 dark:text-green-400 hover:bg-green-500/20',
  info: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 hover:bg-blue-500/20',
}

const sizes = {
  default: 'h-9 px-4 py-2',
  sm: 'h-7 px-3 text-xs',
  lg: 'h-11 px-8',
  icon: 'h-9 w-9',
}
</script>

<template>
  <button
    :class="cn(
      'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
      variants[variant],
      sizes[size],
      props.class
    )"
    v-bind="$attrs"
  >
    <slot />
  </button>
</template>
```

- [ ] **Step 2: Создать Badge.vue**

```vue
<!-- frontend/src/components/ui/Badge.vue -->
<script setup>
import { cn } from '@/lib/utils'

const props = defineProps({
  variant: { type: String, default: 'default' },
  class: { type: String, default: '' },
})

const variants = {
  default: 'bg-primary/10 text-primary',
  active: 'bg-green-500/15 text-green-600 dark:text-green-400',
  revoked: 'bg-red-500/15 text-red-600 dark:text-red-400',
  expired: 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400',
}
</script>

<template>
  <span :class="cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold', variants[variant] || variants.default, props.class)">
    <slot />
  </span>
</template>
```

- [ ] **Step 3: Создать Input.vue**

```vue
<!-- frontend/src/components/ui/Input.vue -->
<script setup>
import { cn } from '@/lib/utils'
defineProps({ class: { type: String, default: '' } })
</script>

<template>
  <input
    :class="cn('flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50', $props.class)"
    v-bind="$attrs"
  />
</template>
```

- [ ] **Step 4: Создать Dialog.vue**

```vue
<!-- frontend/src/components/ui/Dialog.vue -->
<script setup>
defineProps({ open: Boolean, title: String, description: String })
defineEmits(['close'])
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center">
        <!-- Backdrop -->
        <div class="fixed inset-0 bg-black/60" @click="$emit('close')" />
        <!-- Panel -->
        <div class="relative z-50 w-full max-w-lg mx-4 bg-card text-card-foreground rounded-lg shadow-2xl border border-border">
          <div class="flex flex-col space-y-1.5 p-6 border-b border-border">
            <h2 class="text-lg font-semibold leading-none">{{ title }}</h2>
            <p v-if="description" class="text-sm text-muted-foreground">{{ description }}</p>
          </div>
          <div class="p-6">
            <slot />
          </div>
          <div v-if="$slots.footer" class="flex justify-end gap-2 px-6 pb-6">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.dialog-enter-active, .dialog-leave-active { transition: opacity 0.2s; }
.dialog-enter-from, .dialog-leave-to { opacity: 0; }
</style>
```

- [ ] **Step 5: Создать DropdownMenu.vue**

```vue
<!-- frontend/src/components/ui/DropdownMenu.vue -->
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const open = ref(false)
const menuRef = ref(null)

function close(e) {
  if (menuRef.value && !menuRef.value.contains(e.target)) open.value = false
}

onMounted(() => document.addEventListener('click', close))
onUnmounted(() => document.removeEventListener('click', close))
</script>

<template>
  <div ref="menuRef" class="relative inline-block">
    <div @click.stop="open = !open">
      <slot name="trigger" />
    </div>
    <Transition name="dropdown">
      <div
        v-if="open"
        class="absolute right-0 top-full mt-1 z-50 min-w-[160px] overflow-hidden rounded-md border border-border bg-card shadow-lg"
        @click="open = false"
      >
        <slot />
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.dropdown-enter-active, .dropdown-leave-active { transition: opacity 0.1s, transform 0.1s; }
.dropdown-enter-from, .dropdown-leave-to { opacity: 0; transform: translateY(-4px); }
</style>
```

- [ ] **Step 6: Создать Toast.vue (провайдер уведомлений)**

```vue
<!-- frontend/src/components/ui/Toast.vue -->
<script setup>
import { ref } from 'vue'

const toasts = ref([])
let id = 0

export function useToast() {
  function toast({ title, description, variant = 'default' }) {
    const toast = { id: ++id, title, description, variant }
    toasts.value.push(toast)
    setTimeout(() => { toasts.value = toasts.value.filter(t => t.id !== toast.id) }, 4000)
  }
  return { toast }
}
</script>

<template>
  <Teleport to="body">
    <div class="fixed bottom-4 left-4 z-50 flex flex-col gap-2 max-w-sm">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          :class="[
            'rounded-lg border px-4 py-3 shadow-lg text-sm',
            t.variant === 'destructive'
              ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400'
              : t.variant === 'success'
              ? 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400'
              : 'border-border bg-card text-card-foreground'
          ]"
        >
          <div class="font-medium">{{ t.title }}</div>
          <div v-if="t.description" class="text-muted-foreground mt-0.5">{{ t.description }}</div>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active, .toast-leave-active { transition: all 0.3s; }
.toast-enter-from { opacity: 0; transform: translateX(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-20px); }
</style>
```

- [ ] **Step 7: Commit**

```bash
git add frontend/src/components/ui/
git commit -m "feat: add base UI components (Button, Badge, Input, Dialog, DropdownMenu, Toast)"
```

---

## Task 4: api.js — все API вызовы

**Files:**
- Create: `frontend/src/api.js`

- [ ] **Step 1: Создать src/api.js**

```js
import axios from 'axios'

function formData(obj) {
  const d = new URLSearchParams()
  Object.entries(obj).forEach(([k, v]) => d.append(k, v))
  return d
}

export async function fetchUsers() {
  const { data } = await axios.get('api/users/list')
  return Array.isArray(data) ? data : []
}

export async function fetchServerSettings() {
  const { data } = await axios.get('api/server/settings')
  return data // { serverRole, modules }
}

export async function fetchLastSync() {
  const { data } = await axios.get('api/sync/last/successful')
  return data
}

export async function createUser(username, password) {
  const { data } = await axios.post('api/user/create', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function revokeUser(username) {
  const { data } = await axios.post('api/user/revoke', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function unrevokeUser(username) {
  const { data } = await axios.post('api/user/unrevoke', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function rotateUser(username, password) {
  const { data } = await axios.post('api/user/rotate', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function deleteUser(username) {
  const { data } = await axios.post('api/user/delete', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function changePassword(username, password) {
  const { data } = await axios.post('api/user/change-password', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function fetchUserConfig(username) {
  const { data } = await axios.post('api/user/config/show', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function fetchUserCcd(username) {
  const { data } = await axios.post('api/user/ccd', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data // { Name, ClientAddress, CustomRoutes }
}

export async function applyCcd(ccd) {
  const { data } = await axios.post('api/user/ccd/apply', JSON.stringify(ccd), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/api.js
git commit -m "feat: extract all API calls to api.js"
```

---

## Task 5: AppHeader.vue

**Files:**
- Create: `frontend/src/components/AppHeader.vue`

- [ ] **Step 1: Создать AppHeader.vue**

```vue
<!-- frontend/src/components/AppHeader.vue -->
<script setup>
import { useTheme } from '@/composables/useTheme'
import Button from '@/components/ui/Button.vue'

defineProps({
  serverRole: { type: String, default: 'master' },
  lastSync: { type: String, default: '' },
})

defineEmits(['add-user'])

const { isDark, toggle } = useTheme()
</script>

<template>
  <header class="sticky top-0 z-40 h-13 border-b border-border bg-card flex items-center justify-between px-6">
    <div class="flex items-center gap-3">
      <div class="w-7 h-7 rounded-lg bg-primary flex items-center justify-center text-white font-bold text-sm">
        ⬡
      </div>
      <span class="font-bold text-base tracking-tight">OVPN Admin</span>
    </div>

    <div class="flex items-center gap-3">
      <!-- Slave: показываем дату синхронизации -->
      <span v-if="serverRole === 'slave'" class="text-xs text-muted-foreground">
        Синхронизация: {{ lastSync || 'неизвестно' }}
      </span>

      <!-- Theme toggle -->
      <button
        @click="toggle"
        class="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-accent transition-colors"
      >
        {{ isDark ? '☀️ Светлая' : '🌙 Тёмная' }}
      </button>

      <!-- Add user (только master) -->
      <Button v-if="serverRole === 'master'" @click="$emit('add-user')">
        + Добавить пользователя
      </Button>
    </div>
  </header>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/AppHeader.vue
git commit -m "feat: add AppHeader component with theme toggle and slave sync info"
```

---

## Task 6: StatCards.vue

**Files:**
- Create: `frontend/src/components/StatCards.vue`

- [ ] **Step 1: Создать StatCards.vue**

```vue
<!-- frontend/src/components/StatCards.vue -->
<script setup>
import { computed } from 'vue'

const props = defineProps({
  users: { type: Array, default: () => [] },
})

const stats = computed(() => {
  const total = props.users.length
  const active = props.users.filter(u => u.AccountStatus === 'Active').length
  const connected = props.users.filter(u => u.ConnectionStatus === 'Connected').length
  const revoked = props.users.filter(u => u.AccountStatus === 'Revoked').length
  return [
    { label: 'Всего', value: total, color: 'border-primary text-primary' },
    { label: 'Активных', value: active, color: 'border-green-500 text-green-500' },
    { label: 'Подключено', value: connected, color: 'border-yellow-500 text-yellow-500' },
    { label: 'Отозвано', value: revoked, color: 'border-red-500 text-red-500' },
  ]
})
</script>

<template>
  <div class="grid grid-cols-4 gap-3">
    <div
      v-for="stat in stats"
      :key="stat.label"
      :class="['bg-card border border-border border-l-4 rounded-xl p-4', stat.color]"
    >
      <p class="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1">{{ stat.label }}</p>
      <p class="text-3xl font-bold" :class="stat.color.split(' ')[1]">{{ stat.value }}</p>
    </div>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/StatCards.vue
git commit -m "feat: add StatCards component"
```

---

## Task 7: ActionsMenu.vue

**Files:**
- Create: `frontend/src/components/ActionsMenu.vue`

- [ ] **Step 1: Создать ActionsMenu.vue**

Логика видимости кнопок — из оригинального `main.js`:
- `serverRole`: master/slave
- `modulesEnabled`: массив строк ("core", "ccd", "passwdAuth")
- `AccountStatus`: "Active" | "Revoked" | "Expired"

```vue
<!-- frontend/src/components/ActionsMenu.vue -->
<script setup>
import DropdownMenu from '@/components/ui/DropdownMenu.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  user: { type: Object, required: true },
  serverRole: { type: String, default: 'master' },
  modulesEnabled: { type: Array, default: () => [] },
})

const emit = defineEmits([
  'revoke', 'unrevoke', 'rotate', 'delete',
  'download-config', 'edit-ccd', 'change-password'
])

const isMaster = () => props.serverRole === 'master'
const hasModule = (m) => props.modulesEnabled.includes(m)

const isActive  = () => props.user.AccountStatus === 'Active'
const isRevoked = () => props.user.AccountStatus === 'Revoked'
const isExpired = () => props.user.AccountStatus === 'Expired'
</script>

<template>
  <div class="flex items-center gap-2">
    <!-- Главная кнопка -->
    <Button
      v-if="isActive()"
      size="sm"
      variant="info"
      @click="emit('download-config', user.Identity)"
    >
      ⬇ Конфиг
    </Button>
    <Button
      v-else-if="isRevoked() && isMaster()"
      size="sm"
      variant="success"
      @click="emit('unrevoke', user.Identity)"
    >
      ✓ Восстановить
    </Button>

    <!-- Меню ··· -->
    <DropdownMenu v-if="isMaster() || (isActive() && hasModule('ccd'))">
      <template #trigger>
        <button class="h-8 w-8 flex items-center justify-center rounded-md border border-border text-muted-foreground hover:border-primary hover:text-primary hover:bg-accent transition-colors text-lg font-bold tracking-tighter pb-0.5">
          ···
        </button>
      </template>

      <!-- Active user menu -->
      <template v-if="isActive()">
        <button
          v-if="isMaster() && hasModule('core')"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-yellow-600 dark:text-yellow-400 hover:bg-accent cursor-pointer"
          @click="emit('revoke', user.Identity)"
        >
          ⚠ Отозвать
        </button>
        <button
          v-if="hasModule('ccd')"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-violet-600 dark:text-violet-400 hover:bg-accent cursor-pointer"
          @click="emit('edit-ccd', user.Identity)"
        >
          ⇄ {{ serverRole === 'master' ? 'Маршруты' : 'Показать маршруты' }}
        </button>
        <button
          v-if="isMaster() && hasModule('passwdAuth')"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-blue-600 dark:text-blue-400 hover:bg-accent cursor-pointer"
          @click="emit('change-password', user.Identity)"
        >
          🔑 Сменить пароль
        </button>
      </template>

      <!-- Revoked / Expired menu -->
      <template v-if="isRevoked() || isExpired()">
        <button
          v-if="hasModule('core')"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-orange-600 dark:text-orange-400 hover:bg-accent cursor-pointer"
          @click="emit('rotate', user.Identity)"
        >
          ↻ Ротация
        </button>
        <div class="h-px bg-border mx-2" />
        <button
          v-if="hasModule('core')"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-accent cursor-pointer"
          @click="emit('delete', user.Identity)"
        >
          ✕ Удалить
        </button>
      </template>
    </DropdownMenu>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/ActionsMenu.vue
git commit -m "feat: add ActionsMenu with main button + dropdown, respects serverRole and modules"
```

---

## Task 8: UsersTable.vue

**Files:**
- Create: `frontend/src/components/UsersTable.vue`

- [ ] **Step 1: Создать UsersTable.vue**

```vue
<!-- frontend/src/components/UsersTable.vue -->
<script setup>
import { ref, computed } from 'vue'
import Badge from '@/components/ui/Badge.vue'
import ActionsMenu from '@/components/ActionsMenu.vue'

const props = defineProps({
  users: { type: Array, default: () => [] },
  serverRole: { type: String, default: 'master' },
  modulesEnabled: { type: Array, default: () => [] },
})

const emit = defineEmits([
  'revoke', 'unrevoke', 'rotate', 'delete',
  'download-config', 'edit-ccd', 'change-password'
])

const search = ref('')
const hideRevoked = ref(
  localStorage.getItem('hideRevoked') === 'true'
)

function toggleHideRevoked() {
  hideRevoked.value = !hideRevoked.value
  localStorage.setItem('hideRevoked', hideRevoked.value)
}

const filteredUsers = computed(() => {
  let list = props.users
  if (hideRevoked.value) {
    list = list.filter(u => u.AccountStatus === 'Active')
  }
  if (search.value.trim()) {
    const q = search.value.toLowerCase()
    list = list.filter(u => u.Identity.toLowerCase().includes(q))
  }
  return list
})

function rowClass(user) {
  if (user.ConnectionStatus === 'Connected') return 'bg-green-500/5 dark:bg-green-500/5'
  if (user.AccountStatus === 'Revoked') return 'opacity-60'
  if (user.AccountStatus === 'Expired') return 'bg-yellow-500/5 dark:bg-yellow-500/5'
  return ''
}

function badgeVariant(status) {
  if (status === 'Active') return 'active'
  if (status === 'Revoked') return 'revoked'
  return 'expired'
}

function badgeLabel(status) {
  if (status === 'Active') return 'Активен'
  if (status === 'Revoked') return 'Отозван'
  return 'Истёк'
}
</script>

<template>
  <div>
    <!-- Toolbar -->
    <div class="flex justify-end gap-2 mb-3">
      <input
        v-model="search"
        placeholder="🔍  Поиск пользователей..."
        class="h-9 w-52 rounded-md border border-input bg-background px-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
      />
      <button
        @click="toggleHideRevoked"
        :class="[
          'h-9 rounded-md border px-3 text-sm font-medium transition-colors',
          hideRevoked
            ? 'border-primary bg-primary/10 text-primary'
            : 'border-border bg-background text-muted-foreground hover:bg-accent'
        ]"
      >
        {{ hideRevoked ? 'Показать отозванных' : 'Скрыть отозванных' }}
      </button>
    </div>

    <!-- Table -->
    <div class="rounded-xl border border-border bg-card overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/50">
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground w-10">#</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Имя</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Статус</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Подключений</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Дата истечения</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Дата отзыва</th>
            <th class="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-muted-foreground">Действия</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-if="filteredUsers.length === 0"
            class="border-b border-border"
          >
            <td colspan="7" class="px-4 py-10 text-center text-muted-foreground">
              Пользователи не найдены
            </td>
          </tr>
          <tr
            v-for="(user, index) in filteredUsers"
            :key="user.Identity"
            :class="['border-b border-border last:border-0 transition-colors hover:bg-muted/30', rowClass(user)]"
          >
            <td class="px-4 py-3 text-muted-foreground">{{ index + 1 }}</td>
            <td class="px-4 py-3 font-semibold">
              {{ user.Identity }}
              <span
                v-if="user.ConnectionStatus === 'Connected'"
                class="inline-block w-2 h-2 rounded-full bg-green-500 ml-1.5 shadow-[0_0_6px_theme(colors.green.500)]"
              />
            </td>
            <td class="px-4 py-3">
              <Badge :variant="badgeVariant(user.AccountStatus)">
                {{ badgeLabel(user.AccountStatus) }}
              </Badge>
            </td>
            <td class="px-4 py-3 text-muted-foreground">{{ user.Connections || 0 }}</td>
            <td class="px-4 py-3 text-muted-foreground">{{ user.ExpirationDate || '—' }}</td>
            <td class="px-4 py-3 text-muted-foreground">{{ user.RevocationDate || '—' }}</td>
            <td class="px-4 py-3">
              <ActionsMenu
                :user="user"
                :server-role="serverRole"
                :modules-enabled="modulesEnabled"
                @revoke="emit('revoke', $event)"
                @unrevoke="emit('unrevoke', $event)"
                @rotate="emit('rotate', $event)"
                @delete="emit('delete', $event)"
                @download-config="emit('download-config', $event)"
                @edit-ccd="emit('edit-ccd', $event)"
                @change-password="emit('change-password', $event)"
              />
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Legend -->
    <div class="flex justify-center gap-4 mt-3 text-xs text-muted-foreground">
      <span>🟢 Подключён</span>
      <span>⚪ Активен</span>
      <span>🔴 Отозван</span>
      <span>🟡 Истёк</span>
    </div>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/components/UsersTable.vue
git commit -m "feat: add UsersTable with search, filter, row highlighting"
```

---

## Task 9: Модальные окна

**Files:**
- Create: `frontend/src/components/modals/AddUserModal.vue`
- Create: `frontend/src/components/modals/DeleteUserModal.vue`
- Create: `frontend/src/components/modals/RotateUserModal.vue`
- Create: `frontend/src/components/modals/ChangePasswordModal.vue`
- Create: `frontend/src/components/modals/CcdModal.vue`

- [ ] **Step 1: Создать AddUserModal.vue**

```vue
<!-- frontend/src/components/modals/AddUserModal.vue -->
<script setup>
import { ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  modulesEnabled: { type: Array, default: () => [] },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])

const username = ref('')
const password = ref('')

function submit() {
  emit('submit', { username: username.value, password: password.value })
}

function onClose() {
  username.value = ''
  password.value = ''
  emit('close')
}
</script>

<template>
  <Dialog :open="open" title="Добавить пользователя" @close="onClose">
    <div class="space-y-3">
      <Input v-model="username" placeholder="Имя пользователя" autocomplete="off" />
      <Input
        v-if="modulesEnabled.includes('passwdAuth')"
        v-model="password"
        type="password"
        placeholder="Пароль"
        autocomplete="new-password"
        minlength="6"
      />
      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Отмена</Button>
      <Button @click="submit">Создать</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 2: Создать DeleteUserModal.vue**

```vue
<!-- frontend/src/components/modals/DeleteUserModal.vue -->
<script setup>
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])
</script>

<template>
  <Dialog
    :open="open"
    :title="`Удалить пользователя ${username}?`"
    description="Это действие необратимо. Сертификат пользователя будет удалён безвозвратно."
    @close="$emit('close')"
  >
    <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
      {{ error }}
    </div>
    <template #footer>
      <Button variant="ghost" @click="$emit('close')">Отмена</Button>
      <Button variant="destructive" @click="$emit('submit', username)">Удалить</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 3: Создать RotateUserModal.vue**

```vue
<!-- frontend/src/components/modals/RotateUserModal.vue -->
<script setup>
import { ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  modulesEnabled: { type: Array, default: () => [] },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])
const password = ref('')

function submit() {
  emit('submit', { username: props.username, password: password.value })
}

function onClose() {
  password.value = ''
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
    :title="`Ротация сертификатов: ${username}`"
    description="Будет сгенерирован новый сертификат."
    @close="onClose"
  >
    <div class="space-y-3">
      <Input
        v-if="modulesEnabled.includes('passwdAuth')"
        v-model="password"
        type="password"
        placeholder="Новый пароль"
        autocomplete="new-password"
        minlength="6"
      />
      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Отмена</Button>
      <Button variant="destructive" @click="submit">Ротация</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 4: Создать ChangePasswordModal.vue**

```vue
<!-- frontend/src/components/modals/ChangePasswordModal.vue -->
<script setup>
import { ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])
const password = ref('')

function submit() {
  emit('submit', { username: props.username, password: password.value })
}

function onClose() {
  password.value = ''
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
    :title="`Сменить пароль: ${username}`"
    @close="onClose"
  >
    <Input
      v-model="password"
      type="password"
      placeholder="Новый пароль"
      autocomplete="new-password"
      minlength="6"
    />
    <div v-if="error" class="mt-3 rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
      {{ error }}
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Отмена</Button>
      <Button @click="submit">Сохранить</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 5: Создать CcdModal.vue**

```vue
<!-- frontend/src/components/modals/CcdModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  serverRole: { type: String, default: 'master' },
  ccd: { type: Object, default: () => ({ Name: '', ClientAddress: '', CustomRoutes: [] }) },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])

const localCcd = ref({ ...props.ccd, CustomRoutes: [...(props.ccd?.CustomRoutes || [])] })
const newRoute = ref({ Address: '', Mask: '', Description: '' })

watch(() => props.ccd, (val) => {
  localCcd.value = { ...val, CustomRoutes: [...(val?.CustomRoutes || [])] }
}, { deep: true })

const isMaster = () => props.serverRole === 'master'
const isDynamic = () => localCcd.value.ClientAddress === 'dynamic'

function addRoute() {
  if (!newRoute.value.Address) return
  localCcd.value.CustomRoutes.push({ ...newRoute.value })
  newRoute.value = { Address: '', Mask: '', Description: '' }
}

function removeRoute(index) {
  localCcd.value.CustomRoutes.splice(index, 1)
}

function onClose() {
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
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
          class="flex-1"
        />
        <Button
          v-if="isMaster()"
          size="sm"
          variant="warning"
          :disabled="isDynamic()"
          @click="localCcd.ClientAddress = 'dynamic'"
        >
          Сбросить
        </Button>
      </div>

      <!-- Routes table -->
      <div class="rounded-md border border-border overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/50">
            <tr>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Адрес</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Маска</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Описание</th>
              <th v-if="isMaster()" class="px-3 py-2 w-20" />
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(route, i) in localCcd.CustomRoutes"
              :key="i"
              class="border-t border-border"
            >
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Address" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Address }}</span>
              </td>
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Mask" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Mask }}</span>
              </td>
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Description" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Description }}</span>
              </td>
              <td v-if="isMaster()" class="px-3 py-2 text-right">
                <Button size="sm" variant="destructive" @click="removeRoute(i)">✕</Button>
              </td>
            </tr>
            <!-- Add row (только master) -->
            <tr v-if="isMaster()" class="border-t border-border bg-muted/20">
              <td class="px-3 py-2"><Input v-model="newRoute.Address" placeholder="10.0.0.0" class="h-7 text-xs" /></td>
              <td class="px-3 py-2"><Input v-model="newRoute.Mask" placeholder="255.255.255.0" class="h-7 text-xs" /></td>
              <td class="px-3 py-2"><Input v-model="newRoute.Description" placeholder="Описание" class="h-7 text-xs" /></td>
              <td class="px-3 py-2 text-right"><Button size="sm" variant="success" @click="addRoute">+ Добавить</Button></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Закрыть</Button>
      <Button v-if="isMaster()" @click="$emit('submit', localCcd)">Сохранить</Button>
    </template>
  </Dialog>
</template>
```

- [ ] **Step 6: Commit**

```bash
git add frontend/src/components/modals/
git commit -m "feat: add all modal dialogs (AddUser, Delete, Rotate, ChangePassword, CCD)"
```

---

## Task 10: App.vue — главный компонент

**Files:**
- Create: `frontend/src/App.vue`

- [ ] **Step 1: Создать App.vue**

```vue
<!-- frontend/src/App.vue -->
<script setup>
import { ref, onMounted } from 'vue'
import AppHeader from '@/components/AppHeader.vue'
import StatCards from '@/components/StatCards.vue'
import UsersTable from '@/components/UsersTable.vue'
import Toast from '@/components/ui/Toast.vue'
import AddUserModal from '@/components/modals/AddUserModal.vue'
import DeleteUserModal from '@/components/modals/DeleteUserModal.vue'
import RotateUserModal from '@/components/modals/RotateUserModal.vue'
import ChangePasswordModal from '@/components/modals/ChangePasswordModal.vue'
import CcdModal from '@/components/modals/CcdModal.vue'

import {
  fetchUsers, fetchServerSettings, fetchLastSync,
  createUser, revokeUser, unrevokeUser, rotateUser, deleteUser,
  changePassword, fetchUserConfig, fetchUserCcd, applyCcd
} from '@/api.js'

// ── State ──────────────────────────────────────────────────────────
const users = ref([])
const serverRole = ref('master')
const modulesEnabled = ref([])
const lastSync = ref('')

// Toast (simple reactive store)
const toasts = ref([])
let toastId = 0
function notify(title, variant = 'default') {
  const id = ++toastId
  toasts.value.push({ id, title, variant })
  setTimeout(() => { toasts.value = toasts.value.filter(t => t.id !== id) }, 4000)
}

// ── Modal state ────────────────────────────────────────────────────
const activeUser = ref('')

const modals = ref({
  addUser: false,
  deleteUser: false,
  rotateUser: false,
  changePassword: false,
  ccd: false,
})

const modalErrors = ref({
  addUser: '',
  deleteUser: '',
  rotateUser: '',
  changePassword: '',
  ccd: '',
})

const ccdData = ref({ Name: '', ClientAddress: '', CustomRoutes: [] })

function openModal(name, username = '') {
  activeUser.value = username
  Object.keys(modalErrors.value).forEach(k => modalErrors.value[k] = '')
  modals.value[name] = true
}

function closeModal(name) {
  modals.value[name] = false
}

// ── Data loading ───────────────────────────────────────────────────
async function loadUsers() {
  users.value = await fetchUsers()
}

async function loadSettings() {
  const settings = await fetchServerSettings()
  serverRole.value = settings.serverRole
  modulesEnabled.value = settings.modules
  if (settings.serverRole === 'slave') {
    lastSync.value = await fetchLastSync()
  }
}

onMounted(() => {
  loadUsers()
  loadSettings()
})

// ── Actions ────────────────────────────────────────────────────────
async function handleRevoke(username) {
  await revokeUser(username)
  notify(`Пользователь ${username} отозван`, 'default')
  loadUsers()
}

async function handleUnrevoke(username) {
  await unrevokeUser(username)
  notify(`Пользователь ${username} восстановлен`, 'success')
  loadUsers()
}

async function handleDownloadConfig(username) {
  const config = await fetchUserConfig(username)
  const blob = new Blob([config], { type: 'text/plain' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = `${username}.ovpn`
  link.click()
  URL.revokeObjectURL(link.href)
}

async function handleEditCcd(username) {
  ccdData.value = await fetchUserCcd(username)
  openModal('ccd', username)
}

// ── Modal submit handlers ──────────────────────────────────────────
async function submitAddUser({ username, password }) {
  try {
    await createUser(username, password)
    notify(`Пользователь ${username} создан`, 'success')
    closeModal('addUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.addUser = e.response?.data || 'Ошибка создания'
  }
}

async function submitDeleteUser(username) {
  try {
    await deleteUser(username)
    notify(`Пользователь ${username} удалён`, 'default')
    closeModal('deleteUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.deleteUser = e.response?.data?.message || 'Ошибка удаления'
  }
}

async function submitRotateUser({ username, password }) {
  try {
    await rotateUser(username, password)
    notify(`Сертификаты ${username} обновлены`, 'success')
    closeModal('rotateUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.rotateUser = e.response?.data?.message || 'Ошибка ротации'
  }
}

async function submitChangePassword({ username, password }) {
  try {
    await changePassword(username, password)
    notify(`Пароль ${username} изменён`, 'success')
    closeModal('changePassword')
    loadUsers()
  } catch (e) {
    modalErrors.value.changePassword = e.response?.data?.message || 'Ошибка смены пароля'
  }
}

async function submitCcd(ccd) {
  try {
    await applyCcd(ccd)
    notify(`Маршруты для ${activeUser.value} сохранены`, 'success')
    closeModal('ccd')
  } catch (e) {
    modalErrors.value.ccd = e.response?.data || 'Ошибка сохранения маршрутов'
  }
}
</script>

<template>
  <div class="min-h-screen bg-background">
    <AppHeader
      :server-role="serverRole"
      :last-sync="lastSync"
      @add-user="openModal('addUser')"
    />

    <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Обзор</p>
        <StatCards :users="users" />
      </div>

      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Пользователи</p>
        <UsersTable
          :users="users"
          :server-role="serverRole"
          :modules-enabled="modulesEnabled"
          @revoke="handleRevoke"
          @unrevoke="handleUnrevoke"
          @rotate="(u) => openModal('rotateUser', u)"
          @delete="(u) => openModal('deleteUser', u)"
          @download-config="handleDownloadConfig"
          @edit-ccd="handleEditCcd"
          @change-password="(u) => openModal('changePassword', u)"
        />
      </div>
    </main>

    <!-- Modals -->
    <AddUserModal
      :open="modals.addUser"
      :modules-enabled="modulesEnabled"
      :error="modalErrors.addUser"
      @close="closeModal('addUser')"
      @submit="submitAddUser"
    />
    <DeleteUserModal
      :open="modals.deleteUser"
      :username="activeUser"
      :error="modalErrors.deleteUser"
      @close="closeModal('deleteUser')"
      @submit="submitDeleteUser"
    />
    <RotateUserModal
      :open="modals.rotateUser"
      :username="activeUser"
      :modules-enabled="modulesEnabled"
      :error="modalErrors.rotateUser"
      @close="closeModal('rotateUser')"
      @submit="submitRotateUser"
    />
    <ChangePasswordModal
      :open="modals.changePassword"
      :username="activeUser"
      :error="modalErrors.changePassword"
      @close="closeModal('changePassword')"
      @submit="submitChangePassword"
    />
    <CcdModal
      :open="modals.ccd"
      :username="activeUser"
      :server-role="serverRole"
      :ccd="ccdData"
      :error="modalErrors.ccd"
      @close="closeModal('ccd')"
      @submit="submitCcd"
    />

    <!-- Toast notifications -->
    <Teleport to="body">
      <div class="fixed bottom-4 left-4 z-50 flex flex-col gap-2 max-w-sm">
        <TransitionGroup name="toast">
          <div
            v-for="t in toasts"
            :key="t.id"
            :class="[
              'rounded-lg border px-4 py-3 shadow-lg text-sm',
              t.variant === 'success'
                ? 'border-green-500/30 bg-green-500/10 text-green-700 dark:text-green-400'
                : 'border-border bg-card text-card-foreground'
            ]"
          >
            {{ t.title }}
          </div>
        </TransitionGroup>
      </div>
    </Teleport>
  </div>
</template>

<style>
.toast-enter-active, .toast-leave-active { transition: all 0.3s; }
.toast-enter-from { opacity: 0; transform: translateX(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-20px); }
</style>
```

- [ ] **Step 2: Commit**

```bash
git add frontend/src/App.vue
git commit -m "feat: add App.vue — root component wiring all state and modals"
```

---

## Task 11: main.js + финальная сборка

**Files:**
- Create: `frontend/src/main.js`

- [ ] **Step 1: Создать src/main.js**

```js
import { createApp } from 'vue'
import App from './App.vue'
import './style.css'

createApp(App).mount('#app')
```

- [ ] **Step 2: Проверить dev-сборку**

```bash
cd frontend && npm run dev
```

Ожидаемый результат: Vite запустился на `http://localhost:5173`, нет ошибок компиляции.

Если есть ошибки — исправить их до следующего шага.

- [ ] **Step 3: Собрать продакшн-сборку**

```bash
cd frontend && npm run build
```

Ожидаемый результат:
```
✓ built in Xs
dist/index.html   X kB
dist/assets/...   X kB
```

Файлы появятся в `frontend/static/`.

- [ ] **Step 4: Проверить что Go-сервер раздаёт новый frontend**

Запустить ovpn-admin (или использовать тестовый Go-сервер), открыть `http://localhost:8080`.
Убедиться что отображается новый UI, а не старый.

- [ ] **Step 5: Удалить старые файлы Webpack**

```bash
cd frontend && rm -f webpack.config.js build.sh src/style.js
```

- [ ] **Step 6: Обновить .gitignore (если нужно)**

Добавить в корневой `.gitignore`:
```
frontend/node_modules/
frontend/static/assets/
.superpowers/
```

- [ ] **Step 7: Финальный коммит**

```bash
git add frontend/src/main.js
git rm frontend/webpack.config.js frontend/build.sh frontend/src/style.js 2>/dev/null || true
git add -u
git commit -m "feat: complete frontend redesign — Vue3 + shadcn-vue + Tailwind, dark/light theme, Russian UI"
```

---

## Чеклист проверки перед завершением

- [ ] `npm run build` выполняется без ошибок
- [ ] Тёмная тема работает, свитчер переключает
- [ ] Таблица загружает данные с `api/users/list`
- [ ] Строки красятся по статусу (зелёная/серая/жёлтая)
- [ ] Кнопки Конфиг / Восстановить + меню `···` работают
- [ ] Все 5 модальных окон открываются и закрываются
- [ ] Создание пользователя работает
- [ ] Удаление пользователя работает
- [ ] Slave-режим: показывает дату синхронизации, скрывает кнопку Add user
- [ ] Уведомления появляются внизу слева
