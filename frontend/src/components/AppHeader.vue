<!-- frontend/src/components/AppHeader.vue -->
<script setup>
import { useTheme } from '@/composables/useTheme'
import Button from '@/components/ui/Button.vue'
import { Sun, Moon, Plus, LogOut, ShieldCheck } from 'lucide-vue-next'

defineProps({
  serverRole: { type: String, default: 'master' },
  lastSync: { type: String, default: '' },
  // serverInitialized=false блокирует кнопку «Добавить пользователя» (бэкенд
  // вернёт 412 — лучше не давать кликнуть и показать tooltip).
  serverInitialized: { type: Boolean, default: true },
})

defineEmits(['add-user', 'logout', 'open-mfa'])

const { isDark, toggle } = useTheme()
</script>

<template>
  <header class="sticky top-0 z-40 border-b border-border bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/75">
    <div class="max-w-7xl mx-auto px-6 h-14 flex items-center justify-between">
      <!-- Brand -->
      <div class="flex items-center gap-2.5">
        <div class="w-7 h-7 rounded-md bg-primary flex items-center justify-center">
          <ShieldCheck :size="16" class="text-primary-foreground" />
        </div>
        <span class="font-semibold text-[15px] tracking-tight">OVPN Admin</span>
        <span
          v-if="serverRole === 'slave'"
          class="ml-2 text-[11px] font-medium text-muted-foreground bg-muted px-2 py-0.5 rounded font-mono"
        >
          slave · sync {{ lastSync || '?' }}
        </span>
      </div>

      <!-- Actions -->
      <div class="flex items-center gap-1.5">
        <Button variant="ghost" size="icon-sm" :title="isDark ? 'Светлая тема' : 'Тёмная тема'" @click="toggle">
          <Sun v-if="isDark" :size="16" />
          <Moon v-else :size="16" />
        </Button>

        <Button variant="ghost" size="icon-sm" title="Двухфакторная аутентификация" @click="$emit('open-mfa')">
          <ShieldCheck :size="16" />
        </Button>

        <Button
          v-if="serverRole === 'master'"
          size="sm"
          :disabled="!serverInitialized"
          :title="serverInitialized ? '' : 'Сначала настройте сервер во вкладке «Сервер»'"
          @click="$emit('add-user')"
        >
          <Plus :size="14" />
          Добавить пользователя
        </Button>

        <Button variant="ghost" size="icon-sm" title="Выйти" @click="$emit('logout')">
          <LogOut :size="16" />
        </Button>
      </div>
    </div>
  </header>
</template>
