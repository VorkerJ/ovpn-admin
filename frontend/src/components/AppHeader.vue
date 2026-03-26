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
        type="button"
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
