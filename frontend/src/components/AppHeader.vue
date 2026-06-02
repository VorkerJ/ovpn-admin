<!-- frontend/src/components/AppHeader.vue -->
<script setup>
import { useTheme } from '@/composables/useTheme'
import Button from '@/components/ui/Button.vue'
import { Sun, Moon, Plus, LogOut, ShieldCheck } from 'lucide-vue-next'

defineProps({
  // serverInitialized=false блокирует кнопку «Добавить пользователя» (бэкенд
  // вернёт 412 — лучше не давать кликнуть и показать tooltip).
  serverInitialized: { type: Boolean, default: true },
  // adminMfaEnabled=false блокирует все write-операции на бэкенде.
  // Default true: старые билды без MFA-фичи не должны ломаться.
  adminMfaEnabled: { type: Boolean, default: true },
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
          <ShieldCheck
            :size="16"
            class="text-primary-foreground"
          />
        </div>
        <span class="font-semibold text-[15px] tracking-tight">OVPN Admin</span>
      </div>

      <!-- Actions -->
      <div class="flex items-center gap-1.5">
        <Button
          variant="ghost"
          size="icon-sm"
          :title="isDark ? 'Светлая тема' : 'Тёмная тема'"
          @click="toggle"
        >
          <Sun
            v-if="isDark"
            :size="16"
          />
          <Moon
            v-else
            :size="16"
          />
        </Button>

        <Button
          variant="ghost"
          size="icon-sm"
          :title="adminMfaEnabled ? 'Двухфакторная аутентификация' : 'Включите 2FA — без неё write-операции запрещены'"
          class="relative"
          @click="$emit('open-mfa')"
        >
          <ShieldCheck
            :size="16"
            :class="adminMfaEnabled ? '' : 'text-orange-500'"
          />
          <!-- Orange pulsing dot draws the eye when MFA is off and write ops are blocked. -->
          <span
            v-if="!adminMfaEnabled"
            class="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-orange-500 ring-2 ring-background animate-pulse"
            data-testid="admin-mfa-dot"
          />
        </Button>

        <Button
          size="sm"
          data-testid="add-user-button"
          :disabled="!serverInitialized || !adminMfaEnabled"
          :title="!adminMfaEnabled
            ? 'Включите 2FA в правом верхнем углу'
            : (!serverInitialized ? 'Сначала настройте сервер во вкладке «Сервер»' : 'Создать пользователя')"
          @click="$emit('add-user')"
        >
          <Plus :size="14" />
          Добавить пользователя
        </Button>

        <Button
          variant="ghost"
          size="icon-sm"
          title="Выйти"
          @click="$emit('logout')"
        >
          <LogOut :size="16" />
        </Button>
      </div>
    </div>
  </header>
</template>
