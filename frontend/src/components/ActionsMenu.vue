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
      variant="outline"
      @click="emit('unrevoke', user.Identity)"
    >
      ↩ Восстановить
    </Button>

    <!-- Меню ··· -->
    <DropdownMenu v-if="isMaster() || (isActive() && hasModule('ccd'))">
      <template #trigger>
        <button type="button" class="h-8 w-8 flex items-center justify-center rounded-md border border-border text-muted-foreground hover:border-primary hover:text-primary hover:bg-accent transition-colors text-lg font-bold tracking-tighter pb-0.5">
          ···
        </button>
      </template>

      <!-- Active user menu -->
      <template v-if="isActive()">
        <button
          v-if="isMaster() && hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-yellow-600 dark:text-yellow-400 hover:bg-accent cursor-pointer"
          @click="emit('revoke', user.Identity)"
        >
          ⚠ Отозвать
        </button>
        <button
          v-if="hasModule('ccd')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-violet-600 dark:text-violet-400 hover:bg-accent cursor-pointer"
          @click="emit('edit-ccd', user.Identity)"
        >
          ⇄ {{ serverRole === 'master' ? 'Маршруты' : 'Показать маршруты' }}
        </button>
        <button
          v-if="isMaster() && hasModule('passwdAuth')"
          type="button"
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
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-orange-600 dark:text-orange-400 hover:bg-accent cursor-pointer"
          @click="emit('rotate', user.Identity)"
        >
          ↻ Ротация
        </button>
        <div class="h-px bg-border mx-2" />
        <button
          v-if="hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-accent cursor-pointer"
          @click="emit('delete', user.Identity)"
        >
          ✕ Удалить
        </button>
      </template>
    </DropdownMenu>
  </div>
</template>
