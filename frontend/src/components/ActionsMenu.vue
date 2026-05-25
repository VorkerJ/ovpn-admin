<!-- frontend/src/components/ActionsMenu.vue -->
<script setup>
import DropdownMenu from '@/components/ui/DropdownMenu.vue'
import Button from '@/components/ui/Button.vue'
import {
  Download, RotateCcw, MoreHorizontal,
  ShieldOff, RefreshCw, Route, KeyRound, Trash2,
} from 'lucide-vue-next'

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
  <div class="flex items-center gap-1.5">
    <!-- Primary -->
    <Button
      v-if="isActive()"
      size="sm"
      variant="secondary"
      @click="emit('download-config', user.Identity)"
    >
      <Download :size="13" />
      Конфиг
    </Button>
    <Button
      v-else-if="isRevoked() && isMaster()"
      size="sm"
      variant="secondary"
      @click="emit('unrevoke', user.Identity)"
    >
      <RotateCcw :size="13" />
      Восстановить
    </Button>

    <!-- Menu -->
    <DropdownMenu v-if="isMaster() || (isActive() && hasModule('ccd'))">
      <template #trigger>
        <button
          type="button"
          class="h-8 w-8 inline-flex items-center justify-center rounded-md border border-border text-muted-foreground hover:border-foreground/40 hover:text-foreground hover:bg-accent transition-colors"
          title="Действия"
        >
          <MoreHorizontal :size="14" />
        </button>
      </template>

      <!-- Active -->
      <template v-if="isActive()">
        <button
          v-if="isMaster() && hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-yellow-600 dark:text-yellow-400 hover:bg-accent cursor-pointer"
          @click="emit('revoke', user.Identity)"
        >
          <ShieldOff :size="14" /> Отозвать
        </button>
        <button
          v-if="isMaster() && hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-orange-600 dark:text-orange-400 hover:bg-accent cursor-pointer"
          @click="emit('rotate', user.Identity)"
        >
          <RefreshCw :size="14" /> Ротация
        </button>
        <button
          v-if="hasModule('ccd')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-violet-600 dark:text-violet-400 hover:bg-accent cursor-pointer"
          @click="emit('edit-ccd', user.Identity)"
        >
          <Route :size="14" /> {{ serverRole === 'master' ? 'Маршруты' : 'Показать маршруты' }}
        </button>
        <button
          v-if="isMaster() && hasModule('passwdAuth')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-blue-600 dark:text-blue-400 hover:bg-accent cursor-pointer"
          @click="emit('change-password', user.Identity)"
        >
          <KeyRound :size="14" /> Сменить пароль
        </button>
        <div v-if="isMaster()" class="h-px bg-border mx-2 my-1" />
        <button
          v-if="isMaster() && hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-accent cursor-pointer"
          @click="emit('delete', user.Identity)"
        >
          <Trash2 :size="14" /> Удалить
        </button>
      </template>

      <!-- Revoked / Expired -->
      <template v-if="isRevoked() || isExpired()">
        <button
          v-if="hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-orange-600 dark:text-orange-400 hover:bg-accent cursor-pointer"
          @click="emit('rotate', user.Identity)"
        >
          <RefreshCw :size="14" /> Ротация
        </button>
        <div class="h-px bg-border mx-2 my-1" />
        <button
          v-if="hasModule('core')"
          type="button"
          class="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-accent cursor-pointer"
          @click="emit('delete', user.Identity)"
        >
          <Trash2 :size="14" /> Удалить
        </button>
      </template>
    </DropdownMenu>
  </div>
</template>
