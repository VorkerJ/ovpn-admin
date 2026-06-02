<!-- frontend/src/components/UsersTable.vue -->
<script setup>
import { ref, computed } from 'vue'
import Badge from '@/components/ui/Badge.vue'
import ActionsMenu from '@/components/ActionsMenu.vue'
import { Search, Eye, EyeOff } from 'lucide-vue-next'

const props = defineProps({
  users: { type: Array, default: () => [] },
  modulesEnabled: { type: Array, default: () => [] },
  // serverInitialized — пробрасывается ниже в ActionsMenu чтобы при необходимости
  // визуально приглушить «Ротация» (бэкенд всё равно вернёт 412).
  serverInitialized: { type: Boolean, default: true },
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
  if (user.ConnectionStatus === 'Connected') return 'bg-green-500/[0.03]'
  if (user.AccountStatus === 'Revoked') return 'opacity-60'
  if (user.AccountStatus === 'Expired') return 'bg-yellow-500/[0.03]'
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
    <div class="flex justify-end items-center gap-2 mb-3">
      <div class="relative">
        <Search :size="14" class="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground pointer-events-none" />
        <input
          v-model="search"
          placeholder="Поиск пользователя…"
          class="h-9 w-60 rounded-md border border-border bg-background pl-9 pr-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring focus:border-ring transition-colors"
        />
      </div>
      <button
        type="button"
        @click="toggleHideRevoked"
        :class="[
          'h-9 inline-flex items-center gap-2 rounded-md border px-3 text-xs font-medium transition-colors',
          hideRevoked
            ? 'border-primary/40 bg-primary/10 text-primary'
            : 'border-border bg-background text-muted-foreground hover:bg-accent hover:text-foreground'
        ]"
      >
        <component :is="hideRevoked ? EyeOff : Eye" :size="14" />
        {{ hideRevoked ? 'Показать отозванных' : 'Скрыть отозванных' }}
      </button>
    </div>

    <!-- Table -->
    <div class="rounded-lg border border-border bg-card overflow-visible">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/40">
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground w-12">#</th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Имя</th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Статус</th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Подключений</th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Дата истечения</th>
            <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">Дата отзыва</th>
            <th class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-muted-foreground">Действия</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="filteredUsers.length === 0">
            <td colspan="7" class="px-4 py-12 text-center text-sm text-muted-foreground">
              Пользователи не найдены
            </td>
          </tr>
          <tr
            v-for="(user, index) in filteredUsers"
            :key="user.Identity"
            :class="['border-b border-border last:border-0 transition-colors hover:bg-muted/30', rowClass(user)]"
          >
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">{{ index + 1 }}</td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-2">
                <span class="font-medium text-[15px]">{{ user.Identity }}</span>
                <span
                  v-if="user.ConnectionStatus === 'Connected'"
                  class="inline-block w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_theme(colors.green.500)]"
                  title="Подключён"
                />
              </div>
            </td>
            <td class="px-4 py-3">
              <Badge :variant="badgeVariant(user.AccountStatus)">
                {{ badgeLabel(user.AccountStatus) }}
              </Badge>
            </td>
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">{{ user.Connections || 0 }}</td>
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">{{ user.ExpirationDate || '—' }}</td>
            <td class="px-4 py-3 text-muted-foreground font-mono text-sm tabular">{{ user.RevocationDate || '—' }}</td>
            <td class="px-4 py-3">
              <div class="flex justify-end">
                <ActionsMenu
                  :user="user"
                  :modules-enabled="modulesEnabled"
                  @revoke="emit('revoke', $event)"
                  @unrevoke="emit('unrevoke', $event)"
                  @rotate="emit('rotate', $event)"
                  @delete="emit('delete', $event)"
                  @download-config="emit('download-config', $event)"
                  @edit-ccd="emit('edit-ccd', $event)"
                  @change-password="emit('change-password', $event)"
                />
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Legend -->
    <div class="flex justify-center gap-6 mt-4 text-xs text-muted-foreground">
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_6px_theme(colors.green.500)]" />Подключён</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-foreground/40" />Активен</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-red-500" />Отозван</span>
      <span class="inline-flex items-center gap-2"><span class="w-2 h-2 rounded-full bg-yellow-500" />Истёк</span>
    </div>
  </div>
</template>
