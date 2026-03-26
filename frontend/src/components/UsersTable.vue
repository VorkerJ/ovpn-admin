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
        type="button"
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
    <div class="rounded-xl border border-border bg-card overflow-visible">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-border bg-muted/50 rounded-t-xl">
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
