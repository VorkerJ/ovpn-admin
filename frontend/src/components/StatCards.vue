<!-- frontend/src/components/StatCards.vue -->
<script setup>
import { computed } from 'vue'
import { Users, UserCheck, Activity, UserX } from 'lucide-vue-next'

const props = defineProps({
  users: { type: Array, default: () => [] },
})

const stats = computed(() => {
  const total = props.users.length
  const active = props.users.filter(u => u.AccountStatus === 'Active').length
  const connected = props.users.filter(u => u.ConnectionStatus === 'Connected').length
  const revoked = props.users.filter(u => u.AccountStatus === 'Revoked').length
  return [
    { label: 'Всего',      value: total,     icon: Users,      accent: 'text-foreground',    tint: 'bg-muted' },
    { label: 'Активных',   value: active,    icon: UserCheck,  accent: 'text-green-600 dark:text-green-400',  tint: 'bg-green-500/10' },
    { label: 'Подключено', value: connected, icon: Activity,   accent: 'text-yellow-600 dark:text-yellow-400', tint: 'bg-yellow-500/10' },
    { label: 'Отозвано',   value: revoked,   icon: UserX,      accent: 'text-red-600 dark:text-red-400',    tint: 'bg-red-500/10' },
  ]
})
</script>

<template>
  <div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
    <div
      v-for="stat in stats"
      :key="stat.label"
      class="group relative bg-card border border-border rounded-lg p-4 transition-colors hover:border-foreground/20"
    >
      <div class="flex items-start justify-between mb-3">
        <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground">{{ stat.label }}</p>
        <div :class="['w-8 h-8 rounded-md flex items-center justify-center', stat.tint]">
          <component :is="stat.icon" :size="16" :class="stat.accent" />
        </div>
      </div>
      <p class="font-mono text-3xl font-semibold tabular tracking-tight">{{ stat.value }}</p>
    </div>
  </div>
</template>
