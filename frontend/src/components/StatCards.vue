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
