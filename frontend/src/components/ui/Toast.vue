<!-- frontend/src/components/ui/Toast.vue -->
<script setup>
import { toasts } from '@/composables/useToast'
import { CheckCircle2, AlertCircle, Info } from 'lucide-vue-next'

function iconFor(variant) {
  if (variant === 'success') return CheckCircle2
  if (variant === 'destructive') return AlertCircle
  return Info
}

function accentFor(variant) {
  if (variant === 'success') return 'text-green-600 dark:text-green-400'
  if (variant === 'destructive') return 'text-red-600 dark:text-red-400'
  return 'text-muted-foreground'
}
</script>

<template>
  <Teleport to="body">
    <div class="fixed top-4 right-4 z-[100] flex flex-col gap-2 max-w-sm pointer-events-none">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          class="pointer-events-auto flex items-start gap-3 rounded-lg border border-border bg-card text-card-foreground px-4 py-3 shadow-md text-sm"
        >
          <component :is="iconFor(t.variant)" :size="18" :class="['mt-0.5 shrink-0', accentFor(t.variant)]" />
          <div class="min-w-0">
            <div class="font-medium">{{ t.title }}</div>
            <div v-if="t.description" class="text-muted-foreground mt-0.5">{{ t.description }}</div>
          </div>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active, .toast-leave-active { transition: all 0.3s; }
.toast-enter-from { opacity: 0; transform: translateX(20px); }
.toast-leave-to { opacity: 0; transform: translateX(20px); }
.toast-move { transition: transform 0.3s; }
</style>
