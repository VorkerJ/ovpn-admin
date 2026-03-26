<!-- frontend/src/components/ui/Toast.vue -->
<script setup>
import { toasts } from '@/composables/useToast'
</script>

<template>
  <Teleport to="body">
    <div class="fixed bottom-4 left-4 z-50 flex flex-col gap-2 max-w-sm">
      <TransitionGroup name="toast">
        <div
          v-for="t in toasts"
          :key="t.id"
          :class="[
            'rounded-lg border px-4 py-3 shadow-lg text-sm',
            t.variant === 'destructive'
              ? 'border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-400'
              : t.variant === 'success'
              ? 'border-green-500/30 bg-green-500/10 text-green-600 dark:text-green-400'
              : 'border-border bg-card text-card-foreground'
          ]"
        >
          <div class="font-medium">{{ t.title }}</div>
          <div v-if="t.description" class="text-muted-foreground mt-0.5">{{ t.description }}</div>
        </div>
      </TransitionGroup>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active, .toast-leave-active { transition: all 0.3s; }
.toast-enter-from { opacity: 0; transform: translateX(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-20px); }
.toast-move { transition: transform 0.3s; }
</style>
