<!-- frontend/src/components/ui/Dialog.vue -->
<script setup>
defineProps({ open: Boolean, title: String, description: String })
defineEmits(['close'])
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center">
        <!-- Backdrop -->
        <div class="fixed inset-0 bg-black/60" @click="$emit('close')" />
        <!-- Panel -->
        <div class="relative z-50 w-full max-w-lg mx-4 bg-card text-card-foreground rounded-lg shadow-2xl border border-border">
          <div class="flex flex-col space-y-1.5 p-6 border-b border-border">
            <h2 class="text-lg font-semibold leading-none">{{ title }}</h2>
            <p v-if="description" class="text-sm text-muted-foreground">{{ description }}</p>
          </div>
          <div class="p-6">
            <slot />
          </div>
          <div v-if="$slots.footer" class="flex justify-end gap-2 px-6 pb-6">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.dialog-enter-active, .dialog-leave-active { transition: opacity 0.2s; }
.dialog-enter-from, .dialog-leave-to { opacity: 0; }
</style>
