<!-- frontend/src/components/ui/Dialog.vue -->
<script setup>
import { onMounted, onUnmounted } from 'vue'

const props = defineProps({ open: Boolean, title: String, description: String, size: { type: String, default: 'md' } })
const emit = defineEmits(['close'])

function onKeydown(e) {
  if (e.key === 'Escape' && props.open) emit('close')
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => document.removeEventListener('keydown', onKeydown))
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center">
        <!-- Backdrop -->
        <div class="fixed inset-0 bg-black/60" @click="$emit('close')" />
        <!-- Panel -->
        <div
          role="dialog"
          aria-modal="true"
          :aria-labelledby="title ? 'dialog-title' : undefined"
          :class="['relative z-50 w-full mx-4 bg-card text-card-foreground rounded-lg shadow-2xl border border-border', size === 'lg' ? 'max-w-3xl' : size === 'xl' ? 'max-w-5xl' : 'max-w-lg']"
        >
          <div class="flex flex-col space-y-1.5 p-6 border-b border-border">
            <h2 id="dialog-title" class="text-lg font-semibold leading-none">{{ title }}</h2>
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
