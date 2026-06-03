<!-- frontend/src/components/ui/Dialog.vue -->
<script setup>
import { onMounted, onUnmounted, watch } from 'vue'

const props = defineProps({
  open: Boolean,
  title: { type: String, default: '' },
  description: { type: String, default: '' },
  size: { type: String, default: 'md' },
})
const emit = defineEmits(['close'])

function onKeydown(e) {
  if (e.key === 'Escape' && props.open) emit('close')
}
onMounted(() => document.addEventListener('keydown', onKeydown))
onUnmounted(() => {
  document.removeEventListener('keydown', onKeydown)
  // Safety net: if the host component unmounts while a dialog is open,
  // make sure we don't leave <body> permanently scroll-locked.
  document.body.style.overflow = ''
})

// Lock background page scroll whenever a dialog is visible — otherwise the
// modal's internal scroll bubbles to <body> as soon as the cursor leaves
// the panel, and the page behind drifts away. Restored on close.
watch(() => props.open, (isOpen) => {
  document.body.style.overflow = isOpen ? 'hidden' : ''
}, { immediate: true })
</script>

<template>
  <Teleport to="body">
    <Transition name="dialog">
      <div
        v-if="open"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <!-- Backdrop -->
        <div
          class="fixed inset-0 bg-black/60"
          @click="$emit('close')"
        />
        <!-- Panel.
             max-h + flex-col + child shrink/grow lets the body slot scroll
             internally so a long routes table no longer pushes the footer
             past the viewport bottom. Header + footer stay pinned. -->
        <div
          role="dialog"
          aria-modal="true"
          :aria-labelledby="title ? 'dialog-title' : undefined"
          :class="['relative z-50 w-full mx-4 bg-card text-card-foreground rounded-lg shadow-2xl border border-border max-h-[90vh] flex flex-col', size === 'lg' ? 'max-w-3xl' : size === 'xl' ? 'max-w-5xl' : 'max-w-lg']"
        >
          <div class="flex flex-col space-y-1.5 p-6 border-b border-border shrink-0">
            <h2
              id="dialog-title"
              class="text-lg font-semibold leading-none"
            >
              {{ title }}
            </h2>
            <p
              v-if="description"
              class="text-sm text-muted-foreground"
            >
              {{ description }}
            </p>
          </div>
          <div class="p-6 flex-1 min-h-0 overflow-y-auto">
            <slot />
          </div>
          <div
            v-if="$slots.footer"
            class="flex justify-end gap-2 px-6 pb-6 pt-3 border-t border-border shrink-0"
          >
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
