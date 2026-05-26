<!-- frontend/src/components/server-config/SectionCard.vue -->
<script setup>
import { ref } from 'vue'
import { ChevronDown, ChevronRight } from 'lucide-vue-next'

const props = defineProps({
  title: { type: String, required: true },
  description: { type: String, default: '' },
  defaultOpen: { type: Boolean, default: true },
})

const open = ref(props.defaultOpen)
</script>

<template>
  <div class="rounded-lg border border-border bg-card overflow-hidden">
    <button
      type="button"
      class="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/50 transition-colors"
      @click="open = !open"
    >
      <div class="text-left">
        <p class="text-sm font-semibold">{{ title }}</p>
        <p v-if="description" class="text-xs text-muted-foreground mt-0.5">{{ description }}</p>
      </div>
      <component :is="open ? ChevronDown : ChevronRight" :size="16" class="text-muted-foreground" />
    </button>
    <div v-if="open" class="border-t border-border p-4 space-y-3">
      <slot />
    </div>
  </div>
</template>
