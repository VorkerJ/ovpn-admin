<!-- frontend/src/components/ui/Spinner.vue -->
<script setup>
import { Loader2 } from 'lucide-vue-next'

defineProps({
  size: { type: [String, Number], default: 14 },
  class: { type: String, default: '' },
})
</script>

<template>
  <Loader2 :size="size" :class="['animate-spin', $props.class]" />
</template>
