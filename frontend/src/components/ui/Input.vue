<!-- frontend/src/components/ui/Input.vue -->
<script setup>
import { cn } from '@/lib/utils'
defineProps({ class: { type: String, default: '' } })
</script>

<template>
  <input
    :class="cn('flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50', $props.class)"
    v-bind="$attrs"
  />
</template>
