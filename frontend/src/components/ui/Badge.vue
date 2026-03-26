<!-- frontend/src/components/ui/Badge.vue -->
<script setup>
import { cn } from '@/lib/utils'

const props = defineProps({
  variant: { type: String, default: 'default' },
  class: { type: String, default: '' },
})

const variants = {
  default: 'bg-primary/10 text-primary',
  active: 'bg-green-500/15 text-green-600 dark:text-green-400',
  revoked: 'bg-red-500/15 text-red-600 dark:text-red-400',
  expired: 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400',
}
</script>

<template>
  <span :class="cn('inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold', variants[variant] || variants.default, props.class)">
    <slot />
  </span>
</template>
