<!-- frontend/src/components/ui/Badge.vue -->
<script setup>
import { cn } from '@/lib/utils'

const props = defineProps({
  variant: { type: String, default: 'default' },
  class: { type: String, default: '' },
})

const variants = {
  default: 'bg-primary/10 text-primary',
  neutral: 'bg-muted text-muted-foreground border border-border',
  info:    'bg-blue-500/10 text-blue-600 dark:text-blue-400',
  active:  'bg-green-500/12 text-green-600 dark:text-green-400',
  revoked: 'bg-red-500/12 text-red-600 dark:text-red-400',
  expired: 'bg-yellow-500/12 text-yellow-600 dark:text-yellow-400',
}
</script>

<template>
  <span :class="cn('inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium', variants[variant] || variants.default, props.class)">
    <slot />
  </span>
</template>
