<!-- frontend/src/components/ui/Button.vue -->
<script setup>
import { cn } from '@/lib/utils'

const props = defineProps({
  variant: { type: String, default: 'default' },
  size: { type: String, default: 'default' },
  class: { type: String, default: '' },
})

const variants = {
  default: 'bg-primary text-primary-foreground hover:bg-primary/90',
  destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
  outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
  ghost: 'hover:bg-accent hover:text-accent-foreground',
  warning: 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 hover:bg-yellow-500/20',
  success: 'bg-green-500/10 text-green-600 dark:text-green-400 hover:bg-green-500/20',
  info: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 hover:bg-blue-500/20',
}

const sizes = {
  default: 'h-9 px-4 py-2',
  sm: 'h-7 px-3 text-xs',
  lg: 'h-11 px-8',
  icon: 'h-9 w-9',
}
</script>

<template>
  <button
    type="button"
    :class="cn(
      'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
      variants[variant],
      sizes[size],
      props.class
    )"
    v-bind="$attrs"
  >
    <slot />
  </button>
</template>
