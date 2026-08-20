<!-- frontend/src/components/ui/Tooltip.vue
     Lightweight hover tooltip. Wrap any element and pass `text` to show a styled
     bubble above it on hover; empty `text` = no tooltip. Works over a disabled
     button too: the button is pointer-events:none, so hover falls through to this
     wrapper and triggers the tooltip. -->
<script setup>
defineProps({ text: { type: String, default: '' } })
</script>

<template>
  <span class="relative inline-flex group">
    <slot />
    <span
      v-if="text"
      role="tooltip"
      class="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 hidden w-max max-w-xs -translate-x-1/2 whitespace-normal rounded-md border border-border bg-foreground px-2.5 py-1.5 text-xs leading-snug text-background shadow-lg group-hover:block"
    >
      {{ text }}
    </span>
  </span>
</template>
