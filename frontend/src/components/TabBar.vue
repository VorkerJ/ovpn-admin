<!-- frontend/src/components/TabBar.vue -->
<script setup>
defineProps({
  modelValue: { type: String, required: true },
  tabs: { type: Array, required: true }, // [{ key: 'users', label: 'Пользователи' }, ...]
})
defineEmits(['update:modelValue'])
</script>

<template>
  <nav class="max-w-7xl mx-auto px-6 pt-4">
    <div class="flex gap-1 border-b border-border">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        type="button"
        class="px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors"
        :class="modelValue === tab.key
          ? 'border-primary text-foreground'
          : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="$emit('update:modelValue', tab.key)"
      >
        {{ tab.label }}
      </button>
    </div>
  </nav>
</template>
