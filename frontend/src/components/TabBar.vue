<!-- frontend/src/components/TabBar.vue -->
<script setup>
defineProps({
  modelValue: { type: String, required: true },
  tabs: { type: Array, required: true }, // [{ key: 'users', label: 'Пользователи' }, ...]
})
defineEmits(['update:modelValue'])
</script>

<template>
  <nav class="max-w-7xl mx-auto px-6 pt-5">
    <div class="inline-flex items-center gap-1 p-1 rounded-md bg-muted border border-border">
      <button
        v-for="tab in tabs"
        :key="tab.key"
        type="button"
        class="px-3 h-7 text-xs font-medium rounded transition-all"
        :class="modelValue === tab.key
          ? 'bg-background text-foreground shadow-sm'
          : 'text-muted-foreground hover:text-foreground'"
        @click="$emit('update:modelValue', tab.key)"
      >
        {{ tab.label }}
      </button>
    </div>
  </nav>
</template>
