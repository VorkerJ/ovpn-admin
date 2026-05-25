<!-- frontend/src/components/TabBar.vue -->
<script setup>
defineProps({
  modelValue: { type: String, required: true },
  tabs: { type: Array, required: true }, // [{ key: 'users', label: 'Пользователи' }, ...]
})
defineEmits(['update:modelValue'])
</script>

<template>
  <nav class="border-b border-border">
    <div class="max-w-7xl mx-auto px-6">
      <div class="flex gap-6 -mb-px">
        <button
          v-for="tab in tabs"
          :key="tab.key"
          type="button"
          class="relative h-11 inline-flex items-center text-[15px] font-medium border-b-2 transition-colors"
          :class="modelValue === tab.key
            ? 'border-primary text-foreground'
            : 'border-transparent text-muted-foreground hover:text-foreground'"
          @click="$emit('update:modelValue', tab.key)"
        >
          {{ tab.label }}
        </button>
      </div>
    </div>
  </nav>
</template>
