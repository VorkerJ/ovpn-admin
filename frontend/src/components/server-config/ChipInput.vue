<!-- frontend/src/components/server-config/ChipInput.vue -->
<script setup>
import { ref } from 'vue'
import Input from '@/components/ui/Input.vue'
import { X } from 'lucide-vue-next'

const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  placeholder: { type: String, default: '' },
  validator: { type: Function, default: () => true },
})
const emit = defineEmits(['update:modelValue'])

const draft = ref('')

function addChip() {
  const v = draft.value.trim()
  if (!v) return
  if (!props.validator(v)) return
  if (props.modelValue.includes(v)) {
    draft.value = ''
    return
  }
  emit('update:modelValue', [...props.modelValue, v])
  draft.value = ''
}

function removeChip(i) {
  const next = props.modelValue.slice()
  next.splice(i, 1)
  emit('update:modelValue', next)
}
</script>

<template>
  <div class="space-y-2">
    <div class="flex flex-wrap gap-1.5">
      <span
        v-for="(chip, i) in modelValue"
        :key="chip"
        class="inline-flex items-center gap-1 rounded-md bg-secondary px-2 py-0.5 text-xs font-mono"
      >
        {{ chip }}
        <button
          type="button"
          class="text-muted-foreground hover:text-destructive"
          @click="removeChip(i)"
        >
          <X :size="12" />
        </button>
      </span>
    </div>
    <Input
      v-model="draft"
      :placeholder="placeholder"
      class="font-mono"
      @keydown.enter.prevent="addChip"
      @keydown.,.prevent="addChip"
      @blur="addChip"
    />
  </div>
</template>
