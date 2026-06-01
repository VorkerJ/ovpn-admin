<!-- 6-cell OTP code input — auto-advance, paste-aware, backspace-friendly -->
<script setup>
import { ref, watch, nextTick } from 'vue'

const props = defineProps({
  modelValue: { type: String, default: '' },
  length: { type: Number, default: 6 },
})
const emit = defineEmits(['update:modelValue'])

const digits = ref(Array(props.length).fill(''))
const refs = ref([])

watch(() => props.modelValue, (v) => {
  const clean = (v || '').replace(/\D/g, '').slice(0, props.length)
  for (let i = 0; i < props.length; i++) {
    digits.value[i] = clean[i] || ''
  }
}, { immediate: true })

function emitValue() {
  emit('update:modelValue', digits.value.join(''))
}

function onInput(i, e) {
  const v = e.target.value.replace(/\D/g, '')
  if (v.length > 1) {
    // paste-into-single-cell handling
    onPaste(i, v)
    return
  }
  // If the user typed a non-digit, digits[i] stays '' — but the DOM input
  // would visually keep the offending character (one-way :value bind doesn't
  // diff '' → ''). Force the DOM value to match the model.
  if (e.target.value !== v) {
    e.target.value = v
  }
  digits.value[i] = v
  emitValue()
  if (v && i < props.length - 1) {
    nextTick(() => refs.value[i + 1]?.focus())
  }
}

function onKeydown(i, e) {
  if (e.key === 'Backspace' && !digits.value[i] && i > 0) {
    refs.value[i - 1]?.focus()
    digits.value[i - 1] = ''
    emitValue()
    e.preventDefault()
  } else if (e.key === 'ArrowLeft' && i > 0) {
    refs.value[i - 1]?.focus()
  } else if (e.key === 'ArrowRight' && i < props.length - 1) {
    refs.value[i + 1]?.focus()
  }
}

function onPaste(startIdx, pastedRaw) {
  let pasted = pastedRaw
  if (typeof pastedRaw !== 'string') {
    pasted = (pastedRaw.clipboardData || window.clipboardData).getData('text')
    pastedRaw.preventDefault()
  }
  const clean = pasted.replace(/\D/g, '').slice(0, props.length - startIdx)
  for (let k = 0; k < clean.length; k++) {
    digits.value[startIdx + k] = clean[k]
  }
  emitValue()
  const lastIdx = Math.min(startIdx + clean.length, props.length - 1)
  nextTick(() => refs.value[lastIdx]?.focus())
}

function onFocus(i, e) {
  e.target.select()
}
</script>

<template>
  <div class="flex gap-2 justify-center" data-testid="otp-input" @paste.prevent="onPaste(0, $event)">
    <input
      v-for="(d, i) in digits"
      :key="i"
      :ref="el => (refs[i] = el)"
      :data-testid="`otp-cell-${i}`"
      type="text"
      inputmode="numeric"
      autocomplete="one-time-code"
      maxlength="1"
      :value="d"
      @input="onInput(i, $event)"
      @keydown="onKeydown(i, $event)"
      @focus="onFocus(i, $event)"
      class="w-12 h-14 text-center text-2xl font-mono font-semibold rounded-md border border-input bg-background focus:outline-none focus:ring-2 focus:ring-ring focus:border-ring transition"
    />
  </div>
</template>
