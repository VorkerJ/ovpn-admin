<!-- frontend/src/components/ui/DropdownMenu.vue -->
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const open = ref(false)
const menuRef = ref(null)

// Закрыть по клику вне меню
function onDocClick(e) {
  if (menuRef.value && !menuRef.value.contains(e.target)) open.value = false
}

// Закрыть когда другое меню открылось
function onOtherOpen(e) {
  if (e.detail !== menuRef.value) open.value = false
}

function toggle() {
  open.value = !open.value
  if (open.value) {
    // Уведомляем остальные дропдауны закрыться
    document.dispatchEvent(new CustomEvent('dropdown-open', { detail: menuRef.value }))
  }
}

onMounted(() => {
  document.addEventListener('click', onDocClick)
  document.addEventListener('dropdown-open', onOtherOpen)
})
onUnmounted(() => {
  document.removeEventListener('click', onDocClick)
  document.removeEventListener('dropdown-open', onOtherOpen)
})
</script>

<template>
  <div ref="menuRef" class="relative inline-block">
    <div @click.stop="toggle" :aria-expanded="open">
      <slot name="trigger" />
    </div>
    <Transition name="dropdown">
      <div
        v-if="open"
        class="absolute right-0 top-full mt-1 z-50 min-w-[160px] overflow-hidden rounded-md border border-border bg-card shadow-lg"
        @click="open = false"
      >
        <slot />
      </div>
    </Transition>
  </div>
</template>

<style scoped>
.dropdown-enter-active, .dropdown-leave-active { transition: opacity 0.1s, transform 0.1s; }
.dropdown-enter-from, .dropdown-leave-to { opacity: 0; transform: translateY(-4px); }
</style>
