<!-- frontend/src/components/ui/DropdownMenu.vue -->
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const open = ref(false)
const menuRef = ref(null)

function close(e) {
  if (menuRef.value && !menuRef.value.contains(e.target)) open.value = false
}

onMounted(() => document.addEventListener('click', close))
onUnmounted(() => document.removeEventListener('click', close))
</script>

<template>
  <div ref="menuRef" class="relative inline-block">
    <div @click.stop="open = !open">
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
