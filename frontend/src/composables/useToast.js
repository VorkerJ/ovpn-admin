import { ref } from 'vue'

const toasts = ref([])
let id = 0

export function useToast() {
  function toast({ title, description, variant = 'default' }) {
    const t = { id: ++id, title, description, variant }
    toasts.value.push(t)
    setTimeout(() => {
      toasts.value = toasts.value.filter(item => item.id !== t.id)
    }, 4000)
  }
  return { toast }
}

export { toasts }
