import { ref } from 'vue'

// Promise-based replacement for the native window.confirm(): call
// `await confirm({ title, message, ... })` and get a boolean back, rendered as
// a centred in-app dialog (see ui/ConfirmDialog.vue, mounted once in App.vue)
// instead of the browser's default OS popup. Singleton state, same pattern as
// useToast.
const state = ref({
  open: false,
  title: '',
  message: '',
  confirmText: 'Подтвердить',
  cancelText: 'Отмена',
  variant: 'default', // 'default' | 'destructive'
})

let resolver = null

export function useConfirm() {
  function confirm(opts = {}) {
    // If a previous confirm is somehow still pending, resolve it false so we
    // never leak a dangling promise.
    if (resolver) { resolver(false); resolver = null }
    state.value = {
      open: true,
      title: opts.title || 'Подтвердите действие',
      message: opts.message || '',
      confirmText: opts.confirmText || 'Подтвердить',
      cancelText: opts.cancelText || 'Отмена',
      variant: opts.variant || 'default',
    }
    return new Promise((resolve) => { resolver = resolve })
  }

  function settle(value) {
    state.value.open = false
    if (resolver) { resolver(value); resolver = null }
  }

  return { confirm, settle }
}

export { state as confirmState }
