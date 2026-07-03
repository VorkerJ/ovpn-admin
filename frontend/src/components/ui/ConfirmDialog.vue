<!-- frontend/src/components/ui/ConfirmDialog.vue
     Global, promise-based confirm dialog. Mounted once in App.vue; driven by
     the useConfirm() composable. Replaces native window.confirm() with a
     centred in-app popup styled like the rest of the app. -->
<script setup>
import { watch, nextTick, ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'
import { confirmState, useConfirm } from '@/composables/useConfirm.js'

const { settle } = useConfirm()
const confirmBtn = ref(null)

// Autofocus the confirm action when the dialog opens so Enter confirms and the
// keyboard flow matches a native dialog. (Escape → close → settle(false) is
// handled by Dialog.vue's own Escape/backdrop close wiring.)
watch(() => confirmState.value.open, async (open) => {
  if (open) {
    await nextTick()
    confirmBtn.value?.$el?.focus?.()
  }
})
</script>

<template>
  <Dialog
    :open="confirmState.open"
    :title="confirmState.title"
    @close="settle(false)"
  >
    <p
      v-if="confirmState.message"
      class="text-sm text-muted-foreground whitespace-pre-line"
    >
      {{ confirmState.message }}
    </p>
    <template #footer>
      <Button
        variant="ghost"
        @click="settle(false)"
      >
        {{ confirmState.cancelText }}
      </Button>
      <Button
        ref="confirmBtn"
        :variant="confirmState.variant === 'destructive' ? 'destructive' : 'default'"
        @click="settle(true)"
      >
        {{ confirmState.confirmText }}
      </Button>
    </template>
  </Dialog>
</template>
