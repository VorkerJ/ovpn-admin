<!-- frontend/src/components/modals/DeleteUserModal.vue -->
<script setup>
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  error: { type: String, default: '' },
  submitting: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'submit'])

function onClose() {
  if (props.submitting) return
  emit('close')
}

function submit() {
  if (props.submitting) return
  emit('submit', props.username)
}
</script>

<template>
  <Dialog
    :open="open"
    :title="`Удалить пользователя ${username}?`"
    description="Это действие необратимо. Сертификат пользователя будет удалён безвозвратно."
    @close="onClose"
  >
    <div
      v-if="error"
      class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
    >
      {{ error }}
    </div>
    <template #footer>
      <Button
        variant="ghost"
        :disabled="submitting"
        @click="onClose"
      >
        Отмена
      </Button>
      <Button
        variant="destructive"
        :loading="submitting"
        :disabled="submitting"
        @click="submit"
      >
        {{ submitting ? 'Удаление' : 'Удалить' }}
      </Button>
    </template>
  </Dialog>
</template>
