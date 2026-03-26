<!-- frontend/src/components/modals/DeleteUserModal.vue -->
<script setup>
import Dialog from '@/components/ui/Dialog.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])
</script>

<template>
  <Dialog
    :open="open"
    :title="`Удалить пользователя ${username}?`"
    description="Это действие необратимо. Сертификат пользователя будет удалён безвозвратно."
    @close="$emit('close')"
  >
    <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
      {{ error }}
    </div>
    <template #footer>
      <Button variant="ghost" @click="$emit('close')">Отмена</Button>
      <Button variant="destructive" @click="$emit('submit', username)">Удалить</Button>
    </template>
  </Dialog>
</template>
