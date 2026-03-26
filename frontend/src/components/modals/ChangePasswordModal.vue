<!-- frontend/src/components/modals/ChangePasswordModal.vue -->
<script setup>
import { ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])
const password = ref('')

function submit() {
  emit('submit', { username: props.username, password: password.value })
}

function onClose() {
  password.value = ''
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
    :title="`Сменить пароль: ${username}`"
    @close="onClose"
  >
    <Input
      v-model="password"
      type="password"
      placeholder="Новый пароль"
      autocomplete="new-password"
      minlength="6"
    />
    <div v-if="error" class="mt-3 rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
      {{ error }}
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Отмена</Button>
      <Button @click="submit">Сохранить</Button>
    </template>
  </Dialog>
</template>
