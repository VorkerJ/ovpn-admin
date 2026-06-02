<!-- frontend/src/components/modals/AddUserModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  modulesEnabled: { type: Array, default: () => [] },
  error: { type: String, default: '' },
  submitting: { type: Boolean, default: false },
})

const emit = defineEmits(['close', 'submit'])

const username = ref('')
const password = ref('')

function submit() {
  if (props.submitting) return
  emit('submit', { username: username.value, password: password.value })
}

watch(() => props.open, (val) => {
  if (!val) {
    username.value = ''
    password.value = ''
  }
})

function onClose() {
  if (props.submitting) return
  emit('close')
}
</script>

<template>
  <Dialog
    :open="open"
    title="Добавить пользователя"
    @close="onClose"
  >
    <div class="space-y-3">
      <Input
        v-model="username"
        placeholder="Имя пользователя"
        autocomplete="off"
      />
      <Input
        v-if="modulesEnabled.includes('passwdAuth')"
        v-model="password"
        type="password"
        placeholder="Пароль"
        autocomplete="new-password"
        minlength="6"
      />
      <div
        v-if="error"
        class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      >
        {{ error }}
      </div>
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
        :loading="submitting"
        :disabled="submitting"
        @click="submit"
      >
        {{ submitting ? 'Создание' : 'Создать' }}
      </Button>
    </template>
  </Dialog>
</template>
