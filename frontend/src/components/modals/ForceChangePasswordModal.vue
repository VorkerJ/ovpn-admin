<!-- frontend/src/components/modals/ForceChangePasswordModal.vue
     Non-dismissable forced password change. Shown when the admin is on an
     auto-generated temporary password — every other endpoint is blocked by the
     backend (412 "password change required") until this completes. -->
<script setup>
import { ref } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'
import { adminChangePassword } from '@/api.js'

const MIN_LEN = 12

defineProps({
  open: Boolean,
})
const emit = defineEmits(['changed'])

const current = ref('')
const next = ref('')
const confirm = ref('')
const error = ref('')
const submitting = ref(false)

// Non-dismissable: ignore Escape / backdrop close requests entirely.
function noClose() {}

async function submit() {
  if (submitting.value) return
  error.value = ''
  if (next.value.length < MIN_LEN) {
    error.value = `Новый пароль слишком короткий: минимум ${MIN_LEN} символов`
    return
  }
  if (next.value !== confirm.value) {
    error.value = 'Пароли не совпадают'
    return
  }
  if (next.value === current.value) {
    error.value = 'Новый пароль должен отличаться от текущего'
    return
  }
  submitting.value = true
  try {
    await adminChangePassword(current.value, next.value)
    current.value = ''
    next.value = ''
    confirm.value = ''
    emit('changed')
  } catch (e) {
    error.value = e?.response?.data?.error || 'Не удалось сменить пароль'
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <Dialog
    :open="open"
    title="Смените временный пароль"
    description="Вы вошли с временным паролем. Задайте постоянный пароль — до этого остальные действия заблокированы."
    @close="noClose"
  >
    <div class="space-y-3">
      <Input
        v-model="current"
        type="password"
        placeholder="Текущий (временный) пароль"
        autocomplete="current-password"
      />
      <Input
        v-model="next"
        type="password"
        placeholder="Новый пароль (минимум 12 символов)"
        autocomplete="new-password"
        :minlength="MIN_LEN"
        @keyup.enter="submit"
      />
      <Input
        v-model="confirm"
        type="password"
        placeholder="Повторите новый пароль"
        autocomplete="new-password"
        @keyup.enter="submit"
      />
    </div>
    <div
      v-if="error"
      class="mt-3 rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive"
      data-testid="force-pw-error"
    >
      {{ error }}
    </div>
    <template #footer>
      <Button
        :loading="submitting"
        :disabled="submitting"
        data-testid="force-pw-submit"
        @click="submit"
      >
        Сменить пароль
      </Button>
    </template>
  </Dialog>
</template>
