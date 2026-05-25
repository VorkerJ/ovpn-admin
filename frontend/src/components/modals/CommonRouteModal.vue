<!-- frontend/src/components/modals/CommonRouteModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  route: { type: Object, required: true },
  submitting: { type: Boolean, default: false },
})
const emit = defineEmits(['close', 'submit'])

const local = ref({ ...props.route })
const error = ref('')

watch(() => props.route, (v) => { local.value = { ...v }; error.value = '' }, { deep: true })

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/

function onClose() {
  if (props.submitting) return
  emit('close')
}

function submit() {
  if (props.submitting) return
  error.value = ''
  if (local.value.kind === 'ip') {
    if (!ipPattern.test(local.value.address)) { error.value = 'Неверный IP'; return }
    if (!ipPattern.test(local.value.mask)) { error.value = 'Неверная маска'; return }
  } else {
    if (!domainPattern.test(local.value.domain)) { error.value = 'Неверный домен'; return }
  }
  emit('submit', {
    id: local.value.id,
    kind: local.value.kind,
    address: local.value.kind === 'ip' ? local.value.address : '',
    mask: local.value.kind === 'ip' ? local.value.mask : '',
    domain: local.value.kind === 'domain' ? local.value.domain : '',
    description: local.value.description || '',
  })
}
</script>

<template>
  <Dialog :open="open" :title="`Редактирование маршрута`" @close="onClose">
    <div class="space-y-3">
      <div class="text-xs text-muted-foreground">Тип: {{ local.kind === 'ip' ? 'IP / маска' : 'Домен' }}</div>
      <div v-if="local.kind === 'ip'" class="flex gap-2">
        <Input v-model="local.address" placeholder="10.0.0.0" class="w-40" />
        <Input v-model="local.mask" placeholder="255.255.255.0" class="w-40" />
      </div>
      <Input v-else v-model="local.domain" placeholder="youtube.com" />
      <Input v-model="local.description" placeholder="Описание" />
      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">{{ error }}</div>
    </div>
    <template #footer>
      <Button variant="ghost" :disabled="submitting" @click="onClose">Отмена</Button>
      <Button :loading="submitting" :disabled="submitting" @click="submit">
        Сохранить
      </Button>
    </template>
  </Dialog>
</template>
