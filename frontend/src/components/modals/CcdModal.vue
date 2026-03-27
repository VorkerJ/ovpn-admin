<!-- frontend/src/components/modals/CcdModal.vue -->
<script setup>
import { ref, watch } from 'vue'
import Dialog from '@/components/ui/Dialog.vue'
import Input from '@/components/ui/Input.vue'
import Button from '@/components/ui/Button.vue'

const props = defineProps({
  open: Boolean,
  username: { type: String, default: '' },
  serverRole: { type: String, default: 'master' },
  ccd: { type: Object, default: () => ({ Name: '', ClientAddress: '', CustomRoutes: [] }) },
  error: { type: String, default: '' },
})

const emit = defineEmits(['close', 'submit'])

let routeId = 0
function withIds(routes) {
  return (routes || []).map(r => ({ ...r, _id: ++routeId }))
}

const localCcd = ref({ ...props.ccd, CustomRoutes: withIds(props.ccd?.CustomRoutes) })
const newRoute = ref({ Address: '', Mask: '', Description: '' })
const validationError = ref('')

watch(() => props.ccd, (val) => {
  localCcd.value = { ...val, CustomRoutes: withIds(val?.CustomRoutes) }
  validationError.value = ''
}, { deep: true })

const isMaster = () => props.serverRole === 'master'
const isDynamic = () => localCcd.value.ClientAddress === 'dynamic'

const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/
function isValidIp(val) { return ipPattern.test(val) }

function addRoute() {
  validationError.value = ''
  if (!newRoute.value.Address) return
  if (!isValidIp(newRoute.value.Address)) {
    validationError.value = `Неверный формат IP-адреса: "${newRoute.value.Address}"`
    return
  }
  if (newRoute.value.Mask && !isValidIp(newRoute.value.Mask)) {
    validationError.value = `Неверный формат маски: "${newRoute.value.Mask}"`
    return
  }
  localCcd.value.CustomRoutes.push({ ...newRoute.value, _id: ++routeId })
  newRoute.value = { Address: '', Mask: '', Description: '' }
}

function removeRoute(index) {
  localCcd.value.CustomRoutes.splice(index, 1)
  validationError.value = ''
}

function onClose() {
  validationError.value = ''
  emit('close')
}

function submitCcd() {
  validationError.value = ''
  if (newRoute.value.Address) {
    validationError.value = 'Нажмите "+ Добавить", чтобы добавить маршрут из строки ввода.'
    return
  }
  for (const r of localCcd.value.CustomRoutes) {
    if (!isValidIp(r.Address)) {
      validationError.value = `Неверный формат IP-адреса: "${r.Address}"`
      return
    }
    if (r.Mask && !isValidIp(r.Mask)) {
      validationError.value = `Неверный формат маски: "${r.Mask}"`
      return
    }
  }
  const payload = {
    ...localCcd.value,
    CustomRoutes: localCcd.value.CustomRoutes.map(({ _id, ...r }) => r),
  }
  emit('submit', payload)
}
</script>

<template>
  <Dialog
    :open="open"
    size="lg"
    :title="`Маршруты: ${username}`"
    @close="onClose"
  >
    <div class="space-y-4">
      <!-- Static address -->
      <div class="flex gap-2 items-center">
        <label class="text-sm text-muted-foreground w-36 shrink-0">Статический адрес:</label>
        <Input
          v-model="localCcd.ClientAddress"
          placeholder="dynamic"
          :disabled="!isMaster()"
          class="flex-1"
        />
        <Button
          v-if="isMaster()"
          size="sm"
          variant="warning"
          :disabled="isDynamic()"
          @click="localCcd.ClientAddress = 'dynamic'"
        >
          Сбросить
        </Button>
      </div>

      <!-- Routes table -->
      <div class="rounded-md border border-border overflow-hidden">
        <table class="w-full text-sm">
          <thead class="bg-muted/50">
            <tr>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Адрес</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Маска</th>
              <th class="px-3 py-2 text-left text-xs font-semibold text-muted-foreground">Описание</th>
              <th v-if="isMaster()" class="px-3 py-2 w-32" />
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(route, i) in localCcd.CustomRoutes"
              :key="route._id"
              class="border-t border-border"
            >
              <td class="px-3 py-2 w-40">
                <Input v-if="isMaster()" v-model="route.Address" placeholder="10.0.0.0" />
                <span v-else>{{ route.Address }}</span>
              </td>
              <td class="px-3 py-2 w-40">
                <Input v-if="isMaster()" v-model="route.Mask" placeholder="255.255.255.0" />
                <span v-else>{{ route.Mask }}</span>
              </td>
              <td class="px-3 py-2">
                <Input v-if="isMaster()" v-model="route.Description" placeholder="Описание" />
                <span v-else>{{ route.Description }}</span>
              </td>
              <td v-if="isMaster()" class="px-3 py-2 text-right">
                <Button size="sm" variant="destructive" @click="removeRoute(i)">✕</Button>
              </td>
            </tr>
            <!-- Add row (только master) -->
            <tr v-if="isMaster()" class="border-t border-border bg-muted/20">
              <td class="px-3 py-2 w-40"><Input v-model="newRoute.Address" placeholder="10.0.0.0" /></td>
              <td class="px-3 py-2 w-40"><Input v-model="newRoute.Mask" placeholder="255.255.255.0" /></td>
              <td class="px-3 py-2"><Input v-model="newRoute.Description" placeholder="Описание" /></td>
              <td class="px-3 py-2 text-right w-32"><Button size="sm" variant="success" @click="addRoute" class="whitespace-nowrap">+ Добавить</Button></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="validationError" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ validationError }}
      </div>
      <div v-else-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Закрыть</Button>
      <Button v-if="isMaster()" @click="submitCcd">Сохранить</Button>
    </template>
  </Dialog>
</template>
