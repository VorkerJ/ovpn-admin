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

watch(() => props.ccd, (val) => {
  localCcd.value = { ...val, CustomRoutes: withIds(val?.CustomRoutes) }
}, { deep: true })

const isMaster = () => props.serverRole === 'master'
const isDynamic = () => localCcd.value.ClientAddress === 'dynamic'

function addRoute() {
  if (!newRoute.value.Address) return
  localCcd.value.CustomRoutes.push({ ...newRoute.value, _id: ++routeId })
  newRoute.value = { Address: '', Mask: '', Description: '' }
}

function removeRoute(index) {
  localCcd.value.CustomRoutes.splice(index, 1)
}

function onClose() {
  emit('close')
}

function submitCcd() {
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
              <th v-if="isMaster()" class="px-3 py-2 w-20" />
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="(route, i) in localCcd.CustomRoutes"
              :key="route._id"
              class="border-t border-border"
            >
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Address" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Address }}</span>
              </td>
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Mask" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Mask }}</span>
              </td>
              <td class="px-3 py-2">
                <input v-if="isMaster()" v-model="route.Description" class="w-full bg-transparent outline-none text-sm" />
                <span v-else>{{ route.Description }}</span>
              </td>
              <td v-if="isMaster()" class="px-3 py-2 text-right">
                <Button size="sm" variant="destructive" @click="removeRoute(i)">✕</Button>
              </td>
            </tr>
            <!-- Add row (только master) -->
            <tr v-if="isMaster()" class="border-t border-border bg-muted/20">
              <td class="px-3 py-2"><Input v-model="newRoute.Address" placeholder="10.0.0.0" class="h-7 text-xs" /></td>
              <td class="px-3 py-2"><Input v-model="newRoute.Mask" placeholder="255.255.255.0" class="h-7 text-xs" /></td>
              <td class="px-3 py-2"><Input v-model="newRoute.Description" placeholder="Описание" class="h-7 text-xs" /></td>
              <td class="px-3 py-2 text-right"><Button size="sm" variant="success" @click="addRoute">+ Добавить</Button></td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="error" class="rounded-md bg-destructive/10 border border-destructive/30 px-3 py-2 text-sm text-destructive">
        {{ error }}
      </div>
    </div>
    <template #footer>
      <Button variant="ghost" @click="onClose">Закрыть</Button>
      <Button v-if="isMaster()" @click="submitCcd">Сохранить</Button>
    </template>
  </Dialog>
</template>
