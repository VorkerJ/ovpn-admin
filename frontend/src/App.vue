<!-- frontend/src/App.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import axios from 'axios'
import { useToast } from '@/composables/useToast'
import AppHeader from '@/components/AppHeader.vue'
import StatCards from '@/components/StatCards.vue'
import UsersTable from '@/components/UsersTable.vue'
import { AlertTriangle, ShieldAlert } from 'lucide-vue-next'
import Button from '@/components/ui/Button.vue'
import Toast from '@/components/ui/Toast.vue'
import AddUserModal from '@/components/modals/AddUserModal.vue'
import DeleteUserModal from '@/components/modals/DeleteUserModal.vue'
import RotateUserModal from '@/components/modals/RotateUserModal.vue'
import ChangePasswordModal from '@/components/modals/ChangePasswordModal.vue'
import CcdModal from '@/components/modals/CcdModal.vue'
import MfaSetupModal from '@/components/modals/MfaSetupModal.vue'
import ApiTokensModal from '@/components/modals/ApiTokensModal.vue'
import ForceChangePasswordModal from '@/components/modals/ForceChangePasswordModal.vue'
import LoginPage from '@/components/LoginPage.vue'
import TabBar from '@/components/TabBar.vue'
import CommonRoutesView from '@/components/CommonRoutesView.vue'
import ServerConfigView from '@/components/ServerConfigView.vue'
import TrafficView from '@/components/TrafficView.vue'

import {
  fetchUsers, fetchServerSettings,
  createUser, revokeUser, unrevokeUser, rotateUser, deleteUser,
  changePassword, fetchUserConfig, fetchUserCcd, applyCcd, refreshUserCcdDns, importUserCcd
} from '@/api.js'

// ── Auth ───────────────────────────────────────────────────────────
const authenticated = ref(false)
const authChecked = ref(false)

async function checkAuth() {
  try {
    const res = await fetch('/api/auth/check')
    authenticated.value = res.ok
  } catch {
    authenticated.value = false
  }
  authChecked.value = true
  if (authenticated.value) {
    loadUsers()
    loadSettings()
  }
}

async function handleLogout() {
  await fetch('/api/logout', { method: 'POST' })
  authenticated.value = false
}

function handleLogin() {
  authenticated.value = true
  loadUsers()
  loadSettings()
}

// ── State ──────────────────────────────────────────────────────────
const users = ref([])
const modulesEnabled = ref([])
// serverInitialized — admin сохранял настройки сервера через UI хотя бы раз.
// До этого создание/ротация пользователей заблокировано на бэкенде (412).
const serverInitialized = ref(true)
// adminMfaEnabled / adminMfaRequired — гейт обязательной 2FA.
// Когда required && !enabled — все write-операции бэкенд отвергает с 412,
// а UI показывает баннер и блокирует кнопку «Добавить пользователя».
const adminMfaEnabled = ref(true)
const adminMfaRequired = ref(false)
// adminPasswordChangeRequired — admin вошёл с временным паролем. Пока true,
// бэкенд блокирует все эндпоинты кроме смены пароля (412), а UI показывает
// неснимаемую модалку смены пароля.
const adminPasswordChangeRequired = ref(false)

const activeTab = ref('users')

const visibleTabs = computed(() => {
  const tabs = [{ key: 'users', label: 'Пользователи' }, { key: 'traffic', label: 'Трафик' }]
  if (modulesEnabled.value.includes('common-routes')) {
    tabs.push({ key: 'common-routes', label: 'Общие маршруты' })
  }
  if (modulesEnabled.value.includes('server-config')) {
    tabs.push({ key: 'server-config', label: 'Сервер' })
  }
  return tabs
})

const { toast: _toast } = useToast()
function notify(title, variant = 'default') {
  _toast({ title, variant })
}

// Global 401 handler: any API call coming back unauthorized means the session
// expired or was invalidated. Drop straight back to the login screen instead of
// surfacing a raw "unauthorized" inside a view (e.g. the Traffic tab's periodic
// auto-refresh, which would otherwise just print the error and look broken).
axios.interceptors.response.use(
  (r) => r,
  (e) => {
    if (e?.response?.status === 401 && authenticated.value) {
      authenticated.value = false
      notify('Сессия истекла — войдите снова', 'destructive')
    }
    return Promise.reject(e)
  },
)

// ── Modal state ────────────────────────────────────────────────────
const activeUser = ref('')

const modals = ref({
  addUser: false,
  deleteUser: false,
  rotateUser: false,
  changePassword: false,
  ccd: false,
})

const modalErrors = ref({
  addUser: '',
  deleteUser: '',
  rotateUser: '',
  changePassword: '',
  ccd: '',
})

const modalSubmitting = ref({
  addUser: false,
  deleteUser: false,
  rotateUser: false,
  changePassword: false,
  ccd: false,
})

const mfaModalOpen = ref(false)
const apiTokensModalOpen = ref(false)
const ccdData = ref({ Name: '', ClientAddress: '', CustomRoutes: [] })

function openModal(name, username = '') {
  activeUser.value = username
  Object.keys(modalErrors.value).forEach(k => modalErrors.value[k] = '')
  modals.value[name] = true
}

function closeModal(name) {
  modals.value[name] = false
}

// ── Data loading ───────────────────────────────────────────────────
async function loadUsers() {
  users.value = await fetchUsers()
}

async function loadSettings() {
  const settings = await fetchServerSettings()
  modulesEnabled.value = settings.modules
  // Если бэкенд не вернул поле (старый билд) — считаем инициализированным,
  // чтобы не блокировать пользователя на ровном месте.
  serverInitialized.value = settings.serverInitialized !== false
  // MFA fields are new — old backends omit them; treat undefined as
  // "MFA not required" (= no banner, no enforcement) to keep UX sane
  // during a partial rollout.
  adminMfaEnabled.value = settings.adminMfaEnabled !== false
  adminMfaRequired.value = !!settings.adminMfaRequired
  adminPasswordChangeRequired.value = !!settings.adminPasswordChangeRequired
}

// Called after the forced password change succeeds — drop the gate flag and
// refresh state now that the rest of the API is reachable again.
async function onPasswordChanged() {
  adminPasswordChangeRequired.value = false
  notify('Пароль изменён', 'success')
  await loadSettings()
  await loadUsers()
}

// Called after the MFA modal emits status-change (enable/disable). Refetch
// server settings so the banner, header dot and Add-User button refresh.
async function onMfaStatusChange() {
  await loadSettings()
}

// Centralized 412 handler — backend returns Precondition Failed when admin
// MFA is required but not enabled. Surface a toast and pop the modal so the
// admin can fix it in one click instead of hunting for the shield button.
function handleMfa412(e) {
  const msg = e?.response?.data?.error || ''
  if (e?.response?.status === 412 && msg.includes('MFA')) {
    notify('Включите 2FA в правом верхнем углу для этого действия', 'destructive')
    adminMfaEnabled.value = false
    mfaModalOpen.value = true
    return true
  }
  return false
}

// Триггерится дочерними view (ServerConfigView, CommonRoutesView) когда они
// поймали 412 и обработали ошибку у себя — нам нужно только обновить флаг и
// открыть модалку.
function onMfaRequired() {
  adminMfaEnabled.value = false
  mfaModalOpen.value = true
}

onMounted(() => {
  checkAuth()
})

// ── Actions ────────────────────────────────────────────────────────
// handleRevoke/handleUnrevoke delegate to the safe* wrappers below so that
// 412 MFA-gate errors surface as a toast + auto-open MFA modal instead of an
// unhandled rejection (which silently swallows the failure).
function handleRevoke(username) {
  return safeRevoke(username)
}

function handleUnrevoke(username) {
  return safeUnrevoke(username)
}

async function handleDownloadConfig(username) {
  const config = await fetchUserConfig(username)
  const blob = new Blob([config], { type: 'text/plain' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = `${username}.ovpn`
  link.click()
  URL.revokeObjectURL(link.href)
}

async function handleEditCcd(username) {
  ccdData.value = await fetchUserCcd(username)
  openModal('ccd', username)
}

// ── Modal submit handlers ──────────────────────────────────────────
async function submitAddUser({ username, password }) {
  modalSubmitting.value.addUser = true
  try {
    await createUser(username, password)
    notify(`Пользователь ${username} создан`, 'success')
    closeModal('addUser')
    loadUsers()
  } catch (e) {
    if (handleMfa412(e)) {
      closeModal('addUser')
    } else if (e.response?.status === 412) {
      // Backend гейт — обновим локальный флаг и покажем понятное сообщение.
      serverInitialized.value = false
      modalErrors.value.addUser = 'Сервер ещё не настроен. Откройте вкладку «Сервер» и сохраните конфигурацию.'
    } else {
      modalErrors.value.addUser = e.response?.data || 'Ошибка создания'
    }
  } finally {
    modalSubmitting.value.addUser = false
  }
}

async function submitDeleteUser(username) {
  modalSubmitting.value.deleteUser = true
  try {
    await deleteUser(username)
    notify(`Пользователь ${username} удалён`, 'default')
    closeModal('deleteUser')
    loadUsers()
  } catch (e) {
    if (handleMfa412(e)) {
      closeModal('deleteUser')
    } else {
      modalErrors.value.deleteUser = e.response?.data?.message || 'Ошибка удаления'
    }
  } finally {
    modalSubmitting.value.deleteUser = false
  }
}

async function submitRotateUser({ username, password }) {
  modalSubmitting.value.rotateUser = true
  try {
    await rotateUser(username, password)
    notify(`Сертификаты ${username} обновлены`, 'success')
    closeModal('rotateUser')
    loadUsers()
  } catch (e) {
    if (handleMfa412(e)) {
      closeModal('rotateUser')
    } else if (e.response?.status === 412) {
      serverInitialized.value = false
      modalErrors.value.rotateUser = 'Сервер ещё не настроен. Откройте вкладку «Сервер» и сохраните конфигурацию.'
    } else {
      modalErrors.value.rotateUser = e.response?.data?.message || 'Ошибка ротации'
    }
  } finally {
    modalSubmitting.value.rotateUser = false
  }
}

async function submitChangePassword({ username, password }) {
  modalSubmitting.value.changePassword = true
  try {
    await changePassword(username, password)
    notify(`Пароль ${username} изменён`, 'success')
    closeModal('changePassword')
    loadUsers()
  } catch (e) {
    if (handleMfa412(e)) {
      closeModal('changePassword')
    } else {
      modalErrors.value.changePassword = e.response?.data?.message || 'Ошибка смены пароля'
    }
  } finally {
    modalSubmitting.value.changePassword = false
  }
}

async function submitCcd(ccd) {
  modalSubmitting.value.ccd = true
  try {
    await applyCcd(ccd)
    notify(`Маршруты для ${activeUser.value} сохранены`, 'success')
    closeModal('ccd')
  } catch (e) {
    if (handleMfa412(e)) {
      closeModal('ccd')
    } else {
      modalErrors.value.ccd = e.response?.data || 'Ошибка сохранения маршрутов'
    }
  } finally {
    modalSubmitting.value.ccd = false
  }
}

const ccdModalRef = ref(null)

async function importUserRoutes({ username, text }) {
  modalSubmitting.value.ccd = true
  try {
    const res = await importUserCcd(username, text)
    ccdModalRef.value?.setImportReport(res)
    const added = res?.added?.length || 0
    const skipped = res?.skipped?.length || 0
    const errs = res?.errors?.length || 0
    notify(`Импорт: добавлено ${added}, пропущено ${skipped}, ошибок ${errs}`, errs ? 'default' : 'success')
    // Reload CCD so the table reflects the newly imported routes.
    ccdData.value = await fetchUserCcd(username)
  } catch (e) {
    if (!handleMfa412(e)) {
      notify(e.response?.data?.error || e.message || 'Ошибка импорта', 'error')
    }
  } finally {
    modalSubmitting.value.ccd = false
  }
}

async function refreshUserDns(username) {
  modalSubmitting.value.ccd = true
  try {
    const res = await refreshUserCcdDns(username)
    if (res?.changed) {
      notify(`DNS обновлён: ${res.resolved} OK / ${res.failed} ошибок. Маршруты сохранены, клиент будет переподключён.`, 'success')
    } else {
      notify(`DNS обновлён: IP не изменились (${res?.resolved ?? 0} OK / ${res?.failed ?? 0} ошибок)`, 'default')
    }
    // Reload CCD into modal so resolved IPs / timestamps refresh on screen
    ccdData.value = await fetchUserCcd(username)
  } catch (e) {
    if (!handleMfa412(e)) {
      notify(e.response?.data?.error || e.message || 'Ошибка обновления DNS', 'error')
    }
  } finally {
    modalSubmitting.value.ccd = false
  }
}

// Revoke/unrevoke have no modal — surface MFA errors as toasts.
async function safeRevoke(username) {
  try {
    await revokeUser(username)
    notify(`Пользователь ${username} отозван`, 'default')
    loadUsers()
  } catch (e) {
    if (!handleMfa412(e)) {
      notify(`Не удалось отозвать ${username}`, 'destructive')
    }
  }
}

async function safeUnrevoke(username) {
  try {
    await unrevokeUser(username)
    notify(`Пользователь ${username} восстановлен`, 'success')
    loadUsers()
  } catch (e) {
    if (!handleMfa412(e)) {
      notify(`Не удалось восстановить ${username}`, 'destructive')
    }
  }
}
</script>

<template>
  <div class="min-h-screen bg-background">
    <LoginPage
      v-if="authChecked && !authenticated"
      @login="handleLogin"
    />

    <template v-else-if="authenticated">
      <AppHeader
        :server-initialized="serverInitialized"
        :admin-mfa-enabled="adminMfaEnabled"
        @add-user="openModal('addUser')"
        @open-mfa="mfaModalOpen = true"
        @open-api-tokens="apiTokensModalOpen = true"
        @logout="handleLogout"
      />

      <TabBar
        v-model="activeTab"
        :tabs="visibleTabs"
      />

      <!-- MFA enforcement banner — shown on EVERY tab, above the tab content,
         because the gate applies to all write endpoints (users, routes, server-config). -->
      <main
        v-if="adminMfaRequired && !adminMfaEnabled"
        class="max-w-7xl mx-auto px-6 pt-4 -mb-2"
      >
        <div
          class="rounded-md bg-orange-500/10 border-2 border-orange-500/50 px-4 py-3 flex items-start gap-3"
          data-testid="admin-mfa-banner"
        >
          <ShieldAlert
            :size="20"
            class="text-orange-500 mt-0.5 shrink-0"
          />
          <div class="flex-1">
            <p class="font-semibold text-orange-900 dark:text-orange-200">
              Включите двухфакторную аутентификацию
            </p>
            <p class="text-sm text-muted-foreground mt-0.5">
              Без 2FA вы не сможете создавать пользователей, редактировать маршруты или менять настройки сервера.
            </p>
          </div>
          <Button
            size="sm"
            class="bg-orange-500 hover:bg-orange-600 text-white"
            @click="mfaModalOpen = true"
          >
            Включить
          </Button>
        </div>
      </main>

      <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
        <template v-if="activeTab === 'users'">
          <div
            v-if="!serverInitialized"
            class="rounded-md bg-amber-500/10 border border-amber-500/30 px-4 py-3 flex items-start gap-2"
            data-testid="server-not-initialized-banner"
          >
            <AlertTriangle
              :size="16"
              class="text-amber-500 mt-0.5 shrink-0"
            />
            <div class="text-sm">
              <p class="font-medium">
                Сервер не настроен
              </p>
              <p class="text-muted-foreground">
                Откройте вкладку «Сервер», проверьте настройки и нажмите «Сохранить». До этого создание пользователей заблокировано.
              </p>
            </div>
          </div>

          <div>
            <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-3">
              Обзор
            </p>
            <StatCards :users="users" />
          </div>

          <div>
            <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-3">
              Пользователи
            </p>
            <UsersTable
              :users="users"
              :modules-enabled="modulesEnabled"
              :server-initialized="serverInitialized"
              @revoke="handleRevoke"
              @unrevoke="handleUnrevoke"
              @rotate="(u) => openModal('rotateUser', u)"
              @delete="(u) => openModal('deleteUser', u)"
              @download-config="handleDownloadConfig"
              @edit-ccd="handleEditCcd"
              @change-password="(u) => openModal('changePassword', u)"
            />
          </div>
        </template>
        <template v-else-if="activeTab === 'traffic'">
          <TrafficView />
        </template>
        <template v-else-if="activeTab === 'common-routes'">
          <CommonRoutesView @mfa-required="onMfaRequired" />
        </template>
        <template v-else-if="activeTab === 'server-config'">
          <ServerConfigView
            @saved="loadSettings"
            @mfa-required="onMfaRequired"
          />
        </template>
      </main>

      <!-- Modals -->
      <AddUserModal
        :open="modals.addUser"
        :modules-enabled="modulesEnabled"
        :error="modalErrors.addUser"
        :submitting="modalSubmitting.addUser"
        @close="closeModal('addUser')"
        @submit="submitAddUser"
      />
      <DeleteUserModal
        :open="modals.deleteUser"
        :username="activeUser"
        :error="modalErrors.deleteUser"
        :submitting="modalSubmitting.deleteUser"
        @close="closeModal('deleteUser')"
        @submit="submitDeleteUser"
      />
      <RotateUserModal
        :open="modals.rotateUser"
        :username="activeUser"
        :modules-enabled="modulesEnabled"
        :error="modalErrors.rotateUser"
        :submitting="modalSubmitting.rotateUser"
        @close="closeModal('rotateUser')"
        @submit="submitRotateUser"
      />
      <ChangePasswordModal
        :open="modals.changePassword"
        :username="activeUser"
        :error="modalErrors.changePassword"
        :submitting="modalSubmitting.changePassword"
        @close="closeModal('changePassword')"
        @submit="submitChangePassword"
      />
      <CcdModal
        ref="ccdModalRef"
        :open="modals.ccd"
        :username="activeUser"
        :submitting="modalSubmitting.ccd"
        :ccd="ccdData"
        :error="modalErrors.ccd"
        @close="closeModal('ccd')"
        @submit="submitCcd"
        @refresh-dns="refreshUserDns"
        @import-routes="importUserRoutes"
      />

      <ApiTokensModal
        :open="apiTokensModalOpen"
        @close="apiTokensModalOpen = false"
      />

      <MfaSetupModal
        :open="mfaModalOpen"
        @close="mfaModalOpen = false"
        @status-change="onMfaStatusChange"
      />

      <!-- Forced (non-dismissable) temp-password rotation. Backend blocks every
           other endpoint with 412 until this completes. -->
      <ForceChangePasswordModal
        :open="adminPasswordChangeRequired"
        @changed="onPasswordChanged"
      />

      <!-- Toast notifications -->
      <Toast />
    </template>
  </div>
</template>

