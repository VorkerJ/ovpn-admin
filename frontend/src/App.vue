<!-- frontend/src/App.vue -->
<script setup>
import { ref, onMounted, computed } from 'vue'
import { useToast } from '@/composables/useToast'
import AppHeader from '@/components/AppHeader.vue'
import StatCards from '@/components/StatCards.vue'
import UsersTable from '@/components/UsersTable.vue'
import { AlertTriangle } from 'lucide-vue-next'
import Toast from '@/components/ui/Toast.vue'
import AddUserModal from '@/components/modals/AddUserModal.vue'
import DeleteUserModal from '@/components/modals/DeleteUserModal.vue'
import RotateUserModal from '@/components/modals/RotateUserModal.vue'
import ChangePasswordModal from '@/components/modals/ChangePasswordModal.vue'
import CcdModal from '@/components/modals/CcdModal.vue'
import MfaSetupModal from '@/components/modals/MfaSetupModal.vue'
import LoginPage from '@/components/LoginPage.vue'
import TabBar from '@/components/TabBar.vue'
import CommonRoutesView from '@/components/CommonRoutesView.vue'
import ServerConfigView from '@/components/ServerConfigView.vue'

import {
  fetchUsers, fetchServerSettings, fetchLastSync,
  createUser, revokeUser, unrevokeUser, rotateUser, deleteUser,
  changePassword, fetchUserConfig, fetchUserCcd, applyCcd
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
const serverRole = ref('master')
const modulesEnabled = ref([])
// serverInitialized — admin сохранял настройки сервера через UI хотя бы раз.
// До этого создание/ротация пользователей заблокировано на бэкенде (412).
const serverInitialized = ref(true)
const lastSync = ref('')

const activeTab = ref('users')

const visibleTabs = computed(() => {
  const tabs = [{ key: 'users', label: 'Пользователи' }]
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
  serverRole.value = settings.serverRole
  modulesEnabled.value = settings.modules
  // Если бэкенд не вернул поле (старый билд) — считаем инициализированным,
  // чтобы не блокировать пользователя на ровном месте.
  serverInitialized.value = settings.serverInitialized !== false
  if (settings.serverRole === 'slave') {
    lastSync.value = await fetchLastSync()
  }
}

onMounted(() => {
  checkAuth()
})

// ── Actions ────────────────────────────────────────────────────────
async function handleRevoke(username) {
  await revokeUser(username)
  notify(`Пользователь ${username} отозван`, 'default')
  loadUsers()
}

async function handleUnrevoke(username) {
  await unrevokeUser(username)
  notify(`Пользователь ${username} восстановлен`, 'success')
  loadUsers()
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
    if (e.response?.status === 412) {
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
    modalErrors.value.deleteUser = e.response?.data?.message || 'Ошибка удаления'
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
    if (e.response?.status === 412) {
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
    modalErrors.value.changePassword = e.response?.data?.message || 'Ошибка смены пароля'
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
    modalErrors.value.ccd = e.response?.data || 'Ошибка сохранения маршрутов'
  } finally {
    modalSubmitting.value.ccd = false
  }
}
</script>

<template>
  <div class="min-h-screen bg-background">
    <LoginPage v-if="authChecked && !authenticated" @login="handleLogin" />

    <template v-else-if="authenticated">
    <AppHeader
      :server-role="serverRole"
      :last-sync="lastSync"
      :server-initialized="serverInitialized"
      @add-user="openModal('addUser')"
      @open-mfa="mfaModalOpen = true"
      @logout="handleLogout"
    />

    <TabBar v-model="activeTab" :tabs="visibleTabs" />

    <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
      <template v-if="activeTab === 'users'">
        <div
          v-if="!serverInitialized"
          class="rounded-md bg-amber-500/10 border border-amber-500/30 px-4 py-3 flex items-start gap-2"
          data-testid="server-not-initialized-banner"
        >
          <AlertTriangle :size="16" class="text-amber-500 mt-0.5 shrink-0" />
          <div class="text-sm">
            <p class="font-medium">Сервер не настроен</p>
            <p class="text-muted-foreground">
              Откройте вкладку «Сервер», проверьте настройки и нажмите «Сохранить». До этого создание пользователей заблокировано.
            </p>
          </div>
        </div>

        <div>
          <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-3">Обзор</p>
          <StatCards :users="users" />
        </div>

        <div>
          <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground mb-3">Пользователи</p>
          <UsersTable
            :users="users"
            :server-role="serverRole"
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
      <template v-else-if="activeTab === 'common-routes'">
        <CommonRoutesView :server-role="serverRole" />
      </template>
      <template v-else-if="activeTab === 'server-config'">
        <ServerConfigView :server-role="serverRole" @saved="loadSettings" />
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
      :open="modals.ccd"
      :username="activeUser"
      :server-role="serverRole"
      :submitting="modalSubmitting.ccd"
      :ccd="ccdData"
      :error="modalErrors.ccd"
      @close="closeModal('ccd')"
      @submit="submitCcd"
    />

    <MfaSetupModal
      :open="mfaModalOpen"
      @close="mfaModalOpen = false"
    />

    <!-- Toast notifications -->
    <Toast />
    </template>
  </div>
</template>

