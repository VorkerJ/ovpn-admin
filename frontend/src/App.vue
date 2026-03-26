<!-- frontend/src/App.vue -->
<script setup>
import { ref, onMounted } from 'vue'
import AppHeader from '@/components/AppHeader.vue'
import StatCards from '@/components/StatCards.vue'
import UsersTable from '@/components/UsersTable.vue'
import Toast from '@/components/ui/Toast.vue'
import AddUserModal from '@/components/modals/AddUserModal.vue'
import DeleteUserModal from '@/components/modals/DeleteUserModal.vue'
import RotateUserModal from '@/components/modals/RotateUserModal.vue'
import ChangePasswordModal from '@/components/modals/ChangePasswordModal.vue'
import CcdModal from '@/components/modals/CcdModal.vue'

import {
  fetchUsers, fetchServerSettings, fetchLastSync,
  createUser, revokeUser, unrevokeUser, rotateUser, deleteUser,
  changePassword, fetchUserConfig, fetchUserCcd, applyCcd
} from '@/api.js'

// ── State ──────────────────────────────────────────────────────────
const users = ref([])
const serverRole = ref('master')
const modulesEnabled = ref([])
const lastSync = ref('')

// Toast (simple reactive store)
const toasts = ref([])
let toastId = 0
function notify(title, variant = 'default') {
  const id = ++toastId
  toasts.value.push({ id, title, variant })
  setTimeout(() => { toasts.value = toasts.value.filter(t => t.id !== id) }, 4000)
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
  if (settings.serverRole === 'slave') {
    lastSync.value = await fetchLastSync()
  }
}

onMounted(() => {
  loadUsers()
  loadSettings()
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
  try {
    await createUser(username, password)
    notify(`Пользователь ${username} создан`, 'success')
    closeModal('addUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.addUser = e.response?.data || 'Ошибка создания'
  }
}

async function submitDeleteUser(username) {
  try {
    await deleteUser(username)
    notify(`Пользователь ${username} удалён`, 'default')
    closeModal('deleteUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.deleteUser = e.response?.data?.message || 'Ошибка удаления'
  }
}

async function submitRotateUser({ username, password }) {
  try {
    await rotateUser(username, password)
    notify(`Сертификаты ${username} обновлены`, 'success')
    closeModal('rotateUser')
    loadUsers()
  } catch (e) {
    modalErrors.value.rotateUser = e.response?.data?.message || 'Ошибка ротации'
  }
}

async function submitChangePassword({ username, password }) {
  try {
    await changePassword(username, password)
    notify(`Пароль ${username} изменён`, 'success')
    closeModal('changePassword')
    loadUsers()
  } catch (e) {
    modalErrors.value.changePassword = e.response?.data?.message || 'Ошибка смены пароля'
  }
}

async function submitCcd(ccd) {
  try {
    await applyCcd(ccd)
    notify(`Маршруты для ${activeUser.value} сохранены`, 'success')
    closeModal('ccd')
  } catch (e) {
    modalErrors.value.ccd = e.response?.data || 'Ошибка сохранения маршрутов'
  }
}
</script>

<template>
  <div class="min-h-screen bg-background">
    <AppHeader
      :server-role="serverRole"
      :last-sync="lastSync"
      @add-user="openModal('addUser')"
    />

    <main class="max-w-7xl mx-auto px-6 py-6 space-y-6">
      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Обзор</p>
        <StatCards :users="users" />
      </div>

      <div>
        <p class="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">Пользователи</p>
        <UsersTable
          :users="users"
          :server-role="serverRole"
          :modules-enabled="modulesEnabled"
          @revoke="handleRevoke"
          @unrevoke="handleUnrevoke"
          @rotate="(u) => openModal('rotateUser', u)"
          @delete="(u) => openModal('deleteUser', u)"
          @download-config="handleDownloadConfig"
          @edit-ccd="handleEditCcd"
          @change-password="(u) => openModal('changePassword', u)"
        />
      </div>
    </main>

    <!-- Modals -->
    <AddUserModal
      :open="modals.addUser"
      :modules-enabled="modulesEnabled"
      :error="modalErrors.addUser"
      @close="closeModal('addUser')"
      @submit="submitAddUser"
    />
    <DeleteUserModal
      :open="modals.deleteUser"
      :username="activeUser"
      :error="modalErrors.deleteUser"
      @close="closeModal('deleteUser')"
      @submit="submitDeleteUser"
    />
    <RotateUserModal
      :open="modals.rotateUser"
      :username="activeUser"
      :modules-enabled="modulesEnabled"
      :error="modalErrors.rotateUser"
      @close="closeModal('rotateUser')"
      @submit="submitRotateUser"
    />
    <ChangePasswordModal
      :open="modals.changePassword"
      :username="activeUser"
      :error="modalErrors.changePassword"
      @close="closeModal('changePassword')"
      @submit="submitChangePassword"
    />
    <CcdModal
      :open="modals.ccd"
      :username="activeUser"
      :server-role="serverRole"
      :ccd="ccdData"
      :error="modalErrors.ccd"
      @close="closeModal('ccd')"
      @submit="submitCcd"
    />

    <!-- Toast notifications -->
    <Toast />
  </div>
</template>

<style>
.toast-enter-active, .toast-leave-active { transition: all 0.3s; }
.toast-enter-from { opacity: 0; transform: translateX(-20px); }
.toast-leave-to { opacity: 0; transform: translateX(-20px); }
</style>
