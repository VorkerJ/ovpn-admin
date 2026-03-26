import axios from 'axios'

function formData(obj) {
  const d = new URLSearchParams()
  Object.entries(obj).forEach(([k, v]) => d.append(k, v))
  return d
}

export async function fetchUsers() {
  const { data } = await axios.get('api/users/list')
  return Array.isArray(data) ? data : []
}

export async function fetchServerSettings() {
  const { data } = await axios.get('api/server/settings')
  return data // { serverRole, modules }
}

export async function fetchLastSync() {
  const { data } = await axios.get('api/sync/last/successful')
  return data
}

export async function createUser(username, password) {
  const { data } = await axios.post('api/user/create', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function revokeUser(username) {
  const { data } = await axios.post('api/user/revoke', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function unrevokeUser(username) {
  const { data } = await axios.post('api/user/unrevoke', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function rotateUser(username, password) {
  const { data } = await axios.post('api/user/rotate', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function deleteUser(username) {
  const { data } = await axios.post('api/user/delete', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function changePassword(username, password) {
  const { data } = await axios.post('api/user/change-password', formData({ username, password }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function fetchUserConfig(username) {
  const { data } = await axios.post('api/user/config/show', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data
}

export async function fetchUserCcd(username) {
  const { data } = await axios.post('api/user/ccd', formData({ username }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })
  return data // { Name, ClientAddress, CustomRoutes }
}

export async function applyCcd(ccd) {
  const { data } = await axios.post('api/user/ccd/apply', JSON.stringify(ccd), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}
