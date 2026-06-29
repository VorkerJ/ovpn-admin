import axios from 'axios'

export async function fetchUsers() {
  const { data } = await axios.get('api/users/list')
  return Array.isArray(data) ? data : []
}

export async function fetchTraffic(month) {
  const { data } = await axios.get('api/traffic', { params: month ? { month } : {} })
  // New shape: { month, months, rows }. Tolerate the old array shape too.
  if (Array.isArray(data)) return { month: '', months: [], rows: data }
  return { month: data?.month || '', months: data?.months || [], rows: data?.rows || [] }
}

export async function fetchServerSettings() {
  const { data } = await axios.get('api/server/settings')
  return data // { modules, serverInitialized, adminMfaEnabled, adminMfaRequired }
}

export async function createUser(username, password) {
  const { data } = await axios.post('api/user/create', JSON.stringify({ username, password }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function revokeUser(username) {
  const { data } = await axios.post('api/user/revoke', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function unrevokeUser(username) {
  const { data } = await axios.post('api/user/unrevoke', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function rotateUser(username, password) {
  const { data } = await axios.post('api/user/rotate', JSON.stringify({ username, password }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function deleteUser(username) {
  const { data } = await axios.post('api/user/delete', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function changePassword(username, password) {
  const { data } = await axios.post('api/user/change-password', JSON.stringify({ username, password }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function fetchUserConfig(username) {
  const { data } = await axios.post('api/user/config/show', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function fetchUserCcd(username) {
  const { data } = await axios.post('api/user/ccd', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { Name, ClientAddress, CustomRoutes }
}

export async function applyCcd(ccd) {
  const { data } = await axios.post('api/user/ccd/apply', JSON.stringify(ccd), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function fetchCommonRoutes() {
  const { data } = await axios.get('api/common-routes')
  return data // { routes: [...], refreshIntervalHours: 24 }
}

export async function createCommonRoute(payload) {
  const { data } = await axios.post('api/common-routes', JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data.route
}

export async function updateCommonRoute(id, payload) {
  const { data } = await axios.put(`api/common-routes/${id}`, JSON.stringify(payload), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data.route
}

export async function deleteCommonRoute(id) {
  await axios.delete(`api/common-routes/${id}`)
}

export async function refreshCommonRoutesDns() {
  const { data } = await axios.post('api/common-routes/refresh')
  return data // { resolved, failed, changed }
}

export async function refreshUserCcdDns(username) {
  const { data } = await axios.post('api/user/ccd/refresh', JSON.stringify({ username }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { changed, resolved, failed }
}

export async function importCommonRoutes(text) {
  const { data } = await axios.post('api/common-routes/import', JSON.stringify({ text }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { added: [...], skipped: [...], errors: [...] }
}

export async function importUserCcd(username, text) {
  const { data } = await axios.post('api/user/ccd/import', JSON.stringify({ username, text }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function fetchServerConfig() {
  const { data } = await axios.get('api/server-config')
  return data // { config, dco_available }
}

export async function updateServerConfig(cfg) {
  const { data } = await axios.put('api/server-config', JSON.stringify(cfg), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { config, reload_kind }
}

export async function testServerConfig(cfg) {
  const { data } = await axios.post('api/server-config/test', JSON.stringify(cfg), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { valid, errors }
}

export async function fetchServerConfigDefaults() {
  const { data } = await axios.get('api/server-config/defaults')
  return data
}

export async function adminChangePassword(currentPassword, newPassword) {
  const { data } = await axios.post(
    'api/admin/change-password',
    JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    { headers: { 'Content-Type': 'application/json' } },
  )
  return data
}

export async function fetchApiTokens() {
  const { data } = await axios.get('api/api-tokens')
  return Array.isArray(data) ? data : []
}

export async function createApiToken(name) {
  const { data } = await axios.post('api/api-tokens', JSON.stringify({ name }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data // { id, name, token, hint, created_at }
}

export async function revokeApiToken(id) {
  await axios.delete(`api/api-tokens/${id}`)
}

export async function loginMfa(mfaToken, code) {
  const { data } = await axios.post('api/login/mfa', JSON.stringify({ mfa_token: mfaToken, code }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function fetchMfaStatus() {
  const { data } = await axios.get('api/mfa/status')
  return data
}

export async function setupMfa() {
  const { data } = await axios.post('api/mfa/setup')
  return data
}

export async function confirmMfa(code) {
  const { data } = await axios.post('api/mfa/confirm', JSON.stringify({ code }), {
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}

export async function disableMfa(password, code) {
  const { data } = await axios.delete('api/mfa', {
    data: JSON.stringify({ password, code }),
    headers: { 'Content-Type': 'application/json' },
  })
  return data
}
