import { test, expect, Page, request as playwrightRequest } from '@playwright/test'

const ADMIN_USER = 'admin'
const ADMIN_PASS = 'testpassword123'

async function login(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', ADMIN_USER)
  await page.fill('input[type="password"]', ADMIN_PASS)
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

test.describe('API auth gate (unauthenticated)', () => {
  test('without a session cookie, write/read endpoints reject', async () => {
    // Use a fresh API context with NO cookies — must NOT inherit the test
    // browser's auth state. This proves auth gating, not a UI bug.
    const api = await playwrightRequest.newContext({ baseURL: 'http://127.0.0.1:8089' })

    // GET endpoints behind auth — must 401
    for (const url of [
      '/api/server-config',
      '/api/users/list',
      '/api/auth/check',
    ]) {
      const res = await api.get(url)
      expect(res.status(), `GET ${url} should require auth`).toBe(401)
    }

    // POST/PUT endpoints behind auth — must 401
    const ccdApply = await api.post('/api/user/ccd/apply', {
      data: { User: 'whoever', ClientAddress: 'dynamic', CustomRoutes: [] },
    })
    expect(ccdApply.status(), 'POST /api/user/ccd/apply without auth').toBe(401)

    const cfgPut = await api.put('/api/server-config', {
      data: { proto: 'udp', port: 1194 },
    })
    expect(cfgPut.status(), 'PUT /api/server-config without auth').toBe(401)

    await api.dispose()
  })

  test('after logout, the session cookie no longer authorises API calls', async ({ page }) => {
    await login(page)

    // Confirm we ARE authenticated first (sanity).
    const before = await page.request.get('/api/auth/check')
    expect(before.status()).toBe(200)

    // Logout button — find the icon-only LogOut control in the header.
    await page.locator('header button[title="Выйти"], header button[aria-label="Logout"]').first().click()
    // We should see the login page again.
    await expect(page.locator('input[type="password"]')).toBeVisible({ timeout: 5_000 })

    // Now an API call from the same browser should fail.
    const after = await page.request.get('/api/auth/check')
    expect(after.status(), 'API should reject after logout').toBe(401)
  })
})

test.describe('User settings modal — full-tunnel + per-user exclusions', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('toggling full-tunnel + adding a per-user exclusion persists to the CCD', async ({ page }) => {
    // Pick the first user row's action menu. Tests run against a fresh
    // server with no real PKI users — UsersTable shows "Пользователи не
    // найдены" in that case. Inject a fake user list via route stub so the
    // modal opens against deterministic data; the API call we assert on
    // (POST /api/user/ccd/apply) still hits the real backend.
    await page.route('**/api/users/list', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            Identity: 'e2e-saada',
            AccountStatus: 'Active',
            ExpirationDate: '2028-01-01 00:00:00',
            RevocationDate: '',
            ConnectionStatus: 'Disconnected',
            Connections: 0,
          },
        ]),
      })
    })

    // Stub the modules check so the "Настройки" (CCD) action shows up.
    await page.route('**/api/server/settings', async (route) => {
      // Pass through to the real backend but ensure ccd is included.
      const real = await route.fetch()
      const body = await real.json()
      body.modules = Array.from(new Set([...(body.modules || []), 'ccd']))
      body.initialized = true
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(body),
      })
    })

    await page.goto('/')
    await expect(page.locator('text=e2e-saada')).toBeVisible({ timeout: 10_000 })

    // Open the action menu and click "Настройки".
    const row = page.locator('tr', { hasText: 'e2e-saada' })
    await row.locator('button').last().click()
    await page.getByRole('button', { name: /Настройки/ }).click()

    // The modal should open with three tabs.
    await expect(page.getByRole('button', { name: 'Подключение' })).toBeVisible({ timeout: 5_000 })
    await expect(page.getByRole('button', { name: /Маршруты/ })).toBeVisible()
    await expect(page.getByRole('button', { name: /Исключения/ })).toBeVisible()

    // === Tab: Подключение ===
    await page.getByRole('button', { name: 'Подключение', exact: true }).click()
    await expect(page.locator('text=Полный туннель')).toBeVisible()

    await page.locator('span', { hasText: 'Полный туннель' }).first().click()
    const fullTunnel = page.locator('label', { hasText: 'Полный туннель' }).locator('input[type="checkbox"]')
    await expect(fullTunnel).toBeChecked()
    // Sanity probe — confirm the checkbox stays checked AFTER we switch tabs
    // (catches a regression where switching tabs somehow resets local state).
    await page.getByRole('button', { name: /Исключения/ }).click()
    await page.getByRole('button', { name: 'Подключение', exact: true }).click()
    await expect(fullTunnel, 'flag must survive tab switch').toBeChecked()

    // === Tab: Исключения ===
    await page.getByRole('button', { name: /Исключения/ }).click()

    // The empty-state row must be visible before we add anything.
    await expect(page.locator('text=Нет персональных исключений')).toBeVisible()

    // Fill the add form. Other tabs are v-show=false but still in DOM, so
    // we scope locators to the exclusion row (parent of the unique 10.42.0.0
    // placeholder) to avoid picking up the routes-tab inputs by accident.
    const exAddr = page.locator('input[placeholder="10.42.0.0"]')
    const exRow = exAddr.locator('..')
    const exMask = exRow.locator('input[placeholder="255.255.255.0"]')
    const exDesc = exRow.locator('input[placeholder="Описание (опционально)"]')
    await exAddr.fill('10.42.0.0')
    await exMask.fill('255.255.0.0')
    await exDesc.fill('Work VPN')

    // The Add button is the icon-only Plus inside the same row.
    await exRow.locator('button', { hasText: 'Добавить' }).click()

    // The new row should land in the table.
    await expect(page.locator('text=10.42.0.0').first()).toBeVisible()
    await expect(page.locator('text=Work VPN').first()).toBeVisible()

    // Save. Wait for the actual POST /api/user/ccd/apply to settle so the
    // round-trip below is guaranteed to see persisted state (not racing).
    const savePromise = page.waitForResponse(
      (r) => r.url().includes('/api/user/ccd/apply') && r.request().method() === 'POST',
    )
    await page.getByRole('button', { name: 'Сохранить' }).click()
    const saveResp = await savePromise
    expect(saveResp.status(), 'save must succeed').toBe(200)

    // Sanity-check the request body actually carried our toggle. If this
    // passes but the GET below fails, the bug is in render/parse on the
    // backend; if this fails, the bug is in the modal's data binding.
    const sentBody = JSON.parse(saveResp.request().postData() || '{}')
    console.log('SENT BODY:', JSON.stringify(sentBody, null, 2))
    expect(sentBody.RedirectGateway, 'modal must POST RedirectGateway=true').toBe(true)
    expect(sentBody.RedirectGatewayExclusions?.length, 'modal must POST per-user exclusion').toBeGreaterThan(0)

    // === Verify via API: parseCcd should return our flag + exclusion ===
    const res = await page.request.post('/api/user/ccd', {
      data: { username: 'e2e-saada' },
    })
    expect(res.ok(), 'GET ccd after save').toBeTruthy()
    const ccd = await res.json()
    expect(ccd.RedirectGateway, 'RedirectGateway should round-trip true').toBe(true)
    expect(Array.isArray(ccd.RedirectGatewayExclusions)).toBe(true)
    const personal = ccd.RedirectGatewayExclusions.find(
      (e: { address: string }) => e.address === '10.42.0.0',
    )
    expect(personal, 'per-user exclusion should round-trip').toBeTruthy()
    expect(personal!.mask).toBe('255.255.0.0')
    expect(personal!.description).toBe('Work VPN')
  })

  test('exclusion validation rejects garbage (host bits set)', async ({ page }) => {
    // Direct API path — proves backend validation, independent of the UI form.
    const res = await page.request.post('/api/user/ccd/apply', {
      data: {
        User: 'e2e-saada-2',
        ClientAddress: 'dynamic',
        CustomRoutes: [],
        RedirectGateway: true,
        RedirectGatewayExclusions: [
          // host bits set under /16 — canonical would be 192.168.0.0
          { address: '192.168.0.5', mask: '255.255.0.0', description: '' },
        ],
      },
    })
    expect(res.status(), 'invalid exclusion must be rejected').toBe(422)
    const body = await res.text()
    expect(body).toMatch(/host bits/i)
  })
})
