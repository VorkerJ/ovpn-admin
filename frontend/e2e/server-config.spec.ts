import { test, expect, Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

async function openServerConfigTab(page: Page) {
  await page.getByRole('button', { name: 'Сервер' }).click()
  await expect(page.getByTestId('server-config-save')).toBeVisible({ timeout: 10_000 })
}

test.describe('Server config view', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
    await openServerConfigTab(page)
  })

  test('Reset and Save buttons are visible', async ({ page }) => {
    await expect(page.getByTestId('server-config-reset')).toBeVisible()
    await expect(page.getByTestId('server-config-save')).toBeVisible()
  })

  test('Reset and Save buttons have the same height (regression: size consistency)', async ({ page }) => {
    const reset = page.getByTestId('server-config-reset')
    const save = page.getByTestId('server-config-save')

    const [r, s] = await Promise.all([reset.boundingBox(), save.boundingBox()])
    expect(r, 'reset button has no bounding box').not.toBeNull()
    expect(s, 'save button has no bounding box').not.toBeNull()

    // Both Buttons use size="sm" → same height. Allow 1px tolerance for
    // sub-pixel rendering.
    expect(Math.abs(r!.height - s!.height)).toBeLessThanOrEqual(1)
  })

  test('changing proto and saving shows success toast and persists', async ({ page }) => {
    // The default proto is 'udp' (from defaultServerConfig).
    const protoSelect = page.locator('select').filter({ hasText: 'UDP' }).first()
    await expect(protoSelect).toBeVisible()

    // Switch to tcp.
    await protoSelect.selectOption('tcp')
    await page.getByTestId('server-config-save').click()

    // Success toast — accept any of the three success messages.
    await expect(page.locator('text=/Сохранено|Настройки сохранены/')).toBeVisible({ timeout: 10_000 })

    // Verify persistence via the API: fetch the config and check proto.
    const res = await page.request.get('/api/server-config')
    expect(res.ok()).toBeTruthy()
    const body = await res.json()
    expect(body.config.proto).toBe('tcp')

    // Reload the page and re-open the tab — the select should still show TCP.
    await page.reload()
    await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
    await openServerConfigTab(page)
    const reloadedSelect = page.locator('select').filter({ hasText: 'TCP' }).first()
    await expect(reloadedSelect).toBeVisible()
    await expect(reloadedSelect).toHaveValue('tcp')
  })
})
