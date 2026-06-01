import { test, expect } from '@playwright/test'

// Helper: log in to the app.
async function login(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

// State-dependent file — must run BEFORE the server config is saved. The
// playwright project graph schedules this project first.
test.describe.configure({ mode: 'serial' })

test.describe('Server-init gate', () => {
  test('Users tab shows "Сервер не настроен" banner before config save', async ({ page }) => {
    await login(page)

    // Users tab is active by default.
    await expect(page.getByTestId('server-not-initialized-banner')).toBeVisible({ timeout: 5_000 })
    await expect(page.getByTestId('server-not-initialized-banner')).toContainText(/Сервер не настроен/)
  })

  test('"Добавить пользователя" button is disabled until server is saved', async ({ page }) => {
    await login(page)

    const addUserBtn = page.getByTestId('add-user-button')
    await expect(addUserBtn).toBeVisible()
    await expect(addUserBtn).toBeDisabled()
  })

  test('saving server config clears the "не настроен" banner', async ({ page }) => {
    await login(page)

    // Switch to "Сервер" tab.
    await page.getByRole('button', { name: 'Сервер' }).click()

    // Wait for config form to render.
    await expect(page.getByTestId('server-config-save')).toBeVisible({ timeout: 10_000 })

    // Save with the existing defaults — that's enough to flip Initialized=true.
    await page.getByTestId('server-config-save').click()

    // Success toast appears.
    await expect(page.locator('text=/Сохранено|Настройки сохранены/')).toBeVisible({ timeout: 10_000 })

    // Switch back to Users tab and verify the banner is gone.
    await page.getByRole('button', { name: 'Пользователи' }).click()
    await expect(page.getByTestId('server-not-initialized-banner')).toHaveCount(0)
  })
})
