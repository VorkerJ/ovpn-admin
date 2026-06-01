import { test, expect, Page } from '@playwright/test'

// The test backend runs with --mfa.required=false so write operations work
// without enrolling MFA. To verify the UI's enforcement layer (banner, pulse
// dot, disabled add-user button), we override the /api/server/settings
// response to look as if the gate were active.
async function pretendMfaRequired(page: Page) {
  await page.route('**/api/server/settings', async (route) => {
    const response = await route.fetch()
    const body = await response.json()
    body.adminMfaRequired = true
    body.adminMfaEnabled = false
    // Keep serverInitialized as-is so we isolate the MFA-gate signal.
    body.serverInitialized = true
    await route.fulfill({
      response,
      json: body,
    })
  })
}

async function login(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

test.describe('MFA enforcement gate', () => {
  test.beforeEach(async ({ page }) => {
    await pretendMfaRequired(page)
    await login(page)
  })

  test('orange MFA banner is visible when admin has no 2FA', async ({ page }) => {
    const banner = page.getByTestId('admin-mfa-banner')
    await expect(banner).toBeVisible({ timeout: 5_000 })
    await expect(banner).toContainText(/Включите двухфакторную аутентификацию/)
  })

  test('"Включить" button on the banner opens the MFA modal', async ({ page }) => {
    const banner = page.getByTestId('admin-mfa-banner')
    await expect(banner).toBeVisible({ timeout: 5_000 })
    await banner.getByRole('button', { name: 'Включить' }).click()

    // Modal title appears.
    await expect(page.locator('h2', { hasText: 'Двухфакторная аутентификация' })).toBeVisible({ timeout: 5_000 })
  })

  test('header 2FA icon shows an orange pulsing dot when MFA is off', async ({ page }) => {
    await expect(page.getByTestId('admin-mfa-dot')).toBeVisible()
    await expect(page.getByTestId('admin-mfa-dot')).toHaveClass(/animate-pulse/)
  })

  test('"Добавить пользователя" disabled with MFA tooltip', async ({ page }) => {
    const addUserBtn = page.getByTestId('add-user-button')
    await expect(addUserBtn).toBeDisabled()
    await expect(addUserBtn).toHaveAttribute('title', /Включите 2FA/)
  })

  test('clicking 2FA icon opens MFA modal in OFF state', async ({ page }) => {
    await page.click('button[title="Включите 2FA — без неё write-операции запрещены"]')

    await expect(page.locator('h2', { hasText: 'Двухфакторная аутентификация' })).toBeVisible({ timeout: 5_000 })
    // OFF-state hint and the "Включить 2FA" button.
    await expect(page.locator('text=2FA отключена')).toBeVisible()
    await expect(page.locator('button', { hasText: 'Включить 2FA' })).toBeVisible()
  })

  test('starting setup shows QR but NOT the manual secret, and OTP input has 6 cells', async ({ page }) => {
    await page.click('button[title="Включите 2FA — без неё write-операции запрещены"]')
    await page.click('button:has-text("Включить 2FA")')

    // QR code is rendered.
    await expect(page.locator('img[alt="QR code"]')).toBeVisible({ timeout: 10_000 })

    // Manual entry of the TOTP secret was intentionally removed — it must not
    // appear in the DOM.
    await expect(page.locator('text=Или введите ключ вручную')).toHaveCount(0)

    // OtpInput has exactly 6 cells.
    const cells = page.locator('[data-testid^="otp-cell-"]')
    await expect(cells).toHaveCount(6)
  })
})
