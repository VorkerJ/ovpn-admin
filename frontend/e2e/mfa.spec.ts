import { test, expect } from '@playwright/test'

// Helper: log in to the app
async function login(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

test.describe('MFA / TOTP', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('MFA button is visible in header', async ({ page }) => {
    // The shield icon button with title="Двухфакторная аутентификация"
    await expect(
      page.locator('button[title="Двухфакторная аутентификация"]'),
    ).toBeVisible()
  })

  test('MFA modal opens and shows 2FA disabled state', async ({ page }) => {
    await page.click('button[title="Двухфакторная аутентификация"]')

    // Modal title
    await expect(
      page.locator('text=Двухфакторная аутентификация'),
    ).toBeVisible({ timeout: 5_000 })

    // Should show "2FA отключена" since admin has no TOTP configured
    await expect(
      page.locator('text=2FA отключена'),
    ).toBeVisible({ timeout: 5_000 })

    // "Включить 2FA" button should be present
    await expect(
      page.locator('button', { hasText: 'Включить 2FA' }),
    ).toBeVisible()
  })

  test('MFA setup generates QR code and shows secret', async ({ page }) => {
    await page.click('button[title="Двухфакторная аутентификация"]')

    // Wait for modal to load MFA status
    await expect(
      page.locator('button', { hasText: 'Включить 2FA' }),
    ).toBeVisible({ timeout: 5_000 })

    // Click "Включить 2FA"
    await page.click('button:has-text("Включить 2FA")')

    // Should show QR code image
    await expect(
      page.locator('img[alt="QR code"]'),
    ).toBeVisible({ timeout: 10_000 })

    // Should show the manual secret key
    await expect(
      page.locator('text=Или введите ключ вручную'),
    ).toBeVisible()

    // Confirmation code input should be visible
    await expect(
      page.locator('input[placeholder="000000"]'),
    ).toBeVisible()
  })
})
