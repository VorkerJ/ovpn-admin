import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test('shows login page when not authenticated', async ({ page }) => {
    await page.goto('/')

    // Login page has the title "ovpn-admin"
    await expect(page.locator('h1')).toContainText('ovpn-admin')

    // Both username and password inputs are visible
    await expect(page.locator('input[placeholder="admin"]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()

    // Login button is visible
    await expect(page.locator('button[type="submit"]')).toContainText('Войти')
  })

  test('login with valid credentials', async ({ page }) => {
    await page.goto('/')

    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'testpassword123')
    await page.click('button[type="submit"]')

    // After successful login, the AppHeader should appear with "OVPN Admin"
    await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
  })

  test('login with wrong password shows error', async ({ page }) => {
    await page.goto('/')

    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'wrongpassword')
    await page.click('button[type="submit"]')

    // The error message from LoginPage.vue: "Неверный логин или пароль"
    await expect(
      page.locator('.text-destructive', { hasText: /[Нн]еверный логин или пароль/ }),
    ).toBeVisible({ timeout: 5_000 })
  })

  test('login with empty password shows validation error', async ({ page }) => {
    await page.goto('/')

    await page.fill('input[placeholder="admin"]', 'admin')
    // Leave password empty
    await page.click('button[type="submit"]')

    // Client-side validation: "Введите пароль"
    await expect(
      page.locator('.text-destructive', { hasText: 'Введите пароль' }),
    ).toBeVisible({ timeout: 5_000 })
  })

  test('logout returns to login page', async ({ page }) => {
    // Login first
    await page.goto('/')
    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'testpassword123')
    await page.click('button[type="submit"]')
    await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })

    // Click logout button (title="Выйти")
    await page.click('button[title="Выйти"]')

    // Should be back on login page
    await expect(page.locator('h1')).toContainText('ovpn-admin', { timeout: 5_000 })
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })
})
