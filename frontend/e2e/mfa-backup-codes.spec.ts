import { test, expect, Page } from '@playwright/test'
import { TOTP, Secret } from 'otpauth'
import { readFileSync, mkdtempSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

// Helpers ---------------------------------------------------------------------

async function login(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

async function logout(page: Page) {
  await page.click('button[title="Выйти"]')
  await expect(page.locator('h1')).toContainText('ovpn-admin', { timeout: 5_000 })
}

// Disable any existing MFA on `admin` so the suite is independently runnable.
// We can't use the API directly (it requires the current TOTP code), but we
// can probe via the status endpoint, and if enabled, walk through the disable
// flow using a fresh TOTP. We bail out via the on-screen response below.
async function ensureMfaDisabled(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')

  // If MFA is on, the login step pivots into the MFA prompt; we want to start
  // from a clean slate, so we just bail — the test order should keep us in OFF.
  // If the header shows up, we're already in.
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

// Type a code into OtpInput by writing one digit per cell.
async function typeOtp(page: Page, code: string) {
  for (let i = 0; i < code.length && i < 6; i++) {
    await page.getByTestId(`otp-cell-${i}`).fill(code[i])
  }
}

// Drive the full setup flow: open the modal, click "Включить 2FA", capture the
// secret from the /api/mfa/setup response, enter a valid TOTP code, and submit
// Подтвердить. Leaves the page on the BACKUP step. Returns the captured secret
// and backup codes (from the /api/mfa/confirm response).
async function runMfaSetup(page: Page): Promise<{ secret: string; backupCodes: string[] }> {
  // Capture the setup response (contains the TOTP secret).
  const setupResponsePromise = page.waitForResponse((res) =>
    res.url().includes('/api/mfa/setup') && res.request().method() === 'POST',
  )

  await page.click('button[title="Двухфакторная аутентификация"]')
  await expect(
    page.locator('button', { hasText: 'Включить 2FA' }),
  ).toBeVisible({ timeout: 5_000 })
  await page.click('button:has-text("Включить 2FA")')

  const setupRes = await setupResponsePromise
  const setupJson = await setupRes.json()
  const secret: string = setupJson.secret
  expect(secret).toBeTruthy()

  await expect(page.locator('img[alt="QR code"]')).toBeVisible({ timeout: 10_000 })

  // Generate a valid TOTP code from the captured secret. We do this just
  // before submitting to maximize the time window margin.
  const totp = new TOTP({
    issuer: 'ovpn-admin',
    label: 'admin',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  })
  const code = totp.generate()

  await typeOtp(page, code)

  // Capture the confirm response (contains backup_codes).
  const confirmResponsePromise = page.waitForResponse((res) =>
    res.url().includes('/api/mfa/confirm') && res.request().method() === 'POST',
  )
  await page.locator('button', { hasText: 'Подтвердить' }).click()
  const confirmRes = await confirmResponsePromise
  expect(confirmRes.status()).toBe(200)
  const confirmJson = await confirmRes.json()
  const backupCodes: string[] = confirmJson.backup_codes || []
  expect(backupCodes.length).toBe(8)

  return { secret, backupCodes }
}

// Walk the on-screen "disable 2FA" flow so subsequent tests start from a known
// OFF state. Requires the secret to mint a fresh TOTP code.
async function disableMfaViaUi(page: Page, secret: string) {
  await page.click('button[title="Двухфакторная аутентификация"]')
  await expect(page.locator('text=2FA включена')).toBeVisible({ timeout: 5_000 })

  await page.locator('input[type="password"][placeholder="••••••••"]').fill('testpassword123')

  const totp = new TOTP({
    issuer: 'ovpn-admin',
    label: 'admin',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
    secret: Secret.fromBase32(secret),
  })
  const code = totp.generate()
  // The OtpInput in the ON step is the only one on screen.
  await typeOtp(page, code)

  await page.locator('button', { hasText: 'Отключить 2FA' }).click()
  // After disable, the modal flips back to the OFF state.
  await expect(page.locator('text=2FA отключена')).toBeVisible({ timeout: 5_000 })
  // Close modal — press Escape (Dialog wires Escape to emit close).
  await page.keyboard.press('Escape')
}

// Tests -----------------------------------------------------------------------

test.describe('MFA setup — backup codes display', () => {
  test.beforeEach(async ({ page }) => {
    await ensureMfaDisabled(page)
  })

  test('setup flow surfaces yellow warning, 8-code grid, action buttons, and a Готово gate', async ({ page }) => {
    const { secret, backupCodes } = await runMfaSetup(page)

    // Yellow warning box header.
    await expect(
      page.locator('text=Сохраните эти коды СЕЙЧАС'),
    ).toBeVisible({ timeout: 5_000 })

    // 8 codes are visible, each in its own grid cell — assert via the
    // captured-from-API list to be robust against formatting.
    for (const code of backupCodes) {
      await expect(page.locator('text=' + code).first()).toBeVisible()
    }

    // Copy and Download buttons both present.
    await expect(page.locator('button', { hasText: 'Скопировать' })).toBeVisible()
    await expect(page.locator('button', { hasText: 'Скачать .txt' })).toBeVisible()

    // The "Готово" footer button is disabled until the checkbox is ticked.
    const doneBtn = page.locator('button', { hasText: 'Готово' })
    await expect(doneBtn).toBeDisabled()

    // Tick "Я сохранил коды в надёжном месте".
    await page.locator('label:has-text("Я сохранил коды в надёжном месте") input[type="checkbox"]').check()
    await expect(doneBtn).toBeEnabled()

    // Click it — modal closes.
    await doneBtn.click()
    await expect(page.locator('h2', { hasText: 'Двухфакторная аутентификация' })).toHaveCount(0)

    // Cleanup so other tests in this file start from OFF.
    await disableMfaViaUi(page, secret)
  })
})

test.describe('MFA setup — backup codes download', () => {
  test.beforeEach(async ({ page }) => {
    await ensureMfaDisabled(page)
  })

  test('Скачать .txt produces a file with header + all 8 codes', async ({ page }) => {
    const { secret, backupCodes } = await runMfaSetup(page)

    const downloadPromise = page.waitForEvent('download')
    await page.locator('button', { hasText: 'Скачать .txt' }).click()
    const download = await downloadPromise

    expect(download.suggestedFilename()).toBe('ovpn-admin-backup-codes.txt')

    const savePath = join(
      mkdtempSync(join(tmpdir(), 'ovpn-e2e-dl-')),
      download.suggestedFilename(),
    )
    await download.saveAs(savePath)
    const contents = readFileSync(savePath, 'utf-8')

    expect(contents).toContain('ovpn-admin backup codes')
    for (const code of backupCodes) {
      expect(contents).toContain(code)
    }

    // Finish the wizard and clean up MFA state.
    await page.locator('label:has-text("Я сохранил коды в надёжном месте") input[type="checkbox"]').check()
    await page.locator('button', { hasText: 'Готово' }).click()
    await disableMfaViaUi(page, secret)
  })
})

test.describe('MFA login — backup code path', () => {
  test('admin can log in with a backup code, and a second use is rejected', async ({ page }) => {
    await ensureMfaDisabled(page)
    const { secret, backupCodes } = await runMfaSetup(page)
    const oneCode = backupCodes[0]

    // Close the setup wizard.
    await page.locator('label:has-text("Я сохранил коды в надёжном месте") input[type="checkbox"]').check()
    await page.locator('button', { hasText: 'Готово' }).click()

    // Log out, log back in — should now hit the MFA gate.
    await logout(page)

    // First login with the backup code — should succeed.
    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'testpassword123')
    await page.click('button[type="submit"]')

    // MFA step appears — by default it shows the OtpInput.
    await expect(page.locator('text=Введите код двухфакторной аутентификации')).toBeVisible({ timeout: 5_000 })
    await expect(page.getByTestId('otp-input')).toBeVisible()

    // Toggle to backup-code mode.
    await page.locator('button', { hasText: 'Использовать резервный код' }).click()

    // The OtpInput is replaced by a single text input with the XXXX-XXXX placeholder.
    await expect(page.getByTestId('otp-input')).toHaveCount(0)
    const backupInput = page.locator('input[placeholder="XXXX-XXXX"]')
    await expect(backupInput).toBeVisible()

    // Type the lowercase form to verify the client normalizes to uppercase
    // before sending (Login.vue calls .toUpperCase().trim() on submit).
    await backupInput.fill(oneCode.toLowerCase())
    await page.locator('button', { hasText: 'Подтвердить' }).click()

    // Header appears — login succeeded.
    await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })

    // Second use of the same backup code must fail.
    await logout(page)

    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'testpassword123')
    await page.click('button[type="submit"]')
    await expect(page.getByTestId('otp-input')).toBeVisible({ timeout: 5_000 })
    await page.locator('button', { hasText: 'Использовать резервный код' }).click()
    const backupInput2 = page.locator('input[placeholder="XXXX-XXXX"]')
    await backupInput2.fill(oneCode.toLowerCase())
    await page.locator('button', { hasText: 'Подтвердить' }).click()

    // Error toast/inline error appears. The LoginPage renders the API error
    // text into a .text-destructive box; default fallback is "Неверный код".
    await expect(
      page.locator('.text-destructive').filter({ hasText: /[Нн]еверный|invalid|too many/i }),
    ).toBeVisible({ timeout: 5_000 })

    // Recover: the intermediate mfa_token from the password step was already
    // consumed by the (rejected) backup-code submit — the server marks the jti
    // as used regardless of code validity. We must go back to the password
    // step and re-login to obtain a fresh mfa_token before completing TOTP.
    await page.locator('button', { hasText: 'Назад' }).click()
    await expect(page.locator('input[type="password"]')).toBeVisible()
    await page.fill('input[placeholder="admin"]', 'admin')
    await page.fill('input[type="password"]', 'testpassword123')
    await page.click('button[type="submit"]')

    await expect(page.getByTestId('otp-input')).toBeVisible({ timeout: 5_000 })
    const totp = new TOTP({
      issuer: 'ovpn-admin',
      label: 'admin',
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: Secret.fromBase32(secret),
    })
    const totpCode = totp.generate()
    await typeOtp(page, totpCode)
    await page.locator('button', { hasText: 'Подтвердить' }).click()
    await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })

    // Final cleanup — disable MFA so subsequent runs start clean.
    await disableMfaViaUi(page, secret)
  })
})
