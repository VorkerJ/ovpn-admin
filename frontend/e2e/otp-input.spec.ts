import { test, expect, Page } from '@playwright/test'

// Helper: log in to the app.
async function login(page: Page) {
  await page.goto('/')
  await page.fill('input[placeholder="admin"]', 'admin')
  await page.fill('input[type="password"]', 'testpassword123')
  await page.click('button[type="submit"]')
  await expect(page.locator('header')).toContainText('OVPN Admin', { timeout: 10_000 })
}

// Open the MFA setup modal and navigate to the QR/OtpInput step. The OtpInput
// component is rendered by the modal — we test it in this real carrier rather
// than mounting it in isolation, so the test exercises the same code path the
// user sees.
async function openOtpInput(page: Page) {
  await login(page)
  // Click the header 2FA button. With --mfa.required=false the title is the
  // friendly "Двухфакторная аутентификация" label (no enforcement warning).
  await page.click('button[title="Двухфакторная аутентификация"]')
  await page.click('button:has-text("Включить 2FA")')
  await expect(page.locator('img[alt="QR code"]')).toBeVisible({ timeout: 10_000 })
  // The MFA setup modal's OtpInput is the first/only one on the page at this point.
  return page.getByTestId('otp-input').first()
}

test.describe('OtpInput component', () => {
  test('typing 6 digits one by one auto-advances focus', async ({ page }) => {
    await openOtpInput(page)

    for (let i = 0; i < 6; i++) {
      await page.getByTestId(`otp-cell-${i}`).pressSequentially(String(i + 1))
    }

    // All 6 cells filled with the typed digits.
    for (let i = 0; i < 6; i++) {
      await expect(page.getByTestId(`otp-cell-${i}`)).toHaveValue(String(i + 1))
    }
    // Focus landed on the last cell (no more advancement past the end).
    await expect(page.getByTestId('otp-cell-5')).toBeFocused()
  })

  test('Backspace on a filled cell clears it and keeps focus there', async ({ page }) => {
    await openOtpInput(page)

    await page.getByTestId('otp-cell-0').pressSequentially('1')
    // Auto-advance moved focus to cell 1; bring it back to cell 0.
    await page.getByTestId('otp-cell-0').focus()
    await page.keyboard.press('Backspace')

    await expect(page.getByTestId('otp-cell-0')).toHaveValue('')
    await expect(page.getByTestId('otp-cell-0')).toBeFocused()
  })

  test('Backspace on an empty cell moves to previous cell and clears it', async ({ page }) => {
    await openOtpInput(page)

    await page.getByTestId('otp-cell-0').pressSequentially('1')
    // After typing in cell 0, focus auto-advances to cell 1 which is empty.
    await expect(page.getByTestId('otp-cell-1')).toBeFocused()

    await page.keyboard.press('Backspace')

    // Previous cell was cleared and focus moved back to it.
    await expect(page.getByTestId('otp-cell-0')).toHaveValue('')
    await expect(page.getByTestId('otp-cell-0')).toBeFocused()
  })

  test('Pasting "123456" into first cell fills all 6 cells', async ({ page }) => {
    await openOtpInput(page)

    const firstCell = page.getByTestId('otp-cell-0')
    await firstCell.focus()

    // Use the clipboard API to paste real text via a paste event. We dispatch
    // a synthesized paste event on the container, which OtpInput handles.
    await page.evaluate(() => {
      const container = document.querySelector('[data-testid="otp-input"]') as HTMLElement
      const dt = new DataTransfer()
      dt.setData('text', '123456')
      const ev = new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })
      container.dispatchEvent(ev)
    })

    const values = ['1', '2', '3', '4', '5', '6']
    for (let i = 0; i < 6; i++) {
      await expect(page.getByTestId(`otp-cell-${i}`)).toHaveValue(values[i])
    }
    // Focus on the last cell after paste.
    await expect(page.getByTestId('otp-cell-5')).toBeFocused()
  })

  test('Arrow keys navigate between cells', async ({ page }) => {
    await openOtpInput(page)

    await page.getByTestId('otp-cell-0').focus()
    await page.keyboard.press('ArrowRight')
    await expect(page.getByTestId('otp-cell-1')).toBeFocused()

    await page.keyboard.press('ArrowRight')
    await expect(page.getByTestId('otp-cell-2')).toBeFocused()

    await page.keyboard.press('ArrowLeft')
    await expect(page.getByTestId('otp-cell-1')).toBeFocused()
  })

  test('Non-digit characters are filtered out', async ({ page }) => {
    await openOtpInput(page)

    const cell0 = page.getByTestId('otp-cell-0')
    await cell0.focus()
    // Press a letter — the input handler strips non-digits.
    await page.keyboard.type('a')
    await expect(cell0).toHaveValue('')

    // Now a digit goes in.
    await page.keyboard.type('7')
    await expect(cell0).toHaveValue('7')
  })
})
