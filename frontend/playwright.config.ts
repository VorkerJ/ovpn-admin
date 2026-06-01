import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  timeout: 30000,
  retries: 0,
  // One worker — the backend has a 5-attempt login rate limit per IP, and
  // parallel workers all hit the limit from 127.0.0.1.
  workers: 1,
  fullyParallel: false,
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  use: {
    baseURL: 'http://127.0.0.1:8089',
    headless: true,
    screenshot: 'only-on-failure',
  },
  // Tests share a single backend process, so persisted state (Initialized=true)
  // leaks between files. server-init-gate.spec.ts MUST run first — it
  // verifies the "сервер не настроен" banner which disappears the moment any
  // test saves server-config. We model this as a project dependency.
  projects: [
    {
      name: 'server-init-gate',
      testMatch: /server-init-gate\.spec\.ts/,
      use: { browserName: 'chromium' },
    },
    {
      name: 'rest',
      testIgnore: /server-init-gate\.spec\.ts/,
      dependencies: ['server-init-gate'],
      use: { browserName: 'chromium' },
    },
  ],
})
