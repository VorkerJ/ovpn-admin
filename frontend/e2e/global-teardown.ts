import { rmSync } from 'fs'

export default async function globalTeardown() {
  const pid = process.env.E2E_SERVER_PID
  if (pid) {
    try {
      // Kill the process group (detached process)
      process.kill(-Number(pid), 'SIGTERM')
    } catch {
      try {
        process.kill(Number(pid), 'SIGTERM')
      } catch {
        // already dead
      }
    }
  }

  // Clean up temp directory
  const tmp = process.env.E2E_TMPDIR
  if (tmp) {
    try {
      rmSync(tmp, { recursive: true, force: true })
    } catch {
      // best-effort cleanup
    }
  }
}
