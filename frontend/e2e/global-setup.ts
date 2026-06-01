import { execFileSync, spawn } from 'child_process'
import { mkdtempSync, writeFileSync, mkdirSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'

export default async function globalSetup() {
  const tmp = mkdtempSync(join(tmpdir(), 'ovpn-e2e-'))

  // Create required dirs
  mkdirSync(join(tmp, 'easyrsa', 'pki'), { recursive: true })
  mkdirSync(join(tmp, 'ccd'), { recursive: true })
  writeFileSync(join(tmp, 'easyrsa', 'pki', 'index.txt'), '')

  // Generate a self-signed CA cert (needed by setState -> getOvpnCaCertExpireDate)
  const caKeyPath = join(tmp, 'easyrsa', 'pki', 'ca.key')
  const caCrtPath = join(tmp, 'easyrsa', 'pki', 'ca.crt')
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec',
    '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-keyout', caKeyPath,
    '-out', caCrtPath,
    '-days', '3650', '-nodes',
    '-subj', '/CN=E2E Test CA',
  ], { stdio: 'pipe' })

  // Create htpasswd with test credentials (bcrypt)
  const htpasswdOutput = execFileSync('htpasswd', ['-nbB', 'admin', 'testpassword123'], {
    encoding: 'utf-8',
  }).trim()
  writeFileSync(join(tmp, 'htpasswd'), htpasswdOutput + '\n')

  // Build Go binary
  const projectRoot = join(__dirname, '..', '..')
  console.log('[e2e] Building Go binary...')
  execFileSync('go', ['build', '-o', join(tmp, 'ovpn-admin'), '.'], {
    cwd: projectRoot,
    stdio: 'pipe',
    timeout: 120_000,
  })
  console.log('[e2e] Go binary built.')

  // Start server
  // Note: mgmtSetTimeFormat will retry 10 times (2s each) to connect to
  // the non-existent mgmt socket on 19999, then give up and continue.
  // Total startup delay: ~20 seconds.
  //
  // Boolean flags (--firewall, --server-config, --common-routes, --ccd) use
  // kingpin Bool() and cannot be set to false via CLI args. We use env vars instead.
  //
  // server-config IS enabled so the server-init-gate and server-config e2e tests
  // can exercise the real flow. We override OVPN_SERVER_CONFIG_PATH so the
  // initial render writes into the temp dir, not /etc/openvpn.
  const server = spawn(join(tmp, 'ovpn-admin'), [
    '--listen.host=127.0.0.1',
    '--listen.port=8089',
    '--easyrsa.path=' + join(tmp, 'easyrsa'),
    '--ccd.path=' + join(tmp, 'ccd'),
    '--admin.htpasswd-file=' + join(tmp, 'htpasswd'),
    '--mfa',
    '--mfa.db-path=' + join(tmp, 'mfa.json'),
    // MFA gate is OFF (set via OVPN_MFA_REQUIRED env, since kingpin Bool can't
    // accept --flag=false on the CLI) — backend lets write ops through
    // without MFA. UI-level enforcement assertions (banner, pulse dot,
    // disabled add-user) use Playwright route interception to inject the
    // gating flags.
    '--master.sync-token=e2e-test-sync-token-please-replace-in-prod',
    '--ovpn.server=127.0.0.1:1194:udp',
    '--mgmt=main=127.0.0.1:19999',
    '--log.level=warn',
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
    env: {
      ...process.env,
      OVPN_FIREWALL: 'false',
      OVPN_SERVER_CONFIG: 'true',
      OVPN_SERVER_CONFIG_PATH: join(tmp, 'server.conf'),
      OVPN_COMMON_ROUTES: 'false',
      OVPN_CCD: 'false',
      // Disable MFA enforcement at the gate level — see comment above.
      OVPN_MFA_REQUIRED: 'false',
      // Tests run over plain http://127.0.0.1 — Secure-flagged cookies would
      // be dropped by the browser. Mark cookies insecure for the test server.
      OVPN_INSECURE_COOKIES: 'true',
    },
  })

  // Log server output for debugging
  server.stdout?.on('data', (d: Buffer) => process.stdout.write('[server] ' + d.toString()))
  server.stderr?.on('data', (d: Buffer) => process.stderr.write('[server] ' + d.toString()))

  // Store PID and tmpdir for teardown
  process.env.E2E_SERVER_PID = String(server.pid)
  process.env.E2E_TMPDIR = tmp

  // Unref so the parent process can exit even if child is alive (teardown will kill it)
  server.unref()

  // Wait for server to become ready
  console.log('[e2e] Waiting for server (may take ~20s for mgmt timeout)...')
  const deadline = Date.now() + 90_000 // 90 seconds
  while (Date.now() < deadline) {
    try {
      const res = await fetch('http://127.0.0.1:8089/ping')
      if (res.ok) {
        console.log('[e2e] Server ready!')
        return
      }
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, 1000))
  }

  // If we get here, kill the server and fail
  try { process.kill(server.pid!, 'SIGTERM') } catch {}
  throw new Error('Server failed to start within 90 seconds')
}
