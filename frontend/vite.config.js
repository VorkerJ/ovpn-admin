import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

export default defineConfig({
  // Audit F41: emit RELATIVE asset URLs (./assets/…) so the SPA works when
  // served under a non-root base path (OVPN_LISTEN_BASE_URL, e.g. /admin/).
  // With the default absolute '/assets/…' the JS/CSS 404 behind a prefix.
  base: './',
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    outDir: 'static',
    emptyOutDir: false,
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8080',
    },
  },
})
