import js from '@eslint/js'
import pluginVue from 'eslint-plugin-vue'
import globals from 'globals'

export default [
  js.configs.recommended,
  ...pluginVue.configs['flat/recommended'],
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
      ecmaVersion: 'latest',
      sourceType: 'module',
    },
    rules: {
      // Allow unused vars prefixed with _
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      // Vue 3 recommends multi-word component names but we use single-word (App, Toast, Button, Input, Dialog, etc.)
      'vue/multi-word-component-names': 'off',
      // We use v-html consciously NOWHERE — but flag any future addition
      'vue/no-v-html': 'error',
    },
  },
  {
    ignores: [
      'node_modules/**',
      'static/**',
      'e2e/**',
      'playwright-report/**',
      'test-results/**',
    ],
  },
]
