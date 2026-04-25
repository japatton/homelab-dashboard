// ESLint flat config (ESLint 9+).
// Replaces the old .eslintrc cascade. One exported array, one entry per rule
// set — later entries override earlier ones.
//
// Targeted at a Vite + React + TS codebase with React Fast Refresh enabled.

import js from '@eslint/js'
import globals from 'globals'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'
import reactRefresh from 'eslint-plugin-react-refresh'

export default tseslint.config(
  // Ignore build output and dependency dirs
  { ignores: ['dist', 'node_modules', '.vite', 'build', 'coverage'] },

  // Base recommended sets — JS + TS
  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser },
    },
    plugins: {
      'react-hooks':   reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      // React Hooks best practices — these catch real bugs, so keep as errors
      ...reactHooks.configs.recommended.rules,

      // HMR correctness — warn only; noisy but useful during dev
      'react-refresh/only-export-components': [
        'warn',
        { allowConstantExport: true },
      ],

      // Relax a handful of TS rules that are too noisy for a personal homelab
      // codebase that isn't gated on lint. Tighten later if you want.
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': [
        'warn',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
)
