// Lint rules for the whole repository (Rule Book §5, §7, §8). Every rule we add
// or tighten below has a broken snippet in tooling/gate-proofs/lint.test.ts
// that must keep failing.
import comments from '@eslint-community/eslint-plugin-eslint-comments/configs';
import eslint from '@eslint/js';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

import noStringBuiltSql from './tooling/eslint-rules/no-string-built-sql.js';

/** SEC-WEB-03: nothing may write raw HTML into the page. */
const rawHtmlInjection = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'SEC-WEB-03: raw HTML injection is banned. Render text through React instead.',
  },
  {
    selector: 'AssignmentExpression > MemberExpression.left[property.name=/^(innerHTML|outerHTML|srcdoc)$/]',
    message: 'SEC-WEB-03: raw HTML injection is banned. Set textContent instead.',
  },
  {
    selector:
      'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment|setHTMLUnsafe|parseHTMLUnsafe)$/]',
    message: 'SEC-WEB-03: raw HTML injection is banned.',
  },
  {
    selector: "CallExpression[callee.object.name='document'][callee.property.name=/^write(ln)?$/]",
    message: 'SEC-WEB-03: document.write is banned.',
  },
];

/**
 * ADR-006 §3: business code reads the time only through the injected Clock.
 * Building a Date from a known value (`new Date(ms)`) stays allowed.
 */
const wallClock = [
  {
    selector: "NewExpression[callee.name='Date'][arguments.length=0]",
    message: 'ADR-006: read business time from the injected Clock, not new Date().',
  },
  {
    selector: "CallExpression[callee.name='Date']",
    message: 'ADR-006: read business time from the injected Clock, not Date().',
  },
  {
    selector: "CallExpression[callee.object.name='Date'][callee.property.name='now']",
    message: 'ADR-006: read business time from the injected Clock, not Date.now().',
  },
  {
    selector: "MemberExpression[object.name='globalThis'][property.name='Date']",
    message: 'ADR-006: read business time from the injected Clock, not globalThis.Date.',
  },
];

export default defineConfig([
  globalIgnores([
    '**/node_modules/',
    '**/dist/',
    '**/coverage/',
    'Documents/',
    '.playwright-mcp/',
    'tooling/gate-proofs/fixtures/',
  ]),

  {
    linterOptions: {
      reportUnusedDisableDirectives: 'error',
      reportUnusedInlineConfigs: 'error',
    },
  },

  eslint.configs.recommended,
  comments.recommended,
  {
    rules: {
      // Rule Book §5: every eslint-disable carries a written reason.
      '@eslint-community/eslint-comments/require-description': ['error', { ignore: ['eslint-enable'] }],
      eqeqeq: ['error', 'always'],
      'no-new-func': 'error',
    },
  },

  {
    files: ['**/*.{ts,tsx}'],
    extends: [tseslint.configs.strictTypeChecked, tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/switch-exhaustiveness-check': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },

  {
    files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
    extends: [tseslint.configs.disableTypeChecked],
    languageOptions: { globals: globals.node },
  },

  // Product code: packages and apps.
  {
    files: ['packages/**/*.{ts,tsx}', 'apps/**/*.{ts,tsx}'],
    plugins: { agentx: { rules: { 'no-string-built-sql': noStringBuiltSql } } },
    rules: {
      'no-console': 'error',
      'agentx/no-string-built-sql': 'error',
      'no-restricted-syntax': ['error', ...rawHtmlInjection],
      'no-restricted-properties': [
        'error',
        { object: 'Math', property: 'random', message: 'Math.random is predictable. Use node:crypto.' },
      ],
    },
  },

  // Business code in core also takes its time from the Clock (ADR-006 §3).
  // Flat config replaces a rule's options per block, so the list is repeated.
  {
    files: ['packages/core/**/*.{ts,tsx}'],
    ignores: ['packages/core/src/shared-kernel/clock.ts'],
    rules: {
      'no-restricted-syntax': ['error', ...rawHtmlInjection, ...wallClock],
    },
  },
]);
