import { configDefaults, defineConfig } from 'vitest/config';

import { coverageThresholds } from './tooling/coverage-thresholds.ts';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['packages/*/src/**/*.test.{ts,tsx}', 'apps/*/src/**/*.test.{ts,tsx}'],
        },
      },
      {
        test: {
          // Repository checks: the gate proofs and the SEC-SC-01 settings check.
          name: 'repo-checks',
          include: ['tooling/**/*.test.ts'],
          // The fixtures hold deliberately broken tests of their own.
          exclude: [...configDefaults.exclude, 'tooling/gate-proofs/fixtures/**'],
          // Each proof runs a real tool (ESLint, tsc, knip, Vitest) on a broken fixture.
          testTimeout: 120_000,
          hookTimeout: 120_000,
        },
      },
    ],
    coverage: {
      provider: 'v8',
      include: ['packages/*/src/**/*.{ts,tsx}', 'apps/*/src/**/*.{ts,tsx}'],
      exclude: ['**/*.test.{ts,tsx}'],
      reporter: ['text', 'json-summary'],
      thresholds: coverageThresholds,
    },
  },
});
