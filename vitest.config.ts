import { configDefaults, defineConfig } from 'vitest/config';

import { coverageThresholds } from './tooling/coverage-thresholds.ts';
import { POSTGRES_IMAGES } from './tooling/test-db/postgres-images.ts';

/** Tests that need a real Postgres server (Rule Book §6): they run once for each version we support. */
const DATABASE_TESTS = '**/*.db.test.ts';

/** Tests that need the compose stack up (ADR-010 §7): run by `pnpm e2e`, never here. */
const END_TO_END_TESTS = '**/*.e2e.test.ts';

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['packages/*/src/**/*.test.{ts,tsx}', 'apps/*/src/**/*.test.{ts,tsx}'],
          exclude: [...configDefaults.exclude, DATABASE_TESTS],
        },
      },
      {
        test: {
          // Repository checks: the gate proofs, the settings and image checks, and the deploy helpers.
          name: 'repo-checks',
          include: ['tooling/**/*.test.ts', 'deploy/**/*.test.ts'],
          // The fixtures hold deliberately broken tests of their own. The end-to-end
          // suite needs the compose stack, so it has its own config (vitest.e2e.config.ts).
          exclude: [...configDefaults.exclude, 'tooling/gate-proofs/fixtures/**', DATABASE_TESTS, END_TO_END_TESTS],
          // Each proof runs a real tool (ESLint, tsc, knip, Vitest) on a broken fixture.
          testTimeout: 120_000,
          hookTimeout: 120_000,
        },
      },
      // One project per Postgres version, each with its own throwaway server (tooling/test-db).
      ...Object.keys(POSTGRES_IMAGES).map((name) => ({
        test: {
          name,
          // The same places the other projects look, so a database test is never left out.
          include: [`packages/*/src/${DATABASE_TESTS}`, `apps/*/src/${DATABASE_TESTS}`, `tooling/${DATABASE_TESTS}`],
          exclude: [...configDefaults.exclude, 'tooling/gate-proofs/fixtures/**'],
          globalSetup: ['tooling/test-db/global-setup.ts'],
          testTimeout: 30_000,
          hookTimeout: 60_000,
        },
      })),
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
