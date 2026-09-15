import { defineConfig } from 'vitest/config';

/**
 * The end-to-end suite (ADR-010 §7; Security-Test-Catalogue layer E): it runs
 * against the compose stack in deploy/compose, which must be up, with a real
 * browser. `pnpm e2e` runs it, locally and in CI's "End to end" job; the
 * ordinary test run (vitest.config.ts) never picks these files up.
 */
export default defineConfig({
  test: {
    name: 'e2e',
    include: ['tooling/e2e/**/*.e2e.test.ts'],
    globalSetup: ['tooling/e2e/global-setup.ts'],
    // The OIDC callback listens on one fixed port, so files run one at a time.
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 180_000,
  },
});
