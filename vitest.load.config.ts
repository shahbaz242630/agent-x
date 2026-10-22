import { defineConfig } from 'vitest/config';

/**
 * The load test's seed and verify steps (tooling/load/run.ts, Phase 4 D2):
 * they need the load stack up, so `corepack pnpm load` runs them, one at a
 * time, and the ordinary test run (vitest.config.ts) never picks them up.
 */
export default defineConfig({
  test: {
    name: 'load',
    include: ['tooling/load/*.load.test.ts'],
    fileParallelism: false,
    testTimeout: 600_000,
    hookTimeout: 120_000,
  },
});
