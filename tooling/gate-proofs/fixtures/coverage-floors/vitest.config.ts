// Runs only inside the coverage gate proof, with the real thresholds.
import { defineConfig } from 'vitest/config';

import { coverageThresholds } from '../../../coverage-thresholds.ts';

export default defineConfig({
  test: {
    include: ['**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['**/*.ts'],
      exclude: ['**/*.test.ts', 'vitest.config.ts'],
      reporter: ['text'],
      thresholds: coverageThresholds,
    },
  },
});
