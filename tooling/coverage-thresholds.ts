// Coverage floors from Rule Book §6. vitest.config.ts enforces them, and a gate
// proof checks that a file below them fails the run. They apply to every file
// on its own, so a well-tested file can't hide an untested one in an average.

const standard = { lines: 90, functions: 90, statements: 90, branches: 85 };

/**
 * Money-critical modules need at least 95% branch coverage: policy, limits,
 * approvals, instructions and idempotency (owned by spend-requests), plus the
 * hand-off and outcome orchestrators that move and settle money.
 */
export const MONEY_CRITICAL_GLOB =
  'packages/core/src/modules/{policies,limit-reservations,approvals,instructions,spend-requests,handoff,outcomes}/**';

export const coverageThresholds = {
  perFile: true,
  ...standard,
  [MONEY_CRITICAL_GLOB]: { ...standard, branches: 95 },
};
