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

/** The hand-off, its fair turns and its bank breaker (4D2e Stage F): they send money, in the API's own folder. */
const MONEY_CRITICAL_API_GLOB = 'apps/api/src/{fair-lanes,rail-health,handoff,payment-checks}.ts';

/**
 * Each glob says perFile itself: since Vitest 5 a glob's entry no longer takes the top-level one, and would judge its
 * files as one average, so a well-tested money file could hide an untested one (S183; the gate proof caught it).
 */
const moneyCritical = { ...standard, branches: 95, perFile: true };

export const coverageThresholds = {
  perFile: true,
  ...standard,
  [MONEY_CRITICAL_GLOB]: moneyCritical,
  [MONEY_CRITICAL_API_GLOB]: moneyCritical,
};
