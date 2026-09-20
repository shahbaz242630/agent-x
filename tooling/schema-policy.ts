import { SCHEMA_POLICY as PRODUCT_POLICY } from '../packages/platform/src/db/schema-policy.ts';
import type { SchemaPolicy } from '../packages/testing/src/index.ts';

/**
 * CI-06's decisions about our schema (ADR-005 §6, §8, §9), checked on every run
 * against db/migrations (tooling/checks/database-schema.db.test.ts).
 *
 * **The decisions themselves live in the product**, in
 * `@agentx/platform/db`'s schema-policy.ts, because the live schema guard
 * (A3e-1b) checks the running database against the same list as the app role,
 * and a second copy here would be free to drift from it — the mistake A3c-2
 * set out to make impossible. This file only hands it to the CI checks.
 *
 * The annotation is the proof that the two shapes still fit: @agentx/testing
 * declares its own `SchemaPolicy` because it must not depend on
 * @agentx/platform (that way round is the workspace cycle removed in S28), so
 * this assignment is where a change to either shape is caught, at compile time.
 */
export const SCHEMA_POLICY: SchemaPolicy = PRODUCT_POLICY;
