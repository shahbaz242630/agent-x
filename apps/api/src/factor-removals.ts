// Resets of lost second factors carried out, as the API runs it (ADR-003 §4,
// ADR-012 §8; SEC-OPS-04; B6-3c): the identity module's job, removing the
// person's second factors at the login service with the reset token (a
// service user of its own, with the organisation's Org User Manager role) on
// a timer of its own, in the organisations it is given (job-list.ts: those its
// marks say have a cooling-off ended, and every one every few hours, 4D2e D10).
// Off, and every due reset left waiting, unless the config names the token and
// sign-in, whose login service holds the factors.
import type { AuditTables } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  createResetRemovals,
  createSecondFactorRemover,
  type IdentityTables,
  type ResetRemovals,
} from '@agentx/core/modules/identity';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import { type Clock, HOUR_MS, type IdGenerator } from '@agentx/core/shared-kernel';
import type { Config } from '@agentx/platform/config';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';

/** How often due resets are looked for, once the last run has ended: a reset is carried out within this of its cooling-off's end. */
export const FACTOR_REMOVALS_EVERY_MS = 5 * 60_000;

/**
 * How often the job visits every organisation, not only those its marks list (4D2e D10): each visit verifies every
 * reset of the organisation, which no mark can point at (decision 3: the check kept against a reset hidden by a row
 * changed past the app). At 10,000 organisations, about one visit every two seconds, against 33 a second before.
 */
export const FACTOR_REMOVALS_WHOLE_PASS_EVERY_MS = 6 * HOUR_MS;

/** The job, or undefined when the config names no reset token or no sign-in. */
export function resetRemovalsFrom({
  list,
  config,
  database,
  keys,
  ids,
  clock,
  outbox,
  fetch,
  logger,
}: {
  /** The organisations to look in. */
  readonly list: () => Promise<readonly string[]>;
  readonly config: Config;
  readonly database: Database<IdentityTables & DirectoryTables & AuditTables & NotificationsTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly outbox: Outbox;
  readonly fetch: OutboundFetch;
  readonly logger: Logger;
}): ResetRemovals | undefined {
  const { factorResets, signIn } = config;
  if (factorResets === undefined || signIn === undefined) return undefined;
  return createResetRemovals({
    list,
    database,
    factors: createSecondFactorRemover({
      issuer: signIn.issuer,
      internalOrigin: signIn.internalOrigin,
      token: factorResets.token,
      fetch,
    }),
    keys,
    ids,
    clock,
    issuer: signIn.issuer,
    outbox,
    logger,
  });
}
