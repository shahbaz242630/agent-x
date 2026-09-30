// The login service's admin events copied into our audit trail, as the API
// runs it (ADR-003 §4, SEC-OPS-02; B6-2b): the identity module's copier,
// reading Zitadel's event feed with the directory token (B5-3's read-only
// service user, given the instance's read-only role for the feed, IAM Owner
// Viewer) on a timer of its own. Off, and nothing copied, unless the config
// names the token (email) and sign-in, whose login service it reads. A key
// added is judged by how many the person holds, read with the reset token
// (Org User Manager) when the config names it; without it, every key added
// counts toward the restriction (the S68 audit: the rule fails closed).
import type { AuditTables } from '@agentx/core/modules/audit';
import type { DirectoryTables } from '@agentx/core/modules/directory';
import {
  createIdpEventCopier,
  createIdpEventFeed,
  createSecondFactorRemover,
  type IdentityTables,
  type IdpEventCopier,
} from '@agentx/core/modules/identity';
import type { NotificationsTables, Outbox } from '@agentx/core/modules/notifications';
import type { PlatformControlsTables } from '@agentx/core/modules/platform-controls';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Config } from '@agentx/platform/config';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';

/** How often the feed is read, once the last run has ended. */
export const IDP_EVENTS_EVERY_MS = 5 * 60_000;

/** The copier, or undefined when the config names no directory token or no sign-in. */
export function idpEventCopierFrom({
  config,
  database,
  keys,
  ids,
  clock,
  outbox,
  fetch,
  logger,
}: {
  readonly config: Config;
  readonly database: Database<
    IdentityTables & DirectoryTables & AuditTables & NotificationsTables & PlatformControlsTables
  >;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly outbox: Outbox;
  readonly fetch: OutboundFetch;
  readonly logger: Logger;
}): IdpEventCopier | undefined {
  const { email, signIn, factorResets } = config;
  if (email === undefined || signIn === undefined) return undefined;
  return createIdpEventCopier({
    database,
    feed: createIdpEventFeed({
      issuer: signIn.issuer,
      internalOrigin: signIn.internalOrigin,
      token: email.directoryToken,
      fetch,
    }),
    keys,
    ids,
    clock,
    issuer: signIn.issuer,
    outbox,
    passkeys:
      factorResets === undefined
        ? undefined
        : createSecondFactorRemover({
            issuer: signIn.issuer,
            internalOrigin: signIn.internalOrigin,
            token: factorResets.token,
            fetch,
          }),
    logger,
  });
}
