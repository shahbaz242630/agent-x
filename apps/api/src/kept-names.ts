// The login service's names for the audit log, as the API runs it (decision
// 25): read with the directory token the address book uses (B5-3's read-only
// service user). Off unless the config names the token (email) and sign-in,
// whose login service it reads; the log then names people from the copy
// Agent X kept at their sign-in alone. With it on, the copy is also filled
// for people who signed in before it was kept (contact-fill.ts).
import {
  type ContactFill,
  createContactFill,
  createDirectoryNames,
  type DirectoryNames,
  type IdentityTables,
} from '@agentx/core/modules/identity';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Config } from '@agentx/platform/config';
import type { Database } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { OutboundFetch } from '@agentx/platform/outbound';

/** The login service's names, or undefined when the config names no directory token or no sign-in. */
export function directoryNamesFrom(config: Config, fetch: OutboundFetch): DirectoryNames | undefined {
  if (config.signIn === undefined || config.email === undefined) return undefined;
  return createDirectoryNames({
    issuer: config.signIn.issuer,
    internalOrigin: config.signIn.internalOrigin,
    token: config.email.directoryToken,
    fetch,
  });
}

/** The fill of kept names, or undefined without the login service's names to fill them from. */
export function contactFillFrom({
  directory,
  database,
  keys,
  clock,
  logger,
}: {
  readonly directory: DirectoryNames | undefined;
  readonly database: Database<IdentityTables>;
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
}): ContactFill | undefined {
  return directory === undefined ? undefined : createContactFill({ db: database, keys, directory, clock, logger });
}
