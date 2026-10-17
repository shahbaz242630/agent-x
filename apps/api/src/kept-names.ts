// The login service's names for the audit log, as the API runs it (decision
// 25): read with the directory token the address book uses (B5-3's read-only
// service user). Off unless the config names the token (email) and sign-in,
// whose login service it reads; the log then names people from the copy
// Agent X kept at their sign-in alone.
import { createDirectoryNames, type DirectoryNames } from '@agentx/core/modules/identity';
import type { Config } from '@agentx/platform/config';
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
