// Where a sign-out ends the person's sessions at the login service too
// (Shannon AUTH-VULN-01, S88): with the reset token, whose role may end them
// (partner, S88: one token); off unless the config names it and sign-in.
import { createLoginSessions, type LoginSessions } from '@agentx/core/modules/identity';
import type { Config } from '@agentx/platform/config';
import { createOutboundFetch } from '@agentx/platform/outbound';

export function loginSessionsFrom(config: Config): LoginSessions | undefined {
  const { signIn, factorResets } = config;
  if (signIn === undefined || factorResets === undefined) return undefined;
  return createLoginSessions({
    issuer: signIn.issuer,
    internalOrigin: signIn.internalOrigin,
    token: factorResets.token,
    fetch: createOutboundFetch(config.outbound.allowedOrigins),
  });
}
