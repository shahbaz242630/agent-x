// The authorization endpoint's and the registration endpoint's work (6E3a,
// ADR-016; RFC 6749 §4.1.1-§4.1.2.1, RFC 7591; SEC-OAUTH-02, -03, -11, -12,
// -13).
//
// - An authorization request opens a flow for the person's browser, or is
//   refused. A client unknown, or a redirect address it never registered, is
//   never sent back to (an open redirect, RFC 6749 §4.1.2.1): the browser goes
//   to our own page saying so. Anything else wrong goes back to the client's
//   address with OAuth's error, its `state` and our issuer (RFC 9207). PKCE
//   S256 on every request; the resource, if named, is the MCP endpoint
//   exactly (RFC 8707).
// - A registration is checked (client-metadata.ts) and kept, within the day's
//   cap for the whole server; the API's per-address limit is in front.
import {
  checkRegistration,
  type Client,
  clientOf,
  isCodeChallenge,
  isFlowCookie,
  isRegisteredRedirect,
  newFlowCookie,
  hashOf,
  type OauthTables,
  openCodeFlow,
  PKCE_METHOD,
  type RegistrationAsked,
  registerClient,
  scopesAsked,
} from '@agentx/core/modules/oauth';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { backToClient, type Capabilities } from './oauth-wire.ts';

/** What an authorization request names (RFC 6749 §4.1.1, RFC 7636 §4.3, RFC 8707 §2). */
interface AuthorizeAsked {
  readonly response_type?: string | undefined;
  readonly client_id?: string | undefined;
  readonly redirect_uri?: string | undefined;
  readonly scope?: string | undefined;
  readonly state?: string | undefined;
  readonly code_challenge?: string | undefined;
  readonly code_challenge_method?: string | undefined;
  readonly resource?: string | undefined;
}

/** Why a request can't go back to its client: shown on our own page, never sent to an address unproven. */
type NotRedirectable = 'unknown_client' | 'unregistered_redirect';

export type AuthorizeAnswer =
  | { readonly outcome: 'not_redirectable'; readonly problem: NotRedirectable }
  | { readonly outcome: 'refused'; readonly redirectTo: string }
  /** The flow opened: its ID, and the browser's cookie (`set`: a new one to set). */
  | { readonly outcome: 'opened'; readonly flowId: string; readonly cookie: string; readonly set: boolean };

export type RegistrationAnswer =
  | { readonly outcome: 'registered'; readonly client: Client }
  | {
      readonly outcome: 'invalid';
      readonly error: 'invalid_redirect_uri' | 'invalid_client_metadata';
      readonly description: string;
    }
  | { readonly outcome: 'capped' };

export interface OauthAuthorizing {
  authorize(asked: AuthorizeAsked, cookie: string | undefined): Promise<AuthorizeAnswer>;
  register(asked: RegistrationAsked, correlationId: string): Promise<RegistrationAnswer>;
}

/** The most characters of a client's `state` kept and sent back (0093). */
const MOST_STATE = 512;

export function createOauthAuthorizing({
  database,
  clock,
  ids,
  logger,
  capabilities,
}: {
  readonly database: Database<OauthTables>;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  readonly capabilities: Capabilities;
}): OauthAuthorizing {
  return {
    async authorize(asked, cookie) {
      const client = asked.client_id === undefined ? undefined : await clientOf(database, asked.client_id);
      if (client === undefined) return { outcome: 'not_redirectable', problem: 'unknown_client' };
      // OAuth 2.1 §4.1.1: one registered address may be left out; with more, the request must name one.
      const [only] = client.redirectUris.length === 1 ? client.redirectUris : [];
      const redirectUri = asked.redirect_uri ?? only;
      if (redirectUri === undefined || !isRegisteredRedirect(client.redirectUris, redirectUri)) {
        return { outcome: 'not_redirectable', problem: 'unregistered_redirect' };
      }
      const state = asked.state !== undefined && asked.state.length <= MOST_STATE ? asked.state : null;
      const refused = (error: string, description: string): AuthorizeAnswer => ({
        outcome: 'refused',
        redirectTo: backToClient(redirectUri, {
          error,
          error_description: description,
          state,
          iss: capabilities.issuer,
        }),
      });
      if (asked.state !== undefined && state === null) return refused('invalid_request', 'The state is too long.');
      if (asked.response_type !== 'code') return refused('unsupported_response_type', 'Only the code flow is offered.');
      // SEC-OAUTH-02: PKCE S256 on every request, never `plain` (OAuth 2.1).
      const challenge = asked.code_challenge;
      if (challenge === undefined || !isCodeChallenge(challenge) || asked.code_challenge_method !== PKCE_METHOD) {
        return refused('invalid_request', 'A PKCE code_challenge with code_challenge_method S256 is required.');
      }
      const scopes = scopesAsked(asked.scope);
      if (scopes === undefined) return refused('invalid_scope', 'A scope asked for is not one Agent X has.');
      // SEC-OAUTH-01: a connection's tokens are for the MCP endpoint alone.
      if (asked.resource !== undefined && asked.resource !== capabilities.resource) {
        return refused('invalid_target', 'The resource is not this server’s MCP endpoint.');
      }
      const kept = cookie !== undefined && isFlowCookie(cookie) ? cookie : undefined;
      const browser = kept ?? newFlowCookie();
      const flowId = ids.next();
      await openCodeFlow(database, {
        id: flowId,
        clientId: client.clientId,
        redirectUri,
        state,
        codeChallenge: challenge,
        scopesAsked: scopes,
        resource: capabilities.resource,
        browserHash: hashOf(browser),
        createdAt: clock.now(),
      });
      return { outcome: 'opened', flowId, cookie: browser, set: kept === undefined };
    },

    async register(asked, correlationId) {
      const checked = checkRegistration(asked);
      if (checked.outcome === 'invalid') return checked;
      const registered = await registerClient(database, checked.client, clock.now());
      if (registered.outcome === 'capped') {
        logger.child({ correlationId }).warn('oauth.registrations_capped');
      }
      return registered;
    },
  };
}
