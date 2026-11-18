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
  MOST_OPEN_FLOWS,
  openCodeFlow,
  PKCE_METHOD,
  type RegistrationAsked,
  registerClient,
  scopesAsked,
} from '@agentx/core/modules/oauth';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, isRetryable, isStatementLimit } from '@agentx/platform/db';
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
type NotRedirectable = 'unknown_client' | 'unregistered_redirect' | 'temporarily_unavailable';

export type AuthorizeAnswer =
  | { readonly outcome: 'not_redirectable'; readonly problem: NotRedirectable }
  | { readonly outcome: 'refused'; readonly redirectTo: string }
  /** The flow opened: its ID, and the browser's cookie, set again each time so a flow never outlives it. */
  | { readonly outcome: 'opened'; readonly flowId: string; readonly cookie: string };

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

/**
 * Why an authorization request from a known client, to an address it registered, is refused, as OAuth's error and
 * our words; none if it may open a flow. `stateTooLong`: its state past what is kept.
 */
function requestRefusal(
  asked: AuthorizeAsked,
  stateTooLong: boolean,
  resource: string,
): readonly [string, string] | undefined {
  if (stateTooLong) return ['invalid_request', 'The state is too long.'];
  if (asked.response_type !== 'code') return ['unsupported_response_type', 'Only the code flow is offered.'];
  // SEC-OAUTH-02: PKCE S256 on every request, never `plain` (OAuth 2.1).
  const challenge = asked.code_challenge;
  if (challenge === undefined || !isCodeChallenge(challenge) || asked.code_challenge_method !== PKCE_METHOD) {
    return ['invalid_request', 'A PKCE code_challenge with code_challenge_method S256 is required.'];
  }
  if (scopesAsked(asked.scope) === undefined) return ['invalid_scope', 'A scope asked for is not one Agent X has.'];
  // SEC-OAUTH-01: a connection's tokens are for the MCP endpoint alone. Optional (RFC 8707): some clients send none.
  if (asked.resource !== undefined && asked.resource !== resource) {
    return ['invalid_target', 'The resource is not this server’s MCP endpoint.'];
  }
  return undefined;
}

/** How often the flows' cap may warn, at most (lead's re-review): one line a minute, however many are refused. */
const CAP_WARNING_EVERY_MS = 60_000;

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
  /** The flows' cap's warning, at most once a minute, with how many were refused since the last (an attack's flood). */
  let capWarnedAt = Number.NEGATIVE_INFINITY;
  let refusedSince = 0;
  const flowsCapped = (): void => {
    refusedSince += 1;
    const now = clock.now().getTime();
    if (now - capWarnedAt < CAP_WARNING_EVERY_MS) return;
    logger.warn('oauth.flows_capped', { most: MOST_OPEN_FLOWS, refused: refusedSince });
    capWarnedAt = now;
    refusedSince = 0;
  };

  /** The authorize work, a database limit or lost deadlock answered busy (never a 500), where `back` says. */
  const orBusy = async (
    back: { redirectTo?: (error: string, description: string) => AuthorizeAnswer },
    work: () => Promise<AuthorizeAnswer>,
  ): Promise<AuthorizeAnswer> => {
    try {
      return await work();
    } catch (error) {
      if (!isStatementLimit(error) && !isRetryable(error)) throw error;
      logger.warn('oauth.grant_in_trouble', { at: 'authorize' });
      return back.redirectTo === undefined
        ? { outcome: 'not_redirectable', problem: 'temporarily_unavailable' }
        : back.redirectTo('temporarily_unavailable', 'Agent X is busy; try again in a few seconds.');
    }
  };

  return {
    authorize(asked, cookie) {
      // Once the client's address is proven, a busy answer goes back to it; before, to our own page.
      const back: { redirectTo?: (error: string, description: string) => AuthorizeAnswer } = {};
      return orBusy(back, () => authorized(asked, cookie, back));
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

  async function authorized(
    asked: AuthorizeAsked,
    cookie: string | undefined,
    back: { redirectTo?: (error: string, description: string) => AuthorizeAnswer },
  ): Promise<AuthorizeAnswer> {
    const client = asked.client_id === undefined ? undefined : await clientOf(database, asked.client_id);
    if (client === undefined) return { outcome: 'not_redirectable', problem: 'unknown_client' };
    // OAuth 2.1 §4.1.1: one registered address may be left out; with more, the request must name one.
    const [only] = client.redirectUris.length === 1 ? client.redirectUris : [];
    const redirectUri = asked.redirect_uri ?? only;
    if (redirectUri === undefined || !isRegisteredRedirect(client.redirectUris, redirectUri)) {
      return { outcome: 'not_redirectable', problem: 'unregistered_redirect' };
    }
    // An empty state is no state (RFC 6749 §4.1.1 makes it optional): the column holds 1 to 512 characters.
    const given = asked.state === '' ? undefined : asked.state;
    const state = given !== undefined && given.length <= MOST_STATE ? given : null;
    const refused = (error: string, description: string): AuthorizeAnswer => ({
      outcome: 'refused',
      redirectTo: backToClient(redirectUri, {
        error,
        error_description: description,
        state,
        iss: capabilities.issuer,
      }),
    });
    back.redirectTo = refused;
    const wrong = requestRefusal(asked, given !== undefined && state === null, capabilities.resource);
    if (wrong !== undefined) return refused(...wrong);
    // Checked just above: a challenge and scopes there are.
    const challenge = asked.code_challenge ?? '';
    const scopes = scopesAsked(asked.scope) ?? [];
    const kept = cookie !== undefined && isFlowCookie(cookie) ? cookie : undefined;
    const browser = kept ?? newFlowCookie();
    const flowId = ids.next();
    const opened = await openCodeFlow(database, {
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
    if (opened === 'full') {
      flowsCapped();
      return refused('temporarily_unavailable', 'Too many sign-ins are under way; try again in a few minutes.');
    }
    if (opened === 'browser_full') {
      return refused(
        'temporarily_unavailable',
        'This browser has too many connections waiting; finish or wait for one.',
      );
    }
    return { outcome: 'opened', flowId, cookie: browser };
  }
}
