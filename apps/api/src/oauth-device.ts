// Connecting a device (6E3c; RFC 8628; ADR-016 §5; MCP-Guide §2 for Hermes'
// headless gateways): a client with no browser of its own asks for two codes,
// shows the person the short user code and where to type it, and polls the
// token endpoint with its device code (oauth-grants.ts) until the person
// decides.
//
// - `authorize` (`POST /v1/oauth/device_authorization`): a known client
//   (registered, or named by an allowlisted document) that lists the device
//   flow among its grant types, the scopes it asks for
//   and our MCP endpoint as its resource; a flow opened for 15 minutes, the
//   device polling every 5 seconds. Both codes are kept as their SHA-256.
// - `lookup` (`POST /v1/oauth/device/lookup`, a signed-in person, 5 tries a
//   minute each): the user code typed claims the flow for this browser and
//   this person (AG8), by its flow cookie's hash and theirs, once; the console
//   then asks and decides it as a browser's (connection-consents.ts), by that
//   person alone. A code typed wrong, ended, decided or claimed by anyone
//   else: nothing found, and nothing said of which.
// - AG8 (6F1 audit): failed lookups are held server-wide too, each copy its
//   share of MOST_FAILED_LOOKUPS_A_MINUTE, every lookup held for the rest of
//   the minute past it; and a claimed flow's code typed by anyone else is
//   counted on the flow (flows.ts deviceClaimed), and warned of.
//
// The console's `/device` page may be opened from the device's
// verification_uri_complete, with the code filled in; it never looks it up by
// itself (device.tsx): the person presses to look it up, which claims it for
// them, then allows it with step-up, by the same person on the same browser.
import {
  DEVICE_CODE_GRANT,
  deviceClaimed,
  FLOW_SECONDS,
  type FlowSource,
  hashOf,
  isFlowCookie,
  MOST_OPEN_FLOWS_A_NETWORK,
  MOST_OPEN_FLOWS_A_SOURCE,
  newDeviceCode,
  newFlowCookie,
  newUserCode,
  type OauthTables,
  openDeviceFlow,
  scopesAsked,
  userCodeOf,
} from '@agentx/core/modules/oauth';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import { type Database, isRetryable, isStatementLimit } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import { capWarning, flowSourceOf } from './oauth-authorizing.ts';
import type { OauthClients } from './oauth-clients.ts';
import type { OauthError } from './oauth-errors.ts';
import type { Capabilities } from './oauth-wire.ts';
import { shareOfCopies } from './rate-limit.ts';

/** How often a device may poll, in seconds (RFC 8628 §3.2's default). */
const DEVICE_INTERVAL_SECONDS = 5;

/**
 * The most user-code lookups that may fail in a minute, every person together (AG8, the 6F1 audit). Each person has 5
 * tries a minute, so many accounts at once could still walk the 20^8 codes; past this, every lookup is held for the
 * rest of the minute, a right code too, as nothing tells a guess from a slip. Far above a real minute's typing errors.
 */
export const MOST_FAILED_LOOKUPS_A_MINUTE = 120;

/** The failed lookups' window. */
const LOOKUP_WINDOW_MS = 60_000;

/** How many user codes are drawn before giving up: a second draw already held is one chance in billions. */
const MOST_DRAWS = 3;

/** What a device asks for (RFC 8628 §3.1, RFC 8707). */
interface DeviceAsked {
  readonly client_id?: string | undefined;
  readonly scope?: string | undefined;
  readonly resource?: string | undefined;
}

/** A device's codes (RFC 8628 §3.2). */
interface DeviceCodes {
  readonly deviceCode: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete: string;
  readonly expiresIn: number;
  readonly interval: number;
}

export type DeviceAnswer =
  | { readonly outcome: 'opened'; readonly codes: DeviceCodes }
  | {
      readonly outcome: 'refused';
      readonly status: 400 | 401 | 503;
      readonly error: OauthError;
      readonly description: string;
    };

/**
 * The flow claimed for this browser and person: its ID, for the consent page, and the browser's cookie, set again; or
 * none found; or every lookup held for the rest of the minute (AG8).
 */
export type LookupAnswer =
  | { readonly outcome: 'claimed'; readonly requestId: string; readonly cookie: string }
  | { readonly outcome: 'not_found' }
  | { readonly outcome: 'held' };

export interface OauthDevice {
  /** `ip`: the client's address as the trust rule reads it, undefined when it can't be read (rate-limit.ts). */
  authorize(asked: DeviceAsked, correlationId: string, ip: string | undefined): Promise<DeviceAnswer>;
  /** `userId`: the signed-in person typing the code. */
  lookup(typed: string, cookie: string | undefined, userId: string): Promise<LookupAnswer>;
}

const refused = (status: 400 | 401 | 503, error: OauthError, description: string): DeviceAnswer => ({
  outcome: 'refused',
  status,
  error,
  description,
});

const BUSY = refused(503, 'temporarily_unavailable', 'Agent X is busy; try again in a few seconds.');

export function createOauthDevice({
  database,
  clock,
  ids,
  logger,
  capabilities,
  clients,
  copies = 1,
}: {
  readonly database: Database<OauthTables>;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  readonly capabilities: Capabilities;
  readonly clients: OauthClients;
  /** The API's `web` copies (AGENTX_WEB_COPIES): each holds its share of the failed lookups. */
  readonly copies?: number;
}): OauthDevice {
  const sourceCapped = capWarning(logger, clock, 'oauth.source_capped', {
    kind: 'device',
    per: 'source',
    most: MOST_OPEN_FLOWS_A_SOURCE,
  });
  const networkCapped = capWarning(logger, clock, 'oauth.source_capped', {
    kind: 'device',
    per: 'network',
    most: MOST_OPEN_FLOWS_A_NETWORK,
  });
  /** A flow not opened at a cap, noted: the server's warns on each request, a network's or a source's once a minute. */
  const capNoted = (cap: 'full' | 'network_full' | 'source_full', correlationId: string): void => {
    if (cap === 'full') logger.child({ correlationId }).warn('oauth.flows_capped', { kind: 'device' });
    else (cap === 'network_full' ? networkCapped : sourceCapped)();
  };
  const mostFailed = shareOfCopies(MOST_FAILED_LOOKUPS_A_MINUTE, copies);
  const lookupsCapped = capWarning(logger, clock, 'oauth.device_lookups_capped', { most: mostFailed });
  // This copy's failed lookups in the minute that began at `since`, counted in memory as every other limit is.
  const failed = { since: Number.NEGATIVE_INFINITY, count: 0 };
  const failedThisMinute = (): number => {
    const now = clock.now().getTime();
    if (now - failed.since >= LOOKUP_WINDOW_MS) Object.assign(failed, { since: now, count: 0 });
    return failed.count;
  };

  /** The flow claimed for `userId` on this browser, or why not: a claim of anyone else's flow warned of. */
  const claimFor = async (typed: string, browser: string, userId: string): Promise<LookupAnswer> => {
    const userCode = userCodeOf(typed);
    const claim =
      userCode === undefined
        ? ({ outcome: 'not_found' } as const)
        : await deviceClaimed(
            database,
            hashOf(userCode),
            { browserHash: hashOf(browser), personHash: hashOf(userId) },
            clock.now(),
          );
    if (claim.outcome === 'claimed') return { outcome: 'claimed', requestId: claim.flowId, cookie: browser };
    failed.count += 1;
    if (claim.outcome === 'contested') {
      const { flowId, failedClaims, denied } = claim;
      logger.warn('oauth.device_code_contested', { flowId, failedClaims, denied });
    }
    return { outcome: 'not_found' };
  };

  /** The flow opened `from` its source, with a fresh pair of codes, drawn again while the user code is one held. */
  const opened = async (clientId: string, scopes: NonNullable<ReturnType<typeof scopesAsked>>, from: FlowSource) => {
    for (let draw = 0; draw < MOST_DRAWS; draw += 1) {
      const [deviceCode, userCode] = [newDeviceCode(), newUserCode()];
      const outcome = await openDeviceFlow(
        database,
        {
          id: ids.next(),
          clientId,
          scopesAsked: scopes,
          resource: capabilities.resource,
          deviceHash: hashOf(deviceCode),
          userCodeHash: hashOf(userCodeOf(userCode) ?? userCode),
          intervalSeconds: DEVICE_INTERVAL_SECONDS,
          createdAt: clock.now(),
        },
        from,
      );
      if (outcome !== 'collided') return { outcome, deviceCode, userCode };
    }
    return { outcome: 'full' as const };
  };

  return {
    async authorize(asked, correlationId, ip) {
      try {
        const client = asked.client_id === undefined ? undefined : await clients.find(asked.client_id);
        if (client === undefined) return refused(401, 'invalid_client', 'The client is not one Agent X knows.');
        // Only a client whose registration or document lists the device flow (RFC 8628 §3.1): no one may borrow
        // another client's name, Claude's document among them, for a device of their own.
        if (!client.grantTypes.includes(DEVICE_CODE_GRANT)) {
          return refused(400, 'unauthorized_client', 'This client may not use the device flow.');
        }
        const scopes = scopesAsked(asked.scope);
        if (scopes === undefined) return refused(400, 'invalid_scope', 'A scope asked for is not one Agent X has.');
        // SEC-OAUTH-01: optional (RFC 8707), and only ever our MCP endpoint.
        if (asked.resource !== undefined && asked.resource !== capabilities.resource) {
          return refused(400, 'invalid_target', 'The resource is not this server’s MCP endpoint.');
        }
        const flow = await opened(client.clientId, scopes, flowSourceOf(ip));
        if (flow.outcome !== 'opened') {
          capNoted(flow.outcome, correlationId);
          return refused(
            503,
            'temporarily_unavailable',
            'Too many sign-ins are under way; try again in a few minutes.',
          );
        }
        const verificationUri = capabilities.verificationUri;
        return {
          outcome: 'opened',
          codes: {
            deviceCode: flow.deviceCode,
            userCode: flow.userCode,
            verificationUri,
            verificationUriComplete: `${verificationUri}?${new URLSearchParams({ user_code: flow.userCode }).toString()}`,
            expiresIn: FLOW_SECONDS,
            interval: DEVICE_INTERVAL_SECONDS,
          },
        };
      } catch (error) {
        if (!isStatementLimit(error) && !isRetryable(error)) throw error;
        logger.child({ correlationId }).warn('oauth.grant_in_trouble', { at: 'device_authorization' });
        return BUSY;
      }
    },

    lookup(typed, cookie, userId) {
      if (failedThisMinute() >= mostFailed) {
        lookupsCapped();
        return Promise.resolve({ outcome: 'held' });
      }
      const browser = cookie !== undefined && isFlowCookie(cookie) ? cookie : newFlowCookie();
      return claimFor(typed, browser, userId);
    },
  };
}
