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
//   minute each): the user code typed claims the flow for this browser, by
//   its flow cookie's hash, once; the console then asks and decides it as a
//   browser's (connection-consents.ts). A code typed wrong, ended, decided or
//   claimed by another browser: nothing found, and nothing said of which.
import {
  DEVICE_CODE_GRANT,
  deviceClaimed,
  FLOW_SECONDS,
  hashOf,
  isFlowCookie,
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

import { capWarning } from './oauth-authorizing.ts';
import type { OauthClients } from './oauth-clients.ts';
import type { OauthError } from './oauth-errors.ts';
import type { Capabilities } from './oauth-wire.ts';
import { clientKey } from './rate-limit.ts';

/** How often a device may poll, in seconds (RFC 8628 §3.2's default). */
const DEVICE_INTERVAL_SECONDS = 5;

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

/** The flow claimed for this browser: its ID, for the consent page, and the browser's cookie, set again. */
export type LookupAnswer =
  | { readonly outcome: 'claimed'; readonly requestId: string; readonly cookie: string }
  | { readonly outcome: 'not_found' };

export interface OauthDevice {
  /** `ip`: the client's address as the trust rule reads it, undefined when it can't be read (rate-limit.ts). */
  authorize(asked: DeviceAsked, correlationId: string, ip: string | undefined): Promise<DeviceAnswer>;
  lookup(typed: string, cookie: string | undefined): Promise<LookupAnswer>;
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
}: {
  readonly database: Database<OauthTables>;
  readonly clock: Clock;
  readonly ids: IdGenerator;
  readonly logger: Logger;
  readonly capabilities: Capabilities;
  readonly clients: OauthClients;
}): OauthDevice {
  const sourceCapped = capWarning(logger, clock, 'oauth.source_capped', {
    kind: 'device',
    most: MOST_OPEN_FLOWS_A_SOURCE,
  });

  /** The flow opened from `source` with a fresh pair of codes, drawn again while the user code is one already held. */
  const opened = async (clientId: string, scopes: NonNullable<ReturnType<typeof scopesAsked>>, source: string) => {
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
        source,
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
        const flow = await opened(client.clientId, scopes, clientKey(ip));
        if (flow.outcome === 'full' || flow.outcome === 'source_full') {
          if (flow.outcome === 'full') logger.child({ correlationId }).warn('oauth.flows_capped', { kind: 'device' });
          else sourceCapped();
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

    async lookup(typed, cookie) {
      const userCode = userCodeOf(typed);
      if (userCode === undefined) return { outcome: 'not_found' };
      const browser = cookie !== undefined && isFlowCookie(cookie) ? cookie : newFlowCookie();
      const requestId = await deviceClaimed(database, hashOf(userCode), hashOf(browser), clock.now());
      return requestId === undefined ? { outcome: 'not_found' } : { outcome: 'claimed', requestId, cookie: browser };
    },
  };
}
