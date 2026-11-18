// The MCP clients the authorization server knows (6E3a, 6E3c; ADR-016 §5):
// one that registered itself (RFC 7591, `axcl_…`), by what it said; or one
// named by its metadata document's https address (CIMD, decision 2), by what
// it publishes there, fetched from an allowlisted origin at most once a day
// (oauth.client_metadata). Either grants nothing alone: a connection is made
// only by a person's consent, and only by a flow its grant types list.
//
// A document's client is shown "verified by <host>" on a browser's flow: the
// host that serves the document vouches for it, and the code can only reach
// the addresses the document lists. A device's flow has no such binding, so
// it is never shown as verified (connection-consents.ts).
//
// The fetches are held so that varying the address can't make Agent X fetch
// without end from an allowed host: a refused document is not fetched again
// for 5 minutes, and each origin is fetched at most 20 times a minute by
// this copy of the API.
import {
  checkClientMetadataDocument,
  clientOf,
  type GrantType,
  keepClientMetadata,
  keptClientMetadata,
  type OauthTables,
} from '@agentx/core/modules/oauth';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';

import type { ClientMetadataFetch } from './oauth-client-metadata.ts';

/** A client the server knows, as the authorize endpoint and the consent page read it. */
interface KnownClient {
  readonly clientId: string;
  /** What it says it is: shown as such, never as proof. */
  readonly name: string;
  readonly redirectUris: readonly string[];
  /** The flows it may use: those it registered, or its document lists. */
  readonly grantTypes: readonly GrantType[];
  /** The host whose document named the client (CIMD); null for one that registered itself. */
  readonly verifiedBy: string | null;
}

export interface OauthClients {
  /** The client this ID names, its document fetched if none is kept; undefined for none, or one refused. */
  find(clientId: string): Promise<KnownClient | undefined>;
  /** The client as kept, in the caller's transaction, never fetched: for a flow already shown to its person. */
  kept(
    db: Database<OauthTables> | DatabaseTransaction<OauthTables>,
    clientId: string,
  ): Promise<KnownClient | undefined>;
}

/** How long a refused document is not fetched again. */
export const REFUSED_FOR_MS = 5 * 60_000;

/** The most fetches of one origin's documents a minute, by one copy of the API. */
export const MOST_FETCHES_A_MINUTE = 20;

const MINUTE_MS = 60_000;

/** The most refused client IDs remembered: past it, the oldest is forgotten (and may be fetched again). */
const MOST_REMEMBERED = 10_000;

/** The host a document's client ID names, which vouches for it. */
const hostOf = (clientId: string): string => new URL(clientId).host;

export function createOauthClients({
  database,
  clock,
  logger,
  metadata,
}: {
  readonly database: Database<OauthTables>;
  readonly clock: Clock;
  readonly logger: Logger;
  /** None while no origin is allowed (AGENTX_OAUTH_CLIENT_METADATA_ORIGINS): an address names no client then. */
  readonly metadata: ClientMetadataFetch | undefined;
}): OauthClients {
  /** The fetches under way, by client ID: requests at once for a client not kept share one fetch. */
  const fetching = new Map<string, Promise<KnownClient | undefined>>();
  /** Client IDs whose document was refused, and until when it isn't fetched again (oldest first). */
  const refused = new Map<string, number>();
  /** Each origin's fetches this minute: when its minute began, and how many. */
  const fetchesOf = new Map<string, { readonly since: number; count: number }>();

  /** Whether the origin may be fetched once more now; the line, once a minute an origin, when it may not. */
  const roomToFetch = (origin: string, now: number): boolean => {
    const counted = fetchesOf.get(origin);
    if (counted === undefined || now - counted.since >= MINUTE_MS) {
      fetchesOf.set(origin, { since: now, count: 1 });
      return true;
    }
    counted.count += 1;
    if (counted.count === MOST_FETCHES_A_MINUTE + 1) {
      logger.warn('oauth.client_metadata_capped', { origin, most: MOST_FETCHES_A_MINUTE });
    }
    return counted.count <= MOST_FETCHES_A_MINUTE;
  };

  const refuse = (clientId: string, now: number): void => {
    refused.delete(clientId);
    refused.set(clientId, now + REFUSED_FOR_MS);
    if (refused.size > MOST_REMEMBERED) {
      const [oldest] = refused.keys();
      if (oldest !== undefined) refused.delete(oldest);
    }
  };

  const kept: OauthClients['kept'] = async (db, clientId) => {
    if (metadata?.listed(clientId) === true) {
      const document = await keptClientMetadata(db, clientId, clock.now());
      return document === undefined ? undefined : { ...document, verifiedBy: hostOf(clientId) };
    }
    const client = await clientOf(db, clientId);
    return client === undefined ? undefined : { ...client, verifiedBy: null };
  };

  /** The document fetched, checked and kept for a day; undefined, and the line saying why, for one refused. */
  const fetched = async (fetch: ClientMetadataFetch, clientId: string): Promise<KnownClient | undefined> => {
    const answer = await fetch.fetch(clientId);
    const checked = answer.outcome === 'fetched' ? checkClientMetadataDocument(clientId, answer.document) : answer;
    if (checked.outcome !== 'valid') {
      refuse(clientId, clock.now().getTime());
      // The origin alone: the rest of the address is the client's to choose, and says nothing more.
      logger.warn('oauth.client_metadata_refused', { origin: new URL(clientId).origin, reason: checked.reason });
      return undefined;
    }
    await keepClientMetadata(database, checked.document, clock.now());
    return { ...checked.document, verifiedBy: hostOf(clientId) };
  };

  return {
    kept,
    async find(clientId) {
      const known = await kept(database, clientId);
      // Anything but a listed address is never fetched (SEC-OAUTH-09): an unknown client, as a mistyped `axcl_` is.
      if (known !== undefined || metadata?.listed(clientId) !== true) return known;
      const under = fetching.get(clientId);
      if (under !== undefined) return under;
      const now = clock.now().getTime();
      if ((refused.get(clientId) ?? 0) > now) return undefined;
      if (!roomToFetch(new URL(clientId).origin, now)) return undefined;
      const fetch = fetched(metadata, clientId).finally(() => fetching.delete(clientId));
      fetching.set(clientId, fetch);
      return fetch;
    },
  };
}
