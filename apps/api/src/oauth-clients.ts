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
// without end from an allowed host, and so that no one can lock a real
// client out (6E3c reviews):
// - An address never yet valid is fetched at most 20 times a minute an
//   origin by this copy of the API, and one whose document was refused for
//   what it says (not JSON, too large, another client's ID, bad addresses,
//   a secret, grant types) is not fetched again for 5 minutes.
// - An address once valid (its document kept, or seen valid by this copy) is
//   never held by that cap. If its document can't be fetched again for a
//   reason of the network or the site (a status, a refusal, a timeout), the
//   document kept stands in, stale, for up to 7 days past its day, and the
//   fetch is tried again a minute later.
//
// Each is believed only as the app sealed it (S207 H3, R-15; client-seals.ts):
// a registered client or kept document whose seal is not its own raises the
// integrity alarm and is never shown or used; one with no seal (kept before
// 0107) is let go with a warning. A document is then fetched again from its
// own address, as one never kept; a registered client is unknown, and must
// register again.
import {
  checkClientMetadataDocument,
  type ClientJudged,
  type ClientMetadataDocument,
  clientOf,
  type GrantType,
  keepClientMetadata,
  type KeptDocument,
  keptClientMetadata,
  type OauthTables,
  retireClientMetadata,
} from '@agentx/core/modules/oauth';
import type { Clock } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
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
  /** The client this ID names, its document fetched if none is kept fresh; undefined for none, or one refused. */
  find(clientId: string): Promise<KnownClient | undefined>;
  /** The client as kept, fresh or stale, in the caller's transaction, never fetched: for a flow already shown. */
  kept(
    db: Database<OauthTables> | DatabaseTransaction<OauthTables>,
    clientId: string,
  ): Promise<KnownClient | undefined>;
}

/** How long a document refused for what it says is not fetched again. */
export const REFUSED_FOR_MS = 5 * 60_000;

/** The most fetches of one origin's never-valid addresses a minute, by one copy of the API. */
export const MOST_FETCHES_A_MINUTE = 20;

const MINUTE_MS = 60_000;

/** How long after a once-valid document's fetch failed it is tried again, the stale one standing in meanwhile. */
const RETRY_STALE_MS = MINUTE_MS;

/** The most client IDs each memory below holds: past it, the oldest is forgotten. */
const MOST_REMEMBERED = 10_000;

/** Refusals of the network or the site, never of the document: never cached, and a stale document stands in. */
const PASSING: ReadonlySet<string> = new Set(['refused', 'status', 'timeout', 'unreadable']);

/** The host a document's client ID names, which vouches for it. */
const hostOf = (clientId: string): string => new URL(clientId).host;

const fromDocument = (document: ClientMetadataDocument): KnownClient => ({
  ...document,
  verifiedBy: hostOf(document.clientId),
});

/** Remembers `key` until `value`, the oldest forgotten past MOST_REMEMBERED. */
function remember<V>(memory: Map<string, V>, key: string, value: V): void {
  memory.delete(key);
  memory.set(key, value);
  if (memory.size > MOST_REMEMBERED) {
    const [oldest] = memory.keys();
    if (oldest !== undefined) memory.delete(oldest);
  }
}

export function createOauthClients({
  database,
  keys,
  clock,
  logger,
  metadata,
}: {
  readonly database: Database<OauthTables>;
  /** Seals each client as it is kept, and checks it as it is read (client-seals.ts). */
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  /** None while nothing is trusted (AGENTX_OAUTH_CLIENT_METADATA_ORIGINS): an address names no client then. */
  readonly metadata: ClientMetadataFetch | undefined;
}): OauthClients {
  /** The fetches under way, by client ID: requests at once for a client not kept share one fetch. */
  const fetching = new Map<string, Promise<KnownClient | undefined>>();
  /** Client IDs whose document was refused for what it says, and until when it isn't fetched again. */
  const refused = new Map<string, number>();
  /** Client IDs whose document came back valid here (beside those kept), and when a failed refetch may try again. */
  const onceValid = new Map<string, number>();
  /** Each origin's fetches of never-valid addresses this minute: when its minute began, and how many. */
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

  /**
   * The line for a client kept but not believed: one whose seal is not its own, the integrity alarm (a client comes
   * before any organisation, so none is held for it); one with none, or of a pepper version no longer held, a warning.
   * A document's client is named by its origin alone, as on every other line of these.
   */
  const notBelieved = (judged: Exclude<ClientJudged, 'sound'>, clientId: string, kind: 'registered' | 'document') => {
    const named = kind === 'registered' ? { objectId: clientId } : { origin: new URL(clientId).origin };
    if (judged === 'tampered') {
      logger.error('audit.integrity_failed', { chain: 'oauth', check: 'oauth_client', reason: kind, ...named });
    } else {
      logger.warn('oauth.client_unsealed', { kind, reason: judged, ...named });
    }
  };

  /** The document kept for a listed client, believed only as sealed; the line said for one that isn't. */
  const keptDocument = async (
    db: Database<OauthTables> | DatabaseTransaction<OauthTables>,
    clientId: string,
    now: Date,
  ): Promise<KeptDocument | undefined> => {
    const read = await keptClientMetadata(db, keys, clientId, now);
    if (read?.outcome !== 'unsealed') return read;
    notBelieved(read.judged, clientId, 'document');
    return undefined;
  };

  const kept: OauthClients['kept'] = async (db, clientId) => {
    if (metadata?.listed(clientId) === true) {
      const document = await keptDocument(db, clientId, clock.now());
      return document === undefined ? undefined : fromDocument(document.document);
    }
    const read = await clientOf(db, keys, clientId);
    if (read === undefined) return undefined;
    if (read.outcome === 'unsealed') {
      notBelieved(read.judged, clientId, 'registered');
      return undefined;
    }
    return { ...read.client, verifiedBy: null };
  };

  /**
   * The document fetched, checked and kept for a day; else `stale`, the one kept, where the refusal is the network's
   * or the site's; else undefined. Each refusal says why on its line.
   */
  const fetched = async (
    fetch: ClientMetadataFetch,
    clientId: string,
    stale: ClientMetadataDocument | undefined,
  ): Promise<KnownClient | undefined> => {
    const answer = await fetch.fetch(clientId);
    const checked = answer.outcome === 'fetched' ? checkClientMetadataDocument(clientId, answer.document) : answer;
    const now = clock.now().getTime();
    if (checked.outcome === 'valid') {
      await keepClientMetadata(database, keys, checked.document, clock.now());
      remember(onceValid, clientId, 0);
      return fromDocument(checked.document);
    }
    // The origin alone: the rest of the address is the client's to choose, and says nothing more.
    const origin = new URL(clientId).origin;
    logger.warn('oauth.client_metadata_refused', { origin, reason: checked.reason });
    if (!PASSING.has(checked.reason)) {
      // Refused for what it says: held 5 minutes, valid no more, and the old one never stands in again.
      remember(refused, clientId, now + REFUSED_FOR_MS);
      onceValid.delete(clientId);
      await retireClientMetadata(database, clientId, clock.now());
      return undefined;
    }
    // Once valid: tried again a minute on, whether a stale one stands in or none is kept any more.
    if (stale === undefined && !onceValid.has(clientId)) return undefined;
    remember(onceValid, clientId, now + RETRY_STALE_MS);
    if (stale === undefined) return undefined;
    logger.warn('oauth.client_metadata_stale', { origin, reason: checked.reason });
    return fromDocument(stale);
  };

  return {
    kept,
    async find(clientId) {
      // Anything but a listed address is never fetched (SEC-OAUTH-09): an unknown client, as a mistyped `axcl_` is.
      if (metadata?.listed(clientId) !== true) return kept(database, clientId);
      const now = clock.now();
      const keptNow = await keptDocument(database, clientId, now);
      if (keptNow?.fresh === true) return fromDocument(keptNow.document);
      const under = fetching.get(clientId);
      if (under !== undefined) return under;
      // Refused for what it says: held 5 minutes, once valid or not.
      if ((refused.get(clientId) ?? 0) > now.getTime()) return undefined;
      const stale = keptNow?.document;
      const retryAt = onceValid.get(clientId);
      if (stale !== undefined || retryAt !== undefined) {
        // Once valid: never held by the cap, only by its own minute after a failed refetch, the stale one standing in.
        if (retryAt !== undefined && retryAt > now.getTime())
          return stale === undefined ? undefined : fromDocument(stale);
      } else if (!roomToFetch(new URL(clientId).origin, now.getTime())) {
        return undefined;
      }
      const fetch = fetched(metadata, clientId, stale).finally(() => fetching.delete(clientId));
      fetching.set(clientId, fetch);
      return fetch;
    },
  };
}
