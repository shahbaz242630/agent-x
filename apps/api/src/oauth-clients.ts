// The MCP clients the authorization server knows (6E3a, 6E3c; ADR-016 §5):
// one that registered itself (RFC 7591, `axcl_…`), by what it said; or one
// named by its metadata document's https address (CIMD, decision 2), by what
// it publishes there, fetched from an allowlisted origin at most once a day
// (oauth.client_metadata). Either grants nothing alone: a connection is made
// only by a person's consent.
//
// A document's client is shown "verified by <host>": the host that serves
// the document vouches for it, as a registration's name never can.
import {
  checkClientMetadataDocument,
  clientOf,
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
      const fetch = fetched(metadata, clientId).finally(() => fetching.delete(clientId));
      fetching.set(clientId, fetch);
      return fetch;
    },
  };
}
