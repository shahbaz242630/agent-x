// The facts of a client that decide where its codes go, sealed (S207 H3,
// R-15; SEC-OAUTH-17; 0107): oauth.clients and oauth.client_metadata are
// global, hold no signed state, and their owner can write any row. Unsealed,
// the owner could add its own address to a known client's redirect addresses
// (a cached document's, shown "verified by claude.ai", or a registered one's),
// widen its grant types, or keep a document past its day, and a person who
// allows the request would send their code there. So a client is believed
// only with the MAC the app made of it, with a key the database never holds.
//
// - A registered client (`oauth-client-v1`): its ID, name, application type,
//   redirect addresses, grant types, software ID and version, and when it
//   registered: all it said, as it said it, written once.
// - A kept document (`oauth-client-metadata-v1`): its client ID, name,
//   redirect addresses and grant types, and when it was fetched and until
//   when it is kept, so no one can keep it longer.
//
// The key is the agent-key pepper, the OAuth credential family's own (it MACs
// every agent key, connection token and OAuth flow, oauth/flow-seals.ts),
// under labels of their own, so no MAC of one can stand for another's. A list
// is its length, then each item: each part is length-prefixed, so no two
// lists read the same.
import type { KeyProvider, Message } from '@agentx/platform/keys';

import { pepperHeld } from '../../agents/index.ts';
import type { DecisionSeal } from './flow-reads.ts';

/** The labels, versioned: a change to a message is a new label. */
const CLIENT_LABEL = 'oauth-client-v1';
const DOCUMENT_LABEL = 'oauth-client-metadata-v1';

/** The pepper whose MAC a seal is, the version beside it for rotation. */
const PEPPER = 'agent-key-pepper';

/** An absent field: never a value, as each kept one has at least a character (0093 holds them to 1-255). */
const NONE = '';

/** A registered client's sealed fields, as kept (oauth.clients). */
export interface RegisteredFields {
  readonly clientId: string;
  readonly name: string;
  readonly applicationType: string;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly string[];
  readonly softwareId: string | null;
  readonly softwareVersion: string | null;
  readonly createdAt: Date;
}

/** A kept document's sealed fields, as kept (oauth.client_metadata). */
export interface DocumentFields {
  readonly clientId: string;
  readonly name: string;
  readonly redirectUris: readonly string[];
  readonly grantTypes: readonly string[];
  readonly fetchedAt: Date;
  readonly expiresAt: Date;
}

/**
 * Whether a client's row is as the app sealed it: `sound`; `unsealed`, with no seal (kept before 0107, or by the
 * release before while it rolled out, or its seal taken out); `key_not_held`, sealed with a pepper version this process
 * no longer holds; or `tampered`, its seal not its own. Only `sound` is believed.
 */
export type ClientJudged = 'sound' | 'unsealed' | 'key_not_held' | 'tampered';

const listed = (items: readonly string[]): string[] => [String(items.length), ...items];

const registeredMessage = (client: RegisteredFields): Message => [
  CLIENT_LABEL,
  client.clientId,
  client.name,
  client.applicationType,
  ...listed(client.redirectUris),
  ...listed(client.grantTypes),
  client.softwareId ?? NONE,
  client.softwareVersion ?? NONE,
  client.createdAt.toISOString(),
];

const documentMessage = (document: DocumentFields): Message => [
  DOCUMENT_LABEL,
  document.clientId,
  document.name,
  ...listed(document.redirectUris),
  ...listed(document.grantTypes),
  document.fetchedAt.toISOString(),
  document.expiresAt.toISOString(),
];

const sealOf = (keys: KeyProvider, message: Message): DecisionSeal => {
  const { mac, keyVersion } = keys.mac(PEPPER, message);
  return { mac: mac.toString('hex'), keyVersion };
};

function judged(keys: KeyProvider, seal: DecisionSeal | null, message: Message): ClientJudged {
  if (seal === null) return 'unsealed';
  if (!pepperHeld(keys, seal.keyVersion)) return 'key_not_held';
  return keys.verifyMac(PEPPER, seal.keyVersion, message, Buffer.from(seal.mac, 'hex')) ? 'sound' : 'tampered';
}

/** The seal of a client as it registers: made with the pepper's current version. */
export const registeredSealed = (keys: KeyProvider, client: RegisteredFields): DecisionSeal =>
  sealOf(keys, registeredMessage(client));

/** Whether a registered client, as read, is the one that registered. */
export const registeredJudged = (
  keys: KeyProvider,
  client: RegisteredFields,
  seal: DecisionSeal | null,
): ClientJudged => judged(keys, seal, registeredMessage(client));

/** The seal of a document as it is kept: made with the pepper's current version. */
export const documentSealed = (keys: KeyProvider, document: DocumentFields): DecisionSeal =>
  sealOf(keys, documentMessage(document));

/** Whether a kept document, as read, is the one fetched, kept until when it was. */
export const documentJudged = (keys: KeyProvider, document: DocumentFields, seal: DecisionSeal | null): ClientJudged =>
  judged(keys, seal, documentMessage(document));

/** The seal kept beside a row, or null for none (0107 holds the MAC and its version both, or neither). */
export const sealIn = (mac: string | null, keyVersion: number | null): DecisionSeal | null =>
  mac === null || keyVersion === null ? null : { mac, keyVersion };
