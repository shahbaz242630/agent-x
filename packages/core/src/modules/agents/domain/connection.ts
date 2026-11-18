// An MCP connection's tokens (6E3a, ADR-016; MCP-Guide M5): what an OAuth
// client holds once a person has connected it to one of their organisation's
// agents. The connection is a key of that agent's, its secret thrown away
// (agent.ts's keys), and its tokens point at it:
//
// - an access token, `axa_<keyId>_<tokenId>_<secret>`, sent as a bearer token
//   to the MCP endpoint alone, for an hour;
// - a refresh token, `axr_<keyId>_<tokenId>_<secret>`, sent to the token
//   endpoint alone, once, for a new pair: unused for 30 days, it ends.
//
// Each holds its key's ID (public, ADR-011 §1: where to look), its own ID and
// 256 bits of randomness, kept as HMAC-SHA-256 with the agent-key pepper over
// a label of its own, so no key's MAC is ever a token's.
import { DAY_MS } from '../../../shared-kernel/index.ts';
import { KEY_SECRET_BYTES } from './agent.ts';

/** The two kinds of token a connection is given. */
export type ConnectionTokenKind = 'access' | 'refresh';

/** What every access token starts with. */
const ACCESS_TOKEN_PREFIX = 'axa_';
/** What every refresh token starts with. */
const REFRESH_TOKEN_PREFIX = 'axr_';

/** How long an access token works: an hour (decision 5). */
export const ACCESS_TOKEN_SECONDS = 3600;

/** How long a refresh token works unused: each use gives a new one (decision 5). */
export const REFRESH_IDLE_DAYS = 30;

/**
 * The most connections of one agent that work at once: a person's laptop, phone and a few clients each, never one
 * client's hundred. An eleventh waits for one to be revoked or to expire.
 */
export const MOST_LIVE_CONNECTIONS = 10;

/** The most connections an organisation may make in any 24 hours: every one stays a record, as a key does. */
export const MOST_CONNECTIONS_MADE_A_DAY = 20;

/** When a token of this kind, issued at `now`, ends: never after its connection's key. */
export function tokenExpiresAt(kind: ConnectionTokenKind, now: Date, keyExpiresAt: Date): Date {
  const life = kind === 'access' ? ACCESS_TOKEN_SECONDS * 1000 : REFRESH_IDLE_DAYS * DAY_MS;
  return new Date(Math.min(now.getTime() + life, keyExpiresAt.getTime()));
}

const PREFIXES: Readonly<Record<ConnectionTokenKind, string>> = {
  access: ACCESS_TOKEN_PREFIX,
  refresh: REFRESH_TOKEN_PREFIX,
};

/** A uuid as the 32 lower-case hex digits a token holds it as: never a `_`, which the log scrubber keeps IDs by. */
const hexOf = (id: string): string => {
  const hex = id.toLowerCase().replaceAll('-', '');
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new RangeError("A token's IDs are uuids");
  return hex;
};

/** 32 hex digits as a uuid, in lower case. */
const uuidOf = (hex: string): string =>
  `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

/** The token a client is given: its kind's prefix, its key's ID, its own ID, its secret in base64url without padding. */
export function connectionTokenText(kind: ConnectionTokenKind, keyId: string, tokenId: string, secret: Buffer): string {
  if (secret.length !== KEY_SECRET_BYTES) throw new RangeError(`A token's secret is ${String(KEY_SECRET_BYTES)} bytes`);
  return `${PREFIXES[kind]}${hexOf(keyId)}_${hexOf(tokenId)}_${secret.toString('base64url')}`;
}

/** A token a client sent, taken apart. */
export interface PresentedToken {
  readonly kind: ConnectionTokenKind;
  readonly keyId: string;
  readonly tokenId: string;
  readonly secret: Buffer;
}

const TOKEN_TEXT = /^ax([ar])_([0-9a-f]{32})_([0-9a-f]{32})_([A-Za-z0-9_-]{43})$/;

/**
 * The token's parts, if `text` is exactly as connectionTokenText writes one of `kind`, or undefined: no other
 * spelling of it is taken (upper case, padding, stray bits in the secret's last character), so one token has one text.
 */
export function parseConnectionToken(text: string, kind: ConnectionTokenKind): PresentedToken | undefined {
  const parts = TOKEN_TEXT.exec(text);
  if (parts === null) return undefined;
  const [, letter = '', keyHex = '', tokenHex = '', encoded = ''] = parts;
  if (PREFIXES[kind] !== `ax${letter}_`) return undefined;
  const secret = Buffer.from(encoded, 'base64url');
  if (secret.length !== KEY_SECRET_BYTES || secret.toString('base64url') !== encoded) return undefined;
  return { kind, keyId: uuidOf(keyHex), tokenId: uuidOf(tokenHex), secret };
}

/** What a token's row is bound to by its MAC: everything that says what it grants and until when. */
export interface TokenBinding {
  readonly kind: ConnectionTokenKind;
  readonly keyId: string;
  readonly tokenId: string;
  readonly expiresAt: Date;
  /** As scopesText writes them. */
  readonly scopes: string;
}

/**
 * What the agent-key pepper's MAC of a token is taken over: its own label (never a key's `agent-key`), its kind, its
 * key, its ID, its expiry and its scopes, then its secret. A row changed in any of them no longer matches.
 */
export const connectionTokenMessage = (
  { kind, keyId, tokenId, expiresAt, scopes }: TokenBinding,
  secret: Buffer,
): readonly [string, string, string, string, string, string, Buffer] => [
  'connection-token',
  kind,
  keyId.toLowerCase(),
  tokenId.toLowerCase(),
  expiresAt.toISOString(),
  scopes,
  secret,
];
