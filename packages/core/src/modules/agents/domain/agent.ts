// An AI agent and its keys (PRD §3 `Agent` / `AgentCredential`, ADR-011 §1;
// BR-03).
//
// An agent belongs to one organisation and one owner, a member of it. It is
// ACTIVE or SUSPENDED: suspending is the kill switch (ADR-012 §5), instant
// and one click, and reactivating gives its authority back. The database's
// status guard holds the same moves (0027).
//
// A key is ACTIVE until it is revoked, once, and works only until it expires.
// A rotation issues a new key and brings the old one's expiry forward to the
// end of the overlap (ADR-011 §1); an emergency revocation has no overlap.
//
// Scopes say what an agent may ask for. The agent's are the most any of its
// keys may be given, and a request is allowed only what both the key's and
// the agent's scopes hold, so narrowing an agent narrows its keys at once. A
// key alone never grants spending: that is the mandate's (BR-03).
import { defineStateMachine, visibleName } from '../../../shared-kernel/index.ts';

export const AGENT = defineStateMachine({
  name: 'agent',
  states: ['ACTIVE', 'SUSPENDED'],
  initial: 'ACTIVE',
  events: {
    suspend: { from: ['ACTIVE'], to: 'SUSPENDED' },
    reactivate: { from: ['SUSPENDED'], to: 'ACTIVE' },
  },
});

export type AgentStatus = (typeof AGENT.states)[number];

export const AGENT_KEY = defineStateMachine({
  name: 'agent_key',
  states: ['ACTIVE', 'REVOKED'],
  initial: 'ACTIVE',
  events: {
    revoke: { from: ['ACTIVE'], to: 'REVOKED' },
  },
});

export type AgentKeyStatus = (typeof AGENT_KEY.states)[number];

/**
 * Every scope there is, in order:
 * - `requests:write`: ask for a payment, and cancel its own requests (Phase 3)
 * - `requests:read`: read its own requests and their decisions (Phase 3)
 * - `sources:read`: the safe summary of the organisation's funding sources (SEC-AG-05)
 * - `suppliers:read`: the organisation's suppliers, by ID and name alone (SEC-AG-05)
 */
export const SCOPES = ['requests:read', 'requests:write', 'sources:read', 'suppliers:read'] as const;
export type Scope = (typeof SCOPES)[number];

export const isScope = (value: unknown): value is Scope => SCOPES.some((scope) => scope === value);

/** A list of scopes that can't be kept: `problems` say why. */
export class ScopesRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The scopes were refused: ${problems.join('; ')}`);
    this.name = 'ScopesRefused';
    this.problems = problems;
  }
}

/**
 * The scopes as they are kept and sealed: at least one, each a known scope,
 * given once, in SCOPES' order, one space apart; so the same scopes are
 * always the same text. Anything else is `ScopesRefused`.
 */
export function scopesText(scopes: readonly string[]): string {
  const problems: string[] = [];
  if (scopes.length === 0) problems.push('at least one scope is given');
  if (!scopes.every(isScope)) problems.push('a scope is not one there is');
  if (new Set(scopes).size !== scopes.length) problems.push('a scope is given twice');
  if (problems.length > 0) throw new ScopesRefused(problems);
  return SCOPES.filter((scope) => scopes.includes(scope)).join(' ');
}

/**
 * The scopes a kept text holds, in SCOPES' order. The text was sealed as
 * scopesText gave it, so anything else is an error, never an empty grant.
 */
export function scopesOf(text: string): Scope[] {
  const words = text.split(' ');
  const scopes = words.filter(isScope);
  if (scopes.length !== words.length || scopesText(scopes) !== text) {
    throw new Error('Kept scopes are not as scopesText gives them');
  }
  return scopes;
}

/** Whether every one of `some` is among `all`: a key's scopes within its agent's. */
export const scopesWithin = (some: readonly Scope[], all: readonly Scope[]): boolean =>
  some.every((scope) => all.includes(scope));

/** The most characters (Unicode code points) an agent's name may have: the table's own limit. */
const MAX_NAME = 100;

/** The name can't be an agent's; `problems` say why, never what it was. */
export class AgentNameRefused extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`The agent's name was refused: ${problems.join('; ')}`);
    this.name = 'AgentNameRefused';
    this.problems = problems;
  }
}

/**
 * The name as it is kept (composed, NFC), or `AgentNameRefused` for one that
 * isn't a visible name of 1 to 100 characters (the shared kernel's rules, as
 * an organisation's name).
 */
export function agentName(name: string): string {
  const { name: composed, problems } = visibleName(name, MAX_NAME);
  if (problems.length > 0) throw new AgentNameRefused(problems);
  return composed;
}

/** Whether a name can be an agent's: what an API checks before anything is written. */
export const isAgentName = (name: string): boolean => visibleName(name, MAX_NAME).problems.length === 0;

/** The longest a key lives (ADR-011 §1's maximum): a new key expires this many days after it is issued. */
export const KEY_DAYS = 90;

const DAY_MS = 86_400_000;

/** When a key issued at `issuedAt` expires. */
export const keyExpiresAt = (issuedAt: Date): Date => new Date(issuedAt.getTime() + KEY_DAYS * DAY_MS);

/**
 * The most agents an organisation may register in any 24 hours (the B8-2
 * lesson): every agent stays a record, so without a budget one member could
 * fill the organisation's lists in a minute.
 */
export const MOST_AGENTS_ADDED_A_DAY = 10;

/** A key's secret: 256 bits of cryptographic randomness (ADR-011 §1). */
export const KEY_SECRET_BYTES = 32;

/** What every key an agent sends starts with. */
export const KEY_PREFIX = 'axk_';

/**
 * The key an agent sends, `axk_<keyId>_<secret>`: its ID as 32 lower-case hex
 * digits (the uuid without its dashes, so it never holds a `_`, which the log
 * scrubber keeps the ID by), then the secret in base64url without padding.
 */
export function agentKeyText(keyId: string, secret: Buffer): string {
  const hex = keyId.toLowerCase().replaceAll('-', '');
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new RangeError("A key's ID is a uuid");
  if (secret.length !== KEY_SECRET_BYTES) throw new RangeError(`A key's secret is ${String(KEY_SECRET_BYTES)} bytes`);
  return `${KEY_PREFIX}${hex}_${secret.toString('base64url')}`;
}

/** A key an agent sent, taken apart: its ID as a uuid in lower case, and its secret. */
export interface PresentedKey {
  readonly keyId: string;
  readonly secret: Buffer;
}

/** The whole shape agentKeyText writes: `axk_`, 32 lower-case hex digits, `_`, 43 base64url characters. */
const KEY_TEXT = /^axk_([0-9a-f]{32})_([A-Za-z0-9_-]{43})$/;

/**
 * The key's ID and secret, if `text` is exactly as agentKeyText writes a key,
 * or undefined: no other spelling of the same key (upper case, padding, a
 * secret whose last character carries stray bits) is taken, so one key has
 * one text, and nothing is looked up for text that couldn't be a key.
 */
export function parseAgentKey(text: string): PresentedKey | undefined {
  const parts = KEY_TEXT.exec(text);
  if (parts === null) return undefined;
  const [, hex = '', encoded = ''] = parts;
  const secret = Buffer.from(encoded, 'base64url');
  if (secret.length !== KEY_SECRET_BYTES || secret.toString('base64url') !== encoded) return undefined;
  const keyId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  return { keyId, secret };
}

/**
 * What the agent-key pepper's MAC is taken over: a label, the key's ID in
 * lower case and its secret, so a MAC can't be moved to another key.
 */
export const keySecretMessage = (keyId: string, secret: Buffer): readonly [string, string, Buffer] => [
  'agent-key',
  keyId.toLowerCase(),
  secret,
];
