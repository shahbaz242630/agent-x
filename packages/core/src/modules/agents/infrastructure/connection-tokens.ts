// A connection's tokens (0093, 6E3a): each access and refresh token kept as
// HMAC-SHA-256 of its secret with the agent-key pepper, over its kind, key,
// ID, expiry and scopes (domain/connection.ts), never the secret. Not a signed
// state: what a token grants is its connection's and its key's, both signed,
// and a row changed in anything its MAC covers no longer matches its secret.
//
// - issueTokens adds an access token and a refresh token in one statement, in
//   the organisation's transaction that read the connection live.
// - A refresh token is used once: usedNow fills in its use in one statement,
//   only where none was, so two uses at once can't both rotate it; the second
//   is a reuse, and its connection is revoked (the API's oauth-grants.ts).
// - Its family as well (0102, R-15, S206): a refresh token any token names as
//   its parent was used, whatever its `used_at` says, and a parent with two
//   refresh children was split in two (tokenLockedWithFamily). Each row's MAC
//   covers its parent, and each token's secret is the pepper's own MAC of
//   its kind, key and ID (tokenGenuine), so the database's owner can't
//   rewrite a family unseen, nor delete a row without its token, sent later,
//   showing it was issued.
// - The door's read (tokenRowRead, tokenProven): the row read alone, unlocked,
//   outside any share, and its secret checked with exactly one verifyMac
//   whatever is found, a MAC of zeros for no row, so a token's ID not in use
//   takes as long as a wrong secret. The row grants nothing: its connection
//   and key are then read through their signed states.
import { type SentTogether, sendTogether, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, sql } from 'kysely';

import { DAY_MS, type IdGenerator } from '../../../shared-kernel/index.ts';
import { KEY_SECRET_BYTES, type Scope, scopesOf, scopesText } from '../domain/agent.ts';
import {
  type ConnectionTokenKind,
  connectionTokenMessage,
  connectionTokenSecretMessage,
  connectionTokenText,
  type PresentedToken,
  TOKEN_MAC_VERSION,
  tokenExpiresAt,
  type TokenMacVersion,
} from '../domain/connection.ts';
import type { AgentsTransaction } from './agents.ts';
import type { AgentsTables } from './tables.ts';

const TOKENS = 'agents.connection_tokens';

/** A pair just issued: the texts, shown once, and when the access token ends. */
export interface IssuedTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  /** The access token's ID, for the log alone (it is public, as a key's ID is). */
  readonly accessTokenId: string;
  readonly accessExpiresAt: Date;
  readonly scopes: readonly Scope[];
}

/**
 * Issues an access token and a refresh token for the connection whose key this is, in the caller's transaction,
 * which must be withSignedStates' for its organisation and have read the connection and its key live. Neither
 * outlives the key. `parentId`: the refresh token this pair rotates, if any. `alongside`: a statement of the caller's
 * sent on the same trip as the pair's rows, after them (the client's last connection noted, 6E3b), so it costs no trip.
 */
export async function issueTokens(
  tx: AgentsTransaction,
  { keys, ids }: { readonly keys: KeyProvider; readonly ids: IdGenerator },
  {
    orgId,
    keyId,
    scopes,
    now,
    keyExpiresAt,
    parentId = null,
    alongside,
  }: {
    readonly orgId: string;
    readonly keyId: string;
    readonly scopes: readonly Scope[];
    readonly now: Date;
    readonly keyExpiresAt: Date;
    readonly parentId?: string | null;
    readonly alongside?: SentTogether;
  },
): Promise<IssuedTokens> {
  const kept = scopesText(scopes);
  const made = (['access', 'refresh'] as const).map((kind) => {
    const id = ids.next();
    // The secret is the pepper's MAC of what the token is (0102): 256 bits no one without the pepper can make.
    const secret = keys.mac('agent-key-pepper', connectionTokenSecretMessage({ kind, keyId, tokenId: id })).mac;
    if (secret.length !== KEY_SECRET_BYTES) throw new Error("a token's secret is the pepper's 32-byte MAC");
    const expiresAt = tokenExpiresAt(kind, now, keyExpiresAt);
    const { mac, keyVersion } = keys.mac(
      'agent-key-pepper',
      connectionTokenMessage({ kind, keyId, tokenId: id, expiresAt, scopes: kept, parentId }, secret),
    );
    return {
      text: connectionTokenText(kind, keyId, id, secret),
      row: {
        org_id: orgId,
        id,
        key_id: keyId,
        kind,
        scopes: kept,
        secret_mac: mac.toString('hex'),
        secret_key_version: keyVersion,
        expires_at: expiresAt,
        created_at: now,
        parent_id: parentId,
        used_at: null,
        mac_version: TOKEN_MAC_VERSION,
      },
    };
  });
  const [access, refresh] = made;
  if (access === undefined || refresh === undefined) throw new Error('a pair is two tokens');
  const added = tx.insertInto(TOKENS).values(made.map(({ row }) => row));
  if (alongside === undefined) await added.execute();
  else await sendTogether(tx, [added, alongside]);
  return {
    accessToken: access.text,
    refreshToken: refresh.text,
    accessTokenId: access.row.id,
    accessExpiresAt: access.row.expires_at,
    scopes: scopesOf(kept),
  };
}

/** A token's row as kept. */
export interface TokenRow {
  readonly keyId: string;
  readonly kind: ConnectionTokenKind;
  readonly scopes: string;
  readonly secretMac: Buffer;
  readonly secretKeyVersion: number;
  readonly expiresAt: Date;
  readonly usedAt: Date | null;
  readonly parentId: string | null;
  /** 1 or 2 as kept (0102). */
  readonly macVersion: number;
}

interface RawTokenRow {
  readonly key_id: string;
  readonly kind: string;
  readonly scopes: string;
  readonly secret_mac: string;
  readonly secret_key_version: number;
  readonly expires_at: Date;
  readonly used_at: Date | null;
  readonly parent_id: string | null;
  readonly mac_version: number;
}

/** The row as the table's checks hold it, or undefined for none. */
const tokenRowOf = (row: RawTokenRow | undefined): TokenRow | undefined =>
  row === undefined
    ? undefined
    : {
        keyId: row.key_id.toLowerCase(),
        kind: row.kind === 'refresh' ? 'refresh' : 'access',
        scopes: row.scopes,
        secretMac: Buffer.from(row.secret_mac, 'hex'),
        secretKeyVersion: row.secret_key_version,
        expiresAt: row.expires_at,
        usedAt: row.used_at,
        parentId: row.parent_id?.toLowerCase() ?? null,
        macVersion: row.mac_version,
      };

const COLUMNS = [
  'key_id',
  'kind',
  'scopes',
  'secret_mac',
  'secret_key_version',
  'expires_at',
  'used_at',
  'parent_id',
  'mac_version',
] as const;

/** The door's one statement, not run: the token's row by its organisation and ID, unlocked. */
export function tokenRowRead(db: Pick<Kysely<AgentsTables>, 'selectFrom'>, orgId: string, id: string) {
  return db.selectFrom(TOKENS).select(COLUMNS).where('org_id', '=', orgId).where('id', '=', id);
}

/** The door's read, judged: the row, if there is one. */
export const tokenRowFound = (rows: readonly RawTokenRow[]): TokenRow | undefined => tokenRowOf(rows[0]);

/** A refresh token's row locked, and what its family says of its use (R-15). */
export interface TokenFamily {
  readonly row: TokenRow | undefined;
  /** Tokens of either kind that name it as their parent: made by its use (an access token alone is one too). */
  readonly children: number;
  /** Refresh tokens other than it that name its parent: made by another use of the same parent. */
  readonly siblings: number;
}

/**
 * The refresh token's row locked for its use (lock level 3c, after its connection's 3b), in the caller's
 * transaction, and its family counted, on one trip: two
 * statements, the count's taken once the lock is held, so it sees a use that committed while this one waited. On
 * 0102's `connection_tokens_by_parent` alone. The parent counted is the locked row's, which the door proved sealed.
 */
export async function tokenLockedWithFamily(tx: AgentsTransaction, orgId: string, id: string): Promise<TokenFamily> {
  const org = orgId.toLowerCase();
  const token = id.toLowerCase();
  const family = sql<{ children: number; siblings: number }>`
    select
      (select pg_catalog.count(*)::int from agents.connection_tokens c
        where c.org_id = ${org} and c.parent_id = ${token}) as children,
      (select pg_catalog.count(*)::int from agents.connection_tokens s
        where s.org_id = ${org} and s.kind = 'refresh' and s.id <> ${token}
          and s.parent_id = (select t.parent_id from agents.connection_tokens t where t.org_id = ${org} and t.id = ${token})
      ) as siblings
  `;
  const [locked, counted] = await sendTogether(tx, [tokenRowRead(tx, org, token).forUpdate(), family]);
  const counts = counted.rows[0] as { readonly children?: number; readonly siblings?: number } | undefined;
  return {
    row: tokenRowFound(locked.rows as RawTokenRow[]),
    children: counts?.children ?? 0,
    siblings: counts?.siblings ?? 0,
  };
}

/** Fills in the refresh token's use, only where none was: whether this call is the one that used it. */
export async function usedNow(tx: AgentsTransaction, orgId: string, id: string, now: Date): Promise<boolean> {
  const used = await tx
    .updateTable(TOKENS)
    .set({ used_at: now })
    .where('org_id', '=', orgId)
    .where('id', '=', id)
    .where('kind', '=', 'refresh')
    .where('used_at', 'is', null)
    .returning(sql<number>`1`.as('used'))
    .executeTakeFirst();
  return used !== undefined;
}

/** How long a token's row is kept: past every token's life (an hour, 30 idle days, a connection's 90); 0093's policy. */
const TOKEN_RETENTION_DAYS = 120;

/**
 * Deletes up to `most` of the organisation's token rows older than TOKEN_RETENTION_DAYS, oldest first, and says how
 * many, inside its own withTenant (statements limited): 0093's `retention` policy holds the same line.
 */
export async function sweepConnectionTokens(
  db: Kysely<AgentsTables>,
  orgId: string,
  now: Date,
  most: number,
): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one token at a time');
  const past = new Date(now.getTime() - TOKEN_RETENTION_DAYS * DAY_MS);
  return withTenant(
    db,
    orgId,
    async (tx) => {
      const oldest = tx
        .selectFrom(TOKENS)
        .select('id')
        .where('org_id', '=', orgId.toLowerCase())
        .where('created_at', '<', past)
        .orderBy('created_at')
        .limit(most);
      const rows = await tx
        .deleteFrom(TOKENS)
        .where('org_id', '=', orgId.toLowerCase())
        .where('id', 'in', oldest)
        .returning('id')
        .execute();
      return rows.length;
    },
    { limited: true },
  );
}

/** What a sent token's secret came to against its row. */
export type TokenProof =
  | { readonly outcome: 'proven'; readonly row: TokenRow }
  | { readonly outcome: 'unread' | 'wrong_secret' | 'key_not_held' };

/** What a token's secret is compared with when there is no row: the same one verifyMac either way. */
const NO_MAC = Buffer.alloc(32);

/** A time no row's expiry is, for the MAC over zeros. */
const NO_TIME = new Date(0);

/**
 * The sent token's secret against its row: exactly one verifyMac whatever is found (a MAC of zeros, under the
 * pepper's current version, for no row, a row of another key or kind, or a version this process doesn't hold), so
 * the time it takes tells nothing of what was there. `unread`: no row for it; `key_not_held`: a row made with a
 * pepper version this process no longer holds, ours to fix.
 */
export function tokenProven(keys: KeyProvider, row: TokenRow | undefined, presented: PresentedToken): TokenProof {
  const pepper = keys.describe().find(({ purpose }) => purpose === 'agent-key-pepper');
  const ours = row?.keyId === presented.keyId.toLowerCase() && row.kind === presented.kind;
  const held = ours && pepper?.versions.some(({ version }) => version === row.secretKeyVersion) === true;
  const version = held ? row.secretKeyVersion : pepper?.current;
  const binding = {
    kind: presented.kind,
    keyId: presented.keyId,
    tokenId: presented.tokenId,
    expiresAt: ours ? row.expiresAt : NO_TIME,
    scopes: ours ? row.scopes : '',
    parentId: ours ? row.parentId : null,
  };
  // Any version but 1 is taken as the current one: a row moved off its own then fails its MAC.
  const macVersion: TokenMacVersion = ours && row.macVersion === 1 ? 1 : TOKEN_MAC_VERSION;
  // No pepper at all: nothing can be verified, so nothing is.
  const matches =
    version !== undefined &&
    keys.verifyMac(
      'agent-key-pepper',
      version,
      connectionTokenMessage(binding, presented.secret, macVersion),
      held ? row.secretMac : NO_MAC,
    );
  if (!ours) return { outcome: 'unread' };
  if (!held) return { outcome: 'key_not_held' };
  return matches ? { outcome: 'proven', row } : { outcome: 'wrong_secret' };
}

/**
 * Whether a token sent is one the app issued (0102): its secret the pepper's MAC of its kind, key and ID, under any
 * version of the pepper held. Asked only of a token its row doesn't prove, to tell a row deleted or changed (the
 * integrity alarm) from a token never issued. A token made before 0102, its secret random, never is.
 */
export function tokenGenuine(keys: KeyProvider, presented: PresentedToken): boolean {
  const pepper = keys.describe().find(({ purpose }) => purpose === 'agent-key-pepper');
  const message = connectionTokenSecretMessage(presented);
  return (pepper?.versions ?? []).some(({ version }) =>
    keys.verifyMac('agent-key-pepper', version, message, presented.secret),
  );
}
