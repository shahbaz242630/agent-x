// The authorization flows under way (0093; RFC 6749 §4.1, OAuth 2.1): a flow
// is opened when a client sends a person's browser to us, decided once (the
// person allows it, with the organisation and connection key it made, or
// denies it), and its code used once. A global table: the flow comes before
// anyone is signed in, and names its organisation and key by ID alone.
//
// - Only the browser that opened a flow reads or decides it: the flow keeps
//   the SHA-256 of that browser's cookie (browser_hash).
// - Decided once: the decision's UPDATE takes only an undecided flow still in
//   time, in the consent's own transaction.
// - Its code used once (SEC-OAUTH-04): codeTaken fills in its use in one
//   statement, only where none was, so two exchanges at once can't both have
//   it; the second finds it used (codeUsedBefore), and its connection is
//   revoked by the API.
// - A device's flow (6E3c, RFC 8628) has no browser when it opens: the
//   person types its user code into the console, which claims it for that
//   browser and that person, once (deviceClaimed, AG8), and the consent that
//   follows is the code flow's, by that person alone. Anyone else typing the
//   code of a flow claimed is a failed claim, counted on the flow; the third
//   denies it (MOST_FAILED_CLAIMS_A_FLOW). The device polls by its device code's hash, no sooner than its
//   interval (devicePolled), and its tokens are issued once (codeUsed).
import { limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type ExpressionBuilder, type Kysely, sql, type Transaction } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type Scope, scopesOf, scopesText } from '../../agents/index.ts';
import { type DecisionSeal, openSealed } from './flow-seals.ts';
import type { OauthTables } from './tables.ts';

/** How long a person has to sign in and decide (plan §3): long enough to register an agent first. */
export const FLOW_SECONDS = 15 * 60;

/** How long a code may wait to be exchanged (OAuth 2.1 §4.1.2: short). */
export const CODE_SECONDS = 60;

/** A browser's flow, as opened. */
export interface CodeFlow {
  readonly id: string;
  readonly clientId: string;
  readonly redirectUri: string;
  /** The client's own `state`, sent back unchanged; null for none. */
  readonly state: string | null;
  readonly codeChallenge: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly browserHash: string;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/**
 * Whether a flow was decided, and how: when, the organisation and connection key an allowed one made, its decision's
 * seal (0101, flow-seals.ts), and its use.
 */
interface FlowOutcome {
  readonly decided: 'allowed' | 'denied' | null;
  readonly decidedAt: Date | null;
  readonly orgId: string | null;
  readonly keyId: string | null;
  readonly seal: DecisionSeal | null;
  /** The seal it was opened with (0101, flow-seals.ts). */
  readonly openSeal: DecisionSeal | null;
  readonly usedAt: Date | null;
}

/** A browser's flow as read: opened, and whether it was decided and its code used. */
export interface FlowRead extends CodeFlow, FlowOutcome {
  readonly kind: 'code';
  /** Its code's SHA-256, once allowed. */
  readonly codeHash: string | null;
  readonly codeEndsAt: Date | null;
}

/** A device's flow as read (6E3c): the browser that claimed it, if one did, and when the device last polled. */
export interface DeviceFlowRead extends FlowOutcome {
  readonly kind: 'device';
  readonly id: string;
  readonly clientId: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  /** Its device code's SHA-256. */
  readonly deviceHash: string;
  readonly browserHash: string | null;
  /** The SHA-256 of the person who claimed it with that browser (AG8), if one did. */
  readonly personHash: string | null;
  readonly intervalSeconds: number;
  readonly polledAt: Date | null;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/** Either kind of flow, as the consent reads one by its ID. */
export type AnyFlowRead = FlowRead | DeviceFlowRead;

type Database = Kysely<OauthTables>;
/** The database, or a transaction on it holding these tables among others (the consent's own). */
type Handle = Database | Transaction<OauthTables>;

/**
 * The most flows not yet ended at once, every browser together (lead's review, 6E3a): anyone can open one with an
 * anonymous GET, and an image on a busy page beats any per-address limit, so the table is held here whatever comes.
 * Far above any real day: a flow lives 15 minutes.
 */
export const MOST_OPEN_FLOWS = 20_000;

/** The most flows one browser (its flow cookie) holds open and undecided at once: a person connects a few apps. */
export const MOST_OPEN_FLOWS_A_BROWSER = 5;

/**
 * The most flows one source holds open at once, of either kind, decided or not (6F1 G4): its client address, an IPv6
 * /64 as one, as the rate limit counts it. A browser sending no cookie is a fresh browser each time, so the browser's
 * cap never holds it; this does, and a few addresses can't fill MOST_OPEN_FLOWS for every organisation's people.
 */
export const MOST_OPEN_FLOWS_A_SOURCE = 20;

/**
 * The most flows one network holds open at once, of either kind, decided or not (AG8): an IPv4 address alone, or an
 * IPv6 /48, a site's whole allocation. One /48 holds 65,536 sources of a /64 each, so the source's cap alone would let
 * one site fill MOST_OPEN_FLOWS; an IPv4 address is its own source, held to that source's cap first.
 */
export const MOST_OPEN_FLOWS_A_NETWORK = 100;

/** Where a flow comes from (6F1 G4, AG8): its source as the rate limit keys it, and that source's network. */
export interface FlowSource {
  readonly source: string;
  readonly network: string;
}

/** Opened; or not, every browser's flows at their cap, this network's, this source's, or this browser's. */
export type FlowOpened = 'opened' | 'full' | 'network_full' | 'source_full' | 'browser_full';

/**
 * Whether the flows of either kind not ended at `now` are at a cap: every source's together (MOST_OPEN_FLOWS, the ends
 * index), this network's (MOST_OPEN_FLOWS_A_NETWORK, the network index), or this source's own
 * (MOST_OPEN_FLOWS_A_SOURCE, the source index), each count stopping at its cap.
 */
async function flowsFull(
  tx: Transaction<OauthTables>,
  { source, network }: FlowSource,
  now: Date,
): Promise<'full' | 'network_full' | 'source_full' | undefined> {
  const atCap = async (most: number, of?: readonly ['network_key' | 'source_key', string]): Promise<boolean> => {
    const { flows } = await tx
      .selectFrom((inner) => {
        const open = inner.selectFrom('oauth.flows').select('id').where('ends_at', '>', now);
        return (of === undefined ? open : open.where(of[0], '=', of[1])).limit(most).as('open');
      })
      .select(sql<number>`pg_catalog.count(*)::int`.as('flows'))
      .executeTakeFirstOrThrow();
    return flows >= most;
  };
  if (await atCap(MOST_OPEN_FLOWS)) return 'full';
  if (await atCap(MOST_OPEN_FLOWS_A_NETWORK, ['network_key', network])) return 'network_full';
  if (await atCap(MOST_OPEN_FLOWS_A_SOURCE, ['source_key', source])) return 'source_full';
  return undefined;
}

/**
 * Opens the flow from `from` (its client address's source and network, 6F1 G4, AG8), for FLOW_SECONDS from its
 * creation, unless MOST_OPEN_FLOWS have not ended, or this network holds MOST_OPEN_FLOWS_A_NETWORK or this source
 * MOST_OPEN_FLOWS_A_SOURCE not ended, or this browser holds MOST_OPEN_FLOWS_A_BROWSER open and undecided, in a
 * transaction of its own whose statements are limited to 10 seconds, each count stopping at its cap (the ends index,
 * the network index, the source index, the browser index). Best effort, with no lock (lead's re-review: one would make
 * every authorize wait its turn): flows opened at once may pass a cap by a few rows.
 */
export async function openCodeFlow(
  db: Database,
  keys: KeyProvider,
  flow: Omit<CodeFlow, 'endsAt'>,
  from: FlowSource,
): Promise<FlowOpened> {
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const full = await flowsFull(tx, from, flow.createdAt);
    if (full !== undefined) return full;
    const own = await tx
      .selectFrom('oauth.flows')
      .select(sql<number>`pg_catalog.count(*)::int`.as('flows'))
      .where('browser_hash', '=', flow.browserHash)
      .where('ends_at', '>', flow.createdAt)
      .where('decided_at', 'is', null)
      .executeTakeFirstOrThrow();
    if (own.flows >= MOST_OPEN_FLOWS_A_BROWSER) return 'browser_full';
    await insertFlow(tx, keys, flow, from);
    return 'opened';
  });
}

/** When a flow opened at `createdAt` ends: FLOW_SECONDS on. */
const flowEndsFrom = (createdAt: Date): Date => new Date(createdAt.getTime() + FLOW_SECONDS * 1000);

async function insertFlow(
  db: Handle,
  keys: KeyProvider,
  flow: Omit<CodeFlow, 'endsAt'>,
  { source, network }: FlowSource,
): Promise<void> {
  const endsAt = flowEndsFrom(flow.createdAt);
  const seal = openSealed(keys, { ...flow, kind: 'code', deviceHash: null, endsAt });
  await db
    .insertInto('oauth.flows')
    .values({
      id: flow.id,
      kind: 'code',
      client_id: flow.clientId,
      redirect_uri: flow.redirectUri,
      state: flow.state,
      code_challenge: flow.codeChallenge,
      scopes_asked: scopesText(flow.scopesAsked),
      resource: flow.resource,
      browser_hash: flow.browserHash,
      source_key: source,
      network_key: network,
      created_at: flow.createdAt,
      ends_at: endsAt,
      open_mac: seal.mac,
      open_key_version: seal.keyVersion,
    })
    .execute();
}

const COLUMNS = [
  'id',
  'kind',
  'client_id',
  'redirect_uri',
  'state',
  'code_challenge',
  'scopes_asked',
  'resource',
  'browser_hash',
  'person_hash',
  'device_hash',
  'created_at',
  'ends_at',
  'decided_at',
  'outcome',
  'org_id',
  'key_id',
  'decision_mac',
  'decision_key_version',
  'open_mac',
  'open_key_version',
  'code_hash',
  'code_ends_at',
  'used_at',
  'interval_s',
  'polled_at',
] as const;

type FlowRow = {
  readonly [Column in (typeof COLUMNS)[number]]: OauthTables['oauth.flows'][Column];
};

/** How a flow was decided, from its row. */
const outcomeOf = (row: FlowRow): FlowOutcome => ({
  decided: row.outcome === 'allowed' || row.outcome === 'denied' ? row.outcome : null,
  decidedAt: row.decided_at,
  orgId: row.org_id,
  keyId: row.key_id,
  openSeal:
    row.open_mac === null || row.open_key_version === null
      ? null
      : { mac: row.open_mac, keyVersion: row.open_key_version },
  seal:
    row.decision_mac === null || row.decision_key_version === null
      ? null
      : { mac: row.decision_mac, keyVersion: row.decision_key_version },
  usedAt: row.used_at,
});

/** A device flow's row as read; undefined for a code flow's. */
function deviceFlowOf(row: FlowRow | undefined): DeviceFlowRead | undefined {
  if (row?.kind !== 'device' || row.interval_s === null || row.device_hash === null) return undefined;
  return {
    kind: 'device',
    id: row.id,
    clientId: row.client_id,
    scopesAsked: scopesOf(row.scopes_asked),
    resource: row.resource,
    deviceHash: row.device_hash,
    browserHash: row.browser_hash,
    personHash: row.person_hash,
    intervalSeconds: row.interval_s,
    polledAt: row.polled_at,
    createdAt: row.created_at,
    endsAt: row.ends_at,
    ...outcomeOf(row),
  };
}

/** A code flow's row as read; undefined for a device's, which has no redirect address. */
function flowOf(row: FlowRow | undefined): FlowRead | undefined {
  if (row?.kind !== 'code' || row.redirect_uri === null || row.code_challenge === null || row.browser_hash === null) {
    return undefined;
  }
  return {
    kind: 'code',
    id: row.id,
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    state: row.state,
    codeChallenge: row.code_challenge,
    scopesAsked: scopesOf(row.scopes_asked),
    resource: row.resource,
    browserHash: row.browser_hash,
    createdAt: row.created_at,
    endsAt: row.ends_at,
    codeHash: row.code_hash,
    codeEndsAt: row.code_ends_at,
    ...outcomeOf(row),
  };
}

/** The flow this ID names, of either kind, decided or not, in time or not; undefined for none. */
export async function flowById(db: Handle, id: string): Promise<AnyFlowRead | undefined> {
  const row = await db.selectFrom('oauth.flows').select(COLUMNS).where('id', '=', id).executeTakeFirst();
  return flowOf(row) ?? deviceFlowOf(row);
}

/**
 * How a flow was decided: an allowed code flow keeps its code's hash, a device's none (its device code is its own), and
 * either the seal of what it was allowed with (flow-seals.ts decisionSealed, for these fields, decided at the same
 * `now`, its code ending at codeEndsFrom's).
 */
export type FlowDecision =
  | {
      readonly outcome: 'allowed';
      readonly orgId: string;
      readonly keyId: string;
      readonly codeHash: string | null;
      readonly seal: DecisionSeal;
    }
  | { readonly outcome: 'denied' };

/** When a code given at `decidedAt` ends: CODE_SECONDS on; none for no code. */
export const codeEndsFrom = (decidedAt: Date, codeHash: string | null): Date | null =>
  codeHash === null ? null : new Date(decidedAt.getTime() + CODE_SECONDS * 1000);

/**
 * Decides the flow, if it is still undecided and in time at `now`, in the caller's transaction: whether this call
 * decided it. An allowed flow keeps its code's hash for CODE_SECONDS, and its decision's seal.
 */
export async function flowDecided(db: Handle, id: string, decision: FlowDecision, now: Date): Promise<boolean> {
  const allowed = decision.outcome === 'allowed' ? decision : undefined;
  const row = await db
    .updateTable('oauth.flows')
    .set({
      decided_at: now,
      outcome: decision.outcome,
      org_id: allowed?.orgId ?? null,
      key_id: allowed?.keyId ?? null,
      code_hash: allowed?.codeHash ?? null,
      code_ends_at: allowed === undefined ? null : codeEndsFrom(now, allowed.codeHash),
      decision_mac: allowed?.seal.mac ?? null,
      decision_key_version: allowed?.seal.keyVersion ?? null,
    })
    .where('id', '=', id)
    .where('decided_at', 'is', null)
    .where('ends_at', '>', now)
    .returning('id')
    .executeTakeFirst();
  return row !== undefined;
}

/** The flow a code was given in, read unlocked, used or not: where its organisation is, never a decision. */
export async function flowOfCode(db: Database, codeHash: string): Promise<FlowRead | undefined> {
  return flowOf(
    await db.selectFrom('oauth.flows').select(COLUMNS).where('code_hash', '=', codeHash).executeTakeFirst(),
  );
}

/**
 * The flow a code was given in, locked for its use in the caller's transaction (its organisation's, which then issues
 * the tokens), so a second exchange of the same code waits and finds it used: undefined if no flow has it.
 */
export async function codeHeld(db: Handle, codeHash: string): Promise<FlowRead | undefined> {
  return flowOf(
    await db.selectFrom('oauth.flows').select(COLUMNS).where('code_hash', '=', codeHash).forUpdate().executeTakeFirst(),
  );
}

/** A device's flow, as opened (RFC 8628 §3.2): its two codes' hashes and how often it may poll. */
export interface DeviceFlow {
  readonly id: string;
  readonly clientId: string;
  readonly scopesAsked: readonly Scope[];
  readonly resource: string;
  readonly deviceHash: string;
  readonly userCodeHash: string;
  readonly intervalSeconds: number;
  readonly createdAt: Date;
}

/**
 * Opened; or not, every flow at the server's cap, this network's or this source's, or the user code drawn already held
 * (draw another).
 */
export type DeviceFlowOpened = 'opened' | 'full' | 'network_full' | 'source_full' | 'collided';

/**
 * Opens the device's flow from `from` (6F1 G4, AG8), for FLOW_SECONDS, unless MOST_OPEN_FLOWS have not ended or this
 * network holds MOST_OPEN_FLOWS_A_NETWORK or this source MOST_OPEN_FLOWS_A_SOURCE (the code flows' own caps, best
 * effort, as openCodeFlow's), in a transaction of its own whose statements are limited to 10 seconds. A user code
 * another flow holds, ended or not, opens no flow: `collided`, and nothing kept.
 */
export async function openDeviceFlow(
  db: Database,
  keys: KeyProvider,
  flow: DeviceFlow,
  from: FlowSource,
): Promise<DeviceFlowOpened> {
  const endsAt = flowEndsFrom(flow.createdAt);
  const seal = openSealed(keys, { ...flow, kind: 'device', redirectUri: null, codeChallenge: null, endsAt });
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const full = await flowsFull(tx, from, flow.createdAt);
    if (full !== undefined) return full;
    const inserted = await tx
      .insertInto('oauth.flows')
      .values({
        id: flow.id,
        kind: 'device',
        client_id: flow.clientId,
        scopes_asked: scopesText(flow.scopesAsked),
        resource: flow.resource,
        device_hash: flow.deviceHash,
        user_code_hash: flow.userCodeHash,
        interval_s: flow.intervalSeconds,
        source_key: from.source,
        network_key: from.network,
        created_at: flow.createdAt,
        ends_at: endsAt,
        open_mac: seal.mac,
        open_key_version: seal.keyVersion,
      })
      .onConflict((conflict) => conflict.column('user_code_hash').doNothing())
      .returning('id')
      .executeTakeFirst();
    return inserted === undefined ? 'collided' : 'opened';
  });
}

/**
 * How many times someone other than the browser and person that claimed a device flow may type its code before the
 * flow is denied (AG8): its code is then known to more than one person, so neither may finish it, and the device is
 * told no. A few, not one: the person's own second browser, or a colleague reading over a shoulder, is a slip.
 */
export const MOST_FAILED_CLAIMS_A_FLOW = 3;

/** Who types a user code (AG8): their browser's flow cookie's SHA-256, and their own. */
export interface DeviceClaimant {
  readonly browserHash: string;
  readonly personHash: string;
}

/**
 * Claimed, for this browser and person; contested, the flow another's, counted and, at MOST_FAILED_CLAIMS_A_FLOW,
 * denied; or no flow open for that code.
 */
export type DeviceClaim =
  | { readonly outcome: 'claimed'; readonly flowId: string }
  | { readonly outcome: 'contested'; readonly flowId: string; readonly failedClaims: number; readonly denied: boolean }
  | { readonly outcome: 'not_found' };

/**
 * Claims the device flow whose user code this is for the browser and person `by`, at `now`: only an undecided flow in
 * time, claimed by no one (or by this same browser and person before). A flow claimed by anyone else is a failed claim,
 * counted on it in one statement, which denies it at the MOST_FAILED_CLAIMS_A_FLOW-th. Nothing found for a code typed
 * wrong, ended or decided.
 */
export async function deviceClaimed(
  db: Database,
  userCodeHash: string,
  by: DeviceClaimant,
  now: Date,
): Promise<DeviceClaim> {
  const open = (eb: ExpressionBuilder<OauthTables, 'oauth.flows'>) =>
    eb.and([
      eb('user_code_hash', '=', userCodeHash),
      eb('kind', '=', 'device'),
      eb('decided_at', 'is', null),
      eb('ends_at', '>', now),
    ]);
  const claimed = await db
    .updateTable('oauth.flows')
    .set({ browser_hash: by.browserHash, person_hash: by.personHash })
    .where(open)
    .where((eb) =>
      eb.or([
        eb('browser_hash', 'is', null),
        eb.and([eb('browser_hash', '=', by.browserHash), eb('person_hash', '=', by.personHash)]),
      ]),
    )
    .returning('id')
    .executeTakeFirst();
  if (claimed !== undefined) return { outcome: 'claimed', flowId: claimed.id };
  // Another's: counted, and denied at the cap, in one statement, so failed claims at once are each counted.
  const spent = sql<boolean>`failed_claims + 1 >= ${MOST_FAILED_CLAIMS_A_FLOW}`;
  const contested = await db
    .updateTable('oauth.flows')
    .set({
      failed_claims: sql<number>`failed_claims + 1`,
      decided_at: sql<Date | null>`case when ${spent} then ${now}::timestamptz end`,
      outcome: sql<string | null>`case when ${spent} then 'denied' end`,
    })
    .where(open)
    .where('browser_hash', 'is not', null)
    .returning(['id', 'failed_claims', 'outcome'])
    .executeTakeFirst();
  if (contested === undefined) return { outcome: 'not_found' };
  return {
    outcome: 'contested',
    flowId: contested.id,
    failedClaims: contested.failed_claims,
    denied: contested.outcome === 'denied',
  };
}

/** The device flow this device code's hash names, read unlocked: where its organisation is, never a decision. */
export async function deviceFlowOfCode(db: Database, deviceHash: string): Promise<DeviceFlowRead | undefined> {
  return deviceFlowOf(
    await db.selectFrom('oauth.flows').select(COLUMNS).where('device_hash', '=', deviceHash).executeTakeFirst(),
  );
}

/**
 * The device's poll noted at `now`, if it came no sooner than its interval after the last (RFC 8628 §3.5): whether it
 * did. One statement, so two polls at once can't both pass; one too soon leaves the last poll's time as it was.
 */
export async function devicePolled(db: Database, flowId: string, now: Date): Promise<boolean> {
  const row = await db
    .updateTable('oauth.flows')
    .set({ polled_at: now })
    .where('id', '=', flowId)
    .where('kind', '=', 'device')
    .where((eb) =>
      eb.or([
        eb('polled_at', 'is', null),
        eb('polled_at', '<=', sql<Date>`${now}::timestamptz - pg_catalog.make_interval(secs => interval_s)`),
      ]),
    )
    .returning('id')
    .executeTakeFirst();
  return row !== undefined;
}

/**
 * The device flow, locked for its tokens' issue in the caller's transaction (its organisation's), so a second poll of
 * the same allowed flow waits and finds it used: undefined if there is none.
 */
export async function deviceHeld(db: Handle, flowId: string): Promise<DeviceFlowRead | undefined> {
  return deviceFlowOf(
    await db.selectFrom('oauth.flows').select(COLUMNS).where('id', '=', flowId).forUpdate().executeTakeFirst(),
  );
}

/**
 * Marks the held code used, in the same transaction: kept only if that transaction commits, so a busy that rolls the
 * exchange back leaves the code to be sent again.
 */
export async function codeUsed(db: Handle, flowId: string, now: Date): Promise<void> {
  await db
    .updateTable('oauth.flows')
    .set({ used_at: now })
    .where('id', '=', flowId)
    .where('used_at', 'is', null)
    .execute();
}

/**
 * Deletes up to `most` flows that ended more than a day before `now`, and says how many, in a transaction of its own
 * whose statement is limited to 10 seconds. The day keeps a used code's flow for its reuse to be caught.
 */
export async function sweepFlows(db: Database, now: Date, most: number): Promise<number> {
  if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one flow at a time');
  return db.transaction().execute(async (tx) => {
    await limitStatements(tx);
    const ended = tx
      .selectFrom('oauth.flows')
      .select('id')
      .where('ends_at', '<=', new Date(now.getTime() - DAY_MS))
      .limit(most);
    const rows = await tx.deleteFrom('oauth.flows').where('id', 'in', ended).returning('id').execute();
    return rows.length;
  });
}
