// The platform's own audit chain in Postgres (ADR-011 §3, ADR-014 §8):
// schema `platform_controls`, one chain for the whole platform. Recording and
// checking follow the steps in @agentx/platform/audit-chain, as the
// organisation chains do, given a store over these tables. They belong to no
// organisation, so they are global tables: no tenant is needed to reach them.
//
// The head is the table's only row by its key. Should someone with the owner's
// rights drop that key and add a second head, the chain counts as having no
// readable head: recording is refused and the check fails.
//
// **The operator's events carry its own signature too (PL-57).** An event whose
// actor is the operator's command is signed with `operator-signing`, a key only
// the operator's job holds, its signature kept in operator_signatures, which only
// the operator's role may add to. Every read here believes such an event only
// with a signature that checks against that key's public half, which is all the
// API holds: a foothold in the API, with the chains' MAC key and the app's role,
// can't add an operator's act, nor sign one. An operator's event recorded before
// 0079 ran (before PL-57) has none and needs none; any recorded from the place
// 0079 wrote down on does, a place no running role can move. The rule is shared
// with every organisation's chain (audit-chain/operator-signature.ts).
//
// **What the anchor check's walk reads is kept (AT13c).** Given `subjectOf`, the
// walk from the anchor and the whole walk say, for each platform event that is
// some object's signed state (the hand-off pause's moves, a session's signed
// ends), that object's newest place they read: the signed states' digest keeps
// it, so a read finding an older one is tampering at decision time.
//
// **Its head is held to the highest this process has seen (AT13h).** As an
// organisation's chain is (audit-trail.ts, AT13f): the newest events not yet
// anchored deleted, and an earlier sealed head put back, leave every seal true and
// a session's sign-out (or the hand-off pause) reading as never signed. So the
// reads that judge a session (sessions.ts) and the pause (handoff-pause.ts) read
// the head, and the hash of the event at the seen place, in their own statement
// (platformHeadRead), and a head below it, or another event there, is the chain
// cut back (platformCutBack): that session is refused, the pause read as
// tampered (paused), with the alarm. Raised by those reads, from a transaction that hasn't gone to record
// here, and by each event recorded here once its transaction commits, unless
// anything that could undo part of it was sent after (afterCommit). Kept in the
// signed states' digest (statesDigest), in memory: no trip and no file.
import {
  type AnchorPoint,
  appendEvent,
  type Chain,
  type ChainEdgeReader,
  type ChainHead,
  type ChainProblem,
  type ChainReader,
  type ChainReport,
  type ChainStep,
  type ChainWriter,
  CHAIN_START,
  type CheckedPoint,
  clockOf,
  createChainWalker,
  countIn,
  countStep,
  edgesIn,
  entryIsSealed,
  headFields,
  headHeldTo,
  headIsSealed,
  type HeadWatch,
  LAST_COUNTED,
  operatorSignature,
  passStep,
  sealedSigned,
  type SignedSeen,
  type StoredEntry,
  subjectKey,
  verifyChain,
  verifyFromAnchor,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { afterCommit, JOB_ANSWER_WITHIN_MS, limitedTransaction } from '@agentx/platform/db';
import { type Kysely, sql, type Transaction } from 'kysely';

import { canonicalDetails, type IdGenerator } from '../../../shared-kernel/index.ts';
import { statesDigest } from '../../audit/index.ts';
import { checkedPlatformEvent, type PlatformEvent, platformEventContent } from '../domain/event.ts';
import type { PlatformControlsTables } from './tables.ts';

/** A transaction on the platform-controls tables: any transaction, since they belong to no organisation. */
export type PlatformTransaction = Transaction<PlatformControlsTables>;

export interface RecordedPlatformEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
}

export interface PlatformChain {
  /**
   * Adds the event to the platform chain, in the caller's transaction. Takes
   * the chain head's lock, which comes last (ADR-006 §6), waiting at most
   * HEAD_WAIT_SECONDS for it, or less where the caller's transaction already
   * allows less. Anything else holding it (a session left open by hand, a stuck
   * operator action) would otherwise hold the caller up with no line saying
   * why, until the platform gave up on it; this way recording fails with
   * Postgres's lock-timeout error, and says so. The limit is `set local`, so
   * it holds for the rest of the caller's transaction, which takes no lock
   * after this one. Throws PlatformEventRefused for an event that breaks the
   * rules, and ChainBroken if the chain fails its check at the head or holds
   * events past it.
   */
  record(tx: PlatformTransaction, event: PlatformEvent): Promise<RecordedPlatformEvent>;
  /** Records the event in a transaction of its own, as a process does when it starts. */
  recordAlone(db: Kysely<PlatformControlsTables>, event: PlatformEvent): Promise<RecordedPlatformEvent>;
  /** Checks the platform chain up to its head (SEC-EVD-02), and that it still holds its last anchor if given one (SEC-DB-11). Reads only. */
  verify(tx: PlatformTransaction, anchor: AnchorPoint | undefined): Promise<ChainReport>;
  /**
   * The same check in a transaction of its own, as the anchor check runs it,
   * each statement given 10 seconds at most, a wait for a lock included: a
   * held lock or a stalled query then fails the check, which says so. The
   * anchor check keeps its own deadline too, since someone who owns the
   * database can get round this one. One that holds says which signed objects
   * it read, given `subjectOf` (AT13c).
   */
  verifyAlone(db: Kysely<PlatformControlsTables>, anchor: AnchorPoint | undefined): Promise<WalkedReport>;
  /**
   * Every organisation the chain records as created (`organization.created`'s
   * `orgId`, B1c-2b), in the order recorded, in a transaction of its own, 10
   * seconds per statement: the anchor check holds the directory's list to it
   * (B1d-2). Read as stored; the chain's own check is what shows an event
   * changed, added or deleted. Details that aren't an object with an `orgId`
   * text give nothing.
   */
  createdOrganizations(db: Kysely<PlatformControlsTables>, page?: number, answeredWithinMs?: number): Promise<string[]>;
  /**
   * The chain checked from its last anchor (verifyFromAnchor, 4D2e E): at most
   * `most` events past it, in a limited transaction of its own. One that holds
   * says which signed objects it read, given `subjectOf` (AT13c).
   */
  checkFromAnchor(
    db: Kysely<PlatformControlsTables>,
    from: CheckedPoint,
    most?: number,
  ): Promise<ChainStep & { readonly signed?: SignedSeen }>;
  /** One step of a full pass over the chain's old events (passStep, 4D2e E), in a transaction as checkFromAnchor's. */
  passStep(
    db: Kysely<PlatformControlsTables>,
    cursor: CheckedPoint,
    target: CheckedPoint,
    most: number,
  ): Promise<ChainStep>;
  /** Whether every event of a stretch of the chain is stored (countStep, 4D2e E), in a transaction as checkFromAnchor's. */
  countStep(db: Kysely<PlatformControlsTables>, after: bigint, upTo: bigint): Promise<ChainProblem | undefined>;
  /**
   * The organisations `createdOrganizations` gives, recorded past `afterSeq`
   * and no further than `upTo`, and the number to ask from next time: the last
   * such event's, or `afterSeq` if there were none (4D2e E: not the whole list
   * every run). `upTo` is the place the chain's check just reached: a row it
   * hasn't reached is neither believed nor moves the number on, or one planted
   * far past the head and deleted after a single alarm would leave every later
   * organisation unread. An event's number moves on even where its details give
   * no organisation. Limited as checkFromAnchor's, each trip's answer within `answeredWithinMs` where given.
   */
  createdOrganizationsSince(
    db: Kysely<PlatformControlsTables>,
    afterSeq: bigint,
    upTo: bigint,
    answeredWithinMs?: number,
  ): Promise<{ readonly orgIds: readonly string[]; readonly seq: bigint }>;
}

/** A whole check's report, and for one that holds, the signed objects it read (AT13c). */
type WalkedReport = ChainReport & { readonly signed?: SignedSeen };

/**
 * The signed states' object a platform event is, if it is one (AT13c): its type and ID as the digest keys it. Given by
 * the process that keeps the digest, which knows every module's events (job-list.ts).
 */
export type PlatformSubjectOf = (action: string, details: string) => readonly [string, string] | undefined;

/**
 * The walk's reads, each event looked at as it goes for an object it is a signed state of: no read of its own. Kept
 * only for a walk that holds (`walked`).
 */
function seeingSubjects(
  reader: ChainReader & ChainEdgeReader,
  seen: Map<string, bigint>,
  subjectOf: PlatformSubjectOf,
): ChainReader & ChainEdgeReader {
  return {
    ...reader,
    async events(after, upTo, limit) {
      const batch = await reader.events(after, upTo, limit);
      for (const entry of batch) {
        // platformEventContent's order: actor, its type and ID, then the action, then the details.
        const [, , , , action, , details] = entry?.content ?? [];
        if (entry === undefined || typeof action !== 'string' || typeof details !== 'string') continue;
        const subject = subjectOf(action, details);
        if (subject === undefined) continue;
        const key = subjectKey(...subject);
        if ((seen.get(key) ?? 0n) < entry.seq) seen.set(key, entry.seq);
      }
      return batch;
    },
  };
}

/** A walk and what it saw, kept only for one that holds: one that fails read no chain to believe. */
const walked = <Step extends ChainReport>(step: Step, seen: SignedSeen): Step & { readonly signed?: SignedSeen } =>
  step.ok && seen.size > 0 ? { ...step, signed: seen } : step;

/** The platform event that records an organisation made, with its `orgId` in the details. */
const ORGANIZATION_CREATED = 'organization.created';

/** The `orgId` text in an event's stored details, if they hold one. */
function orgIdIn(details: unknown): string | undefined {
  if (typeof details !== 'string') return undefined;
  try {
    const parsed: unknown = JSON.parse(details);
    if (typeof parsed !== 'object' || parsed === null || !('orgId' in parsed)) return undefined;
    return typeof parsed.orgId === 'string' ? parsed.orgId : undefined;
  } catch {
    return undefined;
  }
}

const CHAIN: Chain = { kind: 'platform' };

/**
 * The transactions that have gone to record on the platform chain (AT13h): their reads see their own events, which may
 * never commit, so none of them raises the head this process has seen.
 */
const headsTaken = new WeakSet<object>();

/** The platform chain's head as a read finds it, and the hash of the event at the place it is held to: platformHeadRead's columns. */
export interface PlatformHeadOfRow {
  readonly platform_heads: bigint | null;
  readonly platform_head_seq: bigint | null;
  readonly platform_head_hash: Buffer | null;
  readonly platform_head_mac: Buffer | null;
  readonly platform_head_mac_key_version: number | null;
  readonly platform_seen_hash: Buffer | null;
}

/**
 * The platform chain's head, how many heads there are (one, or none is believed), and the hash of the event at `seenAt`
 * (the place the read is held to, by the events' key), as columns of the caller's statement (AT13h), so all come from
 * its snapshot: a few one-row reads, no trip.
 */
export function platformHeadRead(seenAt: bigint | undefined) {
  const head = <Column>(column: string) =>
    sql<Column | null>`(select ${sql.ref('h.' + column)} from platform_controls.audit_head h limit 1)`;
  const seenHash =
    seenAt === undefined
      ? sql<Buffer | null>`null::bytea`
      : sql<Buffer | null>`(select s.hash from platform_controls.audit_events s where s.seq = ${seenAt} limit 1)`;
  return [
    sql<bigint | null>`(select pg_catalog.count(*) from platform_controls.audit_head)`.as('platform_heads'),
    head<bigint>('seq').as('platform_head_seq'),
    head<Buffer>('hash').as('platform_head_hash'),
    head<Buffer>('mac').as('platform_head_mac'),
    head<number>('mac_key_version').as('platform_head_mac_key_version'),
    seenHash.as('platform_seen_hash'),
  ] as const;
}

/** A platform head as a read holds it: its place and hash. */
type PlatformHead = NonNullable<HeadWatch['seen']>;

/**
 * The head `watch` holds the platform chain to, where the chain was cut back below it (AT13h, the header), as
 * platformHeadRead read it in `tx`'s statement: below it, none, two, not sealed, or another event at its place. Else
 * none, and the head is raised to the one read, unless `tx` has gone to record here. Nothing to hold to without a watch.
 */
export function platformCutBack(
  keys: KeyProvider,
  tx: object,
  watch: Pick<HeadWatch, 'seen' | 'saw'> | undefined,
  row: PlatformHeadOfRow,
): PlatformHead | undefined {
  if (watch === undefined) return undefined;
  const fields =
    row.platform_heads === 1n
      ? headFields({
          seq: row.platform_head_seq,
          hash: row.platform_head_hash,
          mac: row.platform_head_mac,
          mac_key_version: row.platform_head_mac_key_version,
        })
      : undefined;
  const head = fields !== undefined && headIsSealed(keys, CHAIN, fields) ? fields : undefined;
  const { seen } = watch;
  if (seen !== undefined && !headHeldTo(seen, head, row.platform_seen_hash)) return seen;
  if (head !== undefined && !headsTaken.has(tx)) watch.saw({ seq: head.seq, hash: head.hash });
  return undefined;
}

/**
 * The platform chain's head, locked as recording locks it, the last lock of the caller's transaction, if it is the one
 * head and sealed (AT13h: where a cut answered is taken from). One statement.
 */
export async function lockedPlatformHead(
  tx: PlatformTransaction,
  keys: KeyProvider,
): Promise<PlatformHead | undefined> {
  const { rows } = await sql<Record<string, unknown>>`
    select h.seq, h.hash, h.mac, h.mac_key_version from platform_controls.audit_head h for no key update
  `.execute(tx);
  const head = rows.length === 1 ? headFields(rows[0] ?? {}) : undefined;
  return head !== undefined && headIsSealed(keys, CHAIN, head) ? { seq: head.seq, hash: head.hash } : undefined;
}

/** What the platform chain's reads are held to (AT13h): the signed states' digest's watch, none where none is kept. */
const platformHeadWatch = (): HeadWatch | undefined => statesDigest()?.heads?.(CHAIN);

/**
 * Every platform event, each with the operator's signature on it, if any, and
 * where signatures start (`signed_from`, the chain's next place when 0079 ran,
 * null if its row is gone): the read every belief in an event goes through.
 */
export function platformEventsSigned(tx: PlatformTransaction) {
  return tx
    .selectFrom('platform_controls.audit_events as e')
    .leftJoin('platform_controls.operator_signatures as s', 's.seq', 'e.seq')
    .selectAll('e')
    .select([
      sql<boolean>`e.recorded_at = pg_catalog.date_trunc('milliseconds', e.recorded_at)`.as('whole_ms'),
      's.signature as signature',
      's.key_version as signature_key_version',
      // Written once by 0079, by the owner: no running role can move it (PL-57).
      sql<bigint | null>`(select f.signed_from from platform_controls.operator_signing f)`.as('signed_from'),
    ]);
}

/** How many of those events one statement reads. */
const CREATED_PAGE = 10_000;

const isText = (value: unknown): value is string => typeof value === 'string';

/** What the chain sealed for a stored event, from its own columns, or nothing if one can't be read. */
function contentOf(row: Readonly<Record<string, unknown>>): StoredEntry['content'] | undefined {
  const { actor_type: actorType, actor_id: actorId, action, details } = row;
  if (![actorType, actorId, action, details].every(isText)) return undefined;
  return platformEventContent(
    { actor: { type: actorType as 'system', id: actorId as string }, action: action as string },
    details as string,
  );
}

/**
 * Whether one stored platform event, read whole through platformEventsSigned,
 * is sealed: its content hashes to its hash, its MAC is right (entryIsSealed),
 * and an operator's event carries its signature (PL-57). For reading one event
 * on its own, such as the hand-off pause's newest (B1): an event planted or
 * edited past the app isn't believed, without waiting for the whole chain's check.
 */
export function platformEventSealed(keys: KeyProvider, row: Readonly<Record<string, unknown>>): boolean {
  const sealed = sealedSigned(keys, CHAIN, row);
  const content = contentOf(row);
  return sealed !== undefined && content !== undefined && entryIsSealed(keys, CHAIN, { ...sealed, content });
}

/** Recording's steps over the platform-controls tables, for one event. */
function writerFor(tx: PlatformTransaction, event: PlatformEvent, details: string, keys: KeyProvider): ChainWriter {
  return {
    async lockHead() {
      // The clock in the outer select, which reads a row only once the inner one has locked it.
      const { rows } = await sql<Record<string, unknown>>`
        with locked as materialized (
          select h.seq, h.hash, h.mac, h.mac_key_version from platform_controls.audit_head h
          for no key update
        )
        select l.*, pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp()) as now from locked l
      `.execute(tx);
      const [row, ...others] = rows;
      if (row === undefined) return undefined;
      // A second head row means someone went round the app: no head can be trusted.
      return { head: others.length > 0 ? undefined : headFields(row), now: clockOf(row) };
    },

    async start(head) {
      await tx
        .insertInto('platform_controls.audit_head')
        .values({ seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .onConflict((conflict) => conflict.column('only_row').doNothing())
        .execute();
    },

    async append(sealed, head, previous) {
      // An operator's event signed with its own key, which no other process holds: anyone else's sign() throws.
      const signed = operatorSignature(keys, CHAIN, event.actor.id, sealed);
      // The head moves only if it is still `previous` with no event past it.
      const moveHead = sql`
        update platform_controls.audit_head
        set seq = ${head.seq}, hash = ${head.hash}, mac = ${head.mac}, mac_key_version = ${head.macKeyVersion}
        where seq = ${previous.seq} and hash = ${previous.hash}
          and not exists (select from platform_controls.audit_events p where p.seq > ${previous.seq})
        returning seq
      `;
      const addEvent = sql`
        insert into platform_controls.audit_events (seq, id, recorded_at, actor_type, actor_id, action, details,
                                                    prev_hash, hash, mac, mac_key_version)
        select ${sealed.seq}::bigint, ${sealed.id}::uuid, ${sealed.recordedAt}::timestamptz, ${event.actor.type}::text,
               ${event.actor.id}::text, ${event.action}::text, ${details}::text, ${sealed.prevHash}::bytea,
               ${sealed.hash}::bytea, ${sealed.mac}::bytea, ${sealed.macKeyVersion}::integer
        from moved
      `;
      // One statement: the event (and its signature) is written only if the head moved, so a refused one leaves
      // nothing behind.
      const written = await (
        signed === undefined
          ? sql`with moved as (${moveHead}) ${addEvent}`
          : sql`
              with moved as (${moveHead}), added as (${addEvent} returning seq, id)
              insert into platform_controls.operator_signatures (seq, id, signature, key_version)
              select a.seq, a.id, ${signed.signature}::bytea, ${signed.keyVersion}::integer from added a
            `
      ).execute(tx);
      return written.numAffectedRows === 1n;
    },
  };
}

/** Checking's reads of the platform-controls tables. */
function readerFor(tx: PlatformTransaction, keys: KeyProvider): ChainReader & ChainEdgeReader {
  return {
    async edges(anchored) {
      // One statement, so all of it comes from one moment. Each on the events' key, whatever the chain's length.
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.count(*) from platform_controls.audit_head) as heads,
               h.seq as head_seq, h.hash as head_hash, h.mac as head_mac, h.mac_key_version as head_mac_key_version,
               (select pg_catalog.min(p.seq) from platform_controls.audit_events p) as lowest,
               (select pg_catalog.max(p.seq) from platform_controls.audit_events p) as highest,
               (select p.hash from platform_controls.audit_events p where p.seq = h.seq limit 1) as head_event_hash,
               (select pg_catalog.count(distinct p.seq) from platform_controls.audit_events p
                where p.seq > h.seq - ${LAST_COUNTED} and p.seq <= h.seq) as last_stored,
               e.*, e.recorded_at = pg_catalog.date_trunc('milliseconds', e.recorded_at) as whole_ms
        from (values (1)) as one (x)
        left join (select * from platform_controls.audit_head limit 1) as h on true
        left join platform_controls.audit_events e on e.seq = ${anchored}
      `.execute(tx);
      // One row always (`values` and left joins), but two where two events share a number, the table's key
      // gone: neither is the one anchored.
      const row = rows.length > 1 ? { ...rows[0], seq: null } : { ...rows[0] };
      return edgesIn(row, contentOf(row));
    },

    async countBetween(after, upTo) {
      const { rows } = await sql<Record<string, unknown>>`
        select pg_catalog.count(distinct e.seq) as stored from platform_controls.audit_events e
        where e.seq > ${after} and e.seq <= ${upTo}
      `.execute(tx);
      return countIn(rows[0]);
    },

    async state() {
      // One statement, so the head and the count of events come from the same moment.
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.count(*) from platform_controls.audit_events) as stored,
               (select pg_catalog.count(*) from platform_controls.audit_head) as heads,
               h.seq, h.hash, h.mac, h.mac_key_version
        from (values (1)) as one (x)
        left join (select * from platform_controls.audit_head limit 1) as h on true
      `.execute(tx);
      const state = rows[0] ?? {};
      const stored = typeof state.stored === 'bigint' ? state.stored : 0n;
      if (state.heads === 0n) return { head: 'none', stored };
      if (state.heads !== 1n) return { head: 'unreadable', stored };
      return { head: headFields(state) ?? 'unreadable', stored };
    },

    async events(after, upTo, limit) {
      const rows = await platformEventsSigned(tx)
        .where('e.seq', '>', after)
        .where('e.seq', '<=', upTo)
        .orderBy('e.seq')
        .limit(limit)
        .execute();
      return rows.map((row) => {
        const sealed = sealedSigned(keys, CHAIN, row);
        const content = contentOf(row);
        return sealed === undefined || content === undefined ? undefined : { ...sealed, content };
      });
    },
  };
}

/**
 * How long recording waits for the head's lock: a second under the statement
 * limit a request's transaction runs with (STATEMENT_SECONDS), so a wait that
 * runs out ends as the lock timeout it is, never as a statement cut short (a
 * test records under both). Written out in boundHeadWait's SQL too.
 */
export const HEAD_WAIT_SECONDS = 9;

/** A platform event read back and checked in place: what checkPlatformStretch gives. */
export interface CheckedPlatformEvent {
  readonly seq: bigint;
  readonly recordedAt: Date;
  readonly action: string;
  /** Its details, as the exact JSON text that was sealed. */
  readonly details: string;
}

/** A place on the platform chain already checked, with when its event was recorded. */
export interface PlatformPoint extends CheckedPoint {
  readonly recordedAt: Date;
}

/** Where a stretch's check starts: from the last event recorded before a moment, or after a place checked before. */
export type StretchStart =
  /** From a moment; `through`, a place checked before, which the chain must still run through, unchanged. */
  { readonly since: Date; readonly through?: PlatformPoint } | { readonly after: PlatformPoint };

/** What checkPlatformStretch found: the stretch whole up to the head (none for a chain never started), or a problem. */
export type StretchCheck =
  | { readonly kind: 'checked'; readonly reached: PlatformPoint | undefined }
  | { readonly kind: 'broken'; readonly problem: ChainProblem };

/** How many events one statement of a stretch's check reads. */
const STRETCH_PAGE = 1000;

/** Before the chain's first event. */
const START_POINT: PlatformPoint = Object.freeze({ ...CHAIN_START, recordedAt: new Date(0) });

/**
 * The chain's head, its MAC checked: `none` for a chain never started (no head, and no event either), undefined for
 * one that can't be believed (no head over events, two heads, or a MAC that doesn't hold).
 */
async function sealedHead(tx: PlatformTransaction, keys: KeyProvider): Promise<ChainHead | 'none' | undefined> {
  const heads = await tx.selectFrom('platform_controls.audit_head').selectAll().limit(2).execute();
  if (heads.length === 0) {
    const any = await tx.selectFrom('platform_controls.audit_events').select('seq').limit(1).executeTakeFirst();
    return any === undefined ? 'none' : undefined;
  }
  const head = heads.length === 1 ? headFields(heads[0] ?? {}) : undefined;
  return head !== undefined && headIsSealed(keys, CHAIN, head) ? head : undefined;
}

/**
 * Where a stretch from `since` starts: the last event recorded before it, by 0103's index (one entry), which must be
 * sealed itself; the chain's start if there is none. For one that isn't sealed, its place.
 */
async function pointBefore(
  tx: PlatformTransaction,
  keys: KeyProvider,
  since: Date,
  head: ChainHead,
): Promise<PlatformPoint | bigint> {
  const row = await platformEventsSigned(tx)
    .where('e.recorded_at', '<', since)
    .where('e.seq', '<=', head.seq)
    .orderBy('e.recorded_at', 'desc')
    .orderBy('e.seq', 'desc')
    .limit(1)
    .executeTakeFirst();
  if (row === undefined) return START_POINT;
  const sealed = sealedSigned(keys, CHAIN, row);
  if (sealed === undefined || !platformEventSealed(keys, row)) return row.seq;
  return { seq: sealed.seq, hash: sealed.hash, macKeyVersion: sealed.macKeyVersion, recordedAt: row.recorded_at };
}

/**
 * The walk's problem with the next event, if any: out of place or not sealed, or sealed and in place but not the
 * event checked there before (`through`): the chain grown again on a wound-back head.
 */
function rowProblem(
  keys: KeyProvider,
  walker: ReturnType<typeof createChainWalker>,
  row: Readonly<Record<string, unknown>> & { readonly seq: bigint; readonly hash: Buffer },
  through: PlatformPoint | undefined,
): ChainProblem | undefined {
  const sealed = sealedSigned(keys, CHAIN, row);
  const content = contentOf(row);
  const problem =
    sealed === undefined || content === undefined ? walker.unreadable() : walker.check({ ...sealed, content });
  if (problem !== undefined) return problem;
  return row.seq === through?.seq && !row.hash.equals(through.hash) ? { reason: 'anchor', seq: row.seq } : undefined;
}

/**
 * Walks the events after `from` up to the head, a page at a time, giving `seen` each page once it holds: the place
 * reached, the head's, or the first problem. The last event must be the head's: an event missing at the top, under a
 * head left where it was, shows too.
 */
async function walkToHead(
  tx: PlatformTransaction,
  keys: KeyProvider,
  from: PlatformPoint,
  head: ChainHead,
  seen: (events: readonly CheckedPlatformEvent[]) => void,
  through?: PlatformPoint,
): Promise<PlatformPoint | ChainProblem> {
  const walker = createChainWalker(keys, CHAIN, from);
  let reached = from;
  while (reached.seq < head.seq) {
    const rows = await platformEventsSigned(tx)
      .where('e.seq', '>', reached.seq)
      .where('e.seq', '<=', head.seq)
      .orderBy('e.seq')
      .limit(STRETCH_PAGE)
      .execute();
    const events: CheckedPlatformEvent[] = [];
    for (const row of rows) {
      const problem = rowProblem(keys, walker, row, through);
      if (problem !== undefined) return problem;
      events.push({ seq: row.seq, recordedAt: row.recorded_at, action: row.action, details: row.details });
      reached = { seq: row.seq, hash: row.hash, macKeyVersion: row.mac_key_version, recordedAt: row.recorded_at };
    }
    seen(events);
    // A page short of the head: the events between are missing.
    if (rows.length < STRETCH_PAGE) break;
  }
  if (reached.seq === head.seq) return reached.hash.equals(head.hash) ? reached : { reason: 'head', seq: head.seq };
  return { reason: 'gap', seq: reached.seq + 1n };
}

/**
 * Checks the platform chain from `start` through its head, in the caller's transaction (R-15, S206), a page at a time,
 * giving `seen` each page's events once they hold: each following the last in number and link, hashing to its hash
 * with its MAC (an operator's signature too), the last one the head's, whose own MAC holds. So an event of the
 * stretch deleted, edited or planted, even for a moment and put back after, shows while it is so. From `since`: from
 * the last event recorded before that moment (recorded_at rises with seq, taken under the head's lock). From `after`:
 * from a place checked before, whose events the caller keeps; a head behind it is the chain wound back. The head is
 * read first, then the events up to it, so one committed meanwhile is past it and left for the next check.
 * What this can't see: the newest events deleted and the head wound back to an older one, whose MAC still holds,
 * before anyone checked past it; the anchor check finds that once an anchor has passed the events.
 */
export async function checkPlatformStretch(
  tx: PlatformTransaction,
  keys: KeyProvider,
  start: StretchStart,
  seen: (events: readonly CheckedPlatformEvent[]) => void,
): Promise<StretchCheck> {
  const head = await sealedHead(tx, keys);
  if (head === 'none' && !('after' in start)) return { kind: 'checked', reached: undefined };
  if (head === 'none' || head === undefined) return { kind: 'broken', problem: { reason: 'head', seq: 0n } };
  const through = 'after' in start ? start.after : start.through;
  // A head behind a place checked before: the chain wound back.
  if (through !== undefined && head.seq < through.seq) {
    return { kind: 'broken', problem: { reason: 'head', seq: head.seq } };
  }
  const before = 'after' in start ? start.after : await pointBefore(tx, keys, start.since, head);
  if (typeof before === 'bigint') return { kind: 'broken', problem: { reason: 'mac', seq: before } };
  // From the earlier of the two, so the walk covers the moment and runs through the place checked before.
  const from = through !== undefined && through.seq < before.seq ? through : before;
  if (from.seq === through?.seq && !from.hash.equals(through.hash)) {
    return { kind: 'broken', problem: { reason: 'anchor', seq: from.seq } };
  }
  const walked = await walkToHead(tx, keys, from, head, seen, through);
  return 'reason' in walked ? { kind: 'broken', problem: walked } : { kind: 'checked', reached: walked };
}

/**
 * Bounds how long the transaction waits for a lock from here on:
 * HEAD_WAIT_SECONDS, unless the caller has already set a shorter limit, which
 * is kept (Postgres's `0` is no limit at all). A limit that can't be read is
 * replaced.
 */
async function boundHeadWait(tx: PlatformTransaction): Promise<void> {
  const { rows } = await sql<{ longer: boolean | null }>`
    select (limit_now = interval '0' or limit_now > interval '9 seconds') as longer
    from (select pg_catalog.current_setting('lock_timeout')::interval as limit_now) as setting
  `.execute(tx);
  if (rows[0]?.longer !== false) await sql`set local lock_timeout = '9s'`.execute(tx);
}

export function createPlatformChain({
  keys,
  ids,
  subjectOf,
}: {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** Which events are some object's signed state, for the anchor check's walks to say (AT13c): none, and none say. */
  readonly subjectOf?: PlatformSubjectOf;
}): PlatformChain {
  /** The walk's reads, seeing the signed objects where `subjectOf` is given, and what it saw kept for it. */
  const walking = async <Step extends ChainReport>(
    walk: (reader: ChainReader & ChainEdgeReader) => Promise<Step>,
    tx: PlatformTransaction,
  ): Promise<Step & { readonly signed?: SignedSeen }> => {
    if (subjectOf === undefined) return walk(readerFor(tx, keys));
    const seen = new Map<string, bigint>();
    return walked(await walk(seeingSubjects(readerFor(tx, keys), seen, subjectOf)), seen);
  };

  const record = async (tx: PlatformTransaction, input: PlatformEvent): Promise<RecordedPlatformEvent> => {
    const event = checkedPlatformEvent(input, hidesField);
    const details = canonicalDetails(event.details);
    headsTaken.add(tx);
    // AT13h, the header: given before the write, so anything that could undo it, sent from here on, keeps it unraised.
    const moved: { head?: { readonly seq: bigint; readonly hash: Buffer } } = {};
    const watch = platformHeadWatch();
    if (watch !== undefined) {
      await afterCommit(tx, () => {
        if (moved.head !== undefined) watch.saw(moved.head);
      });
    }
    await boundHeadWait(tx);
    const sealed = await appendEvent(keys, CHAIN, writerFor(tx, event, details, keys), {
      nextId: () => ids.next(),
      content: platformEventContent(event, details),
    });
    moved.head = { seq: sealed.seq, hash: sealed.hash };
    return Object.freeze({ id: sealed.id, seq: sealed.seq, recordedAt: sealed.recordedAt });
  };

  return Object.freeze({
    record,

    recordAlone(db: Kysely<PlatformControlsTables>, event: PlatformEvent): Promise<RecordedPlatformEvent> {
      return db
        .transaction()
        .setIsolationLevel('read committed')
        .execute((tx) => record(tx, event));
    },

    verify(tx: PlatformTransaction, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      return verifyChain(keys, CHAIN, readerFor(tx, keys), anchor);
    },

    verifyAlone(db: Kysely<PlatformControlsTables>, anchor: AnchorPoint | undefined): Promise<WalkedReport> {
      // Each statement limited, waits for locks included, so the pool can be closed soon after a stop.
      return limitedTransaction(db, (tx) => walking((reader) => verifyChain(keys, CHAIN, reader, anchor), tx), {
        answeredWithinMs: JOB_ANSWER_WITHIN_MS,
      });
    },

    async createdOrganizations(
      db: Kysely<PlatformControlsTables>,
      page = CREATED_PAGE,
      answeredWithinMs?: number,
    ): Promise<string[]> {
      const created: string[] = [];
      let after = 0n;
      // In pages, each a statement within its limit, so no number of organisations can make the read fail whole.
      for (;;) {
        const rows = await limitedTransaction(
          db,
          (tx) =>
            tx
              .selectFrom('platform_controls.audit_events')
              .select(['seq', 'details'])
              .where('action', '=', ORGANIZATION_CREATED)
              .where('seq', '>', after)
              .orderBy('seq')
              .limit(page)
              .execute(),
          answeredWithinMs === undefined ? {} : { answeredWithinMs },
        );
        for (const row of rows) {
          const id = orgIdIn(row.details);
          if (id !== undefined) created.push(id);
        }
        const last = rows.at(-1);
        if (last === undefined || rows.length < page) return created;
        after = last.seq;
      }
    },

    checkFromAnchor(db: Kysely<PlatformControlsTables>, from: CheckedPoint, most?: number) {
      return limitedTransaction(
        db,
        (tx) => walking((reader) => verifyFromAnchor(keys, CHAIN, reader, from, most), tx),
        { answeredWithinMs: JOB_ANSWER_WITHIN_MS },
      );
    },

    passStep(
      db: Kysely<PlatformControlsTables>,
      cursor: CheckedPoint,
      target: CheckedPoint,
      most: number,
    ): Promise<ChainStep> {
      return limitedTransaction(db, (tx) => passStep(keys, CHAIN, readerFor(tx, keys), cursor, target, most));
    },

    countStep(db: Kysely<PlatformControlsTables>, after: bigint, upTo: bigint): Promise<ChainProblem | undefined> {
      return limitedTransaction(db, (tx) => countStep(readerFor(tx, keys), after, upTo));
    },

    async createdOrganizationsSince(
      db: Kysely<PlatformControlsTables>,
      afterSeq: bigint,
      upTo: bigint,
      answeredWithinMs?: number,
    ) {
      const rows = await limitedTransaction(
        db,
        (tx) =>
          tx
            .selectFrom('platform_controls.audit_events')
            .select(['seq', 'details'])
            .where('action', '=', ORGANIZATION_CREATED)
            .where('seq', '>', afterSeq)
            .where('seq', '<=', upTo)
            .orderBy('seq')
            .execute(),
        answeredWithinMs === undefined ? {} : { answeredWithinMs },
      );
      return Object.freeze({
        orgIds: rows.map((row) => orgIdIn(row.details)).filter((id) => id !== undefined),
        seq: rows.at(-1)?.seq ?? afterSeq,
      });
    },
  });
}
