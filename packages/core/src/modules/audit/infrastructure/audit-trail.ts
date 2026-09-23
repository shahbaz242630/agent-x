// The organisation audit chains in Postgres (ADR-011 §3): schema `audit`, one
// chain per organisation. Recording and checking follow the steps in
// @agentx/platform/audit-chain, given a store over these tables.
//
// Recording an event locks the organisation's chain head, and ADR-006 §6 puts
// that lock last of all: work that records an event takes its other locks
// first. The app role can only add events and read them (SEC-EVD-01); the
// head is the one row it changes.
//
// Everything read back is checked as untrusted: the database owner could have
// changed any of it, or its column types. Each event's details are stored as
// the exact JSON text that was sealed, so a change that keeps their meaning
// (a key moved, a number written another way) still shows.
//
// An event whose details carry a state seal is a signed-state event (ADR-012
// §2, @agentx/platform/audit-chain/signed-state): the latest one for an object
// is what the object's authority fields must equal. It is found by the object
// in the log itself, never from a pointer the row keeps. It is believed only
// with every later event about the object, read in the same statement as the
// chain's head: each must be sealed, and none past the head. So an edit to any
// of them (the newest signed one stripped of its seal, say) shows at once,
// not only at the next chain check. And a chain holding any event past its
// head, which refuses every new event (the integrity hold's among them), is
// read as broken for every object, so a hold kept from being set is never
// read as clear.
//
// The integrity hold's own events are recorded only by the audit module's
// signed states (recordHoldEvent): `record` refuses its subject type, so no
// other module can write an event the hold is read from.
//
// What this read can't see: a later event about the object deleted, or moved
// to another object or organisation, which the chain's check and anchor find;
// an event sealed with a key the app still holds, though rotated out, which
// only the chain's check refuses; and the table's owner rewriting its row
// security so that this query alone skips an event, which leaves the chain
// check blind too. The live schema guard (A3e-1b) and the owner-login alert
// (A3e-2) cover that; owner-tamper.db.test.ts shows the guard naming it.
//
// Events about an authority object are its state changes, few in its life;
// activity goes against other subjects (the rule in signed-states.ts). So the
// read is capped: past that many later events it throws rather than slow
// every decision, and rather than report the object broken, which would raise
// an alarm over nothing but volume.
import {
  type AnchorPoint,
  appendEvent,
  type Chain,
  type ChainHead,
  type ChainReader,
  type ChainReport,
  type ChainWriter,
  entryIsSealed,
  headFields,
  headIsSealed,
  sealedFields,
  type StateSeal,
  stateSealIn,
  type StoredEntry,
  verifyChain,
} from '@agentx/platform/audit-chain';
import { assertTenant, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { type Kysely, sql, type Transaction } from 'kysely';

import { canonicalDetails, type IdGenerator } from '../../../shared-kernel/index.ts';
import {
  type ActorType,
  type AuditEvent,
  AuditEventRefused,
  type AuditSubjectKey,
  checkedEvent,
  eventContent,
  subjectKeyProblems,
} from '../domain/event.ts';
import { HOLD_SUBJECT } from '../domain/integrity-hold.ts';
import type { AuditTables } from './tables.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A transaction on the audit tables, opened by withTenant for the organisation. */
export type AuditTransaction = Transaction<AuditTables>;

export interface RecordedAuditEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
}

/**
 * An object's latest signed state, as the log holds it:
 * - `none`: no event about the object carries a state seal. For an object
 *   that exists, that is tampering too (its only seal stripped), never "not
 *   signed yet": verifiedState (signed-states.ts) denies it and raises the alarm
 * - `signed`: the latest one, whole: its seal, the version it made, its ID and place
 * - `broken`: it can't be believed: it or a later event about the object can't
 *   be read, fails its own hash or MAC, or lies past the chain's head; any
 *   event of the chain lies past the head, or there is no head for the events
 *   there are; the head itself fails its MAC; or the seal in its details is
 *   malformed.
 *   Someone past the app changed or forged it. `seq` is where, when it could
 *   be read.
 */
export type LatestSignedState =
  | { readonly kind: 'none' }
  | {
      readonly kind: 'signed';
      readonly id: string;
      readonly seq: bigint;
      readonly recordedAt: Date;
      readonly version: number;
      readonly seal: StateSeal;
    }
  | { readonly kind: 'broken'; readonly seq?: bigint };

/** The most events about an object, its newest signed one first, that one read takes. */
const LATER_EVENTS_READ = 1000;

/**
 * Thrown by latestSignedState for an object with more than
 * LATER_EVENTS_READ events since its newest signed one: activity recorded
 * against the object itself, which belongs against another subject.
 */
export class TooManyEventsAboutObject extends Error {
  constructor() {
    super(
      `More than ${LATER_EVENTS_READ.toString()} events about the object since its newest signed state; activity belongs against another subject`,
    );
    this.name = 'TooManyEventsAboutObject';
  }
}

export interface AuditTrail {
  /**
   * Adds the event to the organisation's chain, in the caller's transaction:
   * it commits or rolls back with the change it records. Takes the chain
   * head's lock, which comes last (ADR-006 §6). Throws AuditEventRefused for
   * an event that breaks the rules, and ChainBroken if the chain fails its
   * check at the head or holds events past it, so nothing more is added to a
   * chain someone has tampered with.
   */
  record(tx: AuditTransaction, orgId: string, event: AuditEvent): Promise<RecordedAuditEvent>;
  /**
   * Checks the organisation's whole chain up to its head (SEC-EVD-02), and
   * that it still holds its last anchor, which the caller must pass, undefined
   * only for a chain never anchored (SEC-DB-11). Reads only,
   * and only in withTenant's transaction for that organisation: in any other,
   * row security would show its chain as empty.
   */
  verify(tx: AuditTransaction, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport>;
  /**
   * `verify` in a transaction of its own, withTenant's for the organisation,
   * each statement limited to 10 seconds (waits for locks included), so a stop
   * can close the pool soon after: for the anchor check of every
   * organisation's chain (B1d-2). The check keeps its own deadline too, since
   * someone who owns the database can get round this one.
   */
  verifyAlone(db: Kysely<AuditTables>, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport>;
  /**
   * The object's latest signed state (ADR-012 §2): of the events about it,
   * the newest whose details carry a state seal, with every later event about
   * it sealed and no event of the chain past the head (see the file's comment
   * for what it can't see). Only in withTenant's transaction for that
   * organisation, like `verify`.
   */
  latestSignedState(tx: AuditTransaction, orgId: string, subject: AuditSubjectKey): Promise<LatestSignedState>;
}

/** The organisation's chain, named by its ID in lower case, as Postgres returns a uuid. */
function chainOf(orgId: string): Chain & { readonly kind: 'organisation' } {
  if (!UUID.test(orgId)) throw new AuditEventRefused(['the organisation ID must be a UUID']);
  return { kind: 'organisation', orgId: orgId.toLowerCase() };
}

const isText = (value: unknown): value is string => typeof value === 'string';

/**
 * Finds a signed-state event by its details' text: canonical JSON, where the
 * key can only appear as a key, since quotes inside a value are escaped.
 */
const HAS_STATE_SEAL = '"stateFingerprint":';

/** The head read alongside the events, if it is whole: readable and sealed. */
function headIsWhole(keys: KeyProvider, chain: Chain, row: Readonly<Record<string, unknown>>): ChainHead | undefined {
  const head = headFields({
    seq: row.head_seq,
    hash: row.head_hash,
    mac: row.head_mac,
    mac_key_version: row.head_mac_key_version,
  });
  return head !== undefined && headIsSealed(keys, chain, head) ? head : undefined;
}

/** The details' JSON text as an object, or nothing if it isn't one. */
function detailsObject(text: unknown): Readonly<Record<string, unknown>> | undefined {
  if (typeof text !== 'string') return undefined;
  try {
    const parsed: unknown = JSON.parse(text);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Readonly<Record<string, unknown>>)
      : undefined;
  } catch {
    return undefined;
  }
}

/** What the chain sealed for a stored event, from its own columns, or nothing if one can't be read. */
function contentOf(row: Readonly<Record<string, unknown>>): StoredEntry['content'] | undefined {
  const { actor_type: actorType, actor_id: actorId, action, subject_type: subjectType, subject_id: subjectId } = row;
  const { subject_version: subjectVersion, details } = row;
  if (![actorType, actorId, action, subjectType, subjectId, details].every(isText)) return undefined;
  if (typeof subjectVersion !== 'number') return undefined;
  return eventContent(
    {
      actor: { type: actorType as ActorType, id: actorId as string },
      action: action as string,
      subject: { type: subjectType as string, id: subjectId as string, version: subjectVersion },
    },
    details as string,
  );
}

/** Recording's steps over the audit tables, for one organisation and one event. */
function writerFor(tx: AuditTransaction, orgId: string, event: AuditEvent, details: string): ChainWriter {
  return {
    async lockHead() {
      const row = await tx
        .selectFrom('audit.heads')
        .select(['seq', 'hash', 'mac', 'mac_key_version'])
        .where('org_id', '=', orgId)
        .forNoKeyUpdate()
        .executeTakeFirst();
      return row === undefined ? undefined : { head: headFields(row) };
    },

    async start(head) {
      await tx
        .insertInto('audit.heads')
        .values({ org_id: orgId, seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .onConflict((conflict) => conflict.column('org_id').doNothing())
        .execute();
    },

    async hasEventsPast(seq) {
      const past = await tx
        .selectFrom('audit.events')
        .select('seq')
        .where('org_id', '=', orgId)
        .where('seq', '>', seq)
        .limit(1)
        .executeTakeFirst();
      return past !== undefined;
    },

    async now() {
      const { now } = await tx
        .selectNoFrom(sql<Date>`pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp())`.as('now'))
        .executeTakeFirstOrThrow();
      return now;
    },

    async append(sealed, head, previous) {
      const moved = await tx
        .updateTable('audit.heads')
        .set({ seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .where('org_id', '=', orgId)
        .where('seq', '=', previous.seq)
        .where('hash', '=', previous.hash)
        .executeTakeFirst();
      // The head first: the event is written only once it has a place, so a refused one leaves nothing behind.
      if (moved.numUpdatedRows !== 1n) return false;
      await tx
        .insertInto('audit.events')
        .values({
          org_id: orgId,
          seq: sealed.seq,
          id: sealed.id,
          recorded_at: sealed.recordedAt,
          actor_type: event.actor.type,
          actor_id: event.actor.id,
          action: event.action,
          subject_type: event.subject.type,
          subject_id: event.subject.id,
          subject_version: event.subject.version,
          details,
          prev_hash: sealed.prevHash,
          hash: sealed.hash,
          mac: sealed.mac,
          mac_key_version: sealed.macKeyVersion,
        })
        .execute();
      return true;
    },
  };
}

/** Checking's reads of the audit tables, for one organisation. */
function readerFor(tx: AuditTransaction, orgId: string): ChainReader {
  return {
    async state() {
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.count(*) from audit.events e where e.org_id = ${orgId}) as stored,
               h.seq, h.hash, h.mac, h.mac_key_version, h.org_id is not null as has_head
        from (values (1)) as one (x)
        left join audit.heads h on h.org_id = ${orgId}
      `.execute(tx);
      const state = rows[0] ?? {};
      const stored = typeof state.stored === 'bigint' ? state.stored : 0n;
      if (state.has_head !== true) return { head: 'none', stored };
      return { head: headFields(state) ?? 'unreadable', stored };
    },

    async events(after, upTo, limit) {
      const rows = await tx
        .selectFrom('audit.events')
        .selectAll()
        .select(sql<boolean>`recorded_at = pg_catalog.date_trunc('milliseconds', recorded_at)`.as('whole_ms'))
        .where('org_id', '=', orgId)
        .where('seq', '>', after)
        .where('seq', '<=', upTo)
        .orderBy('seq')
        .limit(limit)
        .execute();
      return rows.map((row) => {
        const sealed = sealedFields(row);
        const content = contentOf(row);
        return sealed === undefined || content === undefined ? undefined : { ...sealed, content };
      });
    },
  };
}

/**
 * Each trail's recording step for the integrity hold's own events, which the
 * public `record` refuses: only recordHoldEvent reaches it, from this module.
 */
const holdRecorders = new WeakMap<AuditTrail, AuditTrail['record']>();

/**
 * Adds an event about the integrity hold (domain/integrity-hold.ts) to the
 * chain, as `record` does. For the audit module's signed states alone: the
 * public `record` refuses the hold's subject type, so no other module can
 * write an event the hold would be read from.
 */
export function recordHoldEvent(
  trail: AuditTrail,
  tx: AuditTransaction,
  orgId: string,
  event: AuditEvent,
): Promise<RecordedAuditEvent> {
  const record = holdRecorders.get(trail);
  if (record === undefined) throw new TypeError('The trail was not made by createAuditTrail');
  return record(tx, orgId, event);
}

/**
 * Locks the organisation's chain head, when it has one, to the end of the
 * transaction, as recording does. For the integrity hold, a state kept in the
 * log alone: it is read only once this is held, so two changes can't both
 * start from one state, and a decision can't pass a hold being set. Every
 * caller reads the log straight after, in a read that checks the transaction
 * is withTenant's for the organisation. The head's lock comes last (ADR-006
 * §6), so nothing else is locked after it. For the audit module alone, like
 * recordHoldEvent.
 */
export async function lockChainHead(tx: AuditTransaction, orgId: string): Promise<void> {
  const chain = chainOf(orgId);
  await tx.selectFrom('audit.heads').select('seq').where('org_id', '=', chain.orgId).forNoKeyUpdate().execute();
}

export function createAuditTrail({ keys, ids }: { readonly keys: KeyProvider; readonly ids: IdGenerator }): AuditTrail {
  /** Records the event, which must be about the integrity hold when `hold` says so, and otherwise must not. */
  const recordAs = async (
    hold: boolean,
    tx: AuditTransaction,
    orgId: string,
    input: AuditEvent,
  ): Promise<RecordedAuditEvent> => {
    const event = checkedEvent(input, hidesField);
    if ((event.subject.type === HOLD_SUBJECT) !== hold) {
      throw new AuditEventRefused([
        hold
          ? 'only the integrity hold is recorded by its own steps'
          : `subject.type ${HOLD_SUBJECT} is the integrity hold's, recorded by its own steps`,
      ]);
    }
    if (stateSealIn(event.details) === 'malformed') {
      throw new AuditEventRefused([
        'details.stateFingerprint and details.stateKeyVersion must hold a state seal, both of them or neither',
      ]);
    }
    const chain = chainOf(orgId);
    const details = canonicalDetails(event.details);
    const sealed = await appendEvent(keys, chain, writerFor(tx, chain.orgId, event, details), {
      nextId: () => ids.next(),
      content: eventContent(event, details),
    });
    return Object.freeze({ id: sealed.id, seq: sealed.seq, recordedAt: sealed.recordedAt });
  };

  const trail: AuditTrail = Object.freeze({
    record(tx: AuditTransaction, orgId: string, event: AuditEvent): Promise<RecordedAuditEvent> {
      return recordAs(false, tx, orgId, event);
    },

    async verify(tx: AuditTransaction, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      return verifyChain(keys, chain, readerFor(tx, chain.orgId), anchor);
    },

    verifyAlone(db: Kysely<AuditTables>, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      return withTenant(db, orgId, async (tx) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        return trail.verify(tx, orgId, anchor);
      });
    },

    async latestSignedState(tx: AuditTransaction, orgId: string, subject: AuditSubjectKey): Promise<LatestSignedState> {
      const problems = subjectKeyProblems(subject);
      if (problems.length > 0) throw new AuditEventRefused(problems);
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const id = subject.id.toLowerCase();
      // One statement, so the head and the events come from the same moment.
      const { rows } = await sql<Record<string, unknown>>`
        select h.org_id is not null as has_head, h.seq as head_seq, h.hash as head_hash, h.mac as head_mac,
               h.mac_key_version as head_mac_key_version, past.past_head,
               e.seq, e.id, e.recorded_at, e.actor_type, e.actor_id, e.action, e.subject_type, e.subject_id,
               e.subject_version, e.details, e.prev_hash, e.hash, e.mac, e.mac_key_version,
               e.recorded_at = pg_catalog.date_trunc('milliseconds', e.recorded_at) as whole_ms
        from (values (1)) as one (x)
        left join audit.heads h on h.org_id = ${chain.orgId}
        cross join lateral (
          select pg_catalog.min(p.seq) as past_head from audit.events p
          where p.org_id = ${chain.orgId} and p.seq > coalesce(h.seq, 0)
        ) as past
        left join audit.events e on e.org_id = ${chain.orgId} and e.subject_type = ${subject.type}
          and e.subject_id = ${id}
          and e.seq >= (
            select pg_catalog.max(s.seq) from audit.events s
            where s.org_id = ${chain.orgId} and s.subject_type = ${subject.type} and s.subject_id = ${id}
              and pg_catalog.strpos(s.details, ${HAS_STATE_SEAL}) > 0
          )
        order by e.seq
        limit ${LATER_EVENTS_READ + 1}
      `.execute(tx);
      const [first] = rows;
      // The first event of the chain past its head (or of a chain with no head), if there is one: such a chain
      // refuses every new event, the integrity hold's among them, so nothing about it is believed.
      const past = first?.past_head;
      const pastHead = past !== null;
      const brokenPast: LatestSignedState =
        typeof past === 'bigint' ? { kind: 'broken', seq: past } : { kind: 'broken' };
      if (rows.length > LATER_EVENTS_READ) {
        if (pastHead) return brokenPast;
        throw new TooManyEventsAboutObject();
      }
      const events = rows.filter((row) => row.seq !== null);
      const [newestSigned] = events;
      if (first === undefined || newestSigned === undefined) return pastHead ? brokenPast : { kind: 'none' };

      const head = first.has_head === true ? headIsWhole(keys, chain, first) : undefined;
      const read = events.map((row) => ({ row, sealed: sealedFields(row), content: contentOf(row) }));
      const bad = read.find(
        ({ sealed, content }) =>
          sealed === undefined ||
          content === undefined ||
          head === undefined ||
          sealed.seq > head.seq ||
          !entryIsSealed(keys, chain, { ...sealed, content }),
      );
      const details = detailsObject(newestSigned.details);
      const seal = details === undefined ? undefined : stateSealIn(details);
      const signed = read[0]?.sealed;
      const version = newestSigned.subject_version;
      if (
        bad !== undefined ||
        signed === undefined ||
        typeof version !== 'number' ||
        seal === undefined ||
        seal === 'malformed'
      ) {
        const seq = (bad ?? read[0])?.row.seq;
        return typeof seq === 'bigint' ? { kind: 'broken', seq } : { kind: 'broken' };
      }
      if (pastHead) return brokenPast;
      return Object.freeze({
        kind: 'signed',
        id: signed.id,
        seq: signed.seq,
        recordedAt: signed.recordedAt,
        version,
        seal,
      });
    },
  });
  holdRecorders.set(trail, (tx, orgId, event) => recordAs(true, tx, orgId, event));
  return trail;
}
