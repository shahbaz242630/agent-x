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
  appendEvents,
  type Chain,
  type ChainBatchWriter,
  type ChainHead,
  type ChainReader,
  type ChainReport,
  clockOf,
  entryIsSealed,
  headFields,
  headIsSealed,
  sealedFields,
  type StateSeal,
  stateSealIn,
  type StoredEntry,
  verifyChain,
} from '@agentx/platform/audit-chain';
import { assertTenant, type GatheredRead, sendTogether, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { type Compilable, type Kysely, type QueryResult, type RawBuilder, sql, type Transaction } from 'kysely';

import { canonicalDetails, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import {
  actorAsKept,
  type ActorType,
  type AuditActor,
  type AuditEvent,
  AuditEventRefused,
  type AuditSubjectKey,
  checkedEvent,
  eventContent,
  subjectKeyProblems,
  subjectTypeProblems,
} from '../domain/event.ts';
import { HISTORY_CHECK_SUBJECT, HOLD_SUBJECT, INVESTIGATION_SUBJECT } from '../domain/integrity-hold.ts';
import type { AuditTables } from './tables.ts';

/** A transaction on the audit tables, opened by withTenant for the organisation. */
export type AuditTransaction = Transaction<AuditTables>;

export interface RecordedAuditEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
}

/** A read that can't be believed: `seq` is where, when it could be read. */
interface BrokenRead {
  readonly kind: 'broken';
  readonly seq?: bigint;
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
  | BrokenRead;

/**
 * An object latestSignedStates can't judge now: more than LATER_EVENTS_READ
 * events about it since its newest signed one (latestSignedState's
 * TooManyEventsAboutObject). Not a tamper sign (partner decision 5, Phase 3):
 * a list leaves it out and says so, any other read is refused (A1b).
 */
interface BackloggedRead {
  readonly kind: 'backlog';
}

const BACKLOGGED: BackloggedRead = Object.freeze({ kind: 'backlog' });

/** An event to find: by its own ID, or as the one event about an object recorded once. */
export type EventToFind = { readonly eventId: string } | { readonly onlyAbout: AuditSubjectKey };

/** An event read back whole: its ID, its place in the chain, when it was recorded and what it says. */
export interface ReadEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
  readonly event: AuditEvent;
}

/**
 * One event, found by its ID or its object (recordedEvent):
 * - `none`: no event of the organisation's has that ID, or is about that object
 * - `recorded`: the event, whole, sealed and no later than the chain's head
 * - `broken`: it can't be believed: it can't be read or fails its own hash or
 *   MAC, it lies past the head, or the chain holds any event past its head or
 *   has no head for the events there are (as latestSignedState reads a chain)
 */
export type RecordedEventCheck = { readonly kind: 'none' } | ({ readonly kind: 'recorded' } & ReadEvent) | BrokenRead;

/**
 * Every event about objects of some types (recordedEvents), in chain order:
 * `recorded`, each whole as recordedEvent believes one; or `broken`, at the
 * first that isn't, or where the chain holds an event past its head.
 */
export type RecordedEventsCheck = { readonly kind: 'recorded'; readonly events: readonly ReadEvent[] } | BrokenRead;

/** A page of the organisation's whole log (logPage), newest first, each event with its chain links. */
export interface LogPageToRead {
  /** Recorded at or after it. */
  readonly from: Date;
  /** Recorded before it. */
  readonly to: Date;
  /** Only these actions, when named. */
  readonly actions?: readonly string[] | undefined;
  /** Only this actor's, when named (decision 26: per person, one click). */
  readonly actor?: AuditActor | undefined;
  /** Only events before this one in the chain: the page before's `next`. */
  readonly beforeSeq?: bigint | undefined;
  /** The most events the page holds. */
  readonly limit: number;
}

/** The log's events by one actor, as kept. */
const actorIs = ({ type, id }: AuditActor) => sql`e.actor_type = ${type} and e.actor_id = ${id}`;

/** An event of the log as its page shows it: whole, with the hashes that link it into the chain, as hex. */
export interface LogEvent extends ReadEvent {
  readonly hash: string;
  readonly prevHash: string;
}

/**
 * A page of the log: `read`, its events newest first, each whole, and the
 * seq the next page starts before (null for none); or `broken`.
 */
type LogPageCheck =
  { readonly kind: 'read'; readonly events: readonly LogEvent[]; readonly next: bigint | null } | BrokenRead;

/**
 * Thrown by recordedEvents for more events than its caller's limit: a
 * history read whole or not at all, never cut short unseen.
 */
export class TooManyEventsToRead extends Error {
  constructor(limit: number) {
    super(`More than ${limit.toString()} events to read; the read is whole or not at all`);
    this.name = 'TooManyEventsToRead';
  }
}

/** The most events about an object, its newest signed one first, that one read takes. */
const LATER_EVENTS_READ = 1000;

/** The most objects latestSignedStates reads in one statement. */
const MOST_LATEST_READ = 500;

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
   * Whether the organisation's chain still holds its last anchor, in one read:
   * its head not behind it, and the event anchored there the one anchored (not
   * a chain grown again on a wound-back head). Not the whole check (`verify`):
   * for a decision that must not pass a chain wound back (Tx A, ADR-012 §2),
   * in withTenant's transaction for the organisation, its head locked.
   */
  keepsAnchor(tx: AuditTransaction, orgId: string, anchor: AnchorPoint): Promise<boolean>;
  /**
   * record, with `statement` (a data-modifying one, given the event's ID and
   * a condition to AND to its filter: that the event was written) run in the
   * event's own write (4D2d P8): a signed row's pointer to the event. Every
   * row it gave back as JSON (undefined if they don't read as rows). Nothing
   * it changes stays if the event is refused: the transaction rolls back.
   */
  recordAlong(
    tx: AuditTransaction,
    orgId: string,
    event: AuditEvent,
    statement: (eventId: string, gate: RawBuilder<unknown>) => RawBuilder<unknown>,
  ): Promise<RecordedAuditEvent & { readonly along: readonly Readonly<Record<string, unknown>>[] | undefined }>;
  /**
   * recordAlong for events that belong together, in their order (4D2d P13):
   * the head locked once and moved once, all of them in one statement with
   * `statement`, which is given the last one's ID. They share one time. Each
   * event as recorded, and the statement's rows, as recordAlong gives them.
   */
  recordAllAlong(
    tx: AuditTransaction,
    orgId: string,
    events: readonly AuditEvent[],
    statement: (lastEventId: string, gate: RawBuilder<unknown>) => RawBuilder<unknown>,
  ): Promise<{
    readonly recorded: readonly RecordedAuditEvent[];
    readonly along: readonly Readonly<Record<string, unknown>>[] | undefined;
  }>;
  /**
   * The object's latest signed state (ADR-012 §2): of the events about it,
   * the newest whose details carry a state seal, with every later event about
   * it sealed and no event of the chain past the head (see the file's comment
   * for what it can't see). Only in withTenant's transaction for that
   * organisation, like `verify`.
   */
  latestSignedState(tx: AuditTransaction, orgId: string, subject: AuditSubjectKey): Promise<LatestSignedState>;
  /**
   * latestSignedState in one statement with the object's row, read by the
   * caller's `rowRead` (a select of that one row, which may lock it), run
   * first as a materialized CTE (4D2d P3a). Every row it gave, as it gave it.
   * The log is read on the statement's snapshot, taken before any wait for
   * the row's lock: a row changed during that wait points at an event this
   * read can't see, so a caller believes the pair only when they agree.
   */
  latestSignedStateWithRow(
    tx: AuditTransaction,
    orgId: string,
    subject: AuditSubjectKey,
    rowRead: RawBuilder<unknown>,
  ): Promise<LatestWithRow>;
  /**
   * latestSignedStateWithRow for several rows in one statement (4D2d P8):
   * gatheredRowReads' rows, read and locked in their order, each with its
   * object's latest signed state, of its table's subject type. In the order
   * given: the ID each row's read named (null for none found) and every row
   * it gave, as latestSignedStateWithRow gives them; an object with more
   * than LATER_EVENTS_READ events since its newest signed one is answered
   * `backlog`, as latestSignedStates answers one. The log is read on the
   * statement's snapshot, as latestSignedStateWithRow's.
   */
  latestSignedStatesGathered(
    tx: AuditTransaction,
    orgId: string,
    reads: readonly GatheredRead[],
  ): Promise<readonly GatheredLatest[]>;
  /**
   * Two latestSignedStatesGathered, each of at least one read, behind `before`
   * on one trip (4D2d P17): each its own statement, on its own snapshot.
   */
  latestSignedStatesGatheredBehind(
    tx: AuditTransaction,
    orgId: string,
    before: Compilable,
    firstReads: readonly GatheredRead[],
    secondReads: readonly GatheredRead[],
  ): Promise<{
    readonly ahead: QueryResult<unknown>;
    readonly first: readonly GatheredLatest[];
    readonly second: readonly GatheredLatest[];
  }>;
  /**
   * latestSignedState for many objects of one type, in one statement: each
   * ID asked, in lower case, with its object's latest signed state, judged
   * alone as latestSignedState judges one. At most MOST_LATEST_READ objects.
   * An object with more than LATER_EVENTS_READ events since its newest signed
   * one is answered `backlog`, and the others read again without it (Phase 3
   * A1b): its caller decides whether that refuses the whole read.
   */
  latestSignedStates(
    tx: AuditTransaction,
    orgId: string,
    type: string,
    ids: readonly string[],
  ): Promise<ReadonlyMap<string, LatestSignedState | BackloggedRead>>;
  /**
   * The IDs of every object of this type the organisation's log holds any
   * event about, sealed or not, in order (a uuid, so lower case), after the ID
   * `after` (null from the start): at most `limit` and one more, so the caller
   * can tell a list cut short. For finding an object whose row is gone. Only
   * in withTenant's transaction for that organisation, like `verify`.
   */
  subjectIds(
    tx: AuditTransaction,
    orgId: string,
    type: string,
    limit: number,
    after?: string | null,
  ): Promise<string[]>;
  /**
   * The action of the newest event about the object, as the table holds it,
   * believed in nothing: no hash, MAC or head is checked, so it decides
   * nothing and raises no alarm. Only a cheap look for a job deciding whether
   * to make the verified read at all; null for none. Only in withTenant's
   * transaction for that organisation, like `verify`.
   */
  newestActionUnverified(tx: AuditTransaction, orgId: string, subject: AuditSubjectKey): Promise<string | null>;
  /**
   * One event of the organisation's, found by its own ID, or as the first
   * event about an object recorded once (an investigation of the hold): read
   * with the chain's head in one statement and believed only whole
   * (RecordedEventCheck). A second event about such an object, whole, would
   * need the app's keys. Only in withTenant's transaction for that
   * organisation, like `verify`.
   */
  recordedEvent(tx: AuditTransaction, orgId: string, find: EventToFind): Promise<RecordedEventCheck>;
  /**
   * Every event of the organisation's about an object of `subjectTypes` (and
   * only the one `subjectId` names, and of `actions` alone, when they do), in chain order, each
   * believed only whole as recordedEvent believes one, read with the chain's
   * head in one statement: a history a decision rests on (who granted a
   * member's role, ADR-012 §1; when a supplier was last verified, E3-2a).
   * Past `limit` events it throws
   * TooManyEventsToRead, unless `newest` asks for the latest alone. An event deleted from the history is the chain's
   * check's and anchor's to find, as for any read of the log. Only in
   * withTenant's transaction for that organisation, like `verify`.
   */
  recordedEvents(tx: AuditTransaction, orgId: string, find: HistoryToRead): Promise<RecordedEventsCheck>;
  /**
   * recordedEvents for each history asked, in one statement with the chain's
   * head (4D2d P8): each judged as recordedEvents judges one, in the order
   * asked. At most MOST_HISTORIES_READ.
   */
  recordedHistories(
    tx: AuditTransaction,
    orgId: string,
    finds: readonly HistoryToRead[],
  ): Promise<readonly RecordedEventsCheck[]>;
  /**
   * A page of the organisation's whole log for its admins (Phase 3 E10,
   * decision 24): every event recorded in [from, to), of `actions` and by
   * `actor` when named (decision 26), before `beforeSeq`, newest first, in one
   * statement with the chain's head (0048's and 0051's indexes). Each believed only whole, as recordedEvents believes
   * one: its MAC seals its seq and its link to the event before, so no event
   * on the page can stand anywhere else in the chain. An event deleted is the
   * chain's check's and anchor's to find, as for any read of the log. Only in
   * withTenant's transaction for that organisation.
   */
  logPage(tx: AuditTransaction, orgId: string, find: LogPageToRead): Promise<LogPageCheck>;
}

/**
 * A history to read (recordedEvents): its objects' types, one object (or
 * several: `subjectIds`, never with `subjectId`) and some actions alone if
 * named, and the most events it may hold.
 */
export interface HistoryToRead {
  readonly subjectTypes: readonly string[];
  readonly subjectId?: string;
  readonly subjectIds?: readonly string[];
  readonly actions?: readonly string[];
  readonly limit: number;
  /**
   * Only the newest `limit` events, still in chain order, and never
   * TooManyEventsToRead: for a read that rests on the latest alone, such as
   * the suspension a subject is under now (Phase 3 decision 7).
   */
  readonly newest?: true;
  /**
   * Only the oldest `limit` events, never TooManyEventsToRead: for a read
   * that pages forward, or stops at the first that counts (a cancel since a
   * request's decision, F1 G1). Never with `newest`.
   */
  readonly oldest?: true;
  /** Only events recorded after this seq: those since another event (F1 G1). */
  readonly afterSeq?: bigint;
}

/**
 * The objects a history reads (HistoryToRead), or undefined for every object
 * of its types (compared as uuids, so in any case); refuses a find that breaks
 * its rules.
 */
function objectsToRead({ subjectTypes, subjectId, subjectIds }: HistoryToRead): readonly string[] | undefined {
  const named = subjectId === undefined ? subjectIds : [subjectId];
  const problems = [
    ...subjectTypes.flatMap(subjectTypeProblems),
    ...((named ?? []).every((id) => UUID.test(id)) ? [] : ['subject.id must be a UUID']),
  ];
  if (problems.length > 0) throw new AuditEventRefused(problems);
  if (subjectTypes.length === 0) throw new RangeError('At least one subject type is read');
  if (subjectId !== undefined && subjectIds !== undefined) throw new RangeError('One object or several, not both');
  // None named would read every object's history, which a caller asking for some never means.
  if (named?.length === 0) throw new RangeError('At least one object is read');
  return named;
}

/**
 * The events a history picks (HistoryToRead), refused before any SQL if it
 * breaks its rules: one past the limit tells one cut short, and the newest
 * or oldest alone are never more than asked.
 */
interface HistoryPick {
  readonly which: RawBuilder<unknown>;
  readonly limit: number;
  readonly newest: boolean;
}

function historyPick(find: HistoryToRead): HistoryPick {
  const { subjectTypes, actions, limit, newest = false, oldest = false, afterSeq } = find;
  const objects = objectsToRead(find);
  if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('The limit is a whole number from 1');
  if (newest && oldest) throw new RangeError('The newest events or the oldest, not both');
  const which = sql.join(
    [
      sql`e.subject_type = any(${[...subjectTypes]}::text[])`,
      ...(objects === undefined ? [] : [sql`e.subject_id = any(${[...objects]}::uuid[])`]),
      ...(actions === undefined ? [] : [sql`e.action = any(${[...actions]}::text[])`]),
      ...(afterSeq === undefined ? [] : [sql`e.seq > ${afterSeq}`]),
    ],
    sql` and `,
  );
  return { which, limit: newest || oldest ? limit : limit + 1, newest };
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

/** The chain's head (`h`) and the first event past it (`past`), as every read of events beside the head gives them. */
const HEAD_COLUMNS = sql`h.org_id is not null as has_head, h.seq as head_seq, h.hash as head_hash, h.mac as head_mac,
  h.mac_key_version as head_mac_key_version, past.past_head`;

/** An event's own columns (`e`), as wholeEvent and wholeEntry judge them. */
const EVENT_COLUMNS = sql`e.seq, e.id, e.recorded_at, e.actor_type, e.actor_id, e.action, e.subject_type,
  e.subject_id, e.subject_version, e.details, e.prev_hash, e.hash, e.mac, e.mac_key_version,
  e.recorded_at = pg_catalog.date_trunc('milliseconds', e.recorded_at) as whole_ms`;

/** The chain's head and the first event past it, joined to each row of a read's `from`. */
const headJoins = (chain: Chain & { readonly kind: 'organisation' }): RawBuilder<unknown> => sql`
  left join audit.heads h on h.org_id = ${chain.orgId}
  cross join lateral (
    select pg_catalog.min(p.seq) as past_head from audit.events p
    where p.org_id = ${chain.orgId} and p.seq > coalesce(h.seq, 0)
  ) as past`;

/**
 * The events `which` picks, in chain order and at most `limit`, each beside
 * the chain's head and the first event past it, all in one statement so they
 * come from the same moment. With no event picked, one row with the head alone.
 * With `each`, the limit is each of those objects' own (Phase 3 A1b), so no
 * object's events can crowd out another's.
 */
async function eventsWithHead(
  tx: AuditTransaction,
  chain: Chain & { readonly kind: 'organisation' },
  which: RawBuilder<unknown>,
  limit: number,
  {
    each,
    newest = false,
    alongside,
  }: { readonly each?: readonly string[]; readonly newest?: boolean; readonly alongside?: RawBuilder<unknown> } = {},
): Promise<readonly Readonly<Record<string, unknown>>[]> {
  // The oldest events first, or the newest (HistoryToRead.newest); either way handed back in chain order, below.
  const order = newest ? sql`order by e.seq desc` : sql`order by e.seq`;
  const picked =
    each === undefined
      ? sql`select e.* from audit.events e where e.org_id = ${chain.orgId} and ${which} ${order} limit ${limit}`
      : sql`select e.* from pg_catalog.unnest(${each}::uuid[]) as a (id) cross join lateral (
          select e.* from audit.events e
          where e.org_id = ${chain.orgId} and e.subject_id = a.id and ${which} ${order} limit ${limit}
        ) as e`;
  // A caller's row, read first (it may wait for the row's lock), its rows given back as JSON on every row (rowsAlong).
  let withRow = sql``;
  let rowColumn = sql``;
  if (alongside !== undefined) {
    withRow = sql`with target_row as materialized (${alongside})`;
    rowColumn = sql`, (select pg_catalog.json_agg(pg_catalog.row_to_json(r)) from target_row r) as row_json`;
  }
  const { rows } = await sql<Record<string, unknown>>`
    ${withRow}
    select ${HEAD_COLUMNS},
           ${EVENT_COLUMNS}${rowColumn}
    from (values (1)) as one (x)
    ${headJoins(chain)}
    left join lateral (${picked}) as e on true
    order by e.seq
  `.execute(tx);
  return rows;
}

/** The most histories recordedHistories reads in one statement. */
const MOST_HISTORIES_READ = 8;

/**
 * Each history's events as recordedEvents picks one's (`which`, at most
 * `limit`, the newest when asked), all beside the chain's head and the first
 * event past it in one statement, as eventsWithHead reads one: each row's
 * `find` is its history's place in the list. With no event picked, one row
 * with the head alone.
 */
async function historiesWithHead(
  tx: AuditTransaction,
  chain: Chain & { readonly kind: 'organisation' },
  picks: readonly HistoryPick[],
): Promise<readonly Readonly<Record<string, unknown>>[]> {
  const each = picks.map(
    ({ which, limit, newest }, find) =>
      sql`(select ${find}::integer as find, e.* from audit.events e
        where e.org_id = ${chain.orgId} and ${which} ${newest ? sql`order by e.seq desc` : sql`order by e.seq`}
        limit ${limit})`,
  );
  const { rows } = await sql<Record<string, unknown>>`
    select ${HEAD_COLUMNS}, e.find,
           ${EVENT_COLUMNS}
    from (values (1)) as one (x)
    ${headJoins(chain)}
    left join lateral (${sql.join(each, sql` union all `)}) as e on true
    order by e.find, e.seq
  `.execute(tx);
  return rows;
}

/** latestSignedStateWithRow's answer: the latest signed state, and the caller's rows (undefined if they don't read as rows). */
export interface LatestWithRow {
  readonly latest: LatestSignedState;
  readonly rows: readonly Readonly<Record<string, unknown>>[] | undefined;
}

/** latestSignedStatesGathered's answer for one row: the ID its read named, its latest signed state, and its rows. */
export interface GatheredLatest {
  readonly id: string | null;
  readonly latest: LatestSignedState | BackloggedRead;
  readonly rows: readonly Readonly<Record<string, unknown>>[] | undefined;
}

/**
 * Each gathered row's object's newest signed event and every one after it,
 * at most LATER_EVENTS_READ + 1 each, beside the chain's head and the first
 * event past it, all in one statement with the rows' reads (their CTEs, run
 * first: the objects CTE reads them in order), as eventsWithHead reads one
 * object's with its row. One row at least for each object, its `item` its
 * place in the list, in the list's order.
 */
function gatheredWithHead(
  chain: Chain & { readonly kind: 'organisation' },
  reads: readonly GatheredRead[],
): RawBuilder<Record<string, unknown>> {
  const each = reads.map(
    (read, item) =>
      sql`select ${item}::integer as item, ${read.subject}::text as subject_type, ${read.id} as subject_id,
        (select pg_catalog.json_agg(pg_catalog.row_to_json(r)) from ${read.name} r) as row_json`,
  );
  return sql<Record<string, unknown>>`
    with ${sql.join(reads.map(({ cte }) => cte))},
    objects as materialized (${sql.join(each, sql` union all `)})
    select o.item, o.subject_id::text as asked_id, o.row_json,
           ${HEAD_COLUMNS},
           ${EVENT_COLUMNS}
    from objects o
    ${headJoins(chain)}
    left join lateral (
      select e.* from audit.events e
      where e.org_id = ${chain.orgId} and e.subject_type = o.subject_type and e.subject_id = o.subject_id
        and e.seq >= (
          select pg_catalog.max(s.seq) from audit.events s
          where s.org_id = ${chain.orgId} and s.subject_type = o.subject_type and s.subject_id = o.subject_id
            and pg_catalog.strpos(s.details, ${HAS_STATE_SEAL}) > 0
        )
      order by e.seq limit ${LATER_EVENTS_READ + 1}
    ) as e on true
    order by o.item, e.seq
  `;
}

/** Refuses reads of a subject type the log doesn't take. */
function gatheredAllowed(reads: readonly GatheredRead[]): void {
  const problems = reads.flatMap(({ subject }) => subjectTypeProblems(subject));
  if (problems.length > 0) throw new AuditEventRefused(problems);
}

/** The caller's rows eventsWithHead read alongside (its `row_json`), none when it found none: undefined if they don't read as rows. */
function rowsAlong(
  first: Readonly<Record<string, unknown>> | undefined,
): readonly Readonly<Record<string, unknown>>[] | undefined {
  const found: unknown = first?.row_json ?? [];
  if (!Array.isArray(found)) return undefined;
  const rows = found.filter((row): row is Record<string, unknown> => typeof row === 'object' && row !== null);
  return rows.length === found.length ? rows : undefined;
}

/**
 * The event a row holds, if it is whole: readable and sealed by its own hash
 * and MAC, with `head` whole. Its callers have refused a chain holding any
 * event past the head, in the same statement, so none here lies past it.
 */
function wholeEvent(
  keys: KeyProvider,
  chain: Chain,
  row: Readonly<Record<string, unknown>>,
  head: ChainHead | undefined,
): ReadEvent | undefined {
  return wholeEntry(keys, chain, row, head)?.read;
}

/** As wholeEvent, with the sealed fields it checked: the log's page shows their hashes (E10). */
function wholeEntry(
  keys: KeyProvider,
  chain: Chain,
  row: Readonly<Record<string, unknown>>,
  head: ChainHead | undefined,
): { readonly read: ReadEvent; readonly sealed: Omit<StoredEntry, 'content'> } | undefined {
  const sealed = sealedFields(row);
  const content = contentOf(row);
  const details = detailsObject(row.details);
  if (
    sealed === undefined ||
    content === undefined ||
    details === undefined ||
    head === undefined ||
    !entryIsSealed(keys, chain, { ...sealed, content })
  ) {
    return undefined;
  }
  // contentOf read each of these as text, and the version as a number, or the row wasn't whole.
  const { actor_type: actorType, actor_id: actorId, action, subject_type: type, subject_id: subjectId } = row;
  const read = Object.freeze({
    id: sealed.id,
    seq: sealed.seq,
    recordedAt: sealed.recordedAt,
    event: Object.freeze({
      actor: { type: actorType as ActorType, id: String(actorId) },
      action: String(action),
      subject: { type: String(type), id: String(subjectId), version: Number(row.subject_version) },
      details: Object.freeze({ ...details }) as AuditEvent['details'],
    }),
  });
  return { read, sealed };
}

/** A read that can't be believed, at `seq` when it could be read. */
function brokenAt(seq: unknown): BrokenRead {
  return typeof seq === 'bigint' ? { kind: 'broken', seq } : { kind: 'broken' };
}

/** An event as recording writes it: checked, with its details' text as sealed. */
interface EventToWrite {
  readonly event: AuditEvent;
  readonly details: string;
}

/** Recording's steps over the audit tables, for one organisation and the events recorded together, in their order. */
function writerFor(
  tx: AuditTransaction,
  orgId: string,
  toWrite: readonly EventToWrite[],
  along?: Along,
): ChainBatchWriter {
  return {
    async lockHead() {
      // The clock in the outer select, which reads a row only once the inner one has locked it.
      const { rows } = await sql<Record<string, unknown>>`
        with locked as materialized (
          select h.seq, h.hash, h.mac, h.mac_key_version from audit.heads h
          where h.org_id = ${orgId}
          for no key update
        )
        select l.*, pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp()) as now from locked l
      `.execute(tx);
      const row = rows[0];
      return row === undefined ? undefined : { head: headFields(row), now: clockOf(row) };
    },

    async start(head) {
      await tx
        .insertInto('audit.heads')
        .values({ org_id: orgId, seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .onConflict((conflict) => conflict.column('org_id').doNothing())
        .execute();
    },

    async appendAll(sealedEvents, head, previous) {
      // One statement: the head moves only if it is still `previous` with no event past it,
      // and the events are written only if the head moved, so a refused one leaves nothing behind.
      const last = sealedEvents.at(-1);
      if (last === undefined) return false;
      const selects = sealedEvents.map((sealed, index) => {
        // One sealed for each, in their order (recordAllAs).
        const written = toWrite[index];
        if (written === undefined) throw new RangeError('An event sealed that was not asked for');
        const { event, details } = written;
        return sql`
          select m.org_id, ${sealed.seq}::bigint, ${sealed.id}::uuid, ${sealed.recordedAt}::timestamptz,
                 ${event.actor.type}::text, ${event.actor.id}::text, ${event.action}::text,
                 ${event.subject.type}::text, ${event.subject.id}::uuid, ${event.subject.version}::integer,
                 ${details}::text, ${sealed.prevHash}::bytea, ${sealed.hash}::bytea, ${sealed.mac}::bytea,
                 ${sealed.macKeyVersion}::integer
          from moved m
        `;
      });
      const insert = sql`
        insert into audit.events (org_id, seq, id, recorded_at, actor_type, actor_id, action, subject_type,
                                  subject_id, subject_version, details, prev_hash, hash, mac, mac_key_version)
        ${sql.join(selects, sql` union all `)}
      `;
      const move = sql`
        update audit.heads
        set seq = ${head.seq}, hash = ${head.hash}, mac = ${head.mac}, mac_key_version = ${head.macKeyVersion}
        where org_id = ${orgId} and seq = ${previous.seq} and hash = ${previous.hash}
          and not exists (select from audit.events p where p.org_id = ${orgId} and p.seq > ${previous.seq})
        returning org_id
      `;
      const allWritten = BigInt(sealedEvents.length);
      if (along !== undefined) {
        // The row's pointer too, only once the events are written (4D2d P8): the statement it came with, run here.
        const { rows } = await sql<{ written: bigint; along: unknown }>`
          with moved as (${move}), written as (${insert} returning 1),
          along as (${along.statement(last.id, sql`exists (select from written)`)})
          select (select pg_catalog.count(*) from written) as written,
                 (select pg_catalog.json_agg(pg_catalog.row_to_json(a)) from along a) as along
        `.execute(tx);
        const [row] = rows;
        along.rows = rowsAlong({ row_json: row?.along });
        return row?.written === allWritten;
      }
      const written = await sql`with moved as (${move}) ${insert}`.execute(tx);
      return written.numAffectedRows === allWritten;
    },
  };
}

/** A statement an event's write carries (recordAlong): built with the event's ID, and the rows it gave once run. */
interface Along {
  readonly statement: (eventId: string, gate: RawBuilder<unknown>) => RawBuilder<unknown>;
  rows?: readonly Readonly<Record<string, unknown>>[] | undefined;
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
 * The subject types only the integrity hold's own steps record: the hold, and
 * its investigations (B3+-2b), which clearing it rests on.
 */
const HOLD_SUBJECTS: ReadonlySet<string> = new Set([HOLD_SUBJECT, INVESTIGATION_SUBJECT, HISTORY_CHECK_SUBJECT]);

/**
 * Each trail's recording step for the integrity hold's own events, which the
 * public `record` refuses: only recordHoldEvent reaches it, from this module.
 */
const holdRecorders = new WeakMap<AuditTrail, AuditTrail['record']>();

/**
 * Adds an event about the integrity hold (domain/integrity-hold.ts), or one of
 * its investigations, to the chain, as `record` does. For the audit module's
 * signed states alone: the public `record` refuses both subject types, so no
 * other module can write an event the hold, or its clearing, is read from.
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

/**
 * The detail every event a request records carries: the request's correlation
 * ID, sealed with it, so the activity log's row for the request and the events
 * it wrote link (ADR-011 §7). Only the trail adds it, never a caller.
 */
const CORRELATION_DETAIL = 'correlationId';

export function createAuditTrail({
  keys,
  ids,
  correlationId,
}: {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  /** The request's or job's correlation ID (a UUID), sealed into each event's details; none when left out. */
  readonly correlationId?: string | undefined;
}): AuditTrail {
  if (correlationId !== undefined && !UUID.test(correlationId)) {
    throw new TypeError('A correlation ID sealed into the audit log must be a UUID');
  }
  const sealedCorrelation = correlationId?.toLowerCase();

  /** The event checked, which must be about the integrity hold when `hold` says so, and otherwise must not. */
  const checkedToWrite = (hold: boolean, input: AuditEvent): EventToWrite => {
    const event = checkedEvent(input, hidesField);
    if (Object.hasOwn(event.details, CORRELATION_DETAIL)) {
      throw new AuditEventRefused([`details.${CORRELATION_DETAIL} is the request's own, added by the trail alone`]);
    }
    if (HOLD_SUBJECTS.has(event.subject.type) !== hold) {
      throw new AuditEventRefused([
        hold
          ? 'only the integrity hold and its investigations are recorded by their own steps'
          : `subject.type ${event.subject.type} is the integrity hold's, recorded by its own steps`,
      ]);
    }
    if (stateSealIn(event.details) === 'malformed') {
      throw new AuditEventRefused([
        'details.stateFingerprint and details.stateKeyVersion must hold a state seal, both of them or neither',
      ]);
    }
    const details = canonicalDetails(
      sealedCorrelation === undefined ? event.details : { ...event.details, [CORRELATION_DETAIL]: sealedCorrelation },
    );
    return { event, details };
  };

  /** Records the events, each as `checkedToWrite` lets it, in one step of the chain, in their order. */
  const recordAllAs = async (
    hold: boolean,
    tx: AuditTransaction,
    orgId: string,
    inputs: readonly AuditEvent[],
    along?: Along,
  ): Promise<readonly RecordedAuditEvent[]> => {
    const events = inputs.map((input) => checkedToWrite(hold, input));
    const chain = chainOf(orgId);
    const sealed = await appendEvents(
      keys,
      chain,
      writerFor(tx, chain.orgId, events, along),
      events.map(({ event, details }) => ({ nextId: () => ids.next(), content: eventContent(event, details) })),
    );
    return sealed.map(({ id, seq, recordedAt }) => Object.freeze({ id, seq, recordedAt }));
  };

  /** recordAllAs for one event. */
  const recordAs = async (
    hold: boolean,
    tx: AuditTransaction,
    orgId: string,
    input: AuditEvent,
    along?: Along,
  ): Promise<RecordedAuditEvent> => {
    const [recorded] = await recordAllAs(hold, tx, orgId, [input], along);
    if (recorded === undefined) throw new Error('One event asked and none recorded');
    return recorded;
  };

  /**
   * The latest signed state in `rows`, an object's newest signed event and
   * every one after it as eventsWithHead read them (none at all: no event of
   * the object's), judged with the chain's head and the first event past it,
   * which every row of the statement carries alike (`first`).
   */
  const latestIn = (
    chain: Chain & { readonly kind: 'organisation' },
    rows: readonly Readonly<Record<string, unknown>>[],
    first: Readonly<Record<string, unknown>> | undefined,
  ): LatestSignedState => {
    if (first === undefined) return { kind: 'none' };
    // The first event of the chain past its head (or of a chain with no head), if there is one: such a chain
    // refuses every new event, the integrity hold's among them, so nothing about it is believed.
    const past = first.past_head;
    const pastHead = past !== null;
    const brokenPast = brokenAt(past);
    if (rows.length > LATER_EVENTS_READ) {
      if (pastHead) return brokenPast;
      throw new TooManyEventsAboutObject();
    }
    const events = rows.filter((row) => row.seq !== null);
    const [newestSigned] = events;
    if (newestSigned === undefined) return pastHead ? brokenPast : { kind: 'none' };

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
      return brokenAt((bad ?? read[0])?.row.seq);
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
  };

  /** gatheredWithHead's rows, as each read's answer. */
  const gatheredAnswers = (
    chain: Chain & { readonly kind: 'organisation' },
    reads: readonly GatheredRead[],
    rows: readonly Readonly<Record<string, unknown>>[],
  ): readonly GatheredLatest[] => {
    const byItem = reads.map((): Readonly<Record<string, unknown>>[] => []);
    for (const row of rows) if (typeof row.item === 'number') byItem[row.item]?.push(row);
    return byItem.map((own) => {
      const [first] = own;
      const asked = first?.asked_id;
      // A backlog, past the head or not, is left to the row's own read, which judges it as it always has.
      return {
        id: typeof asked === 'string' ? asked : null,
        latest: own.length > LATER_EVENTS_READ ? BACKLOGGED : latestIn(chain, own, first),
        rows: rowsAlong(first),
      };
    });
  };

  /** latestSignedState, with the caller's row read in the same statement when `rowRead` is given. */
  const latestWith = async (
    tx: AuditTransaction,
    orgId: string,
    subject: AuditSubjectKey,
    rowRead?: RawBuilder<unknown>,
  ): Promise<LatestWithRow> => {
    const problems = subjectKeyProblems(subject);
    if (problems.length > 0) throw new AuditEventRefused(problems);
    await assertTenant(tx, orgId);
    const chain = chainOf(orgId);
    const id = subject.id.toLowerCase();
    // The object's newest signed event and every one after it.
    const events = await eventsWithHead(
      tx,
      chain,
      sql`e.subject_type = ${subject.type} and e.subject_id = ${id}
        and e.seq >= (
          select pg_catalog.max(s.seq) from audit.events s
          where s.org_id = ${chain.orgId} and s.subject_type = ${subject.type} and s.subject_id = ${id}
            and pg_catalog.strpos(s.details, ${HAS_STATE_SEAL}) > 0
        )`,
      LATER_EVENTS_READ + 1,
      rowRead === undefined ? {} : { alongside: rowRead },
    );
    const rows = rowRead === undefined ? undefined : rowsAlong(events[0]);
    return { latest: latestIn(chain, events, events[0]), rows };
  };

  /**
   * A history's events (recordedEvents), as read beside the chain's head
   * (`first`, which every row of the statement carries alike): each whole, or
   * where one isn't; more than `limit` throws TooManyEventsToRead.
   */
  const historyIn = (
    chain: Chain & { readonly kind: 'organisation' },
    rows: readonly Readonly<Record<string, unknown>>[],
    first: Readonly<Record<string, unknown>> | undefined,
    limit: number,
  ): RecordedEventsCheck => {
    const past = first?.past_head;
    if (typeof past === 'bigint') return brokenAt(past);
    if (rows.length > limit) throw new TooManyEventsToRead(limit);
    const head = first?.has_head === true ? headIsWhole(keys, chain, first) : undefined;
    const events: ReadEvent[] = [];
    for (const row of rows) {
      if (row.seq === null) continue;
      const read = wholeEvent(keys, chain, row, head);
      if (read === undefined) return brokenAt(row.seq);
      events.push(read);
    }
    return Object.freeze({ kind: 'recorded', events: Object.freeze(events) });
  };

  const trail: AuditTrail = Object.freeze({
    record(tx: AuditTransaction, orgId: string, event: AuditEvent): Promise<RecordedAuditEvent> {
      return recordAs(false, tx, orgId, event);
    },

    async recordAlong(
      tx: AuditTransaction,
      orgId: string,
      event: AuditEvent,
      statement: (eventId: string, gate: RawBuilder<unknown>) => RawBuilder<unknown>,
    ): Promise<RecordedAuditEvent & { readonly along: readonly Readonly<Record<string, unknown>>[] | undefined }> {
      const along: Along = { statement };
      const recorded = await recordAs(false, tx, orgId, event, along);
      return Object.freeze({ ...recorded, along: along.rows });
    },

    async recordAllAlong(
      tx: AuditTransaction,
      orgId: string,
      events: readonly AuditEvent[],
      statement: (lastEventId: string, gate: RawBuilder<unknown>) => RawBuilder<unknown>,
    ) {
      const along: Along = { statement };
      const recorded = await recordAllAs(false, tx, orgId, events, along);
      return Object.freeze({ recorded, along: along.rows });
    },

    async verify(tx: AuditTransaction, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      return verifyChain(keys, chain, readerFor(tx, chain.orgId), anchor);
    },

    verifyAlone(db: Kysely<AuditTables>, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      return withTenant(db, orgId, (tx) => trail.verify(tx, orgId, anchor), { limited: true });
    },

    async keepsAnchor(tx: AuditTransaction, orgId: string, anchor: AnchorPoint): Promise<boolean> {
      await assertTenant(tx, orgId);
      // An empty chain's anchor (seq 0, the genesis hash) is held by every chain grown from it: no event to compare.
      if (anchor.seq === 0n) return true;
      const chain = chainOf(orgId);
      const { rows } = await sql<{ head_seq: bigint | null; anchored: Buffer | null }>`
        select h.seq as head_seq,
               (select e.hash from audit.events e where e.org_id = ${chain.orgId} and e.seq = ${anchor.seq}) as anchored
        from (values (1)) as one (x)
        left join audit.heads h on h.org_id = ${chain.orgId}
      `.execute(tx);
      const head = rows[0]?.head_seq ?? null;
      const anchored = rows[0]?.anchored ?? null;
      // No head, a head behind the anchor, or another event where the anchored one was: wound back.
      return head !== null && head >= anchor.seq && anchored?.equals(anchor.hash) === true;
    },

    async latestSignedState(tx: AuditTransaction, orgId: string, subject: AuditSubjectKey): Promise<LatestSignedState> {
      return (await latestWith(tx, orgId, subject)).latest;
    },

    latestSignedStateWithRow(
      tx: AuditTransaction,
      orgId: string,
      subject: AuditSubjectKey,
      rowRead: RawBuilder<unknown>,
    ): Promise<LatestWithRow> {
      return latestWith(tx, orgId, subject, rowRead);
    },

    async latestSignedStatesGathered(
      tx: AuditTransaction,
      orgId: string,
      reads: readonly GatheredRead[],
    ): Promise<readonly GatheredLatest[]> {
      gatheredAllowed(reads);
      if (reads.length === 0) return [];
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      return gatheredAnswers(chain, reads, (await gatheredWithHead(chain, reads).execute(tx)).rows);
    },

    async latestSignedStatesGatheredBehind(
      tx: AuditTransaction,
      orgId: string,
      before: Compilable,
      firstReads: readonly GatheredRead[],
      secondReads: readonly GatheredRead[],
    ) {
      gatheredAllowed([...firstReads, ...secondReads]);
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const [ahead, first, second] = await sendTogether(tx, [
        before,
        gatheredWithHead(chain, firstReads),
        gatheredWithHead(chain, secondReads),
      ]);
      return {
        ahead,
        first: gatheredAnswers(chain, firstReads, first.rows as Readonly<Record<string, unknown>>[]),
        second: gatheredAnswers(chain, secondReads, second.rows as Readonly<Record<string, unknown>>[]),
      };
    },

    async latestSignedStates(
      tx: AuditTransaction,
      orgId: string,
      type: string,
      ids: readonly string[],
    ): Promise<ReadonlyMap<string, LatestSignedState | BackloggedRead>> {
      const problems = [
        ...subjectTypeProblems(type),
        ...(ids.every((id) => UUID.test(id)) ? [] : ['subject.id must be a UUID']),
      ];
      if (problems.length > 0) throw new AuditEventRefused(problems);
      const asked = [...new Set(ids.map((id) => id.toLowerCase()))];
      if (asked.length > MOST_LATEST_READ) {
        throw new RangeError(`At most ${MOST_LATEST_READ.toString()} objects' signed states are read at once`);
      }
      if (asked.length === 0) return new Map();
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      // Each object's newest signed event and every one after it, as latestSignedState reads one object's, each
      // object's at most LATER_EVENTS_READ + 1 of its own: past that, its judgement below says so.
      const rows = await eventsWithHead(
        tx,
        chain,
        sql`e.subject_type = ${type}
          and e.seq >= (
            select pg_catalog.max(s.seq) from audit.events s
            where s.org_id = ${chain.orgId} and s.subject_type = ${type} and s.subject_id = e.subject_id
              and pg_catalog.strpos(s.details, ${HAS_STATE_SEAL}) > 0
          )`,
        LATER_EVENTS_READ + 1,
        { each: asked },
      );
      const [first] = rows;
      const byObject = new Map<string, Readonly<Record<string, unknown>>[]>(asked.map((id) => [id, []]));
      for (const row of rows) if (typeof row.subject_id === 'string') byObject.get(row.subject_id)?.push(row);
      // A chain past its head is judged as it is: every object broken, a backlogged one too.
      const pastHead = (first?.past_head ?? null) !== null;
      return new Map(
        asked.map((id) => {
          const own = byObject.get(id) ?? [];
          return [id, !pastHead && own.length > LATER_EVENTS_READ ? BACKLOGGED : latestIn(chain, own, first)];
        }),
      );
    },

    async subjectIds(
      tx: AuditTransaction,
      orgId: string,
      type: string,
      limit: number,
      after: string | null = null,
    ): Promise<string[]> {
      const problems = subjectTypeProblems(type);
      if (problems.length > 0) throw new AuditEventRefused(problems);
      if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('The limit is a whole number from 1');
      if (after !== null && !UUID.test(after)) throw new RangeError('A subject is named by a UUID');
      await assertTenant(tx, orgId);
      let query = tx
        .selectFrom('audit.events')
        .select('subject_id')
        .distinct()
        .where('org_id', '=', chainOf(orgId).orgId)
        .where('subject_type', '=', type);
      if (after !== null) query = query.where('subject_id', '>', after.toLowerCase());
      const rows = await query
        .orderBy('subject_id')
        .limit(limit + 1)
        .execute();
      return rows.map(({ subject_id: id }) => id);
    },

    async newestActionUnverified(
      tx: AuditTransaction,
      orgId: string,
      subject: AuditSubjectKey,
    ): Promise<string | null> {
      const problems = subjectKeyProblems(subject);
      if (problems.length > 0) throw new AuditEventRefused(problems);
      await assertTenant(tx, orgId);
      const row = await tx
        .selectFrom('audit.events')
        .select('action')
        .where('org_id', '=', chainOf(orgId).orgId)
        .where('subject_type', '=', subject.type)
        .where('subject_id', '=', subject.id.toLowerCase())
        .orderBy('seq', 'desc')
        .limit(1)
        .executeTakeFirst();
      return row?.action ?? null;
    },

    async recordedEvent(tx: AuditTransaction, orgId: string, find: EventToFind): Promise<RecordedEventCheck> {
      let which;
      if ('eventId' in find) {
        // Refused before any SQL, as an object's key is: the ID can come from outside (a route's export or file).
        if (!UUID.test(find.eventId)) throw new AuditEventRefused(['eventId must be a UUID']);
        which = sql`e.id = ${find.eventId}`;
      } else {
        const problems = subjectKeyProblems(find.onlyAbout);
        if (problems.length > 0) throw new AuditEventRefused(problems);
        which = sql`e.subject_type = ${find.onlyAbout.type} and e.subject_id = ${find.onlyAbout.id}`;
      }
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const [row] = await eventsWithHead(tx, chain, which, 1);
      const past = row?.past_head;
      if (typeof past === 'bigint') return brokenAt(past);
      if (row === undefined || row.seq === null) return { kind: 'none' };
      const head = row.has_head === true ? headIsWhole(keys, chain, row) : undefined;
      const read = wholeEvent(keys, chain, row, head);
      if (read === undefined) return brokenAt(row.seq);
      return Object.freeze({ kind: 'recorded', ...read });
    },

    async recordedEvents(tx: AuditTransaction, orgId: string, find: HistoryToRead): Promise<RecordedEventsCheck> {
      const pick = historyPick(find);
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const rows = await eventsWithHead(tx, chain, pick.which, pick.limit, { newest: pick.newest });
      return historyIn(chain, rows, rows[0], find.limit);
    },

    async recordedHistories(
      tx: AuditTransaction,
      orgId: string,
      finds: readonly HistoryToRead[],
    ): Promise<readonly RecordedEventsCheck[]> {
      if (finds.length > MOST_HISTORIES_READ) {
        throw new RangeError(`At most ${MOST_HISTORIES_READ.toString()} histories are read at once`);
      }
      const picks = finds.map(historyPick);
      if (picks.length === 0) return [];
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const rows = await historiesWithHead(tx, chain, picks);
      return finds.map((find, index) =>
        historyIn(
          chain,
          rows.filter((row) => row.find === index),
          rows[0],
          find.limit,
        ),
      );
    },

    async logPage(tx: AuditTransaction, orgId: string, { from, to, actions, actor, beforeSeq, limit }: LogPageToRead) {
      if (!Number.isSafeInteger(limit) || limit < 1) throw new RangeError('The limit is a whole number from 1');
      if (from.getTime() >= to.getTime()) throw new RangeError('The page’s range starts before it ends');
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      const which = sql.join(
        [
          sql`e.recorded_at >= ${from} and e.recorded_at < ${to}`,
          ...(actions === undefined ? [] : [sql`e.action = any(${[...actions]}::text[])`]),
          ...(actor === undefined ? [] : [actorIs(actorAsKept(actor))]),
          ...(beforeSeq === undefined ? [] : [sql`e.seq < ${beforeSeq}`]),
        ],
        sql` and `,
      );
      // One past the limit tells there is a next page; the rows come back in chain order.
      const rows = await eventsWithHead(tx, chain, which, limit + 1, { newest: true });
      const [first] = rows;
      const past = first?.past_head;
      if (typeof past === 'bigint') return brokenAt(past);
      const head = first?.has_head === true ? headIsWhole(keys, chain, first) : undefined;
      const picked = rows.filter((row) => row.seq !== null);
      const shown = picked.slice(Math.max(0, picked.length - limit));
      const events: LogEvent[] = [];
      for (const row of shown) {
        const whole = wholeEntry(keys, chain, row, head);
        if (whole === undefined) return brokenAt(row.seq);
        const { read, sealed } = whole;
        events.push(
          Object.freeze({ ...read, hash: sealed.hash.toString('hex'), prevHash: sealed.prevHash.toString('hex') }),
        );
      }
      const next = picked.length > limit ? (events[0]?.seq ?? null) : null;
      return Object.freeze({ kind: 'read', events: Object.freeze(events.toReversed()), next });
    },
  });
  holdRecorders.set(trail, (tx, orgId, event) => recordAs(true, tx, orgId, event));
  return trail;
}
