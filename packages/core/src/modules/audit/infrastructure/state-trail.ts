// Each object's earlier events, named by its newest (TR-3 residual 75). The digest holds an object's newest signed
// event alone, and a path frontier walks only what came since F: an older event moved off its object below F (its
// hash kept, so no one-row check sees it) is missed by every history read, yet a decision may rest on it (a cancel
// since a request's decision, the choice a stop was made with).
//
// So a table that `tracks` actions has each of its state events name, in its own details (sealed with the event's
// hash and MAC), the newest earlier event of each of those actions about its object: by version and seq. The newest,
// held by the state read and the digest, names the newest of each; each of those names the one before. A history
// read that rests on them follows the names back from the state it holds (trailGap): every event so named inside
// what the read covered must be among what it got, or it can't be believed.
//
// Events recorded before this (and so a state whose event names none) are read as before, from the log alone: a
// state's names start from the first event that carried them (`from`), its object's older events unnamed. The plan
// for those: the operator's re-seal of each tracked object after a whole-chain check (Outstanding-Work).
import type { SignedStateTable } from '@agentx/platform/db';

import type { AuditDetails } from '../domain/event.ts';

/** Where a state event names its object's earlier events. */
export const TRACKED_BEFORE = 'trackedBefore';

/** An earlier event about the same object: its version, and its seq (null: the event just before this one in the chain, recorded in the same step). */
interface EarlierEvent {
  readonly version: number;
  readonly seq: bigint | null;
}

/** What one state event names: each tracked action's newest earlier event, complete from `from` on (0: every one). */
export interface TrackedBefore {
  readonly from: bigint;
  readonly last: ReadonlyMap<string, EarlierEvent>;
}

/** A state's own event, as its newest place: where the names start. */
export interface StateTrail {
  readonly seq: bigint;
  readonly action: string;
  /** None: an event recorded before the names (or a test's state), its object's earlier events unnamed. */
  readonly tracked: TrackedBefore | undefined;
}

/** What the state a change starts from gives its event to name: none for a new object; the event just before, unrecorded yet, for a new object's first move. */
export type TrailStart =
  | 'new'
  | { readonly version: number; readonly trail?: StateTrail | undefined }
  | { readonly adjacent: { readonly version: number; readonly action: string } }
  /** Names rebuilt from the object's whole history, read once its chain was checked whole (namesFromHistory). */
  | { readonly rebuilt: TrackedBefore };

const SEQ = /^(?:0|[1-9]\d{0,18})$/;

/** Whether a value is a plain object (JSON's), not an array or null. */
const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/** One action's name as written: [version, seq or null]; undefined for anything else. */
function earlierIn(value: unknown): EarlierEvent | undefined {
  if (!Array.isArray(value) || value.length !== 2) return undefined;
  const [version, seq] = value as readonly unknown[];
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 1) return undefined;
  if (seq === null) return { version, seq: null };
  return typeof seq === 'string' && SEQ.test(seq) ? { version, seq: BigInt(seq) } : undefined;
}

/** The names as their detail's text. */
function trackedText({ from, last }: TrackedBefore): string {
  const named = Object.fromEntries(
    [...last].map(([action, { version, seq }]) => [action, [version, seq === null ? null : seq.toString()]]),
  );
  return JSON.stringify({ from: from.toString(), last: named });
}

/** The names an event's details carry: none (an event from before them), or `malformed` (never one the app wrote). */
export function trackedBeforeIn(details: Readonly<Record<string, unknown>>): TrackedBefore | undefined | 'malformed' {
  const text = details[TRACKED_BEFORE];
  if (text === undefined) return undefined;
  if (typeof text !== 'string') return 'malformed';
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return 'malformed';
  }
  if (!isRecord(parsed) || Object.keys(parsed).length !== 2) return 'malformed';
  const { from, last } = parsed;
  if (typeof from !== 'string' || !SEQ.test(from) || !isRecord(last)) return 'malformed';
  const named = new Map<string, EarlierEvent>();
  for (const [action, value] of Object.entries(last)) {
    const earlier = earlierIn(value);
    if (earlier === undefined) return 'malformed';
    named.set(action, earlier);
  }
  return Object.freeze({ from: BigInt(from), last: named });
}

/** The names a table's next state event carries, from the state it moves on from; none for a table that tracks nothing, or a start that names none. */
function trackedFrom(tracks: readonly string[], start: TrailStart): TrackedBefore | undefined {
  if (start === 'new') return { from: 0n, last: new Map() };
  if ('rebuilt' in start) return start.rebuilt;
  if ('adjacent' in start) {
    const { version, action } = start.adjacent;
    return { from: 0n, last: new Map(tracks.includes(action) ? [[action, { version, seq: null }]] : []) };
  }
  const { trail } = start;
  if (trail === undefined) return undefined;
  // A state from before the names: they start at its own event, its object's older ones unnamed.
  const last = new Map(trail.tracked?.last ?? []);
  if (tracks.includes(trail.action)) last.set(trail.action, { version: start.version, seq: trail.seq });
  return { from: trail.tracked?.from ?? trail.seq, last };
}

/** A state event's details with its names added (sealedEvent): as they were for a table that tracks nothing. */
export function withTracked(
  table: SignedStateTable,
  start: TrailStart,
  details: AuditDetails,
): { readonly details: AuditDetails; readonly tracked: TrackedBefore | undefined } {
  if (table.tracks === undefined) return { details, tracked: undefined };
  if (Object.hasOwn(details, TRACKED_BEFORE)) throw new RangeError(`details.${TRACKED_BEFORE} is added here`);
  const tracked = trackedFrom(table.tracks, start);
  return tracked === undefined
    ? { details, tracked }
    : { details: { ...details, [TRACKED_BEFORE]: trackedText(tracked) }, tracked };
}

/**
 * An object's names rebuilt from its whole history (`events`: every event of its tracked actions, read once its
 * chain was checked whole): the newest of each, complete from the start (state-names.ts names an object recorded
 * before the names this way). Its own older events of each action carry no names of their own.
 */
export function namesFromHistory(table: SignedStateTable, events: readonly TrailEvent[]): TrackedBefore {
  const last = new Map<string, EarlierEvent>();
  for (const { seq, event } of events) {
    if (table.tracks?.includes(event.action) !== true) continue;
    const kept = last.get(event.action)?.seq;
    if (kept === undefined || kept === null || kept < seq)
      last.set(event.action, { version: event.subject.version, seq });
  }
  return { from: 0n, last };
}

/** Whether a state's names reach back to its object's start: false for a state from before them, or one named from its own event on. */
export const namedFromStart = (trail: StateTrail | undefined): boolean => trail?.tracked?.from === 0n;

/** An object a history read rests on, as its state was verified (held by the digest). */
export interface TrailObject {
  readonly table: SignedStateTable;
  readonly id: string;
  readonly version: number;
  readonly trail: StateTrail | undefined;
}

/** An event a history read got. */
export interface TrailEvent {
  readonly seq: bigint;
  readonly event: {
    readonly action: string;
    readonly subject: { readonly type: string; readonly id: string; readonly version: number };
    readonly details: Readonly<Record<string, unknown>>;
  };
}

/** The gap's action for a state that carries no names where every one must (trailGap's `allNamed`). */
export const NO_NAMES = 'names.missing';

/** The event a read should have got and didn't: about which object, of which action, at which version. */
export interface TrailGap {
  readonly table: SignedStateTable;
  readonly id: string;
  readonly action: string;
  readonly version: number;
}

/** Where a named event is: its seq resolved against the event naming it. */
const placeOf = (named: EarlierEvent, namer: bigint): { readonly version: number; readonly seq: bigint } => ({
  version: named.version,
  seq: named.seq ?? namer - 1n,
});

/** The objects a read rests on by subject, lower-cased. */
const keyOf = (type: string, id: string) => `${type}:${id.toLowerCase()}`;

/**
 * The first event the read should have got and didn't (or none): each object's newest event of each of `actions` it
 * tracks, as its state names it, and each one named by an event got, wherever it falls after `after` (the read
 * covering every event of those actions about those objects past it, to the newest). An event got that is newer
 * than its object's state, or whose names can't be read, is a gap too: the state read is the newest, under its lock.
 */
export function trailGap(
  events: readonly TrailEvent[],
  objects: readonly TrailObject[],
  actions: readonly string[],
  after: bigint | undefined,
  /** Every object's state must carry names: its organisation's own reach back to its start (born so, or named whole since). */
  allNamed = false,
): TrailGap | undefined {
  // A state with none where every one has them was never the app's (an owner can't write a sealed event): the gap.
  const unnamed = allNamed
    ? objects.find(({ trail }) => trail !== undefined && trail.tracked === undefined)
    : undefined;
  if (unnamed !== undefined)
    return { table: unnamed.table, id: unnamed.id, action: NO_NAMES, version: unnamed.version };
  const got = new Set(events.map(({ seq, event }) => `${keyOf(event.subject.type, event.subject.id)}@${seq}`));
  const missed: Missed = (object, action, named, namer) => {
    const { version, seq } = placeOf(named, namer);
    const inRead = after === undefined || seq > after;
    return inRead && !got.has(`${keyOf(object.table.subject, object.id)}@${seq}`)
      ? { table: object.table, id: object.id, action, version }
      : undefined;
  };
  for (const object of objects) {
    const gap = newestMissed(object, actions, missed);
    if (gap !== undefined) return gap;
  }
  const byKey = new Map(objects.map((object) => [keyOf(object.table.subject, object.id), object]));
  for (const each of events) {
    const gap = namedMissed(each, byKey.get(keyOf(each.event.subject.type, each.event.subject.id)), missed);
    if (gap !== undefined) return gap;
  }
  return undefined;
}

/** The event named (from the event at `namer`) as the read's gap, when it falls in what the read covers and wasn't got. */
type Missed = (object: TrailObject, action: string, named: EarlierEvent, namer: bigint) => TrailGap | undefined;

/** The object's newest event of any of `actions` it tracks, as its state names it, when the read didn't get it. */
function newestMissed(object: TrailObject, actions: readonly string[], missed: Missed): TrailGap | undefined {
  const { trail, table } = object;
  if (trail === undefined) return undefined;
  for (const action of actions.filter((each) => table.tracks?.includes(each) === true)) {
    const newest =
      trail.action === action ? { version: object.version, seq: trail.seq } : trail.tracked?.last.get(action);
    const gap = newest === undefined ? undefined : missed(object, action, newest, trail.seq);
    if (gap !== undefined) return gap;
  }
  return undefined;
}

/** The event before one got (of its action, about its object) when the read didn't get it; the one got itself when it can't be held. */
function namedMissed(
  { seq, event }: TrailEvent,
  object: TrailObject | undefined,
  missed: Missed,
): TrailGap | undefined {
  if (object?.trail === undefined || object.table.tracks?.includes(event.action) !== true) return undefined;
  const tracked = trackedBeforeIn(event.details);
  if (seq > object.trail.seq || tracked === 'malformed') {
    return { table: object.table, id: object.id, action: event.action, version: event.subject.version };
  }
  const before = tracked?.last.get(event.action);
  return before === undefined ? undefined : missed(object, event.action, before, seq);
}

/** Where a newest-first read of at most `limit` covers to: everything when it got fewer, else from its oldest on. */
export const newestCovered = (events: readonly { readonly seq: bigint }[], limit: number): bigint | undefined =>
  events.length < limit ? undefined : (events[0]?.seq ?? 0n) - 1n;
