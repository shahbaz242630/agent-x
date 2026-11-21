// The signed states' digest kept apart from the database (AT13, R-15): what state-digest.ts holds in memory, written to
// the anchors' write-once store beside the anchors, where someone with the database's keys can't reach it, and read back
// at a start the way the anchors are. Tx A and every decision read it from memory, with no trip.
//
// Files, gzipped lines, each closed by a line signed with the `audit-anchor` key for the file's own name, its epoch, how
// many lines it holds and the hash of every byte before it, under its own label, so no anchor file can pass for one:
//   e<epoch>/digests/deltas/<inverted-ms>-<id>     what the walks found, at each write the anchors make
//   e<epoch>/digests/snapshots/<inverted-ms>-<id>  every chain's digest, hourly, where something moved
// A line is one chain's objects of one class (`p` for a payment's: below), at most MOST_ENTRIES_A_LINE of them, packed
// (state-digest.ts) as base64, dated when the walk that read them began (`t`), and the stretch of the chain that walk
// read whole (`f` to `u`, `h`, `k`). Every fact a line holds is a place the chain's own walk read, sealed by the app's
// MAC key, so it stays true however often or late it is read: a read merges them, the higher place winning, in any
// order. So a delta is always written for what moved, and a snapshot is only a quicker start, never the one copy.
//
// Coverage: a chain's digest stands for the chain only up to where the stretches its walks read join up unbroken from
// the chain's first event (`covered`). Tx A asks `covers` of the anchor it compares with: a stretch lost (a crash between
// the anchor's write and the digest's, a spoiled delta) or a rebase leaves the chain uncovered, so its hand-offs wait
// (`digest_pending`, that organisation alone) until the anchor check's catch-up walk reads on from where it is covered
// (anchor-check.ts). Every other read goes on with the facts held, which are true either way. Coverage can sit past
// the chain's last anchor: the catch-up walk records it to the head it read, writing no anchor, and an anchor whose
// write failed beside a digest delta that was written leaves it so. Each is a place the app's chain truly reached.
//
// A start reads the newest sound snapshot, then every delta named since it, less five minutes for the clocks. A file
// whose closing line fails is spoiled: the alarm, and nothing in it counts. A snapshot spoiled is passed over for the one
// before it, at most a day's worth; with none sound past that, every delta is read instead: slower, and nothing lost.
// Until a start's read has ended whole, no chain is covered. A name dated past the clock is the alarm and passed over.
//
// A rebase (rebase.ts, E11) blesses a chain wound back: its old facts may no longer hold, so a line dated before the
// chain's newest rebase is passed over, and a chain holding a fact from before it is set aside whole when next asked,
// facts and coverage, until walks read it again from its first event. The digest learns of rebases from the anchors'
// log, which reads them first. A walk's facts are dated when it began, so a walk a rebase lands during counts as before.
//
// Said only while the anchors' log holds the chain's shard (PL-65 PR3; a shard let go may hold a rebase not read again).
// Whether this process leads the jobs decides only what it writes (`writes`: a walk recorded, a delta or a snapshot
// written), never what it says (TR-1 A). A copy that loses the lease keeps every fact, coverage and head it holds, and
// goes on reading the store as a web copy does (job-list.ts), so it learns of rebases and of the leader's walks; when
// it leads again it writes what it held back. Forgetting at a lease lost was a hole: the owner, taking the lease row
// for a moment, made the copy forget the heads it had seen above the anchor, and a cut back to below them passed.
//
// What it holds is bounded (`mostBytes`), and one organisation's growth never stops another's. Past it, a chain gives
// way: the objects that grow with use first (`GROWING_SUBJECTS`: a payment's requests, instructions, transactions; the
// platform chain's session ends), then the whole chain, each with that organisation's alarm. Only a chain holding more
// than its fair share (what may be held over the chains held) is chosen while one does, those with growing objects
// first, then the largest: so many small organisations never push out a large one within its share, and as the whole is
// over what may be held, the largest chain is always past its share. A chain given way reads as before the digest, Tx A
// included (today's checks), never as a stop. How far it gave way is written with what moved and in every snapshot
// (`g`, with what it let go, `b`), so a restart holds it so at once, never as a chain to wait for: given way whole, it
// reads as before the digest; its growing objects alone, it stays covered, as a fact missing only loses protection,
// never raises the alarm. The anchors' log counts what is held here against its own budget too (`alsoHeld`), and lets
// its shards go to make room.
//
// A chain given way comes back (AT13e) once what is held is under half of what may be, with room for what it let go,
// and an hour after it gave way: so it never flaps. Its coverage starts again from nothing, and the anchor check's
// catch-up walk reads it from its first event (`owed`), facts kept as it goes; until that walk reaches the anchor, it
// reads as given way (today's checks: no wait, and no alarm from facts it doesn't hold yet). Each chain's give-way state
// has a generation (`n`), odd while it comes back: written on every mark line and stretch, read as the highest
// generation, then the highest give-way within it, so files read in any order agree and a restart holds it as it was. A
// stretch counts only from the generation its chain last began coming back in, so none from before stands for it.
//
// A spend request's facts are forgotten past the approval horizon (AT13d, `forgetRequestsAfterMs`): the hand-off
// refuses an approval sealed longer ago (voids.ts), and every version of a request is no newer than its newest signed
// event, so once that is older than the horizon no version the database could be rolled back to can be handed off, and
// one waiting for approval has waited out its own wait (72 hours at most) and can't be approved. Each request's facts
// are kept in a table for the day they were known by (`y`: a time no event they name can be newer than, the app's clock
// when the walk recorded them), and a day's table is let go whole once that time is FORGET_MARGIN_MS past the horizon:
// the margin is for a walk's length and the two clocks. A request with a newer fact keeps it in a newer day's table.
// Coverage is untouched, and a fact missing only loses protection, never raises the alarm. Written as payments' lines
// with `y`, so an image before this one reads them as payments' facts, kept; a payments' line without `y` (written
// before this) stays a payments' fact for good, as before. Instructions, transactions, failure proposals and remittances
// are kept: the bank may still move a payment past the horizon, and nothing seals one's end yet.
//
// The platform chain's session ends are forgotten the same way (AT13g, `forgetSessionEndsAfterMs`): a sign-out, a
// rotation and a person's sessions all ended matter only while a session they end could still be used, and a session
// is used only before its absolute end, which its row's MAC holds as the app set it at sign-in (sessions.ts: never
// further than the longest absolute timeout there can be past it). Every session such an end names opened before the
// end was signed, so once its facts were known by a time the longest timeout and FORGET_MARGIN_MS ago, every version of
// every row it names is past its absolute end, put back or not. Kept by the day they were known by, as a request's, on
// payments' lines with `s` (the platform chain's own field, where an organisation's say `y`), so an image before this
// one reads them as payments' facts, kept; one without (written before) stays kept for good. Which horizon a day's facts
// go by is the chain's: only session ends are dated on the platform chain, only requests on an organisation's.
//
// The chain cut back (AT13f): an object first signed above the last anchor is in no walk yet, so the owner deleting
// the chain's end not yet anchored, its events with it, and putting back an earlier sealed head, leaves every seal true
// and the object reading as never made (a month's total as nothing held). So each read of an organisation's chain also
// holds the chain's head, read in its own statement, to the highest head this process has seen the chain at (`heads`):
// a head below it, or another event at its place, is the chain cut back past the app, tampering for every object it
// holds, never an object missing. Raised by the reads themselves, from what is committed, asked before the statement as
// `latest` is; in memory, with no trip and no file. A rebase after the read that saw it sets it aside, as it does the
// facts. Where the digest covers the chain (a head a walk read, from the store: about its last anchor, or past it), that
// is held to as well, so a restart keeps the chain held that far; what this process saw above it goes with the process,
// never with its lease (TR-1 A: a lease taken from it, even for a moment, leaves every head it saw held to).
// So a sanctioned repair that leaves the chain below, or other than, a head a copy saw or a walk covered (rows taken
// away or replaced, though the anchor holds) is followed by a rebase (the operator's `chain-rebase --after-restore`),
// which sets every copy's heads and coverage aside within one read of the anchors.
// Another copy sees only what it read itself. Held at most a tenth of what may be held, the one raised longest ago going
// first: only weaker, never a stop.
//
// A cut answered (AT13h, S208's partner decision): the console's sessions answer a cut platform chain by a signed end of
// every session, recorded on the chain as it now stands (identity's sessions-all-ended.ts). Once that commits, the
// chain may be taken as it stands for those reads alone (`accept`): a head kept beside the one seen, which `accepted`
// gives while the head seen is still the one it was taken over, raised as that is, and set aside by a rebase. Never
// lowers what the other reads hold to: the hand-off pause's reads stay held to the head seen.
//
// Held to every copy's heads too (TR-1, witness-log.ts): another copy's stop was never seen here, so each read is also
// held to the highest heads any copy witnessed above the chain's anchor (`witnessed`, at most MOST_WITNESSED), each at
// its place with its hash, in the read's own statement (`heldTo`): a list, never only the highest, as a stale copy's
// head on a cut branch must not bury the honest one. The chain taken as it stands (AT13h) holds its reads to the heads
// witnessed after it alone: one the cut took away, witnessed before, would lock the console again (S208's decision).
import type { KeyProvider } from '../keys/key-provider.ts';
import type { Logger } from '../observability/index.ts';
import type { WriteOnceStore } from '../storage/write-once.ts';
import { type Chain, chainName, type CheckedPoint } from './chain.ts';
import { isCount, timeIn } from './rebase.ts';
import { bodyLines, fileName, type FileKind, isSoundFile, namesIn, signedFile, timeOfName } from './signed-files.ts';
import {
  ChainDigest,
  fingerprintOf,
  packEntries,
  placeOf,
  type SignedSeen,
  subjectKey,
  unpackEntries,
} from './state-digest.ts';

/** A stretch of a chain a walk read whole: after `from`, up to and at `to`. */
interface Stretch {
  readonly from: bigint;
  readonly to: CheckedPoint;
}

/** A chain's head as a read found it, sealed (AT13f): its place, and the hash of its event there. */
export interface HeadSeen {
  readonly seq: bigint;
  readonly hash: Buffer;
}

/** What a read holds the chain's head to (AT13f), asked before its statement is sent. */
export interface HeadWatch {
  /** The highest head this process has seen the chain at, or the digest covers it to; none, nothing to hold to. */
  readonly seen: HeadSeen | undefined;
  /**
   * Every head the read is held to (TR-1): the head this process saw, where the digest covers the chain to, and the
   * highest heads any copy witnessed above the chain's anchor (witness-log.ts), at most MOST_WITNESSED: each at its place
   * with its hash, the chain's head no lower than the highest. Kept apart, never only the highest: a stale copy's head
   * on a cut branch must not bury the honest one below it. Empty, nothing to hold to.
   */
  readonly heldTo: readonly HeadSeen[];
  /** The head the read found, sealed and not cut back: kept as seen where higher, dated when this watch was asked. */
  saw(head: HeadSeen): void;
  /**
   * Where the chain was taken as it stands after a signed answer to its cut (AT13h, the header), raised since: while
   * `seen` is still the head it was taken over. Its `saw` raises it alone; its `heldTo` adds only heads witnessed after
   * it was taken (TR-1: a head the cut took away, witnessed before, must not lock the console again). None else.
   */
  readonly accepted: Pick<HeadWatch, 'seen' | 'saw' | 'heldTo'> | undefined;
  /**
   * Takes the chain as it stands at `to`, a sealed head at or above a signed answer to the cut of the head this watch
   * gave as `seen`, for the reads that answer allows: only while that is still the head seen, and never from a watch
   * asked before a rebase. Nothing where this watch gave none.
   */
  accept(to: HeadSeen): void;
}

/** The places a read asks the hashes of, in its own statement, in the order `heldTo` gives them (TR-1). */
export const placesOf = (heads: readonly HeadSeen[]): readonly string[] => heads.map(({ seq }) => seq.toString());

/** The first head without its hash at its place, `hashes` read in the order given (placesOf). */
const hashMissing = (heads: readonly HeadSeen[], hashes: unknown): HeadSeen | undefined => {
  const read: readonly unknown[] = Array.isArray(hashes) ? hashes : [];
  return heads.find(({ hash }, at) => {
    const there = read[at];
    return !(there instanceof Buffer) || !there.equals(hash);
  });
};

/**
 * Whether the chain, as a write found it under its head's lock, still runs through every head in `at` (AT13h, TR-1):
 * none to hold to, or the event at each place (read at or below the head locked, in the lock's statement) with its
 * hash. A write on a chain cut back below a head this process holds raises nothing from it: the write goes on from the
 * cut, and raising it would hide the cut.
 */
export const heldThrough = (at: readonly HeadSeen[], hashesThere: unknown): boolean =>
  hashMissing(at, hashesThere) === undefined;

/**
 * What a write committed raises (AT13h): the head seen, and the head taken with it, where the chain ran through both;
 * only the head taken, where it ran through that alone (a cut answered); nothing where it ran through neither.
 */
export function raiseWritten(
  watch: HeadWatch,
  head: HeadSeen,
  held: { readonly seen: boolean; readonly accepted: boolean },
): void {
  if (!held.accepted) return;
  if (held.seen) watch.saw(head);
  else watch.accepted?.saw(head);
}

/** Whether two heads are the same: the same place, with the same hash. */
const sameHead = (one: HeadSeen, other: HeadSeen): boolean => one.seq === other.seq && one.hash.equals(other.hash);

/**
 * Where a chain's head, read in one statement with the hashes of the events at the places held to (`seenHashes`, in
 * `heldTo`'s order), fails the heads the read was held to (AT13f, TR-1): none where it is sealed (`head`, none where it
 * isn't), no lower than the highest, with the same event at each place, and at its own place only with its hash.
 * Nothing held to, nothing to hold to. Else the chain was cut back past the app, at the head named.
 */
export function headCutBelow(
  heldTo: readonly HeadSeen[],
  head: HeadSeen | undefined,
  seenHashes: unknown,
): HeadSeen | undefined {
  const [first] = heldTo;
  if (first === undefined) return undefined;
  const highest = heldTo.reduce((one, other) => (other.seq > one.seq ? other : one), first);
  if (head === undefined || head.seq < highest.seq) return highest;
  return hashMissing(heldTo, seenHashes) ?? heldTo.find(({ seq, hash }) => seq === head.seq && !head.hash.equals(hash));
}

/** Whether the chain's head, read as headCutBelow reads it, holds to every head held to. */
export const headHeldTo = (heldTo: readonly HeadSeen[], head: HeadSeen | undefined, seenHashes: unknown): boolean =>
  headCutBelow(heldTo, head, seenHashes) === undefined;

/** A head seen, with when the read that saw it was asked: a rebase after that sets it aside. */
type HeadKept = HeadSeen & { readonly at: number };

/**
 * A chain taken as it stands (AT13h, `accept`): the head seen it was taken over (none where this process held it to
 * witnessed heads alone, TR-1), and the head held to since.
 */
type HeadAccepted = HeadKept & { readonly over: HeadSeen | undefined };

/** The most witnessed heads a read is held to: the highest, as each is one more place read in the read's statement. */
export const MOST_WITNESSED = 8;

/**
 * How long after a chain was taken as it stands a witnessed head must have been noted to hold the reads it allows: the
 * writers' clocks may run ahead of this one, and a head the cut took away, noted just before, must not count.
 */
const ACCEPT_MARGIN_MS = 60_000;

/** The same head twice, or none of either. */
const sameOrNone = (one: HeadSeen | undefined, other: HeadSeen | undefined): boolean =>
  one === undefined || other === undefined ? one === other : sameHead(one, other);

/** What a decision reads of the digest. */
export interface StateDigest {
  /** The newest signed place known for the object on the chain; nothing where it knows none, or can't say now. */
  latest(chain: Chain, type: string, id: string): bigint | undefined;
  /**
   * What a read of the chain holds its head to (AT13f, the header); none where the digest can't say now (the chain's
   * shard let go). A copy that doesn't lead says it as one that does (TR-1 A). A head read below `seen`, or another event at its place, is the chain
   * cut back past the app.
   */
  heads(chain: Chain): HeadWatch | undefined;
  /**
   * Whether Tx A may go on a chain anchored at `seq`: the digest covers it to there, or has given the chain up for memory
   * (today's checks, its alarm said). False until the store is read, and while a stretch below `seq` is missing.
   */
  covers(chain: Chain, seq: bigint): boolean;
}

/** The digest, kept: what the anchor check records into it and how it is read and written. */
export interface DigestLog extends StateDigest {
  /** What a walk that began at `began` read: each object's newest signed place, and the stretch it read whole. */
  record(chain: Chain, seen: SignedSeen, began: Date, stretch?: Stretch): void;
  /** Where the chain is covered to, for a catch-up walk to go on from: none, from its first event. */
  coverage(chain: Chain): CheckedPoint | undefined;
  /**
   * Whether the chain, anchored at `seq`, owes a catch-up walk: read, not wholly given way, and not covered to there
   * (one coming back included, AT13e). A chain coming back whose walk has reached `seq` is back, from here.
   */
  owed(chain: Chain, seq: bigint): boolean;
  /** Reads what the store holds that this process has not. Never throws; one at a time, a second call joins the first. */
  read(): Promise<void>;
  /** Writes what moved, and hourly the whole. Never throws; one at a time, a second call joins the first. */
  flush(): Promise<void>;
  state(): 'unread' | 'read';
  /** What the digest holds, in bytes, against what it may. */
  memoryHeld(): {
    readonly bytes: number;
    readonly mostBytes: number;
    readonly chains: number;
    readonly objects: number;
  };
  /** What the chains' tables take, in bytes, kept as they change: no count, for the anchors' log at every line. */
  bytesHeld(): number;
}

/** What the digest asks of the anchors' log: the rebases it read, and which shards it holds. */
export interface DigestAnchors {
  rebasedAfter(chain: Chain, at: Date): boolean;
  holds(chain: Chain): boolean;
}

/**
 * The subject types that grow with use: one or more a payment, and on the platform chain one a sign-out or step-up
 * (AT13c: the session ends' facts, identity's signed-ends.ts names them). Given way first under memory, as the authority
 * a payment rests on (agents, keys, mandates, members, policies, suppliers, sources, the hold, the hand-off pause) is
 * what an attacker rolls back first.
 */
const GROWING_SUBJECTS: ReadonlySet<string> = new Set([
  'spend_request',
  'instruction',
  'transaction',
  'failure_proposal',
  'supplier_remittance',
  'identity.session_ended',
  'identity.session_rotated',
  'identity.sessions_ended',
]);

/** A spend request's subject type: its facts forgotten past the approval horizon (AT13d). */
const REQUEST_SUBJECT = 'spend_request';

/**
 * The platform chain's session ends' subject types: their facts forgotten past the longest session (AT13g). Every
 * session's end at once (AT13h, a cut chain answered) too: it ends only sessions signed in before it.
 */
const SESSION_ENDS: ReadonlySet<string> = new Set([
  'identity.session_ended',
  'identity.session_rotated',
  'identity.sessions_ended',
  'identity.sessions_all_ended',
]);

/** A day: a request's or session end's facts are kept in one table a day they were known by. */
const DAY_MS = 24 * 60 * 60_000;

/**
 * How far past the horizon a request's facts are kept beyond the time they were known by: far more than a walk takes
 * between reading an event and recording it, and than the app's clock and Postgres's may differ, so no event they name
 * can be younger than the horizon when they go. Shared with the spend requests' ends, which keep the capacity of a
 * request past it (endings.ts), so the two can't drift.
 */
export const FORGET_MARGIN_MS = DAY_MS;

/** How often the chains' days' tables are looked over for one past its horizon. */
const FORGET_EVERY_MS = 60 * 60_000;

/** The most objects on one line: 32 KB of entries, 44 KB of base64. */
const MOST_ENTRIES_A_LINE = 2048;

/** How often the whole is written, where something moved. */
const SNAPSHOT_EVERY_MS = 60 * 60_000;

/** How far past this process's clock a name may be dated, as the anchors' log allows. */
const MOST_AHEAD_MS = 5 * 60_000;

/** How far before the newest file read a later read looks again: a file named earlier may land later. */
const LAG_MS = MOST_AHEAD_MS;

/** How many spoiled snapshots a start goes back past: a day's at one an hour. */
const MOST_SPOILED_SNAPSHOTS = 24;

/** How near what is held may come to what it may before that is said. */
const NEAR_MEMORY = 0.5;

/** How far below what it may hold giving way goes, so the next few facts don't give way again. */
const GIVE_WAY_TO = 0.9;

/** What a chain costs beside its slots: its name, coverage and the map's entry. */
const CHAIN_BYTES = 300;

/** How many stretches a chain keeps that don't join its coverage yet: a gap's far side, a few. */
const MOST_STRETCHES = 16;

/** How often a chain given way says so again. */
const SAY_EVERY_MS = 60 * 60_000;

/** How long after it gave way a chain may come back: at most once an hour, so it never flaps (AT13e). */
const BACK_AFTER_MS = 60 * 60_000;

/** What a chain's head seen takes (AT13f): the map's entry, its name and a 32-byte hash, generously. */
const HEAD_BYTES = 200;

/** The share of what may be held the heads seen may take, at most: past it the one raised longest ago goes. */
const HEADS_SHARE = 0.1;

const CHAIN = /^(?:platform|organisation:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const SEQ = /^(?:0|[1-9]\d{0,18})$/;
const HASH = /^[0-9a-f]{64}$/;

type Kind = 'deltas' | 'snapshots';
type Entries = readonly (readonly [number, number, number])[];

/** What a digest file's closing line signs under: its own label, so an anchor file's closing line can't close one. */
const DIGEST_FILE: FileKind = { label: 'audit-digest-file', purpose: 'audit-anchor' };

/** How much of a chain gave way for memory, in which generation, and what it let go (AT13e): a mark line's. */
interface Mark {
  /** 0 none, 1 its growing objects, 2 all of it. */
  readonly gaveWay: 0 | 1 | 2;
  /** Odd while the chain comes back; raised each time it begins to, and once more when it is back. */
  readonly gen: number;
  /** About how many bytes its tables held when it gave way: what coming back would take. */
  readonly letGo: number;
}

/** A line of a file, read: its chain, when its walk began, its entries and their class, and the stretch read. */
interface DigestLine {
  readonly chain: string;
  readonly at: Date;
  readonly payments: boolean;
  readonly entries: Entries;
  /** On a payments' line, for dated facts (`y`, AT13d/g): the time no event they name can be newer than. */
  readonly knownBy?: number | undefined;
  readonly stretch?: Stretch | undefined;
  /** How much of the chain had given way for memory where the line was written (`g`): kept so across a restart. */
  readonly gaveWay?: 1 | 2 | undefined;
  /** The chain's give-way generation (`n`), on a mark line or a stretch; none, 0. */
  readonly gen?: number | undefined;
  /** What the chain let go (`b`), on a mark line. */
  readonly letGo?: number | undefined;
}

/** A line's stretch, none where it names none, or `undefined` read as a line not ours where one is half there. */
function stretchFrom({ f, u, h, k }: Record<string, unknown>): Stretch | 'none' | undefined {
  if (f === undefined && u === undefined && h === undefined && k === undefined) return 'none';
  if (typeof f !== 'string' || !SEQ.test(f) || typeof u !== 'string' || !SEQ.test(u)) return undefined;
  if (typeof h !== 'string' || !HASH.test(h) || !isCount(k) || BigInt(f) > BigInt(u)) return undefined;
  return { from: BigInt(f), to: { seq: BigInt(u), hash: Buffer.from(h, 'hex'), macKeyVersion: k } };
}

/** A line's mark fields as they may be: a generation any line may carry, what was let go only with how far. */
const markFieldsHold = ({ g, n, b }: Record<string, unknown>): boolean =>
  (g === undefined || g === 1 || g === 2) &&
  (n === undefined || isCount(n)) &&
  (b === undefined || (isCount(b) && g !== undefined));

/**
 * A line's class as it may be: payments' or none; a time its dated facts were known by only on a payments' one, `y` on
 * an organisation's chain (its requests', AT13d), `s` on the platform's (its session ends', AT13g).
 */
const classFieldsHold = (chain: unknown, { p, y, s }: Record<string, unknown>): boolean =>
  (p === undefined || p === 1) &&
  (y === undefined || (p === 1 && chain !== 'platform' && timeIn(y) !== undefined)) &&
  (s === undefined || (p === 1 && chain === 'platform' && timeIn(s) !== undefined));

function lineFrom(fields: unknown): DigestLine | undefined {
  if (typeof fields !== 'object' || fields === null) return undefined;
  const said = fields as Record<string, unknown>;
  const { c, t, e, p, g, n, b, y, s } = said;
  const at = timeIn(t);
  const stretch = stretchFrom(said);
  if (typeof c !== 'string' || !CHAIN.test(c) || at === undefined || stretch === undefined) return undefined;
  if (!classFieldsHold(c, said) || !markFieldsHold(said)) return undefined;
  const entries = e === undefined ? [] : typeof e === 'string' ? unpackEntries(Buffer.from(e, 'base64')) : undefined;
  if (entries === undefined || (entries.length === 0 && stretch === 'none' && g === undefined && n === undefined)) {
    return undefined;
  }
  return {
    chain: c,
    at,
    payments: p === 1,
    entries,
    knownBy: timeIn(y ?? s)?.getTime(),
    ...(stretch === 'none' ? {} : { stretch }),
    ...(g === undefined ? {} : { gaveWay: g as 1 | 2 }),
    ...(n === undefined ? {} : { gen: n as number }),
    ...(b === undefined ? {} : { letGo: b as number }),
  };
}

/** What a line holds beside its chain and time. */
interface LineParts {
  readonly payments?: boolean;
  readonly entries?: Entries;
  /** Dated facts' time known by, on a payments' line (AT13d/g). */
  readonly knownBy?: number;
  readonly stretch?: Stretch | undefined;
  readonly mark?: Mark;
  /** A stretch's generation, where it has no mark. */
  readonly gen?: number;
}

/** A line's text. */
function lineText(
  chain: string,
  at: number,
  { payments = false, entries = [], knownBy, stretch, mark, gen }: LineParts,
): string {
  const generation = mark?.gen ?? gen ?? 0;
  return JSON.stringify({
    c: chain,
    t: new Date(at).toISOString(),
    ...(mark === undefined || mark.gaveWay === 0 ? {} : { g: mark.gaveWay, b: mark.letGo }),
    ...(generation === 0 ? {} : { n: generation }),
    ...(entries.length === 0 ? {} : { e: packEntries(entries, entries.length).toString('base64') }),
    ...(payments ? { p: 1 } : {}),
    ...(knownBy === undefined ? {} : { [chain === 'platform' ? 's' : 'y']: new Date(knownBy).toISOString() }),
    ...(stretch === undefined
      ? {}
      : {
          f: stretch.from.toString(),
          u: stretch.to.seq.toString(),
          h: stretch.to.hash.toString('hex'),
          k: stretch.to.macKeyVersion,
        }),
  });
}

/** A stretch as written: with the generation of its chain when its walk was recorded. */
interface Walked {
  readonly stretch: Stretch;
  readonly gen: number;
}

/**
 * A day's table of a chain's dated facts (its requests', AT13d; the platform's session ends, AT13g): the latest time
 * no event they name can be newer than.
 */
interface DatedDay {
  readonly table: ChainDigest;
  knownBy: number;
}

/**
 * A chain's lines: how much of it gave way for memory and its generation, if either, first; each class's entries, at
 * most MOST_ENTRIES_A_LINE a line, its dated facts a day's table at a time with the time they were known by (AT13d/g);
 * the stretches on lines of their own.
 */
function* linesOf(
  chain: string,
  at: number,
  [kept, spent]: readonly [Entries, Entries],
  stretches: readonly Walked[],
  mark: Mark | undefined,
  dated: Iterable<DatedDay>,
): Generator<string> {
  if (mark !== undefined && (mark.gaveWay !== 0 || mark.gen !== 0)) yield lineText(chain, at, { mark });
  const classes: (readonly [boolean, Entries, number | undefined])[] = [
    [false, kept, undefined],
    [true, spent, undefined],
  ];
  for (const { table, knownBy } of dated) classes.push([true, [...table.entries()], knownBy]);
  for (const [payments, entries, knownBy] of classes) {
    for (let from = 0; from < entries.length; from += MOST_ENTRIES_A_LINE) {
      const part = entries.slice(from, from + MOST_ENTRIES_A_LINE);
      yield lineText(chain, at, { payments, entries: part, ...(knownBy === undefined ? {} : { knownBy }) });
    }
  }
  for (const { stretch, gen } of stretches) yield lineText(chain, at, { stretch, gen });
}

/** The chain's object, from its name in a line. */
const chainOfName = (name: string): Chain =>
  name === 'platform' ? { kind: 'platform' } : { kind: 'organisation', orgId: name.slice('organisation:'.length) };

/** Whether a subject key is of a type that grows with use. */
const grows = (key: string): boolean => GROWING_SUBJECTS.has(key.slice(0, key.indexOf('\n')));

/** The generation from which a chain's stretches count: the one it last began coming back in (odd), else all. */
const baseOf = (gen: number): number => (gen % 2 === 1 ? gen : Math.max(gen - 1, 0));

/**
 * One chain as held: its authority's and its payments' tables, when its oldest fact's walk began, where it is covered to
 * and the stretches beyond a gap; and how much of it has given way for memory (1 its payments, 2 all of it). Its dated
 * facts (requests, AT13d; session ends, AT13g), where they are forgotten past a horizon, by the day they were known by,
 * of its payments.
 */
interface ChainState {
  bornAt: number;
  readonly tables: [ChainDigest, ChainDigest];
  readonly dated: Map<number, DatedDay>;
  covered: CheckedPoint | undefined;
  readonly stretches: Map<bigint, CheckedPoint>;
  gaveWay: 0 | 1 | 2;
  /** Its give-way generation (AT13e, the header): odd while it comes back. */
  gen: number;
  /** About what its tables held when it gave way, for coming back to fit. */
  letGo: number;
  /** When it gave way, here or as read: it comes back no sooner than BACK_AFTER_MS after. */
  gaveWayAt?: number;
  /** In what waits to be written: its mark moved, so a mark line goes with it. */
  marked?: boolean;
  saidAt?: number;
  saidWhat?: 1 | 2;
}

/** Joins a stretch to the chain's coverage where it reaches it, else keeps it for when a stretch fills the gap. */
function extend(state: ChainState, { from, to }: Stretch): boolean {
  if (from !== 0n && (state.covered === undefined || from > state.covered.seq)) {
    keepBeyond(state, from, to);
    return false;
  }
  const before = state.covered?.seq;
  let covered = farther(state.covered, to);
  for (let joined = true; joined;) {
    joined = false;
    for (const [start, end] of state.stretches) {
      if (start > covered.seq) continue;
      state.stretches.delete(start);
      covered = farther(covered, end);
      joined = true;
    }
  }
  state.covered = covered;
  return covered.seq !== before;
}

/** The farther of two places. */
const farther = (one: CheckedPoint | undefined, other: CheckedPoint): CheckedPoint =>
  one === undefined || other.seq > one.seq ? other : one;

/** A stretch beyond a gap, kept: beyond the bound the farthest is let go, as a catch-up walk joins the nearest first. */
function keepBeyond(state: ChainState, from: bigint, to: CheckedPoint): void {
  state.stretches.set(from, farther(state.stretches.get(from), to));
  if (state.stretches.size > MOST_STRETCHES) {
    state.stretches.delete([...state.stretches.keys()].reduce((one, other) => (one > other ? one : other)));
  }
}

export function createDigestLog({
  store,
  keys,
  logger,
  now,
  epoch,
  anchors,
  writes,
  alertAfterMs,
  mostBytes,
  mostFileBytes = mostBytes,
  forgetRequestsAfterMs,
  forgetSessionEndsAfterMs,
  witnessed,
}: {
  /** Where it is kept; none in development and test with no store, where it lives in memory alone and reads as read. */
  readonly store?: WriteOnceStore | undefined;
  readonly keys: KeyProvider;
  readonly logger: Logger;
  readonly now: () => Date;
  readonly epoch: number;
  /** The anchors' log, for its rebases and its shards held; none where the anchors are in memory alone. */
  readonly anchors?: DigestAnchors | undefined;
  /**
   * Whether this process may write now: it leads the jobs (none, always). Only a walk's record, a delta and a snapshot
   * wait for it; every read and answer goes on regardless (TR-1 A), what was held back written once it leads again.
   */
  readonly writes?: (() => boolean) | undefined;
  /** How long reads or writes may fail before that is the alert, not just a warning. */
  readonly alertAfterMs: number;
  /** What it may hold, in bytes. */
  readonly mostBytes: number;
  /**
   * The most a file it fetches or writes may hold: what it may hold unless a test says. A snapshot is smaller than the
   * tables it was made from (16.5 bytes an object gzipped, against at least 21 held), so it fits; one that didn't is
   * not written, and a start reads the deltas instead.
   */
  readonly mostFileBytes?: number;
  /**
   * How long an approval stands unpaid (the spend requests' APPROVAL_HORIZON_MS, AT13d): a request's facts are forgotten
   * once FORGET_MARGIN_MS past it from when they were known by. None: kept with the other payments' facts, for good.
   */
  readonly forgetRequestsAfterMs?: number | undefined;
  /**
   * The longest a session can be used from its sign-in, whatever any copy's setting (identity's LONGEST_ABSOLUTE_SECONDS,
   * AT13g): the platform chain's session ends are forgotten once FORGET_MARGIN_MS past it from when they were known by.
   * None: kept for good.
   */
  readonly forgetSessionEndsAfterMs?: number | undefined;
  /**
   * Every head any copy witnessed above the chain's anchor, the highest first (TR-1, witness-log.ts's `pending`): each
   * read is held to the highest of them too. None, only to the heads this process saw and its walks covered.
   */
  readonly witnessed?: ((chain: Chain) => readonly (HeadSeen & { readonly at: number })[]) | undefined;
}): DigestLog {
  const chains = new Map<string, ChainState>();
  // The highest head each chain was read at here (AT13f), with when that read was asked, the one raised longest ago first.
  const heads = new Map<string, HeadKept>();
  // Each chain taken as it stands after a signed answer to its cut (AT13h): a few at most, one a chain cut.
  const accepted = new Map<string, HeadAccepted>();
  const mostHeads = Math.max(1, Math.floor((mostBytes * HEADS_SHARE) / HEAD_BYTES));
  // What moved since the last write, by chain, in the same shape: given way to nothing, written then dropped.
  let pending = new Map<string, ChainState>();
  // Each chain's stretches since the last write, in order, each with its chain's generation then.
  let pendingStretches = new Map<string, Walked[]>();
  let state: 'unread' | 'read' = store === undefined ? 'read' : 'unread';
  // What the chains' tables take, kept as they change (the anchors' log asks it at every line it stages).
  let heldBytes = 0;
  let nearSaid = false;
  let changedSinceSnapshot = false;
  let lastSnapshotAt: number | undefined;
  // The newest delta read or written, by its name's time, and the names read since a look back past it.
  let deltasFrom: number | undefined;
  const namesRead = new Set<string>();
  let reading: Promise<void> | undefined;
  let flushing: Promise<void> | undefined;
  let readFailingSince: number | undefined;
  let writeFailingSince: number | undefined;
  const folder = (kind: Kind): string => `e${String(epoch)}/digests/${kind}/`;

  const alarm = (reason: string, more: Record<string, unknown>): void => {
    logger.error('audit.integrity_failed', { chain: 'store', check: 'digest_store', reason, ...more });
  };

  /** What its days' tables take (AT13d/g). */
  const datedBytes = (state: ChainState): number => {
    let bytes = 0;
    for (const { table } of state.dated.values()) bytes += table.bytes;
    return bytes;
  };

  /** How many dated facts its days' tables hold, an object once a day it was known by. */
  const datedSize = (state: ChainState): number => {
    let size = 0;
    for (const { table } of state.dated.values()) size += table.size;
    return size;
  };

  const tablesBytes = (state: ChainState): number => state.tables[0].bytes + state.tables[1].bytes + datedBytes(state);

  /** The horizon the chain's dated facts go by: the platform's session ends' (AT13g), an organisation's requests' (AT13d). */
  const horizonOf = (name: string): number | undefined =>
    name === 'platform' ? forgetSessionEndsAfterMs : forgetRequestsAfterMs;

  /** Whether facts of a subject type are dated on the chain: forgotten past its horizon. */
  const datedType = (name: string, type: string): boolean =>
    horizonOf(name) !== undefined && (name === 'platform' ? SESSION_ENDS.has(type) : type === REQUEST_SUBJECT);

  /** Whether a subject key's facts are dated on the chain. */
  const dated = (name: string, key: string): boolean => datedType(name, key.slice(0, key.indexOf('\n')));

  /** A fresh chain, counted. */
  const newChain = (bornAt: number, counted: boolean): ChainState => {
    const made: ChainState = {
      bornAt,
      tables: [new ChainDigest(bornAt), new ChainDigest(bornAt)],
      dated: new Map(),
      covered: undefined,
      stretches: new Map(),
      gaveWay: 0,
      gen: 0,
      letGo: 0,
    };
    if (counted) heldBytes += tablesBytes(made) + CHAIN_BYTES;
    return made;
  };

  /** A chain set aside, uncounted. */
  const dropped = (name: string): void => {
    const held = chains.get(name);
    if (held === undefined) return;
    heldBytes -= tablesBytes(held) + CHAIN_BYTES;
    chains.delete(name);
  };

  /** Whether this process may write: it leads, or nothing says otherwise. Never forgets anything (TR-1 A). */
  const writing = (): boolean => writes === undefined || writes();

  /** The chain held, set aside whole where it was rebased after its oldest fact. */
  const chainOf = (name: string): ChainState | undefined => {
    const held = chains.get(name);
    if (held !== undefined && anchors?.rebasedAfter(chainOfName(name), new Date(held.bornAt)) === true) {
      dropped(name);
      return undefined;
    }
    return held;
  };

  /** The chain held, made where there is none, dated by the oldest walk that put a fact in it. */
  const heldChain = (name: string, at: number): ChainState => {
    let held = chainOf(name);
    if (held === undefined) {
      held = newChain(at, true);
      chains.set(name, held);
    }
    held.bornAt = Math.min(held.bornAt, at);
    return held;
  };

  /** A fact into a chain's table of its class, counted. Whether it moved. */
  const putInto = (held: ChainState, payment: boolean, high: number, low: number, place: number): boolean => {
    if (held.gaveWay === 2 || (payment && held.gaveWay === 1)) return false;
    const table = held.tables[payment ? 1 : 0];
    const before = table.bytes;
    const moved = table.put(high, low, place);
    heldBytes += table.bytes - before;
    return moved;
  };

  /** The chain's dated facts' table for the day `knownBy` falls in, made where there is none (counted if held), later. */
  const dayOf = (held: ChainState, knownBy: number, counted: boolean): DatedDay => {
    const day = Math.floor(knownBy / DAY_MS);
    let found = held.dated.get(day);
    if (found === undefined) {
      found = { table: new ChainDigest(held.bornAt), knownBy };
      held.dated.set(day, found);
      if (counted) heldBytes += found.table.bytes;
    }
    found.knownBy = Math.max(found.knownBy, knownBy);
    return found;
  };

  /** A dated fact into the chain's table for the day it was known by, counted: a payment's, given way with them. */
  const putDated = (held: ChainState, knownBy: number, high: number, low: number, place: number): boolean => {
    if (held.gaveWay !== 0) return false;
    const { table } = dayOf(held, knownBy, true);
    const before = table.bytes;
    const moved = table.put(high, low, place);
    heldBytes += table.bytes - before;
    return moved;
  };

  let forgottenAt: number | undefined;

  /** The chain's days whose facts were known by `before` or earlier, let go: how many facts went. */
  const daysLetGo = (held: ChainState, before: number): number => {
    let objects = 0;
    for (const [day, { table, knownBy }] of held.dated) {
      if (knownBy > before) continue;
      objects += table.size;
      heldBytes -= table.bytes;
      held.dated.delete(day);
      changedSinceSnapshot = true;
    }
    return objects;
  };

  /**
   * Each chain's days whose facts were known by a time FORGET_MARGIN_MS past the chain's horizon, let go: no version of
   * a request they name can be handed off or approved any more (AT13d), nor of a session they end used (AT13g). Looked
   * over at most every FORGET_EVERY_MS, or `atOnce` (a read: what it took in may be past it already).
   */
  const forgetPast = (atOnce: boolean): void => {
    if (forgetRequestsAfterMs === undefined && forgetSessionEndsAfterMs === undefined) return;
    const at = now().getTime();
    if (!atOnce && forgottenAt !== undefined && at - forgottenAt < FORGET_EVERY_MS) return;
    forgottenAt = at;
    const forgot = { requests: 0, sessionEnds: 0 };
    for (const [name, held] of chains) {
      const horizon = horizonOf(name);
      if (horizon === undefined) continue;
      forgot[name === 'platform' ? 'sessionEnds' : 'requests'] += daysLetGo(held, at - horizon - FORGET_MARGIN_MS);
    }
    if (forgot.requests > 0) {
      logger.info('audit.state_digest_requests_forgotten', { objects: forgot.requests, bytes: heldBytes });
    }
    if (forgot.sessionEnds > 0) {
      logger.info('audit.state_digest_session_ends_forgotten', { objects: forgot.sessionEnds, bytes: heldBytes });
    }
  };

  /** The chain's own logger: an organisation's names it. */
  const logFor = (name: string): Logger =>
    name.startsWith('organisation:') ? logger.child({ orgId: name.slice('organisation:'.length) }) : logger;

  /** The organisation's line, for a chain that gave way. */
  const sayGaveWay = (name: string, held: ChainState): void => {
    const at = now().getTime();
    if (held.saidWhat === held.gaveWay && held.saidAt !== undefined && at - held.saidAt < SAY_EVERY_MS) return;
    held.saidAt = at;
    held.saidWhat = held.gaveWay === 2 ? 2 : 1;
    logFor(name).error('audit.state_digest_chain_gave_way', {
      // The platform chain's growing objects are its session ends, never payments.
      what: held.gaveWay === 2 ? 'chain' : name === 'platform' ? 'session_ends' : 'payments',
      bytes: heldBytes,
      mostBytes,
    });
  };

  /**
   * Past what may be held, chains give way (`toGiveWay`) until under GIVE_WAY_TO of it: so one organisation's growth
   * costs it alone. Said at half, once. Under half, chains given way come back as they fit (`comeBack`).
   */
  const judgeMemory = (): void => {
    forgetPast(false);
    if (heldBytes > mostBytes * NEAR_MEMORY && !nearSaid) {
      nearSaid = true;
      logger.warn('audit.state_digest_near_memory', { bytes: heldBytes, mostBytes });
    }
    while (heldBytes > mostBytes) {
      const chosen = toGiveWay();
      if (chosen === undefined) return;
      giveWay(...chosen);
      if (heldBytes <= mostBytes * GIVE_WAY_TO) return;
    }
    comeBack();
  };

  /**
   * The chain to give way next, of those not wholly given way: one past its fair share first, one with growing objects
   * still held before one without, the largest of those; only with none past its share, the largest.
   */
  const toGiveWay = (): [string, ChainState] | undefined => {
    const share = (mostBytes - chains.size * CHAIN_BYTES) / Math.max(chains.size, 1);
    let chosen: [string, ChainState] | undefined;
    let chosenRank = -1;
    for (const entry of chains) {
      const held = entry[1];
      if (held.gaveWay === 2) continue;
      const bytes = tablesBytes(held);
      const rank = bytes <= share ? 0 : held.gaveWay === 0 && paymentsHeld(held) ? 2 : 1;
      if (rank > chosenRank || (rank === chosenRank && chosen !== undefined && bytes > tablesBytes(chosen[1]))) {
        chosen = entry;
        chosenRank = rank;
      }
    }
    return chosen;
  };

  /** The chain gives way: its growing objects' table, or with none or those gone already, all of it. Said. */
  const giveWay = (name: string, held: ChainState): void => {
    const before = tablesBytes(held);
    dropTo(held, held.gaveWay === 0 && paymentsHeld(held) ? 1 : 2);
    held.letGo += before - tablesBytes(held);
    held.gaveWayAt = now().getTime();
    // Written with what moved, so a restart holds the chain as given way at once, never as a chain to walk again.
    markPending(name, held);
    sayGaveWay(name, held);
  };

  /** Whether the chain holds a growing object's fact: in its payments' table, or a day's (AT13d/g). */
  const paymentsHeld = (held: ChainState): boolean => held.tables[1].size > 0 || held.dated.size > 0;

  /** The chain held as given way this far: its growing objects' tables let go (its days with them), or all. */
  const dropTo = (held: ChainState, level: 1 | 2): void => {
    for (const index of level === 1 ? ([1] as const) : ([0, 1] as const)) {
      heldBytes -= held.tables[index].bytes;
      held.tables[index] = new ChainDigest(held.bornAt, 1);
      heldBytes += held.tables[index].bytes;
    }
    heldBytes -= datedBytes(held);
    held.dated.clear();
    held.gaveWay = level;
  };

  /**
   * Under half of what may be held, each chain given way an hour or more ago comes back where what it let go fits in
   * the room left under half, the smallest first (AT13e): the hysteresis between giving way past the whole and coming
   * back under half, with what it let go counted, so a chain comes back only where it would fit again.
   */
  const comeBack = (): void => {
    let room = mostBytes * NEAR_MEMORY - heldBytes;
    if (room <= 0) return;
    const at = now().getTime();
    const ready = [...chains].filter(
      ([, held]) => held.gaveWay !== 0 && held.gaveWayAt !== undefined && at - held.gaveWayAt >= BACK_AFTER_MS,
    );
    for (const [name, held] of ready.toSorted(([, one], [, other]) => one.letGo - other.letGo)) {
      if (held.letGo > room) return;
      room -= held.letGo;
      beginComingBack(name, held);
    }
  };

  /**
   * The chain begins to come back: a new odd generation, so no stretch from before stands for it; its coverage from
   * nothing, for the catch-up walk to read it from its first event; facts kept from here. It reads as given way until
   * that walk reaches the anchor (`covers`). Written, so a restart agrees.
   */
  const beginComingBack = (name: string, held: ChainState): void => {
    const was = held.gaveWay;
    held.gen += held.gen % 2 === 1 ? 2 : 1;
    held.gaveWay = 0;
    held.letGo = 0;
    held.covered = undefined;
    held.stretches.clear();
    delete held.gaveWayAt;
    delete held.saidWhat;
    changedSinceSnapshot = true;
    markPending(name, held);
    logFor(name).info('audit.state_digest_chain_coming_back', {
      was: was === 2 ? 'chain' : name === 'platform' ? 'session_ends' : 'payments',
      bytes: heldBytes,
      mostBytes,
    });
  };

  /** A chain coming back whose walk has reached `seq`, back: its generation even again, written. Facts all held. */
  const settle = (name: string, held: ChainState, seq: bigint): void => {
    if (held.gen % 2 === 0 || held.gaveWay !== 0 || held.covered === undefined || held.covered.seq < seq) return;
    held.gen += 1;
    changedSinceSnapshot = true;
    markPending(name, held);
    logFor(name).info('audit.state_digest_chain_back', { seq });
  };

  /** The chain's mark into what waits to be written: the newest is the highest, so it stands. */
  const markPending = (name: string, held: ChainState): void => {
    if (store === undefined) return;
    const waiting = pendingChain(name, now().getTime());
    waiting.gen = held.gen;
    waiting.gaveWay = held.gaveWay;
    waiting.letGo = held.letGo;
    waiting.marked = true;
  };

  /**
   * A mark read (AT13e): a higher generation, or a further give-way within the same, stands; anything lower is passed
   * over, as files are read in any order. A generation that begins a chain's coming back anew sets its coverage aside,
   * since no stretch from before it stands for the chain. Given way where it was written: so here at once, said again.
   */
  const raise = (name: string, held: ChainState, gen: number, level: 0 | 1 | 2, letGo: number): void => {
    if (gen < held.gen || (gen === held.gen && level <= held.gaveWay)) return;
    if (baseOf(gen) > baseOf(held.gen)) {
      held.covered = undefined;
      held.stretches.clear();
    }
    if (gen > held.gen) {
      held.gen = gen;
      held.gaveWay = 0;
      held.letGo = 0;
      delete held.gaveWayAt;
    }
    changedSinceSnapshot = true;
    if (level === 0) return;
    dropTo(held, level);
    held.letGo = letGo;
    held.gaveWayAt = now().getTime();
    sayGaveWay(name, held);
  };

  /** A line read: passed over if dated before its chain's rebase, else merged. */
  const take = (line: DigestLine): void => {
    if (anchors?.rebasedAfter(chainOfName(line.chain), line.at) === true) return;
    const at = line.at.getTime();
    const held = heldChain(line.chain, at);
    const gen = line.gen ?? 0;
    raise(line.chain, held, gen, line.gaveWay ?? 0, line.letGo ?? 0);
    // Dated facts by the day they were known by, where the chain's are forgotten past a horizon; else payments' facts.
    const knownBy = horizonOf(line.chain) === undefined ? undefined : line.knownBy;
    for (const [high, low, place] of line.entries) {
      const moved =
        knownBy === undefined
          ? putInto(held, line.payments, high, low, place)
          : putDated(held, knownBy, high, low, place);
      if (moved) changedSinceSnapshot = true;
    }
    // A stretch from before the chain last began coming back stands for nothing.
    if (line.stretch !== undefined && gen >= baseOf(held.gen) && extend(held, line.stretch)) {
      changedSinceSnapshot = true;
    }
  };

  /** Whether a file is sound: closed for its own name, and every line before it one of ours (signed-files.ts). */
  const isSound = (bytes: Buffer, name: string): Promise<boolean> =>
    isSoundFile(keys, DIGEST_FILE, bytes, name, epoch, (fields) => lineFrom(fields) !== undefined);

  /** A file taken in if it is sound: whether it was. One listed and then gone is a failure of the store's. */
  const takeFile = async (from: WriteOnceStore, name: string): Promise<boolean> => {
    const got = await from.getAtMost(name, mostFileBytes);
    if (got === 'missing') throw new Error('a digest file listed and then not there');
    if (typeof got === 'string' || !(await isSound(got, name))) return false;
    // Every line but the closing one, each known to read by the pass above.
    for await (const fields of bodyLines(got)) {
      const line = lineFrom(fields);
      if (line !== undefined) take(line);
    }
    return true;
  };

  /** Every well-named file of a kind, newest first. A name dated past the clock is the alarm, and passed over. */
  const namesOf = (from: WriteOnceStore, kind: Kind) =>
    namesIn(
      from,
      folder(kind),
      () => now().getTime() + MOST_AHEAD_MS,
      (at) => {
        alarm('future', { kind, fileAt: new Date(at).toISOString() });
      },
    );

  /**
   * The newest sound snapshot taken in, and its time: none for a store with none, or with only spoiled ones as far back
   * as a start goes. Then every delta is read instead, which loses nothing: each fact was in a delta first.
   */
  const readSnapshot = async (from: WriteOnceStore): Promise<number | undefined> => {
    let spoiled = 0;
    for await (const { name, at } of namesOf(from, 'snapshots')) {
      if (await takeFile(from, name)) return at;
      spoiled += 1;
      alarm('file', { kind: 'snapshots', fileAt: new Date(at).toISOString() });
      if (spoiled >= MOST_SPOILED_SNAPSHOTS) return undefined;
    }
    return undefined;
  };

  /** Every delta named at or after `since` (all of them, with none), not read yet, taken in. */
  const readDeltas = async (from: WriteOnceStore, since: number | undefined): Promise<void> => {
    for await (const { name, at } of namesOf(from, 'deltas')) {
      if (since !== undefined && at < since) break;
      if (namesRead.has(name)) continue;
      if (!(await takeFile(from, name))) alarm('file', { kind: 'deltas', fileAt: new Date(at).toISOString() });
      namesRead.add(name);
      deltasFrom = Math.max(deltasFrom ?? at, at);
    }
  };

  // Read whether or not this process leads: a copy following reads what the leader writes, as a web copy does (TR-1 A).
  const readOnce = async (): Promise<void> => {
    if (store === undefined) return;
    try {
      if (state === 'read') {
        await readDeltas(store, deltasFrom === undefined ? undefined : deltasFrom - LAG_MS);
      } else {
        const snapshot = await readSnapshot(store);
        if (snapshot !== undefined) lastSnapshotAt = snapshot;
        await readDeltas(store, snapshot === undefined ? undefined : snapshot - LAG_MS);
        state = 'read';
      }
      // Names older than any later look back reaches need no remembering.
      const keepFrom = (deltasFrom ?? 0) - 2 * LAG_MS;
      for (const name of namesRead) {
        if (timeOfName(name.slice(folder('deltas').length, folder('deltas').length + 13)) < keepFrom) {
          namesRead.delete(name);
        }
      }
      readFailingSince = undefined;
      // What it took in may be past the horizon already: let go before memory is judged, so nothing gives way for it.
      forgetPast(true);
      judgeMemory();
    } catch (error) {
      failed('read', error);
    }
  };

  /** A read or write that failed: a warning, and past `alertAfterMs` of failing, the alert. */
  const failed = (what: 'read' | 'write', error: unknown): void => {
    const at = now().getTime();
    if (what === 'read') readFailingSince ??= at;
    else writeFailingSince ??= at;
    const since = (what === 'read' ? readFailingSince : writeFailingSince) ?? at;
    if (at - since >= alertAfterMs) logger.error('audit.state_digest_store_failing', { what, err: error });
    else logger.warn('audit.state_digest_store_failed', { what, err: error });
  };

  /** A file of the lines, closed and signed, named for `at`: made a line at a time, its closing line last. */
  const fileOf = async (kind: Kind, lines: Iterable<string>, at: number): Promise<{ name: string; bytes: Buffer }> => {
    const name = fileName(folder(kind), at);
    return { name, bytes: await signedFile(keys, DIGEST_FILE, name, epoch, lines) };
  };

  /** What moved, as a delta's lines: each chain's facts, then the stretches its walks read. */
  function* deltaLines(
    facts: ReadonlyMap<string, ChainState>,
    stretches: ReadonlyMap<string, readonly Walked[]>,
  ): Generator<string> {
    for (const name of new Set([...facts.keys(), ...stretches.keys()])) {
      const held = facts.get(name);
      const entries = [
        held === undefined ? [] : [...held.tables[0].entries()],
        held === undefined ? [] : [...held.tables[1].entries()],
      ] as const;
      // Every chain with a stretch has its pending entry too (record makes one), dated by its walk.
      const mark = held?.marked === true ? held : undefined;
      const days = held?.dated.values() ?? [];
      yield* linesOf(name, held?.bornAt ?? now().getTime(), entries, stretches.get(name) ?? [], mark, days);
    }
  }

  /**
   * The whole, as a snapshot's lines, each chain with its mark: its growing objects given way keep their coverage (a
   * fact missing only loses protection, never raises the alarm); one given way whole needs none, as it reads as before
   * the digest. A coverage is written in the chain's generation, as it stands for the chain in it.
   */
  function* snapshotLines(): Generator<string> {
    for (const [name, held] of chains) {
      const coverage =
        held.gaveWay < 2 && held.covered !== undefined
          ? [{ stretch: { from: 0n, to: held.covered }, gen: held.gen }]
          : ([] as Walked[]);
      const tables = [[...held.tables[0].entries()], [...held.tables[1].entries()]] as const;
      // Its days as held: none past the horizon, so a start from it holds what memory does (AT13d/g).
      yield* linesOf(name, held.bornAt, tables, coverage, held, held.dated.values());
    }
  }

  const flushOnce = async (): Promise<void> => {
    // Only the leader writes; what moved waits, kept, until this process leads again (TR-1 A).
    if (store === undefined || !writing()) return;
    const at = now().getTime();
    if ((pending.size > 0 || pendingStretches.size > 0) && !(await deltaWritten(store, at))) return;
    // A snapshot only after a whole read: one made from less would stand for the whole at the next start.
    const due = lastSnapshotAt === undefined || at - lastSnapshotAt >= SNAPSHOT_EVERY_MS;
    if (state === 'read' && changedSinceSnapshot && due) await snapshotWritten(store, at);
  };

  /** A chain's facts and mark from a delta not written, back into what waits: the higher mark of the two, as a read takes it. */
  const keptAgain = (kept: ChainState, held: ChainState): void => {
    if (held.marked === true && (held.gen > kept.gen || (held.gen === kept.gen && held.gaveWay > kept.gaveWay))) {
      kept.gen = held.gen;
      kept.gaveWay = held.gaveWay;
      kept.letGo = held.letGo;
      kept.marked = true;
    }
    for (const index of [0, 1] as const) {
      for (const [high, low, place] of held.tables[index].entries()) kept.tables[index].put(high, low, place);
    }
    for (const { table, knownBy } of held.dated.values()) {
      const day = dayOf(kept, knownBy, false);
      for (const [high, low, place] of table.entries()) day.table.put(high, low, place);
    }
  };

  /** What moved, written as a delta: whether it was. One that failed is kept for the next, its facts as true then. */
  const deltaWritten = async (into: WriteOnceStore, at: number): Promise<boolean> => {
    const [facts, stretches] = [pending, pendingStretches];
    pending = new Map();
    pendingStretches = new Map();
    try {
      const file = await fileOf('deltas', deltaLines(facts, stretches), at);
      await into.put(file.name, file.bytes);
      namesRead.add(file.name);
      deltasFrom = Math.max(deltasFrom ?? at, at);
      writeFailingSince = undefined;
      return true;
    } catch (error) {
      for (const [name, held] of facts) keptAgain(pendingChain(name, held.bornAt), held);
      for (const [name, walked] of stretches) {
        pendingStretches.set(name, [...walked, ...(pendingStretches.get(name) ?? [])]);
      }
      failed('write', error);
      return false;
    }
  };

  /** The whole, written as a snapshot, never past what a start fetches. */
  const snapshotWritten = async (into: WriteOnceStore, at: number): Promise<void> => {
    try {
      const file = await fileOf('snapshots', snapshotLines(), at);
      lastSnapshotAt = at;
      // Never past what a start fetches: the deltas hold every fact, so a start reads them instead, slower.
      if (file.bytes.length > mostFileBytes) {
        logger.error('audit.state_digest_snapshot_too_large', { bytes: file.bytes.length, mostBytes: mostFileBytes });
        return;
      }
      await into.put(file.name, file.bytes);
      changedSinceSnapshot = false;
    } catch (error) {
      failed('write', error);
    }
  };

  /**
   * A walk's facts into the chain, and those that moved into what waits to be written. Dated ones are known by now:
   * every event the walk read was recorded before it recorded them (AT13d/g).
   */
  const recordFacts = (name: string, held: ChainState, seen: SignedSeen, at: number): void => {
    const knownBy = now().getTime();
    for (const [key, seq] of seen) {
      const [high, low] = fingerprintOf(key);
      const place = placeOf(seq);
      const byDay = dated(name, key);
      const moved = byDay ? putDated(held, knownBy, high, low, place) : putInto(held, grows(key), high, low, place);
      if (!moved) continue;
      changedSinceSnapshot = true;
      if (store !== undefined) pendingTable(pendingChain(name, at), key, byDay, knownBy).put(high, low, place);
    }
  };

  /** The table a fact waits to be written in: a day's, for a dated one (AT13d/g), else its class's. */
  const pendingTable = (waiting: ChainState, key: string, byDay: boolean, knownBy: number): ChainDigest =>
    byDay ? dayOf(waiting, knownBy, false).table : waiting.tables[grows(key) ? 1 : 0];

  /**
   * A walk's stretch into the chain's coverage, and into what waits to be written, in the chain's generation: never for
   * a chain given way whole, which holds less than the stretch would claim.
   */
  const recordStretch = (name: string, held: ChainState, stretch: Stretch, at: number): void => {
    if (extend(held, stretch)) changedSinceSnapshot = true;
    if (store === undefined || held.gaveWay === 2) return;
    pendingChain(name, at);
    pendingStretches.set(name, [...(pendingStretches.get(name) ?? []), { stretch, gen: held.gen }]);
  };

  /** The chain's facts waiting to be written, made where there are none. */
  const pendingChain = (name: string, at: number): ChainState => {
    let held = pending.get(name);
    if (held === undefined) {
      held = newChain(at, false);
      pending.set(name, held);
    }
    held.bornAt = Math.min(held.bornAt, at);
    return held;
  };

  /** The chain's head seen here, set aside where a rebase came after the read that saw it (AT13f). */
  const headOf = (name: string, chain: Chain): HeadSeen | undefined => {
    const held = heads.get(name);
    if (held === undefined || anchors?.rebasedAfter(chain, new Date(held.at)) !== true) return held;
    heads.delete(name);
    heldBytes -= HEAD_BYTES;
    return undefined;
  };

  /**
   * A head a read found, kept where it is higher than the one seen: never from a read asked before a rebase the anchors'
   * log knows, which may have found the chain as it was. Past what they may take, the one raised longest ago goes.
   */
  const raiseHead = (name: string, chain: Chain, { seq, hash }: HeadSeen, asked: number): void => {
    if (seq < 1n) return;
    const held = headOf(name, chain);
    if ((held !== undefined && held.seq >= seq) || anchors?.rebasedAfter(chain, new Date(asked)) === true) return;
    if (held === undefined) heldBytes += HEAD_BYTES;
    heads.delete(name);
    heads.set(name, { seq, hash: Buffer.from(hash), at: asked });
    for (const oldest of heads.keys()) {
      if (heads.size <= mostHeads) break;
      heads.delete(oldest);
      heldBytes -= HEAD_BYTES;
    }
  };

  /** Where the digest covers the chain to, from its first event: a head a walk read (an anchor's, or past it), read back at a start. */
  const coveredHead = (name: string): HeadSeen | undefined => {
    const held = chainOf(name);
    // Given way whole, or coming back: it reads as before the digest until its walk is back (`covers`).
    if (held === undefined || held.gaveWay === 2 || held.gen % 2 === 1) return undefined;
    const covered = held.covered;
    return covered === undefined || covered.seq < 1n ? undefined : { seq: covered.seq, hash: covered.hash };
  };

  /** The head a read of the chain is held to: the higher of its own seen here and where the digest covers it. */
  const seenOf = (name: string, chain: Chain): HeadSeen | undefined => {
    const own = headOf(name, chain);
    const covered = coveredHead(name);
    return own === undefined || (covered !== undefined && covered.seq > own.seq) ? covered : own;
  };

  /** The chain taken as it stands (AT13h), while `seen` is still the head it was taken over and no rebase came after. */
  const acceptedOf = (name: string, chain: Chain, seen: HeadSeen | undefined): HeadKept | undefined => {
    const held = accepted.get(name);
    if (held === undefined) return undefined;
    if (sameOrNone(held.over, seen) && anchors?.rebasedAfter(chain, new Date(held.at)) !== true) return held;
    accepted.delete(name);
    heldBytes -= HEAD_BYTES;
    return undefined;
  };

  /** A head a read found, or a write moved to, raising where the chain was taken as it stands, as raiseHead does the seen. */
  const raiseAccepted = (name: string, chain: Chain, { seq, hash }: HeadSeen, asked: number): void => {
    const held = accepted.get(name);
    // Never from a watch asked before the read that found the cut: it may have read the chain before the cut.
    if (held === undefined || held.seq >= seq || asked < held.at) return;
    if (anchors?.rebasedAfter(chain, new Date(asked)) === true) return;
    accepted.set(name, { ...held, seq, hash: Buffer.from(hash) });
  };

  /**
   * The chain taken as it stands at `to` over the head seen `over` (AT13h): only while that is still the head seen, and
   * only where the watch held the chain to something (a head seen, or witnessed heads alone: TR-1).
   */
  const acceptAt = (
    name: string,
    chain: Chain,
    { over, heldTo }: { readonly over: HeadSeen | undefined; readonly heldTo: readonly HeadSeen[] },
    to: HeadSeen,
    asked: number,
  ): void => {
    if (heldTo.length === 0 || to.seq < 1n || anchors?.rebasedAfter(chain, new Date(asked)) === true) return;
    if (!sameOrNone(seenOf(name, chain), over)) return;
    if (!accepted.has(name)) heldBytes += HEAD_BYTES;
    accepted.set(name, {
      over: over === undefined ? undefined : { seq: over.seq, hash: Buffer.from(over.hash) },
      seq: to.seq,
      hash: Buffer.from(to.hash),
      at: asked,
    });
  };

  /** The chain's witnessed heads, the highest first, at most MOST_WITNESSED: only those noted after `after` where given. */
  const witnessedOf = (chain: Chain, after?: number): HeadSeen[] => {
    const found: HeadSeen[] = [];
    for (const { seq, hash, at } of witnessed?.(chain) ?? []) {
      if (found.length >= MOST_WITNESSED) break;
      if (after === undefined || at > after) found.push({ seq, hash });
    }
    return found;
  };

  /** The heads a read is held to, each once, in the order given. */
  const distinct = (heads: readonly (HeadSeen | undefined)[]): readonly HeadSeen[] => {
    const kept: HeadSeen[] = [];
    for (const head of heads) {
      if (head !== undefined && !kept.some((one) => sameHead(one, head))) {
        kept.push(Object.freeze({ seq: head.seq, hash: head.hash }));
      }
    }
    return Object.freeze(kept);
  };

  return Object.freeze({
    heads(chain: Chain): HeadWatch | undefined {
      if (anchors?.holds(chain) === false) return undefined;
      const name = chainName(chain);
      const asked = now().getTime();
      const seen = seenOf(name, chain);
      const taken = acceptedOf(name, chain, seen);
      const heldTo = distinct([headOf(name, chain), coveredHead(name), ...witnessedOf(chain)]);
      return Object.freeze({
        seen: seen === undefined ? undefined : Object.freeze({ seq: seen.seq, hash: seen.hash }),
        heldTo,
        saw: (head: HeadSeen) => {
          raiseHead(name, chain, head, asked);
          raiseAccepted(name, chain, head, asked);
        },
        accepted:
          taken === undefined
            ? undefined
            : Object.freeze({
                seen: Object.freeze({ seq: taken.seq, hash: taken.hash }),
                heldTo: distinct([taken, ...witnessedOf(chain, taken.at + ACCEPT_MARGIN_MS)]),
                saw: (head: HeadSeen) => {
                  raiseAccepted(name, chain, head, asked);
                },
              }),
        accept: (to: HeadSeen) => {
          acceptAt(name, chain, { over: seen, heldTo }, to, asked);
        },
      });
    },
    latest(chain: Chain, type: string, id: string): bigint | undefined {
      if (anchors?.holds(chain) === false) return undefined;
      const held = chainOf(chainName(chain));
      if (held === undefined) return undefined;
      const [high, low] = fingerprintOf(subjectKey(type, id));
      let place = held.tables[GROWING_SUBJECTS.has(type) ? 1 : 0].get(high, low) ?? 0;
      // A dated fact's newest by the days it was known by too (AT13d/g): the highest, a day let go only lowering it.
      if (datedType(chainName(chain), type)) {
        for (const { table } of held.dated.values()) place = Math.max(place, table.get(high, low) ?? 0);
      }
      return place === 0 ? undefined : BigInt(place);
    },
    covers(chain: Chain, seq: bigint): boolean {
      if (state !== 'read' || anchors?.holds(chain) === false) return false;
      if (seq === 0n) return true;
      const name = chainName(chain);
      const held = chainOf(name);
      if (held === undefined) return false;
      settle(name, held, seq);
      // Given way whole, or coming back until its walk reaches the anchor: today's checks, never a wait (AT13e).
      if (held.gaveWay === 2 || held.gen % 2 === 1) return true;
      return held.covered !== undefined && held.covered.seq >= seq;
    },
    coverage(chain: Chain): CheckedPoint | undefined {
      return chainOf(chainName(chain))?.covered;
    },
    owed(chain: Chain, seq: bigint): boolean {
      if (state !== 'read' || seq === 0n) return false;
      const name = chainName(chain);
      const held = chainOf(name);
      if (held === undefined) return true;
      settle(name, held, seq);
      return held.gaveWay !== 2 && (held.covered === undefined || held.covered.seq < seq);
    },
    record(chain: Chain, seen: SignedSeen, began: Date, stretch?: Stretch): void {
      // A walk recorded only by the leader, whose walks alone are written (TR-1 A).
      if (!writing()) return;
      const name = chainName(chain);
      const at = began.getTime();
      // Dated before the chain's newest rebase: it read the chain as it was, which nothing goes on from.
      if (anchors?.rebasedAfter(chain, began) === true) return;
      const held = heldChain(name, at);
      recordFacts(name, held, seen, at);
      if (stretch !== undefined) recordStretch(name, held, stretch, at);
      judgeMemory();
    },
    read(): Promise<void> {
      reading ??= readOnce().finally(() => {
        reading = undefined;
      });
      return reading;
    },
    flush(): Promise<void> {
      flushing ??= flushOnce().finally(() => {
        flushing = undefined;
      });
      return flushing;
    },
    state: () => state,
    bytesHeld: () => heldBytes,
    memoryHeld() {
      let objects = 0;
      for (const held of chains.values()) objects += held.tables[0].size + held.tables[1].size + datedSize(held);
      return { bytes: heldBytes, mostBytes, chains: chains.size, objects };
    },
  });
}
