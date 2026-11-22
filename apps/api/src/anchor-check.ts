// The anchor check (ADR-012 §2, SEC-DB-11): every few minutes the API checks
// each audit chain against its last anchor, kept in this process's memory and,
// deployed, in the write-once store (anchor-log.ts, PL-58), and anchors it
// again. A chain wound back to an earlier state, or grown again on a wound-back
// head, passes its own seals; only the anchor, held apart from the database,
// shows it.
//
// No organisation's chain is read whole (4D2e E8). Each run first probes every
// anchored chain (the trail's probeHeads, a page of organisations a trip, each
// under its own wall): its head against its anchor, and its last 1,000 events
// counted (decision 1). A chain found unmoved takes its turn with no read of its
// own, one found failing is the alarm and its hold; one that moved, has no
// anchor yet, or wasn't answered for is read from its anchor in its turn, up to
// 100,000 events a turn, the anchor moving on with each. The old events below an
// anchor are the rotation's (below). The platform's chain is read from its anchor
// each run and whole once a day (anchor-rotation.ts's platformChainCheck).
//
// The probe reads up to four pages at once (`probePages`), never more than the lanes'
// places free (it waits for one, as a turn does: checks from the last run may hold
// them), and holds those it takes until it ends, so it takes no hand-off's
// connection and turns wait for it. It is cut short by the run's time like any step,
// keeping what it reached. The trade: an organisation the probe didn't reach takes no
// turn that run, so a chain wound back there is seen at its next probe, which comes
// first next run (those left over go first, so the tail never starves);
// `audit.probe_unfinished` says how many were reached, and one unprobed past the
// stale limit is the `unchecked` alarm, no hold.
//
// A run first reads the store, then checks, writing what moved each minute and
// at its end. A store that
// can't be read after a restart means no chain is anchored for the first time,
// every organisation's payments wait (`anchor_pending`), the seals are still
// checked and decisions go on; one that can't be written is a warning and in time
// the store's own alert, never a hold. As the API stops, or the lease goes, what
// moved is written within a few seconds; after a crash, what's kept is at most a
// minute behind, and one store write.
//
// A run is bounded (4D2e E6), and any number of organisations may slow the check but
// not break it or raise a false alarm. Chains are checked side by side, a few lanes of
// them (AGENTX_AUDIT_ANCHOR_LANES), so one slow or locked organisation holds its own
// lane and nobody else's; whose turn it is is anchor-turns.ts's. Checks in flight, those
// past their deadline among them, never pass the lanes, so the hand-offs' connections
// stay theirs; every trip of theirs has a limit on its answer, so a dead connection ends.
// A check past its deadline isn't thrown away: when it ends it is compared and anchored
// all the same, and if it fails then, that counts as any failure does. While it runs it is
// capacity, not the alarm, up to a ceiling of the same 63 minutes at the default: every trip of
// it has a limit, but the whole has none, so someone answering each page slowly could
// otherwise keep one chain from ever being compared. Past it, `unchecked`, no hold. A run stops at four minutes, ends with its
// line whatever is under way, and the next goes on from where it stopped. So the
// check's line comes at most every 10 minutes at the default interval: 5 between runs,
// 4 of run, 1 for the last write. With lines up to 9 minutes late, the 30 minutes the
// outside's dead-man rule allows hold (D3), and the setting refuses an interval that
// wouldn't.
//
// Wherever the lanes get through them all in a run (a run's lane-time is 16 minutes at
// the default), each chain's turn comes every run. Past that, a round spreads over
// runs. Past seven runs' time (63 minutes at the default) an organisation is late: with
// turns completing that is capacity, `audit.anchor_check_behind`, SEV-2, by count; with
// no run's turn completed for that whole time it is the alarm (`unreached`), and one
// bad run says nothing. A chain whose own check keeps failing is the alarm too. A chain
// whose anchor landed during its check goes among
// the first next run: its alarm comes within one interval and one run, 9 minutes.
//
// Any number of organisations may be listed. AGENTX_AUDIT_MOST_ORGANISATIONS only limits
// the chains this check notes that have no anchor yet in the store: every chain in the store
// is noted whatever it says, its notes small beside its anchor. Those past it take their turns
// from a cursor through the list, and `audit.anchor_check_over_size`, SEV-2, says so; their anchors are
// still held, as Tx A and their own comparison need them, the store being a log with no way
// to read one chain's. So the true limit is memory: more anchors than the heap holds take
// more hardware, and a store file past it says so (`audit.anchor_store_beyond_memory`).
//
// Past that, the log lets shards go (PL-65 PR3), and a round walks the store a shard at a time (PR4, anchor-walk.ts): its
// organisations by shard, the shards by the oldest anchor in each, so each shard let go is read back once a round and the
// log's least-recently-used rule lets one go only once the walk is past it. The run's probe asks only of chains whose shard
// is held; each shard let go is probed as the walk reaches it, pinned meanwhile. Before reading one back a turn has what
// waits written (`roomToReadBack`): signing idle chains again leaves a line waiting in every shard behind it, and none of
// those may go until written. The walk's place is the turns' within a process; after a restart its order begins again
// with the shards waiting longest, by the anchors' signed times in the store. No cursor is written anywhere, so nothing
// short of the `audit-anchor` key moves it, and it only orders work: every verdict is the comparison's, as ever.
//
// What that means for tamper: a chain wound back is seen at its turn, and with the probe
// a turn is a few microseconds for a chain that hasn't moved, so a round is a run until
// the moved chains alone outlast it. Tx A compares a payment with the last anchor alone
// (handoff.ts `chainStops`), so events past that anchor can be taken away unseen until
// the chain's next turn.
//
// Each walk under a new anchor also records, for each signed object it read, where its
// newest signed event is (the signed states' digest, AT13, digest-log.ts), kept with the
// anchors and read back with them; the full pass's steps add what they read, so a chain
// anchored before the digest comes into it. Every decision's read of a signed state is
// held to it (audit-trail.ts): an object's newest signed events deleted or moved below
// the anchor, past the last 1,000, with its row rolled back, are refused at once, not
// only at the day's count or the full pass, which stay as defence in depth.
// The platform chain's walks record too (AT13c: the hand-off pause, the sessions' signed
// ends), each from where it began: from the anchor, or the first event when walked whole,
// a whole walk recorded even where the anchor stays; a platform chain the digest doesn't
// cover is walked whole (anchor-rotation.ts's platformChainCheck), its catch-up.
//
// After the organisations' turns, the rotation (anchor-rotation.ts, 4D2e E7): each
// organisation's daily count and walk, and the full pass's share, within what is left
// of the run, one read at a time, inside the lanes' share of the connections. It is
// what finds an event below the anchor deleted past the last 1,000, or edited.
//
// A chain that fails raises the integrity alarm (`audit.integrity_failed`; its
// SEV-1 alert rule is A2c-2) and keeps its last good anchor, so the alarm
// repeats every run until someone looks. Someone with the database's keys can
// also try to stop the check from finishing: so a database that refuses the
// check (a right, a table or a
// column gone) is the alarm too, whenever it comes, and so is a check that keeps failing
// for three intervals, or one still running past the ceiling above. Anything else that
// stops a check (the database unreachable, or a check past its deadline but going on)
// is a warning until then. Every run ends with one
// line, so a check that has stopped can be told from one with nothing to say.
// The platform chain is checked every run; each organisation's chain too, probed,
// found from the directory's list at each run (B1d-2). The list is held to
// what the platform chain records: every organisation created there
// (`organization.created`, sealed, so one deleted breaks the platform chain's
// own check) must be listed, and so must every one this process has seen
// listed, and every one with a chain in the store. One missing is the alarm
// (`unlisted`): the app never deletes an entry, so one gone is tampering, and
// its chain would otherwise never be checked again. A list the database refuses, or one
// that isn't IDs, is the alarm (`list`); a list that
// can't be read otherwise is a warning until three intervals pass without one.
// An organisation whose chain fails is put on its integrity hold (B1d-3),
// naming the alarm's reason, and each run tries again a hold this process
// could not record yet: an unlisted organisation's too, since its chain is
// still reached by its ID. A chain left unchecked too long is the alarm but
// no hold: that is as often the database slow or away as anything done to
// it, and a hold on every organisation at once, each cleared only by its
// own admin, would do an attacker's work for them. People look at the alarm.
//
// Held to the witness log (TR-1, witness-log.ts): every head any copy wrote and this copy hasn't confirmed, asked
// before each walk. A walk anchors only on a read of the store that began after the walk did (one is waited for
// before signing where the last is older): an anchor made on a stale view could stand over a stop not yet read. The
// probe reads each head's hash in its statement, and a chain whose head is below one, or that holds another event at
// one's place, is the chain cut back: the alarm (`check: witness`, `cut_back`) and the hold. A moved chain's walk from
// its anchor re-hashes every event to the head, and a walk that didn't pass through each head below where it reached
// refuses (the trail's checkFromAnchor), so an anchor never stands over a cut. It anchors only where every head held at
// or below where it reached was asked of its walk (one read in during the walk waits for the next), and then lets go
// just those. A head held at or below the chain's anchor (one landing after the anchor, or read back at a start) is
// confirmed before the chain is anchored again: against the hash its anchoring walk read there, where this process made
// that anchor (the walk keeps each event's hash from the last RECENT_MS before it began, until the next); else by a walk
// from the lowest such head to the anchor, a pass step at a time, every event re-hashed, every other head's place checked
// on the way: within a budget of events a run (CONFIRM_EVENTS_A_RUN), going on from where it reached at the next. The
// budget is shared fairly, whatever the run's order: each chain walking may take an even share of it, and at least
// CONFIRM_FLOOR_EVENTS however much the others took; a hand-off's first anchor walks within its own allowance
// (CONFIRM_EVENTS_A_HAND_OFF), apart from the run's.
// On the chain, it is let go; a fork is the alarm and the hold; one that can't be walked is kept, said
// (`audit.witness_head_unconfirmed`), and the chain anchored no more until it is: never let go unseen.
// Between runs (TR-3), the leader's probe after each read of the log (the chains that gained a head, and those holding
// most) releases every head above the anchor it found on the chain but the highest, compact, the next walk from the
// anchor held to them until it passes them (never let go on the probe alone, as it reads no link): so a burst never
// fills what the log may hold. A chain that let heads go for memory anyway anchors again once a walk held to every head
// still held and to the fingerprints of those let go (each its place and its hash's first 16 bytes, checked as a
// head's) runs from below the lowest let go to at or past the highest (the log's walkedPast), with no rebase.
import { MOST_WALKED_WITHIN } from '@agentx/core/modules/audit';
import type { Clock } from '@agentx/core/shared-kernel';
import {
  type Anchor,
  type AnchorLog,
  type AnchorPoint,
  type AnchorStore,
  type Chain,
  type ChainProbe,
  CHAIN_START,
  type ChainReport,
  type ChainStep,
  ChainStoreError,
  type CheckedPoint,
  createMemoryAnchorStore,
  createMemoryPassRecord,
  type DigestLog,
  hashHolds,
  sameAnchor,
  type SignedSeen,
  signAnchor,
  type WitnessLog,
} from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { createRotation, type RotatedChecks, type RotationCheck } from './anchor-rotation.ts';
import { createTurns, shuffledAfresh, startAnywhere } from './anchor-turns.ts';
import { shardOfOrganisation, shardWalk } from './anchor-walk.ts';
import { PastDeadline, scheduleRuns, Stopped, withinDeadline } from './background.ts';

/**
 * How far the platform chain may grow between two anchors before it is said (TR-13): half of what a hand-off's walk
 * reads past its anchor. Any signed-in person adds platform events (a step-up, a sign-out, a download of their own log),
 * and past the whole of it every organisation's hand-off is held `too_far` until the next anchor: safe, but a cheap
 * way to stop every payment, so it is said well before.
 */
export const PLATFORM_GROWTH_SAID = MOST_WALKED_WITHIN / 2;

/**
 * The platform chain's growth from its last anchor to the one just made, said where past PLATFORM_GROWTH_SAID: an error
 * (`audit.platform_chain_fast`), which the apps' error alerts carry in plain words.
 */
function sayPlatformGrowth(log: Logger, last: Anchor, seq: bigint, now: Date): void {
  const grew = seq - last.seq;
  if (grew <= BigInt(PLATFORM_GROWTH_SAID)) return;
  const minutes = Math.max(1, Math.round((now.getTime() - last.at.getTime()) / 60_000));
  log.error('audit.platform_chain_fast', {
    grew: Number(grew),
    minutes,
    fromSeq: last.seq,
    toSeq: seq,
    said: PLATFORM_GROWTH_SAID,
    most: MOST_WALKED_WITHIN,
  });
}

/**
 * A check's report, and for a walk that holds, the signed objects it read (the trail's WalkedStep, AT13), when it began,
 * and where it read from where that is not the chain's last anchor (a whole walk's first event, AT13c).
 */
export type WalkedReport = ChainReport & {
  readonly signed?: SignedSeen;
  readonly began?: Date;
  readonly walkedFrom?: bigint;
  /** The witnessed heads its walk was asked (TR-1): the ones it confirmed, where it holds. */
  readonly heldTo?: readonly Witnessed[];
  /** The hash of each event it read recorded in the RECENT_MS before it began (TR-1): late heads are held to them. */
  readonly recent?: ReadonlyMap<bigint, Buffer>;
};

/** The places a confirming walk keeps the hashes of as it reads them (TR-1), and where. */
export interface WatchedPlaces {
  readonly heads: readonly Witnessed[];
  readonly found: Map<bigint, Buffer>;
}

/** What a walk keeps of the events it read from a time on (TR-1): each one's hash, by its place. */
export interface RecentPlaces {
  readonly since: Date;
  readonly found: Map<bigint, Buffer>;
}

/**
 * How far before a walk began the events whose hashes it keeps were recorded: past how late an honest head lands (its
 * flush, a few retries, the listing) and the clocks, so most late heads are confirmed with no read at all.
 */
const RECENT_MS = 90_000;

/**
 * How many events a run walks, across every chain, to confirm heads held below their anchors (TR-1): a pass step at a
 * time, each walk going on from where it reached at the next run, so a deep one confirms over several and none holds the
 * run, or the hand-offs' first anchors, for long.
 */
const CONFIRM_EVENTS_A_RUN = 200_000;

/** What each chain may walk in a run however much of the budget the chains before it took (TR-1): none starves. */
const CONFIRM_FLOOR_EVENTS = 5_000;

/** What a hand-off's first anchor may walk to confirm its chain's heads (TR-1), apart from the run's budget. */
const CONFIRM_EVENTS_A_HAND_OFF = 10_000;

/** What a confirming walk may still take (TR-1): the run's shared budget, or a hand-off's own allowance. */
interface ConfirmAllowance {
  may(key: string): boolean;
  took(key: string, events: number): void;
}

/**
 * A run's budget (TR-1): each chain may take an even share of it among those with a walk under way as the run began,
 * while any is left, and its floor whatever the rest took, so a deep chain early in the order starves none after it.
 */
function runAllowance(walking: number): ConfirmAllowance {
  let left = CONFIRM_EVENTS_A_RUN;
  const share = Math.max(CONFIRM_FLOOR_EVENTS, Math.floor(CONFIRM_EVENTS_A_RUN / Math.max(1, walking)));
  const taken = new Map<string, number>();
  return {
    may: (key) => {
      const own = taken.get(key) ?? 0;
      return own < CONFIRM_FLOOR_EVENTS || (own < share && left > 0);
    },
    took: (key, events) => {
      taken.set(key, (taken.get(key) ?? 0) + events);
      left -= events;
    },
  };
}

/** A hand-off's own allowance (TR-1): its first anchor never waits on what the run spent. */
function handOffAllowance(): ConfirmAllowance {
  let left = CONFIRM_EVENTS_A_HAND_OFF;
  return {
    may: () => left > 0,
    took: (_key, events) => {
      left -= events;
    },
  };
}

/** A witnessed head as a walk is held to it. */
interface Witnessed {
  readonly seq: bigint;
  readonly hash: Buffer;
}

/** A chain the check covers, and how to check it against its last anchor, if it has one. */
export interface CheckedChain {
  readonly chain: Chain;
  /**
   * Held to the heads witnessed (TR-1) where given: a walk that missed one refuses (`cut_back`); the hashes of the events
   * it reads from `recent.since` on kept in `recent.found`.
   */
  readonly verify: (
    anchor: CheckedPoint | undefined,
    heldTo?: readonly Witnessed[],
    recent?: RecentPlaces,
  ) => Promise<WalkedReport>;
  /**
   * One step of a walk from `cursor` towards `target`, at most a pass step's events (the trail's passStep, TR-1), the
   * hashes at `watch.heads`' places kept as it reads them: how heads held at or below the chain's anchor are confirmed
   * on it. None, and such a head is never confirmed.
   */
  readonly confirm?: (cursor: CheckedPoint, target: CheckedPoint, watch?: WatchedPlaces) => Promise<ChainStep>;
  /**
   * The chain's head read against the heads copies witnessed, in one statement (TR-3: the platform chain's probe between
   * runs): the one it was cut back below, or none. None given, it waits for the run.
   */
  readonly probe?: (heldTo: readonly Witnessed[]) => Promise<Witnessed | undefined>;
}

/** What the probe found of one organisation's chain against its anchor, or that its read failed (the trail's probeHeads). */
export type ProbeAnswer = ChainProbe | { readonly kind: 'missed'; readonly error: unknown };

export interface AnchorCheck {
  /**
   * Checks the platform's chain, then as many organisations' as its time allows,
   * going on from where the last run stopped, and ends at once when `signal` aborts
   * or its time is up. Never throws: every outcome is logged.
   */
  run(signal?: AbortSignal): Promise<void>;
  /**
   * One organisation's chain checked and anchored now, as a run would (its
   * alarm and hold too): for the hand-off, which compares every payment with
   * the chain's anchor and so can't wait for the next run after a restart
   * (gate H11, partner S146). With the store unreadable it makes no anchor, so
   * the payment waits. Never throws.
   */
  anchorOrganisation(orgId: string, signal?: AbortSignal): Promise<void>;
  /** Writes what has moved as the API stops, within a few seconds whatever the store does. Never throws. */
  finish(): Promise<void>;
  /**
   * The organisations' chains probed now against the heads copies witnessed (TR-1): one cut back below one is the
   * alarm and the hold, as in a run; anything else waits for the run. Passed over while the run's probe is under way,
   * which asks the same. Never throws.
   */
  probeWitnessed(orgIds: readonly string[], signal?: AbortSignal): Promise<void>;
}

/** Where the organisations' chains come from (B1d-2). */
export interface OrganisationChains {
  /** Every organisation the directory lists, by ID. */
  list(): Promise<readonly string[]>;
  /** Every organisation the platform chain records as created, by ID: each must be listed. */
  recorded(): Promise<readonly string[]>;
  /** Checks one organisation's chain from its last anchor, or from its start where it has none, held to `heldTo`. */
  verify(
    orgId: string,
    anchor: CheckedPoint | undefined,
    heldTo?: readonly Witnessed[],
    recent?: RecentPlaces,
  ): Promise<WalkedReport>;
  /**
   * Each chain's head read against its anchor at a run's start (4D2e E8), in pages, stopping between them once `signal`
   * aborts. None given, every organisation is read in its turn.
   */
  probe?(
    chains: readonly {
      readonly orgId: string;
      readonly from: CheckedPoint;
      readonly heldTo?: readonly { readonly seq: bigint; readonly hash: Buffer }[];
    }[],
    signal: AbortSignal,
    pagesAtOnce: number,
  ): Promise<ReadonlyMap<string, ProbeAnswer>>;
  /**
   * Puts the organisation on its integrity hold for how its chain failed (the
   * alarm's reason), or, given none, tries again a hold waiting in this
   * process for it, if one is. Never throws: every outcome is logged (B1d-3).
   */
  hold(orgId: string, failure: string | undefined): Promise<void>;
  /** One step of a walk from `cursor` towards `target` (the trail's passStep, TR-1): CheckedChain's `confirm`. */
  confirm?(orgId: string, cursor: CheckedPoint, target: CheckedPoint, watch?: WatchedPlaces): Promise<ChainStep>;
}

export interface AnchorCheckOptions {
  /** The chains checked every run: the platform's. */
  readonly chains: readonly CheckedChain[];
  /** The organisations' chains, listed afresh each run. None when not given. */
  readonly organizations?: OrganisationChains;
  readonly keys: KeyProvider;
  readonly clock: Clock;
  readonly logger: Logger;
  /** How long a chain may go without a completed check before that is the alarm too, where a run reaches them all. */
  readonly staleAfterMs: number;
  /** How long an organisation may wait for its turn before it is late (see the header). As `staleAfterMs` unless given. */
  readonly reachWithinMs?: number;
  /** How many chains with no anchor in the store it keeps notes on: those past it go by a cursor (the header), never unchecked. */
  readonly mostOrganisations?: number;
  /** A round's order where there is no store to go by: a fresh shuffle unless given. */
  readonly shuffled?: (orgIds: readonly string[]) => readonly string[];
  /** Where a process starts among those past the cap: a random place unless given. */
  readonly pastCapStart?: (count: number) => number;
  /**
   * How long one chain's check may take. Postgres's own limits can be got round
   * by someone who owns the database, and a connection can die without a word,
   * so the app keeps its own: a check past it has not completed.
   */
  readonly deadlineMs: number;
  readonly anchors?: AnchorStore;
  /** The same anchors, where they are kept durable: read and written around each run. None in development with no store. */
  readonly durable?: AnchorLog;
  /**
   * The signed states' digest (AT13): each chain's walk under a new anchor records the signed objects it read into it,
   * read and written with the anchors. None, and nothing is recorded.
   */
  readonly digest?: DigestLog;
  /** How long the last write may take as the API stops: the store's calls may take 30 seconds, and the stop has 25 in all. */
  readonly stopFlushMs?: number;
  /** How many organisations are checked at once. */
  readonly lanes?: number;
  /** How long a run may go on. */
  readonly runWithinMs?: number;
  /** How often a run writes what has moved so far. */
  readonly writeEveryMs?: number;
  /** The organisations' chains' reads for the rotation (4D2e E7): none, and a run has no rotation. */
  readonly rotation?: RotatedChecks;
  /** Whether this environment sleeps when unused (staging), so a full pass's lateness counts from a process's start. */
  readonly sleeps?: boolean;
  /** How many of the probe's pages are read at once, each on a connection of its own: never more than the lanes. */
  readonly probePages?: number;
  /** The witness log (TR-1): the heads each probe and walk is held to, let go once confirmed. None, held to none. */
  readonly witness?:
    | (Pick<WitnessLog, 'pending' | 'heldTo' | 'prune' | 'refresh' | 'freshAt' | 'beyondMemory'> &
        Partial<Pick<WitnessLog, 'walkedPast' | 'fingerprints' | 'release' | 'baseBelow'>>)
    | undefined;
}

/** See `stopFlushMs`. */
const STOP_FLUSH_MS = 5_000;

/** See `lanes`. Each holds a connection for a check, and none across a call to the store. */
const LANES = 4;

/** See `probePages`: 10,000 organisations in 3.6 s at four, 9.4 s at one (measured locally, 4D2e E8); 100,000 about 36 s. */
const PROBE_PAGES = 4;

/**
 * See `runWithinMs`. Not the interval's double: lines are up to 9 minutes late, so 10 minutes of run and 5 between would
 * read as stopped under the dead-man rule's 20 (the header).
 */
export const RUN_WITHIN_MS = 240_000;

/** See `writeEveryMs`: a crash loses at most this much, and a store gone is known this soon. */
const WRITE_EVERY_MS = 60_000;

/** How long a run's write may take: two of the store's calls at 30 seconds, a file unsent and a new one. */
const WRITE_WITHIN_MS = 60_000;

/** How long the digest's own read or write may take (AT13): an hourly snapshot of a few tens of MB, or a start's read. */
const DIGEST_WITHIN_MS = 60_000;

/** How many runs' time an organisation may wait for its turn. */
const RUNS_FOR_A_TURN = 7;

/** How long an organisation may wait for its turn, at this interval between runs: the answer for `reachWithinMs`. */
export const reachWithin = (intervalMs: number): number => RUNS_FOR_A_TURN * (intervalMs + RUN_WITHIN_MS);

/** How many IDs a line about many organisations names. The count is the whole of it; these are where to start looking. */
const NAMED_ON_A_LINE = 5;

/** How many organisations gone from the list a run names on a line each, with their holds' reason; the rest are a count. */
const UNLISTED_NAMED = 20;

/** How many times running a chain's check must fail, with rounds spreading, before it is that chain's own: one could be anyone's bad moment. */
const MISSES_TO_SAY = 2;

/**
 * Postgres's refusals that only a changed database gives the app's role: a
 * right taken away, a table or a column gone. The check can't be run until
 * someone puts them back, which is itself the alarm.
 */
const CHANGED_DATABASE = new Set(['42501', '42P01', '42703']);

/**
 * AGENTX_AUDIT_MOST_ORGANISATIONS's default, what memory allows: each one this process has seen holds about 885 bytes
 * for its life (measured, S168), so 100,000 is about 88 MB of the API's 1 GiB. A count past it is no alarm.
 */
export const MOST_ORGANIZATIONS = 100_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The IDs in lower case, or nothing if any isn't a UUID given as text. */
function organisationIds(ids: unknown): string[] | undefined {
  if (!Array.isArray(ids)) return undefined;
  const checked: string[] = [];
  for (const id of ids as unknown[]) {
    if (typeof id !== 'string' || !UUID.test(id)) return undefined;
    checked.push(id.toLowerCase());
  }
  return checked;
}

const refusedByDatabase = (error: unknown): boolean =>
  typeof error === 'object' && error !== null && 'code' in error && CHANGED_DATABASE.has(String(error.code));

/** Whether a chain's head is at or past its anchor, and at it, the same event. */
const stillHolds = (head: CheckedPoint, anchor: AnchorPoint): boolean =>
  head.seq > anchor.seq || (head.seq === anchor.seq && head.hash.equals(anchor.hash));

/** A chain's last check is still going: progress, not a failure. */
class UnderWay extends Error {}

/** `unanchored`: checked and sound, and not anchored: the store is yet to be read, or landed during the check. */
type Outcome = 'anchored' | 'unchanged' | 'unanchored' | 'failed' | 'unchecked';

/** The in-flight key of the organisations' list, which no chain's key can be. */
const LIST = 'list';

/** The in-flight key of the rotation's read: one at a time. */
const ROTATION = 'rotation';

/** The in-flight key of the probe: one at a time. */
const PROBE = 'probe';

/** The in-flight key of the probe after a refresh of the witness log (TR-1): one at a time. */
const WITNESS_PROBE = 'witness_probe';
const PLATFORM_WITNESS_PROBE = 'witness_probe|platform';

/** A chain the run's probe answered for, and the anchor it was compared with. */
interface Probed {
  readonly anchor: CheckedPoint;
  readonly answer: Exclude<ChainProbe, { readonly kind: 'moved' }>;
}

const samePoint = (one: CheckedPoint, other: CheckedPoint): boolean =>
  one.seq === other.seq && one.hash.equals(other.hash) && one.macKeyVersion === other.macKeyVersion;

/** The probe's answer as a check's report on the chain at the anchor it compared with. */
const reportOf = ({ anchor, answer }: Probed): ChainReport =>
  answer.kind === 'same'
    ? { ok: true, seq: anchor.seq, hash: anchor.hash, macKeyVersion: anchor.macKeyVersion }
    : { ok: false, problem: answer.problem };

export function createAnchorCheck({
  chains,
  organizations,
  keys,
  clock,
  logger,
  staleAfterMs,
  reachWithinMs = staleAfterMs,
  mostOrganisations = MOST_ORGANIZATIONS,
  shuffled = shuffledAfresh,
  pastCapStart = startAnywhere,
  deadlineMs,
  durable,
  digest,
  anchors = durable ?? createMemoryAnchorStore(),
  stopFlushMs = STOP_FLUSH_MS,
  lanes = LANES,
  runWithinMs = RUN_WITHIN_MS,
  writeEveryMs = WRITE_EVERY_MS,
  rotation: rotatedChecks,
  sleeps = false,
  probePages = PROBE_PAGES,
  witness,
}: AnchorCheckOptions): AnchorCheck {
  // From when this process began, so a check that never once completes is caught too.
  const started = clock.now().getTime();
  const lastChecked = new Map<string, number>();
  // Each organisation's alarm reason this run, until its hold is tried.
  const failures = new Map<string, string>();
  const keyOf = (chain: Chain): string => (chain.kind === 'platform' ? 'platform' : chain.orgId);
  // Checks, holds and the list's read under way, past their deadline or not: one each at most, each with a connection.
  const inFlight = new Set<string>();
  // When each chain's check under way began: past the ceiling it is no longer capacity.
  const checkBegan = new Map<string, number>();
  // Lanes waiting for room among those.
  const waitingForRoom = new Set<() => void>();
  /** One of those has ended. */
  const ended = (key: string): void => {
    inFlight.delete(key);
    checkBegan.delete(key);
    turns.ended(key);
    for (const wake of waitingForRoom) wake();
    waitingForRoom.clear();
  };
  /**
   * Work that holds a connection, one at a time under `key`, within the deadline: past it, it stays in flight until it
   * ends, so a hung database can't take a connection every run.
   */
  const tracked = <T>(
    key: string,
    busy: string,
    start: () => Promise<T>,
    signal: AbortSignal | undefined,
    connections = 1,
  ) => {
    if (inFlight.has(key)) throw new Error(busy);
    // Work on several connections at once holds as many of the lanes' places, each until the whole of it ends.
    const held = [key, ...Array.from({ length: connections - 1 }, (_, place) => `${key}#${String(place + 1)}`)];
    for (const each of held) inFlight.add(each);
    const work = Promise.resolve().then(start);
    const end = (): void => {
      for (const each of held.slice(1)) inFlight.delete(each);
      ended(key);
    };
    void work.then(end, end);
    return withinDeadline(work, deadlineMs, signal);
  };
  // Every organisation this process has seen listed or recorded, so one that leaves the list is noticed, and when it was
  // first seen, so its stale period starts then, not when the process began. Every one in the store comes here, past any
  // cap, counted in the anchor log's memory budget (anchor-log.ts, PL-65): one map, its keys what a set of them would be.
  const firstSeen = new Map<string, number>();
  // When the list was last read whole, so a list never read is the alarm in time too.
  let listRead: number | undefined;
  /** The time a chain's stale period counts from. */
  const since = (key: string): number => lastChecked.get(key) ?? firstSeen.get(key) ?? started;
  // Whether the last run left organisations waiting, so a chain's last check may rightly be longer ago than a run's.
  let spreading = false;
  let leftLastRun = false;
  // The organisations in use: the last list read, or with none yet, those seen.
  let inUse: readonly string[] | undefined;
  // Those past the cap, no notes kept on any, and when their round began.
  let pastCap: readonly string[] = [];
  let pastCapNow: ReadonlySet<string> = new Set();
  let pastCapSince = started;
  // When a run's turn last completed, hand-offs' apart: wedged lanes are the alarm, one bad run is not.
  let lastTurn = started;
  // Checks completed this run, and how many times running each chain's has not.
  let completed = 0;
  const misses = new Map<string, number>();
  // Organisations whose check couldn't run this run, and those of them gone too long: a line a run, not a line each, as
  // a database down is every chain at once. The first failure stands for the rest.
  let missedThisRun: string[] = [];
  let staleThisRun: string[] = [];
  // Organisations gone from the list this run: the first named, line by line, and the rest counted.
  let unlistedThisRun = 0;
  let firstMiss: unknown;
  /** Whether a chain has gone unchecked too long. With rounds spreading its turn may rightly be long ago, so a miss alone says nothing. */
  const isStale = (key: string): boolean =>
    clock.now().getTime() - since(key) >= staleAfterMs &&
    ((!spreading && !pastCapNow.has(key)) || key === 'platform' || (misses.get(key) ?? 0) >= MISSES_TO_SAY);
  /**
   * When the chain's anchor was last signed, as the store says, held or let go (PL-65 PR4): what is last known of it, never
   * read back for it. Nothing for one never anchored, or with no store.
   */
  const anchoredAt = (orgId: string): number | undefined =>
    durable?.lastKnown({ kind: 'organisation', orgId })?.anchoredAt;
  /** When a chain is last known to have been checked: after a restart, as its anchor says. */
  const lastKnown = (orgId: string): number => lastChecked.get(orgId) ?? anchoredAt(orgId) ?? since(orgId);
  /**
   * By the store where there is one, a shard at a time (anchor-walk.ts, PL-65 PR4): the shards by the oldest anchor in
   * each, never anchored oldest of all, and in each the oldest first. So a round reads each shard the log has let go back
   * once, and after a restart begins with the shards waiting longest. Its reads are this process's memory.
   */
  const walkOrder = (orgIds: readonly string[]): readonly string[] =>
    shardWalk(
      orgIds,
      (orgId) => orgId,
      (orgId) => anchoredAt(orgId) ?? 0,
    );
  const turns = createTurns(lanes, durable === undefined ? shuffled : walkOrder, pastCapStart);

  /**
   * Whether a chain's first anchor must wait: it could hide a chain wound back until the store has been read, and, for a
   * chain, its shard is held whole (PL-65 PR3: one let go says nothing of the chain, so nothing is compared with it).
   */
  const storeUnread = (chain?: Chain): boolean =>
    durable !== undefined && (durable.state() !== 'read' || (chain !== undefined && !durable.holds(chain)));

  /** A chain's integrity alarm on its own line, its reason kept for its hold. */
  const alarmed = (chain: Chain, log: Logger, reason: string, seq?: bigint): Outcome => {
    if (chain.kind === 'organisation') failures.set(keyOf(chain), reason);
    const held = anchors.latest(chain);
    log.error('audit.integrity_failed', {
      chain: chain.kind,
      // A chain that no longer runs through a head a copy witnessed (TR-1) is the witness log's finding, not the anchor's.
      check: reason === 'cut_back' ? 'witness' : 'anchor',
      reason,
      ...(seq === undefined ? {} : { seq }),
      ...(held === undefined ? {} : { anchorSeq: held.seq }),
    });
    return 'failed';
  };

  /** A walk that held, into the digest: its facts, and the stretch it read, from where it began (AT13, AT13c). */
  const recordWalk = (
    chain: Chain,
    report: Extract<WalkedReport, { readonly ok: true }>,
    last: Anchor | undefined,
    at: Date,
  ): void => {
    digest?.record(chain, report.signed ?? new Map(), report.began ?? at, {
      from: report.walkedFrom ?? last?.seq ?? 0n,
      to: { seq: report.seq, hash: report.hash, macKeyVersion: report.macKeyVersion },
    });
  };

  /** Whether the witness log's last whole read began at or after `since`. */
  const readSince = (since: Date | undefined): boolean =>
    witness === undefined ||
    (since !== undefined && (witness.freshAt()?.getTime() ?? Number.NEGATIVE_INFINITY) >= since.getTime());

  /**
   * A walk that held, on a read of the witness log begun after it did (TR-1): where the last is older, one is waited
   * for (coalesced: one that begins after this call), so the heads landed meanwhile are known before it anchors.
   */
  const readAfterWalk = async (report: WalkedReport, last: Anchor | undefined): Promise<void> => {
    // Only for one that would anchor anew: an unmoved chain's report signs nothing.
    if (witness === undefined || !report.ok || report.seq === last?.seq || readSince(report.began)) return;
    await witness.refresh();
  };

  // Each chain's anchor this process made, with the hashes its walk kept of its last events (TR-1), until the next.
  const anchoredHere = new Map<string, { readonly seq: bigint; readonly recent: ReadonlyMap<bigint, Buffer> }>();

  // The chains holding a head at or below their anchor that isn't confirmed yet: anchored no more until it is.
  const unconfirmed = new Set<string>();
  // Each chain's confirming walk under way: where it has reached towards the anchor, and the heads it has checked so far.
  const confirming = new Map<string, { readonly cursor: CheckedPoint; readonly checked: readonly Witnessed[] }>();
  // What this run may still walk to confirm heads: set again at each run's start, shared among the chains walking.
  let confirmBudget = runAllowance(1);

  const sameHead = (one: Witnessed, other: Witnessed): boolean => one.seq === other.seq && one.hash.equals(other.hash);

  /**
   * Where a chain's confirming walk starts: where it reached at the last run, where every head below that was checked on
   * it; else afresh from the lowest head (one that came in since below where it reached starts it again). A compact one
   * lowest (a head released, or a fingerprint: TR-3) gives no whole hash to link from: from the highest anchor at or
   * below it that the log kept as one its compact heads went above (baseBelow), else from the chain's start. A wrong
   * start can't pass: the walk links every event from it and must end on the anchor's own hash.
   */
  const walkStart = (chain: Chain, heads: readonly Witnessed[], lowest: Witnessed) => {
    const saved = confirming.get(keyOf(chain));
    const resumes =
      saved !== undefined &&
      heads.every((head) => head.seq > saved.cursor.seq || saved.checked.some((one) => sameHead(one, head)));
    if (resumes) return { cursor: saved.cursor, checked: [...saved.checked] };
    const base = lowest.hash.length === CHAIN_START.hash.length ? lowest : witness?.baseBelow?.(chain, lowest.seq);
    return {
      cursor: base === undefined ? CHAIN_START : { seq: base.seq, hash: base.hash, macKeyVersion: 0 },
      checked: [] as Witnessed[],
    };
  };

  /** Each head a step passed over checked against the hash it read at the head's place: whether all hold, those kept. */
  const passedHold = (
    heads: readonly Witnessed[],
    from: bigint,
    step: Extract<ChainStep, { readonly ok: true }>,
    found: ReadonlyMap<bigint, Buffer>,
    checked: Witnessed[],
  ): boolean => {
    for (const head of heads.filter(({ seq }) => seq > from && seq <= step.seq)) {
      if (!hashHolds(head.seq === step.seq ? step.hash : found.get(head.seq), head.hash)) return false;
      checked.push(head);
    }
    return true;
  };

  /**
   * The heads held at or below the chain's anchor, confirmed by one walk from the lowest of them to the anchor, a pass
   * step at a time, every event re-hashed, each other head's hash checked on the way (TR-1, the header). Goes on from
   * where it reached at the last run (walkStart). `cut` where the walk breaks or a head's place holds another event;
   * `waiting` where this run's budget, its end or the database stopped it (kept, to go on).
   */
  const walkTheirPlaces = async (
    { chain, confirm }: CheckedChain,
    heads: readonly Witnessed[],
    anchor: CheckedPoint,
    signal: AbortSignal | undefined,
    allowance: ConfirmAllowance,
  ): Promise<'holds' | 'cut' | 'waiting'> => {
    const key = keyOf(chain);
    const [lowest] = heads;
    if (lowest === undefined) return 'holds';
    if (confirm === undefined) return 'waiting';
    const started = walkStart(chain, heads, lowest);
    let { cursor } = started;
    const { checked } = started;
    // Those at the walk's own starting place: its hash, or a fork.
    const start = cursor;
    const atStart = heads.filter((one) => one.seq === start.seq && !checked.some((done) => sameHead(done, one)));
    if (atStart.some((head) => !hashHolds(start.hash, head.hash))) return 'cut';
    checked.push(...atStart);
    while (cursor.seq < anchor.seq) {
      const from = cursor;
      const watch: WatchedPlaces = { heads: heads.filter(({ seq }) => seq > from.seq), found: new Map() };
      const step =
        !allowance.may(key) || signal?.aborted === true
          ? undefined
          : await withinDeadline(confirm(from, anchor, watch), deadlineMs, signal);
      if (step !== undefined && !step.ok) return 'cut';
      if (step === undefined || step.seq <= from.seq) {
        confirming.set(key, { cursor, checked });
        return 'waiting';
      }
      allowance.took(key, Number(step.seq - from.seq));
      if (!passedHold(heads, from.seq, step, watch.found, checked)) return 'cut';
      cursor = step;
    }
    confirming.delete(key);
    return cursor.hash.equals(anchor.hash) ? 'holds' : 'cut';
  };

  /**
   * Each head held at or below the chain's anchor, judged (TR-1, the header): against the hash its anchoring walk read
   * there, where this process made the anchor and kept it; the rest by one walk from the lowest of them (above). All on
   * the chain, let go; a fork, the alarm and the hold (`failed`); a walk not done (its budget, the run's end, the database,
   * no way to walk) keeps them, said, and the chain anchored no more until it is (`unconfirmed`). Never let go unseen.
   * The compact heads at or below the anchor (TR-3: released, or fingerprints, that no anchoring walk passed, as after a
   * restart or a new leader) are judged the same way, by their hashes' first bytes, and let go on the chain.
   */
  const lateHeadsHold = async (
    checked: CheckedChain,
    log: Logger,
    signal: AbortSignal | undefined,
    alone: boolean,
  ): Promise<'held' | 'failed' | 'unconfirmed'> => {
    const { chain } = checked;
    const key = keyOf(chain);
    unconfirmed.delete(key);
    const anchor = anchors.latest(chain);
    if (witness === undefined || anchor === undefined) return 'held';
    const compact = (witness.fingerprints?.(chain) ?? []).filter(({ seq }) => seq <= anchor.seq);
    const late = [...witness.pending(chain).filter(({ seq }) => seq <= anchor.seq), ...compact];
    if (late.length === 0) {
      confirming.delete(key);
      return 'held';
    }
    const here = anchoredHere.get(key);
    const recent = here?.seq === anchor.seq ? here.recent : new Map<bigint, Buffer>();
    const known = late.filter(({ seq }) => recent.has(seq));
    const fork = known.find((head) => !hashHolds(recent.get(head.seq), head.hash));
    if (fork !== undefined) {
      alarmed(chain, log, 'cut_back', fork.seq);
      return 'failed';
    }
    const others = late.filter(({ seq }) => !recent.has(seq)).toSorted((one, other) => (one.seq < other.seq ? -1 : 1));
    let verdict: 'holds' | 'cut' | 'waiting';
    try {
      const allowance = alone ? handOffAllowance() : confirmBudget;
      verdict = await walkTheirPlaces(checked, others, anchor, signal, allowance);
    } catch (error) {
      log.warn('audit.anchor_check_failed', { chain: chain.kind, check: 'witness', err: error });
      verdict = 'waiting';
    }
    if (verdict === 'cut') {
      confirming.delete(key);
      alarmed(chain, log, 'cut_back', others[0]?.seq);
      return 'failed';
    }
    // Compact ones confirmed, told as passed by a walk from the chain's start (the log's walkedPast), so they go too.
    const confirmed = (heads: readonly Witnessed[]): void => {
      witness.prune(chain, heads);
      const compactOnes = heads.filter((head) => compact.includes(head));
      if (compactOnes.length > 0) witness.walkedPast?.(chain, 0n, anchor.seq, compactOnes);
    };
    if (verdict === 'holds') {
      confirmed(late);
      return 'held';
    }
    confirmed(known);
    unconfirmed.add(key);
    log.error('audit.witness_head_unconfirmed', {
      chain: chain.kind,
      heads: others.length,
      anchorSeq: anchor.seq.toString(),
      walkedTo: confirming.get(key)?.cursor.seq.toString() ?? null,
    });
    return 'unconfirmed';
  };

  /**
   * The witnessed heads a walk confirmed, for an anchor where it reached (TR-1): those it was asked above where it
   * began, at or below where it reached; none to confirm without a witness log. Undefined, and no anchor, where this
   * run's read of the log was stale, the chain let a head go for memory (said), or a head held at or below where it
   * reached was never asked of the walk (read in during it, compact heads too: the next run's walk is asked it).
   */
  const witnessConfirmed = (
    chain: Chain,
    log: Logger,
    report: Extract<WalkedReport, { readonly ok: true }>,
    last: Anchor | undefined,
  ): readonly Witnessed[] | undefined => {
    if (witness === undefined) return [];
    if (!readSince(report.began) || unconfirmed.has(keyOf(chain))) return undefined;
    const asked = report.heldTo ?? [];
    const from = report.walkedFrom ?? last?.seq ?? 0n;
    // By place and hash's first bytes (TR-9): a head released since it was asked is the same head, compact; one read in
    // during the walk and released by a probe alongside it is in the held set still, never asked, so no anchor.
    const askedOf = (head: Witnessed) => asked.some(({ seq, hash }) => seq === head.seq && hashHolds(hash, head.hash));
    if (witness.heldTo(chain).some((head) => head.seq <= report.seq && !askedOf(head))) return undefined;
    // The compact heads it was held to (TR-3), told: released ones it passed, linked from the anchor, let go; heads let go
    // for memory set aside once it passed every fingerprint, from below the lowest to at or past the highest; else the
    // chain waits for a walk that does (or a rebase), said. A place holding another event was this walk's `cut_back`.
    const beyond = witness.walkedPast?.(chain, from, report.seq, asked) ?? witness.beyondMemory(chain);
    if (beyond) {
      log.error('audit.witness_beyond_memory', { chain: chain.kind, anchoring: false });
      return undefined;
    }
    return asked.filter(({ seq }) => seq > from && seq <= report.seq);
  };

  /** What a completed check comes to: the alarm, nothing moved, or the chain anchored where it stands. */
  const afterCheck = (chain: Chain, log: Logger, report: WalkedReport, last: Anchor | undefined): Outcome => {
    if (!report.ok) return alarmed(chain, log, report.problem.reason, report.problem.seq);
    // A store's read past its deadline, or another copy's anchor, can land during the check, and the head read before
    // it says nothing against it: an honest copy may have moved on since. The next run compares with it, the alarm a run
    // late at most, one interval and that run's length; Tx A compares with it at once, so a payment is refused meanwhile.
    // By what it says, not by identity: the anchor log gives a new copy at each read (packed-lines.ts, PL-65).
    if (!sameAnchor(anchors.latest(chain), last)) return 'unanchored';
    // The check compared the anchored event already; this backs it up should a store not pass the anchor on.
    if (last !== undefined && !stillHolds(report, last)) return alarmed(chain, log, 'anchor', last.seq);
    if (last?.seq === report.seq) {
      // A whole walk read the chain from its first event, which no walk from the anchor did: its facts kept (AT13c).
      if (report.walkedFrom !== undefined) recordWalk(chain, report, last, clock.now());
      // Said again in the store now and then, so its time tells a restart this chain has had its turn (anchor-turns.ts).
      if (
        durable !== undefined &&
        !storeUnread(chain) &&
        clock.now().getTime() - last.at.getTime() >= reachWithinMs / 2
      ) {
        anchors.keep(signAnchor(keys, chain, report, clock.now(), durable.epoch));
      }
      return 'unchanged';
    }
    if (storeUnread(chain)) return 'unanchored';
    const confirmed = witnessConfirmed(chain, log, report, last);
    if (confirmed === undefined) return 'unanchored';
    const anchor = signAnchor(keys, chain, report, clock.now(), durable?.epoch);
    anchors.keep(anchor);
    // The walk to it passed through each of them (checkFromAnchor refuses one that didn't): let go, and only those.
    witness?.prune(chain, confirmed);
    if (witness !== undefined) anchoredHere.set(keyOf(chain), { seq: report.seq, recent: report.recent ?? new Map() });
    // What the walk to it read of each signed object, and the stretch it read whole, kept with it (AT13): facts as true
    // as the anchor, as a decision will hold the database to them. The platform chain's too (AT13c).
    recordWalk(chain, report, last, anchor.at);
    if (chain.kind === 'platform' && last !== undefined) sayPlatformGrowth(log, last, report.seq, anchor.at);
    log.info('audit.anchored', {
      chain: chain.kind,
      seq: report.seq,
      headHash: report.hash.toString('hex'),
      keyVersion: anchor.keyVersion,
    });
    return 'anchored';
  };

  /** A check has completed, and how it came out. */
  const compared = (
    chain: Chain,
    log: Logger,
    report: WalkedReport,
    last: Anchor | undefined,
    alone: boolean,
  ): Outcome => {
    const key = keyOf(chain);
    const at = clock.now().getTime();
    if (!pastCapNow.has(key)) lastChecked.set(key, at);
    misses.delete(key);
    if (chain.kind === 'organisation' && !alone) {
      completed += 1;
      lastTurn = at;
    }
    return afterCheck(chain, log, report, last);
  };

  /** A check that ended past its deadline or the run: compared all the same, its alarm and hold as ever. Never throws. */
  const landedLate = (
    chain: Chain,
    log: Logger,
    report: WalkedReport,
    last: Anchor | undefined,
    alone: boolean,
  ): void => {
    try {
      afterLate(chain, compared(chain, log, report, last, alone));
    } catch (error) {
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: error });
    }
  };

  /** What came of a check that ended past its turn: it goes again where that is owed, and its hold is tried. */
  const afterLate = (chain: Chain, outcome: Outcome): void => {
    if (chain.kind !== 'organisation' || (outcome !== 'failed' && outcome !== 'unanchored')) return;
    turns.repeat(chain.orgId);
    if (outcome === 'failed' && organizations !== undefined) void settle(organizations, chain.orgId, undefined);
  };

  /** How a check that didn't come back comes out, the same in its turn or after: the database's refusal, or a miss. */
  const failedOutcome = (chain: Chain, log: Logger, error: unknown, alone: boolean): Outcome =>
    // A store that breaks its contract may be a hostile database too (a planted operator, a view for a table).
    error instanceof ChainStoreError || refusedByDatabase(error)
      ? alarmed(chain, log, 'store')
      : missedCheck(chain, log, error, alone);

  /** A check that failed past its deadline or the run: said on its own line, as no run sums it up. Never throws. */
  const failedLate = (chain: Chain, log: Logger, error: unknown): void => {
    try {
      afterLate(chain, failedOutcome(chain, log, error, true));
    } catch (crash) {
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: crash });
    }
  };

  /**
   * A check that didn't come back, said at once on its own line where `alone`, or else in the run's one line. One that
   * failed counts towards the alarm; one still running doesn't, as every trip of it has a limit: that is capacity.
   */
  const missedCheck = (chain: Chain, log: Logger, error: unknown, alone: boolean): Outcome => {
    const key = keyOf(chain);
    const failed = !(error instanceof UnderWay || error instanceof PastDeadline);
    if (failed) misses.set(key, (misses.get(key) ?? 0) + 1);
    const stale = failed && isStale(key);
    if (alone || chain.kind === 'platform') {
      log.warn('audit.anchor_check_failed', { chain: chain.kind, err: error });
      return stale ? alarmed(chain, log, 'unchecked') : 'unchecked';
    }
    missedThisRun.push(key);
    firstMiss ??= error;
    if (!stale) return 'unchecked';
    staleThisRun.push(key);
    failures.set(key, 'unchecked');
    return 'failed';
  };

  /** The run's one line for the checks that couldn't run, its one alarm for those gone too long, and one for those gone from the list past the named. */
  const sayMissed = (): void => {
    if (unlistedThisRun > UNLISTED_NAMED) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unlisted',
        organisations: unlistedThisRun - UNLISTED_NAMED,
      });
    }
    if (missedThisRun.length > 0) {
      logger.warn('audit.anchor_check_failed', {
        chain: 'organisation',
        chains: missedThisRun.length,
        firstFew: missedThisRun.slice(0, NAMED_ON_A_LINE),
        err: firstMiss,
      });
    }
    if (staleThisRun.length > 0) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unchecked',
        organisations: staleThisRun.length,
        firstFew: staleThisRun.slice(0, NAMED_ON_A_LINE),
      });
    }
  };

  /**
   * The chain's shard pinned. A turn about to read it back makes room first (PR4: the walk leaves lines waiting behind
   * it); a hand-off's anchor never waits on a write.
   */
  const pinFor = (log: AnchorLog, chain: Chain, alone: boolean): Promise<(() => void) | undefined> =>
    alone || log.holds(chain) ? log.pin(chain) : log.roomToReadBack().then(() => log.pin(chain));

  const checkOne = async (
    checked: CheckedChain,
    signal: AbortSignal | undefined,
    alone = false,
    ran: (ms: number) => void = () => undefined,
  ): Promise<Outcome> => {
    const { chain } = checked;
    // An organisation's ID goes on the line as the logger's own field, which an event can't set.
    const log = chain.kind === 'platform' ? logger : logger.child({ orgId: chain.orgId });
    let release: (() => void) | undefined;
    try {
      // Its shard held while it is compared, read again first if it was let go (PL-65 PR3): one that can't be waits.
      release = durable === undefined ? () => undefined : await pinFor(durable, chain, alone);
      if (release === undefined) return 'unanchored';
      let checkMs = 0;
      const timed = (ms: number): void => {
        checkMs = ms;
        ran(ms);
      };
      const outcome = await checkHeld(checked, signal, { alone, ran: timed, log });
      if (outcome !== 'failed' && chain.kind === 'organisation') {
        // The catch-up's time is the turn's too, so the turns' order stays fair to the chains that need it.
        const began = performance.now();
        if (await caughtUp(chain, signal, log)) ran(checkMs + performance.now() - began);
      }
      return outcome;
    } catch (error) {
      // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
      log.error('audit.anchor_check_crashed', { chain: chain.kind, err: error });
      return 'unchecked';
    } finally {
      release?.();
    }
  };

  /**
   * The digest's catch-up (AT13): a chain whose digest doesn't cover its anchor (a stretch lost between the anchor's write
   * and the digest's, a rebase, or a chain anchored before the digest) is walked on from
   * where it is covered, or its first event, one step a turn, as its check is, until it does; its hand-offs wait meanwhile
   * (`digest_pending`). Only reads: nothing is anchored, and a walk that fails is the alarm. Whether it walked, so its
   * time counts in the turn's. Never throws.
   */
  const caughtUp = async (
    chain: Chain & { readonly kind: 'organisation' },
    signal: AbortSignal | undefined,
    log: Logger,
  ): Promise<boolean> => {
    const anchor = anchors.latest(chain);
    if (digest === undefined || organizations === undefined || anchor === undefined) return false;
    // Not covered to its anchor, a chain coming back after it gave way for memory included (AT13e).
    if (!digest.owed(chain, anchor.seq)) return false;
    // Its regular check still under way past its deadline: the catch-up waits for a turn of its own, quietly.
    if (inFlight.has(keyOf(chain))) return false;
    const from = digest.coverage(chain) ?? CHAIN_START;
    const began = clock.now();
    try {
      const report: WalkedReport = await tracked(
        keyOf(chain),
        'the last check of this chain has not finished',
        () => organizations.verify(chain.orgId, from),
        signal,
      );
      if (!report.ok) {
        alarmed(chain, log, report.problem.reason, report.problem.seq);
        return true;
      }
      const to = { seq: report.seq, hash: report.hash, macKeyVersion: report.macKeyVersion };
      digest.record(chain, report.signed ?? new Map(), began, { from: from.seq, to });
      return true;
    } catch (error) {
      if (!(error instanceof Stopped)) log.warn('audit.state_digest_catch_up_failed', { err: error });
      return true;
    }
  };

  /** One chain's check, its shard held: apart from `checkOne`, which holds it and catches what escapes, to keep each short. */
  const checkHeld = async (
    checked: CheckedChain,
    signal: AbortSignal | undefined,
    { alone, ran, log }: { alone: boolean; ran: (ms: number) => void; log: Logger },
  ): Promise<Outcome> => {
    const { chain, verify } = checked;
    const key = keyOf(chain);
    const last = anchors.latest(chain);
    // Heads at or below its anchor, judged first (TR-1): a fork among them is the alarm.
    // Only with a witness log: with none it takes no turn of the event loop, as before (the lanes' timing).
    if (witness !== undefined && (await lateHeadsHold(checked, log, signal, alone)) === 'failed') return 'failed';
    let report: WalkedReport;
    let cutOff = false;
    const began = performance.now();
    try {
      if (inFlight.has(key)) throw new UnderWay('the last check of this chain has not finished');
      inFlight.add(key);
      checkBegan.set(key, clock.now().getTime());
      // Dated when the walk began (AT13): a rebase landing during it sets what it read aside, as the anchors do.
      const walkBegan = clock.now();
      // The heads it is held to, asked before its first statement (TR-1): each committed before it began. Its last
      // events' hashes kept, for a head landing after it anchors.
      // With the compact heads (TR-3: let go for memory, or released): a place holding another event is a fork, as at a
      // head. The one held set every consumer reads (TR-9).
      const heldTo = witness?.heldTo(chain) ?? [];
      const recent: RecentPlaces = { since: new Date(walkBegan.getTime() - RECENT_MS), found: new Map() };
      const checking = Promise.resolve()
        .then(() => (witness === undefined ? verify(last) : verify(last, heldTo, recent)))
        .then((made): WalkedReport => ({ ...made, began: walkBegan, heldTo, recent: recent.found }));
      // Handled here too, so a check that ends after its deadline never goes unhandled.
      void checking.then(
        (ending) => {
          ended(key);
          if (cutOff) landedLate(chain, log, ending, last, alone);
        },
        (error: unknown) => {
          ended(key);
          if (cutOff) failedLate(chain, log, error);
        },
      );
      report = await withinDeadline(checking, deadlineMs, signal);
      await readAfterWalk(report, last);
    } catch (error) {
      cutOff = true;
      if (error instanceof Stopped) return 'unchecked';
      if (error instanceof PastDeadline) ran(performance.now() - began);
      return failedOutcome(chain, log, error, alone);
    }
    ran(performance.now() - began);
    return compared(chain, log, report, last, alone);
  };

  /**
   * The organisations listed and recorded, or what stopped them being read:
   * `stopped` when the run was, `refused` for a database that refuses the
   * read or answers with anything but IDs (the alarm), `failed` for anything
   * else. One read at a time: a read still under way past its deadline counts
   * as failed, so a hung database can't take a connection every run.
   */
  const listOrganizations = async (
    from: OrganisationChains,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly listed: string[]; readonly recorded: string[] } | 'stopped' | 'refused' | 'failed'> => {
    const refused = (): 'refused' => {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
      return 'refused';
    };
    let answers: readonly [unknown, unknown];
    try {
      // The record first, then the list: an organisation is recorded and listed
      // in one transaction, so any recorded before the list is read is in it,
      // and one created between the two reads can't be taken for one unlisted.
      // One after the other, so the guard holds until both have ended.
      answers = await tracked(
        LIST,
        'the last read of the list has not finished',
        async (): Promise<readonly [unknown, unknown]> => {
          const recorded = await from.recorded();
          return [await from.list(), recorded];
        },
        signal,
      );
    } catch (error) {
      if (error instanceof Stopped) return 'stopped';
      if (error instanceof ChainStoreError || refusedByDatabase(error)) return refused();
      logger.warn('audit.anchor_check_failed', { chain: 'organisation', check: 'list', err: error });
      return 'failed';
    }
    const [listed, recorded] = [organisationIds(answers[0]), organisationIds(answers[1])];
    if (listed === undefined || recorded === undefined) return refused();
    listRead = clock.now().getTime();
    return { listed, recorded };
  };

  /** An organisation seen before and off the list now: the alarm. */
  const unlisted = (orgId: string): Outcome => {
    const last = anchors.latest({ kind: 'organisation', orgId });
    failures.set(orgId, 'unlisted');
    unlistedThisRun += 1;
    if (unlistedThisRun > UNLISTED_NAMED) return 'failed';
    logger.child({ orgId }).error('audit.integrity_failed', {
      chain: 'organisation',
      check: 'anchor',
      reason: 'unlisted',
      ...(last === undefined ? {} : { anchorSeq: last.seq }),
    });
    return 'failed';
  };

  /**
   * Puts an organisation whose chain failed this run on its integrity hold,
   * or tries again a hold waiting for one that didn't (or only went
   * unchecked), within the check's deadline and one at a time for each
   * organisation, so a hold hung on the database can't take a connection
   * every run. A hold not set in time is the alarm: the hold records its own
   * outcome if it ends later.
   */
  const settle = async (from: OrganisationChains, orgId: string, signal: AbortSignal | undefined): Promise<void> => {
    const reason = failures.get(orgId);
    failures.delete(orgId);
    if (signal?.aborted === true) return;
    const failure = reason === 'unchecked' ? undefined : reason;
    try {
      await tracked(
        `hold|${orgId}`,
        'the last hold of this organisation has not finished',
        () => from.hold(orgId, failure),
        signal,
      );
    } catch (error) {
      if (error instanceof Stopped) return;
      logger
        .child({ orgId })
        .error('audit.integrity_failed', { chain: 'organisation', check: 'hold', reason: 'not_recorded', err: error });
    }
  };

  // What this run's probe found, by organisation: those it didn't answer for are read in their turns.
  const probed = new Map<string, Probed>();
  // Those the last run's time left unprobed, probed first next run.
  let unprobed: ReadonlySet<string> = new Set();
  // Those whose shard the log had let go at the run's probe (PL-65 PR3), by shard, and each shard's probe under way or
  // done this run: probed as the walk reaches the shard, never read back for the run's probe alone (PR4).
  let awayShards: ReadonlyMap<number, readonly string[]> = new Map();
  const shardProbes = new Map<number, Promise<void>>();

  /** The probe's misses, in one line: their turns read them as before, so a warning, never the alarm. */
  const sayProbeMissed = (count: number, error: unknown): void => {
    logger.warn('audit.anchor_check_failed', { chain: 'organisation', check: 'probe', chains: count, err: error });
  };

  /**
   * Every listed chain with an anchor probed at the run's start (4D2e E8): its head against its anchor and its last
   * events counted, a page of organisations a trip, on one of the lanes' connections. A chain found unmoved, or
   * failing, takes its turn with no read of its own; one moved, never anchored or not answered for is read from its
   * anchor in its turn. One whose check from the last run is still under way meets that in its turn, as ever.
   */
  const probeAll = async (
    from: OrganisationChains,
    orgIds: readonly string[],
    cap: AbortSignal,
    stop: AbortSignal | undefined,
  ): Promise<void> => {
    const probe = from.probe?.bind(from);
    if (probe === undefined) return;
    // Those the last run's time left unprobed first, so a tail never starves.
    const order = [...orgIds.filter((orgId) => unprobed.has(orgId)), ...orgIds.filter((orgId) => !unprobed.has(orgId))];
    const asked = withAnchors(order);
    if (asked.length === 0) return;
    // Within the lanes' share, as a turn and the rotation: checks from the last run may still hold some of it.
    while (inFlight.size >= lanes && !cap.aborted) await roomOrEnd(cap);
    if (cap.aborted) {
      // None reached: said as any probe cut short, and all of them first next run in the order they had.
      sayUnprobed(
        asked.map(({ orgId }) => orgId),
        asked.length,
      );
      return;
    }
    const pages = Math.max(1, Math.min(probePages, lanes - inFlight.size));
    let answers: ReadonlyMap<string, ProbeAnswer>;
    try {
      // The run's time ends the probe between pages, and what it reached is kept; only the stop ends the wait at once.
      answers = await tracked(PROBE, 'the last probe has not finished', () => probe(asked, cap, pages), stop, pages);
    } catch (error) {
      if (!(error instanceof Stopped)) sayProbeMissed(asked.length, error);
      return;
    }
    sayUnprobed(
      asked.filter(({ orgId }) => !answers.has(orgId)).map(({ orgId }) => orgId),
      asked.length,
    );
    takeAnswers(asked, answers);
  };

  /**
   * Those of them with an anchor held, each with it: what a probe asks of. Read from the log without counting their
   * shards as used (PR4), so the probe's list order doesn't decide which shard goes first.
   */
  const withAnchors = (orgIds: readonly string[]) =>
    orgIds.flatMap((orgId) => {
      const chain = { kind: 'organisation', orgId } as const;
      const anchor = durable !== undefined && anchors === durable ? durable.heldAnchor(chain) : anchors.latest(chain);
      return anchor === undefined ? [] : [{ orgId, from: anchor, heldTo: heldToOf(chain) }];
    });

  /**
   * The heads copies witnessed above the chain's anchor (TR-1), asked before a probe's statement: none without a log.
   * Whole heads alone (TR-9): the probe is what releases them, reads no link, and lets nothing pay; every walk and read
   * that does is held to the compact ones too (heldTo).
   */
  const heldToOf = (chain: Chain): readonly { readonly seq: bigint; readonly hash: Buffer }[] =>
    witness?.pending(chain) ?? [];

  /**
   * The chains that gained a witnessed head, probed now (TR-1): with an anchor, against it; with none, from the chain's
   * start, as only the heads are judged. One cut back below a head is the alarm and the hold; the rest wait for the run.
   */
  const probeWitnessedNow = async (orgIds: readonly string[], signal: AbortSignal | undefined): Promise<void> => {
    await probeChainsWitnessed(signal);
    const probe = organizations?.probe?.bind(organizations);
    if (organizations === undefined || probe === undefined || inFlight.has(PROBE) || storeUnread()) return;
    const asked = orgIds.flatMap((orgId) => {
      const chain = { kind: 'organisation', orgId: orgId.toLowerCase() } as const;
      const heldTo = heldToOf(chain);
      return heldTo.length === 0 ? [] : [{ orgId: chain.orgId, from: anchors.latest(chain) ?? CHAIN_START, heldTo }];
    });
    if (asked.length === 0) return;
    const stop = signal ?? new AbortController().signal;
    const answers = await tracked(
      WITNESS_PROBE,
      'the last witness probe has not finished',
      () => probe(asked, stop, 1),
      signal,
    );
    for (const { orgId, heldTo } of asked) {
      const answer = answers.get(orgId);
      const chain = { kind: 'organisation', orgId } as const;
      if (answer === undefined || answer.kind === 'missed') continue;
      if (answer.kind !== 'failed') {
        letGoBelowHighest(chain, heldTo);
        continue;
      }
      if (answer.problem.reason !== 'cut_back') continue;
      alarmed(chain, logger.child({ orgId }), 'cut_back', answer.problem.seq);
      await settle(organizations, orgId, signal);
    }
  };

  /**
   * The chains the check covers that can be probed (the platform's: TR-3), each against the heads copies witnessed, after
   * every read of the log as the organisations that gained one are: a cut below one is the alarm, as in a run; all on the
   * chain, all but the highest let go. A miss is a warning: the run asks the same.
   */
  const probeChainsWitnessed = async (signal: AbortSignal | undefined): Promise<void> => {
    for (const { chain, probe } of chains) {
      const heldTo = heldToOf(chain);
      if (probe === undefined || heldTo.length === 0 || inFlight.has(PLATFORM_WITNESS_PROBE) || storeUnread(chain)) {
        continue;
      }
      try {
        const cut = await tracked(
          PLATFORM_WITNESS_PROBE,
          'the last witness probe has not finished',
          () => probe(heldTo),
          signal,
        );
        if (cut === undefined) letGoBelowHighest(chain, heldTo);
        else alarmed(chain, logger, 'cut_back', cut.seq);
      } catch (error) {
        if (!(error instanceof Stopped)) {
          logger.warn('audit.anchor_check_failed', { chain: chain.kind, check: 'probe', chains: 1, err: error });
        }
      }
    }
  };

  /**
   * The heads above the chain's anchor a probe found on the chain, each its event's hash at its place in the probe's one
   * statement (TR-3), released but the highest: compact, and every later walk held to them until one from the anchor
   * passes them (the log's release), so a burst between anchor runs never fills what may be held. Never let go outright:
   * the probe reads no link between them, so rows put back beside a cut branch for its statement alone would pass it.
   * Those at or below the anchor wait for their own linked walk (lateHeadsHold). With no anchor known (never anchored,
   * or its shard let go: PL-65), none released.
   */
  const letGoBelowHighest = (chain: Chain, heldTo: readonly Witnessed[]): void => {
    // The anchor as held (its shard read, as withAnchors asks it): with none known, nothing released.
    const anchored = (durable !== undefined && anchors === durable ? durable.heldAnchor(chain) : anchors.latest(chain))
      ?.seq;
    if (anchored === undefined) return;
    const [, ...below] = heldTo
      .filter(({ seq }) => seq > anchored)
      .toSorted((one, other) => (one.seq > other.seq ? -1 : 1));
    if (below.length > 0) witness?.release?.(chain, below);
  };

  /** A probe's answers kept for the turns: unmoved or failing as found, read anyway; its misses said in one line. */
  const takeAnswers = (
    asked: readonly { readonly orgId: string; readonly from: CheckedPoint }[],
    answers: ReadonlyMap<string, ProbeAnswer>,
  ): void => {
    const missed: unknown[] = [];
    for (const { orgId, from: anchor } of asked) {
      const answer = answers.get(orgId);
      if (answer?.kind === 'same' || answer?.kind === 'failed') probed.set(orgId, { anchor, answer });
      else if (answer?.kind === 'missed') missed.push(answer.error);
    }
    if (missed.length > 0) sayProbeMissed(missed.length, missed[0]);
  };

  /**
   * Those listed whose shard the log had let go as the run's probe read the anchors (PR3), by shard: the probe asked
   * nothing of them, and nothing is read back for it, so each shard's are probed as the walk reaches it (PR4).
   */
  const awayByShard = (from: OrganisationChains, orgIds: readonly string[]): ReadonlyMap<number, string[]> => {
    const away = new Map<number, string[]>();
    if (durable === undefined || from.probe === undefined) return away;
    for (const orgId of orgIds) {
      if (probed.has(orgId) || durable.holds({ kind: 'organisation', orgId })) continue;
      const shard = shardOfOrganisation(orgId);
      const those = away.get(shard);
      if (those === undefined) away.set(shard, [orgId]);
      else those.push(orgId);
    }
    return away;
  };

  /**
   * One shard's chains, let go at the run's probe, probed as the walk first reaches it (PR4): its shard read back and
   * pinned meanwhile, one page on a connection of the lanes', as a turn's. Those it doesn't answer for are read in their
   * turns, as any the run's probe missed. Never throws.
   */
  const probeAway = async (
    probe: NonNullable<OrganisationChains['probe']>,
    shard: number,
    away: readonly string[],
    signal: AbortSignal,
  ): Promise<void> => {
    const [first] = away;
    if (durable === undefined || first === undefined || signal.aborted) return;
    // A shard that can't be read back: each turn finds the same, and its organisations wait (anchor-log.ts said why).
    await durable.roomToReadBack();
    const release = await durable.pin({ kind: 'organisation', orgId: first });
    if (release === undefined) return;
    try {
      const asked = withAnchors(away);
      if (asked.length === 0) return;
      const answers = await tracked(
        `${PROBE}|${String(shard)}`,
        'the last probe of this shard has not finished',
        () => probe(asked, signal, 1),
        signal,
      );
      takeAnswers(asked, answers);
    } catch (error) {
      if (!(error instanceof Stopped)) sayProbeMissed(away.length, error);
    } finally {
      release();
    }
  };

  // The organisation whose turn the walk last took, so the log hears when the walk leaves its shard.
  let walkedFrom: string | undefined;
  /** The walk takes this organisation's turn: if that leaves the last one's shard, the log lets that shard go first. */
  const walkTo = (orgId: string): void => {
    if (durable === undefined) return;
    const from = walkedFrom;
    walkedFrom = orgId;
    if (from !== undefined && shardOfOrganisation(from) !== shardOfOrganisation(orgId)) {
      durable.walkedPast({ kind: 'organisation', orgId: from });
    }
  };

  /** Where the organisation's shard was let go at the run's probe: that shard's probe, begun by the first of it to come. */
  const probedAway = (from: OrganisationChains, orgId: string, signal: AbortSignal): Promise<void> | undefined => {
    const probe = from.probe?.bind(from);
    if (awayShards.size === 0 || probe === undefined) return undefined;
    const shard = shardOfOrganisation(orgId);
    const away = awayShards.get(shard);
    if (away === undefined) return undefined;
    let probing = shardProbes.get(shard);
    if (probing === undefined) {
      probing = probeAway(probe, shard, away, signal);
      shardProbes.set(shard, probing);
    }
    return probing;
  };

  /** What the probe found, each as a check completed in its turn would count, for a run with no time left for turns. */
  const landProbed = async (from: OrganisationChains): Promise<Outcome[]> => {
    const outcomes: Outcome[] = [];
    for (const [orgId, found] of probed) {
      const chain = { kind: 'organisation', orgId } as const;
      const latest = anchors.latest(chain);
      // 6F1 G5: as probedReport, the answer counts only against the very anchor it compared with. One anchored since (a
      // hand-off, another copy) is read next run, never compared with the newer anchor: a false 'anchor' alarm and hold.
      if (latest === undefined || !samePoint(found.anchor, latest)) {
        outcomes.push('unanchored');
        continue;
      }
      const outcome = compared(chain, logger.child({ orgId }), reportOf(found), latest, false);
      if (outcome === 'failed') await settle(from, orgId, undefined);
      outcomes.push(outcome);
    }
    return outcomes;
  };

  /**
   * Those the run's time left unprobed: first next run, a warning, and past the stale limit unchecked the alarm, no hold,
   * as for any chain unchecked. They take no turn this run either: the time is gone.
   */
  const sayUnprobed = (left: readonly string[], total: number): void => {
    unprobed = new Set(left);
    if (left.length === 0) return;
    logger.warn('audit.probe_unfinished', { reached: total - left.length, total });
    const now = clock.now().getTime();
    const stale = left.filter((orgId) => now - since(orgId) >= staleAfterMs);
    if (stale.length > 0) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unchecked',
        organisations: stale.length,
        firstFew: stale.slice(0, NAMED_ON_A_LINE),
      });
    }
  };

  /** An organisation's `confirm`, where its chains have one (TR-1). */
  const confirmOf = (from: OrganisationChains, orgId: string): Pick<CheckedChain, 'confirm'> => {
    const step = from.confirm?.bind(from);
    return step === undefined ? {} : { confirm: (cursor, target, watch) => step(orgId, cursor, target, watch) };
  };

  /** A chain's report from this run's probe, where it compared the very anchor its turn holds: none, and it is read. */
  const probedReport = (orgId: string, anchor: CheckedPoint | undefined): Promise<ChainReport> | undefined => {
    const found = probed.get(orgId);
    if (found === undefined || anchor === undefined || !samePoint(found.anchor, anchor)) return undefined;
    return Promise.resolve(reportOf(found));
  };

  const remember = (orgId: string): void => {
    if (firstSeen.has(orgId)) return;
    firstSeen.set(orgId, clock.now().getTime());
  };

  /**
   * One organisation's turn: its check, or, off the list, its alarm; then its hold. A chain reached with the run's time
   * up goes first next run, as does one whose alarm must repeat or whose comparison is owed.
   */
  const turn = async (
    from: OrganisationChains,
    orgId: string,
    listed: ReadonlySet<string>,
    signal: AbortSignal,
  ): Promise<Outcome> => {
    let ranMs: number | undefined;
    walkTo(orgId);
    // Awaited only where there is one, so a run with every shard held takes its turns as before, tick for tick.
    const away = listed.has(orgId) ? probedAway(from, orgId, signal) : undefined;
    if (away !== undefined) await away;
    const outcome = listed.has(orgId)
      ? await checkOne(
          {
            chain: { kind: 'organisation', orgId },
            verify: (anchor, heldTo, recent) =>
              probedReport(orgId, anchor) ?? from.verify(orgId, anchor, heldTo, recent),
            ...confirmOf(from, orgId),
          },
          signal,
          false,
          (ms) => {
            ranMs = ms;
          },
        )
      : unlisted(orgId);
    if (!listed.has(orgId)) turns.ended(orgId);
    await settle(from, orgId, signal);
    turns.after(orgId, {
      ms: pastCapNow.has(orgId) ? undefined : ranMs,
      again: outcome === 'failed' || outcome === 'unanchored' || (outcome === 'unchecked' && signal.aborted),
    });
    return outcome;
  };

  /** Until a check, hold or read ends, or the run does. */
  const roomOrEnd = (signal: AbortSignal): Promise<void> =>
    new Promise((resolve) => {
      waitingForRoom.add(resolve);
      signal.addEventListener(
        'abort',
        () => {
          resolve();
        },
        { once: true },
      );
    });

  /**
   * Turns taken in `lanes` side by side until none is left or the run's time is up. Nothing starts while the lanes' share
   * of the connections is in use, those past their deadline among them: it must not take the hand-offs'. Every trip these
   * make, its start and commit too, goes unanswered only so long (JOB_ANSWER_WITHIN_MS), so a dead connection ends, and with
   * it the wait.
   */
  const takeTurns = async (from: OrganisationChains, listed: ReadonlySet<string>, signal: AbortSignal) => {
    const outcomes: Outcome[] = [];
    const lane = async (): Promise<void> => {
      while (!signal.aborted && turns.left() > 0) {
        if (inFlight.size >= lanes) {
          await roomOrEnd(signal);
          continue;
        }
        const orgId = turns.next();
        // With all that's left under way's share.
        if (orgId === undefined) return;
        outcomes.push(await turn(from, orgId, listed, signal));
      }
    };
    await Promise.all(Array.from({ length: lanes }, () => lane()));
    return outcomes;
  };

  /** Whether this one, new to the check, takes a note: while the cap has room. */
  const noted = (orgId: string): boolean => {
    if (firstSeen.has(orgId) || firstSeen.size >= mostOrganisations) return false;
    remember(orgId);
    return true;
  };

  /** A list read whole: those noted and new as far as the cap allows, the rest by the cursor, with one line to say so. */
  const adopted = (read: { readonly listed: readonly string[]; readonly recorded: readonly string[] }) => {
    const listedNow = new Set(read.listed);
    // From the two lists alone, so one past the cap, with no note kept on it, is seen to have gone too.
    const gone = new Set(read.recorded.filter((orgId) => !listedNow.has(orgId)));
    // One recorded and off the list goes first as gone, whatever its place here.
    const fresh = read.recorded.filter((orgId) => noted(orgId));
    const past: string[] = [];
    for (const orgId of read.listed) {
      if (firstSeen.has(orgId)) continue;
      if (noted(orgId)) fresh.push(orgId);
      else past.push(orgId);
    }
    if (past.length > 0) {
      logger.error('audit.anchor_check_over_size', {
        listed: read.listed.length,
        beyond: past.length,
        most: mostOrganisations,
      });
    }
    for (const orgId of firstSeen.keys()) if (!listedNow.has(orgId)) gone.add(orgId);
    pastCap = past;
    pastCapNow = new Set(past);
    inUse = read.listed.filter((orgId) => !pastCapNow.has(orgId));
    return { fresh, unlisted: [...gone] };
  };

  const checkOrganizations = async (
    from: OrganisationChains,
    cap: AbortSignal,
    stop: AbortSignal | undefined,
  ): Promise<Outcome[]> => {
    const read = await listOrganizations(from, cap);
    if (read === 'stopped' && stop?.aborted === true) return [];
    // Any list not read, or a run's time gone before one was, counts against the list, and the last goes on in use.
    if (
      typeof read === 'string' &&
      read !== 'refused' &&
      clock.now().getTime() - (listRead ?? started) >= staleAfterMs
    ) {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'list' });
    }
    const { fresh, unlisted: gone } = typeof read === 'string' ? { fresh: [], unlisted: [] } : adopted(read);
    const listed = inUse ?? [...firstSeen.keys()];
    turns.begin(listed, fresh, gone, pastCap);
    if (turns.pastCapStarts()) pastCapSince = clock.now().getTime();
    await probeAll(from, [...listed, ...pastCap], cap, stop);
    // The run's time gone during the probe: no turn follows, so what it found counts now, alarms and holds as ever.
    if (cap.aborted) return landProbed(from);
    awayShards = awayByShard(from, [...listed, ...pastCap]);
    return takeTurns(from, new Set([...listed, ...pastCap]), cap);
  };

  /**
   * Checks still under way past the ceiling, which no longer read as capacity: the alarm, no hold, as for any chain unchecked
   * (one line for the organisations'). Slow answers could otherwise keep a chain from being compared for ever.
   */
  const sayOverCeiling = (at: number): ReadonlySet<string> => {
    const over = new Set([...checkBegan].filter(([, began]) => at - began >= reachWithinMs).map(([key]) => key));
    if (over.delete('platform')) {
      alarmed({ kind: 'platform' }, logger, 'unchecked');
      over.add('platform');
    }
    const organisations = [...over].filter((key) => key !== 'platform');
    if (organisations.length > 0) {
      logger.error('audit.integrity_failed', {
        chain: 'organisation',
        check: 'anchor',
        reason: 'unchecked',
        organisations: organisations.length,
        firstFew: organisations.slice(0, NAMED_ON_A_LINE),
      });
    }
    return over;
  };

  /**
   * Those past the bound, over all of them, by count as there may be thousands: capacity, or with no run's turn completed
   * for that whole time, the alarm. In a bad run while a turn has completed since, nothing: the next run says.
   */
  const sayLate = (): void => {
    const at = clock.now().getTime();
    const overCeiling = sayOverCeiling(at);
    const late = (inUse ?? [...firstSeen.keys()]).filter(
      (orgId) => at - lastKnown(orgId) >= reachWithinMs && !overCeiling.has(orgId),
    );
    const pastLate = pastCap.length > 0 && at - pastCapSince >= reachWithinMs ? pastCap : [];
    // One whose own check fails has its own alarm: this is for one that goes on.
    const others = chains
      .map(({ chain }) => keyOf(chain))
      .filter((key) => !misses.has(key) && !overCeiling.has(key) && at - since(key) >= reachWithinMs);
    const named = [...others, ...late, ...pastLate.slice(0, NAMED_ON_A_LINE)];
    if (named.length === 0) return;
    const count = {
      organisations: others.length + late.length + pastLate.length,
      firstFew: named.slice(0, NAMED_ON_A_LINE),
    };
    if (completed > 0 || late.length + pastLate.length === 0) {
      logger.error('audit.anchor_check_behind', { ...count, left: turns.left(), lanes });
    } else if (at - lastTurn >= reachWithinMs) {
      logger.error('audit.integrity_failed', { chain: 'organisation', check: 'anchor', reason: 'unreached', ...count });
    }
  };

  /** What a run that ran out of time, or left organisations for the next, says it has left. */
  const sayLeft = (cap: AbortSignal): void => {
    const left = turns.left() > 0;
    // Until a whole round has gone by in one run: after the run finishing a long round come chains checked long ago.
    spreading = left || leftLastRun;
    leftLastRun = left;
    if (left || cap.aborted) {
      logger.warn('audit.anchor_check_unfinished', { left: turns.left(), lanes, withinMs: runWithinMs });
    }
    sayLate();
  };

  /**
   * Where the last process left off: the newest file in the store at this process's first whole read, taken before this
   * process writes any, so the rotation's first look back sees the whole outage (4D2e E7).
   */
  let leftOffAt: Date | undefined;
  let leftOffTaken = false;

  /** What the store holds that this process hasn't read, and every organisation in it as seen. Never throws. */
  const readStore = async (from: AnchorLog, signal: AbortSignal | undefined): Promise<void> => {
    try {
      await withinDeadline(from.read(), deadlineMs, signal);
    } catch (error) {
      if (error instanceof Stopped) return;
      from.readFailed(error);
    }
    if (!leftOffTaken && from.state() === 'read') {
      leftOffTaken = true;
      leftOffAt = from.lastFileAt();
    }
    for (const orgId of from.organisations()) remember(orgId);
    // The digest after the anchors, which read the rebases it passes lines over by (AT13). Its own failures it says itself.
    if (digest === undefined) return;
    try {
      await withinDeadline(digest.read(), Math.min(deadlineMs, DIGEST_WITHIN_MS), signal);
    } catch (error) {
      if (!(error instanceof Stopped)) logger.warn('audit.state_digest_store_failed', { what: 'read', err: error });
    }
  };

  /**
   * What the digest holds unwritten into the store, beside the anchors' write (AT13), within a deadline of its own, so a
   * slow hourly snapshot is never an anchor write failed: its own warning. Never throws.
   */
  const digestWritten = async (stop: AbortSignal | undefined, withinMs: number): Promise<void> => {
    if (digest === undefined) return;
    try {
      await withinDeadline(digest.flush(), withinMs, stop);
    } catch (error) {
      if (!(error instanceof Stopped)) logger.warn('audit.state_digest_store_failed', { what: 'write', err: error });
    }
  };

  /**
   * What has moved so far into the store. A run stopped leaves it to `finish`. Never throws. `twice`: a write is under way,
   * which this joins, and what moved since must not wait a whole interval for the next run.
   */
  const writeStore = async (to: AnchorLog, stop: AbortSignal | undefined, twice = false): Promise<void> => {
    try {
      const writing = twice ? to.flush().then(() => to.flush()) : to.flush();
      const digestWriting = digestWritten(stop, Math.min(deadlineMs, DIGEST_WITHIN_MS));
      await withinDeadline(writing, Math.min(deadlineMs, WRITE_WITHIN_MS), stop).finally(() => digestWriting);
    } catch (error) {
      if (!(error instanceof Stopped)) to.writeFailed(error);
    }
  };

  /**
   * Writes on a timer of their own while a run goes on, so what a lane has finished is kept however long another takes:
   * no lane waits for a write, and a write holds no connection. One at a time; `flush` joins any under way. Ends when told.
   */
  let writingAlong = false;
  const writeAlong = (to: AnchorLog, stop: AbortSignal | undefined): (() => void) => {
    let timer: ReturnType<typeof setTimeout>;
    let ended = false;
    const later = (): void => {
      timer = setTimeout(() => {
        writingAlong = true;
        void writeStore(to, stop).then(() => {
          writingAlong = false;
          if (!ended) later();
        });
      }, writeEveryMs);
      timer.unref();
    };
    later();
    return () => {
      ended = true;
      clearTimeout(timer);
    };
  };

  /** A chain the rotation found failing: the alarm, naming which read, and its hold. */
  const rotationFailed = async (
    from: OrganisationChains,
    orgId: string,
    check: RotationCheck,
    reason: string,
    seq?: bigint,
  ): Promise<void> => {
    failures.set(orgId, reason);
    logger
      .child({ orgId })
      .error('audit.integrity_failed', { chain: 'organisation', check, reason, ...(seq === undefined ? {} : { seq }) });
    await settle(from, orgId, undefined);
  };

  /** The rotation, where it has reads: its own memory of what is due, kept across runs. */
  const rotationOf = (from: OrganisationChains | undefined) =>
    from === undefined || rotatedChecks === undefined
      ? undefined
      : createRotation({
          checks: rotatedChecks,
          anchors,
          passes: durable ?? createMemoryPassRecord(),
          keys,
          clock,
          logger,
          epoch: durable?.epoch,
          lateAfterMs: reachWithinMs,
          lastRanAt: () => leftOffAt,
          sleeps,
          bounded: async (work, signal) => {
            // Within the lanes' share, as a turn: never a hand-off's connection.
            while (inFlight.size >= lanes && !signal.aborted) await roomOrEnd(signal);
            if (signal.aborted) throw new Stopped('the run has ended');
            return tracked(ROTATION, 'the last read of the rotation has not finished', work, signal);
          },
          // Its shards pinned for each step, where the log lets them go (PL-65 PR3).
          ...(durable === undefined ? {} : { shards: durable }),
          digest,
          failed: (orgId, check, { reason, seq }) => rotationFailed(from, orgId, check, reason, seq),
          missed: async (orgId, check, error) => {
            // A database that refuses the read is the alarm, as for any check; anything else a warning, and next run.
            if (error instanceof ChainStoreError || refusedByDatabase(error)) {
              await rotationFailed(from, orgId, check, 'store');
              return;
            }
            logger.child({ orgId }).warn('audit.anchor_check_failed', { chain: 'organisation', check, err: error });
          },
        });
  const rotation = rotationOf(organizations);

  /** Everything a run does up to its last write, each step cut off by `cap`: the run's time, or the stop. */
  const checkAll = async (cap: AbortSignal, stop: AbortSignal | undefined): Promise<Outcome[]> => {
    const outcomes: Outcome[] = [];
    for (const one of chains) {
      if (cap.aborted) break;
      outcomes.push(await checkOne(one, cap));
    }
    if (organizations !== undefined && !cap.aborted) {
      try {
        // Not spread into a call: past about 120,000, that is out of stack.
        for (const outcome of await checkOrganizations(organizations, cap, stop)) outcomes.push(outcome);
        // Not while a store kept is unread: its first look back must go to where the last process left off (E7).
        if (inUse !== undefined && (durable === undefined || leftOffTaken))
          await rotation?.run([...inUse, ...pastCap], cap, stop);
      } catch (error) {
        // Nothing may escape a run: the schedule would stop, and an unhandled rejection would end the process.
        logger.error('audit.anchor_check_crashed', { chain: 'organisation', err: error });
      }
    }
    return outcomes;
  };

  return Object.freeze({
    async probeWitnessed(orgIds: readonly string[], signal?: AbortSignal): Promise<void> {
      try {
        await probeWitnessedNow(orgIds, signal);
      } catch (error) {
        // The run's probe asks the same of every chain: a miss here is a warning, never the alarm.
        if (!(error instanceof Stopped)) sayProbeMissed(orgIds.length, error);
      }
    },

    async anchorOrganisation(orgId: string, signal?: AbortSignal): Promise<void> {
      if (organizations === undefined) return;
      // A hand-off may come before the run's first read, and joins it; once the store has failed, the run alone tries again.
      if (durable?.state() === 'unread') await readStore(durable, signal);
      if (storeUnread()) return;
      const id = orgId.toLowerCase();
      const outcome = await checkOne(
        {
          chain: { kind: 'organisation', orgId: id },
          verify: (anchor, heldTo, recent) => organizations.verify(id, anchor, heldTo, recent),
          ...confirmOf(organizations, id),
        },
        signal,
        true,
      );
      if (outcome === 'failed') await settle(organizations, id, signal);
    },

    async finish(): Promise<void> {
      if (durable === undefined) return;
      try {
        // Twice: a run's write may be under way, and the first joins it.
        const writing = durable.flush().then(() => durable.flush());
        const digestWriting = digestWritten(undefined, stopFlushMs);
        await withinDeadline(writing, stopFlushMs, undefined).finally(() => digestWriting);
      } catch (error) {
        durable.writeFailed(error);
      }
    },

    async run(signal?: AbortSignal): Promise<void> {
      // Ended by the run's time or the stop, whichever comes first.
      const ending = new AbortController();
      const end = (): void => {
        ending.abort();
      };
      const cap = ending.signal;
      const timer = setTimeout(end, runWithinMs);
      timer.unref();
      if (signal?.aborted === true) end();
      signal?.addEventListener('abort', end, { once: true });
      completed = 0;
      confirmBudget = runAllowance(confirming.size);
      probed.clear();
      awayShards = new Map();
      shardProbes.clear();
      missedThisRun = [];
      staleThisRun = [];
      unlistedThisRun = 0;
      firstMiss = undefined;
      if (durable !== undefined) await readStore(durable, cap);
      const endWrites = durable === undefined ? undefined : writeAlong(durable, signal);
      const outcomes = await checkAll(cap, signal);
      clearTimeout(timer);
      signal?.removeEventListener('abort', end);
      endWrites?.();
      sayMissed();
      if (signal?.aborted !== true) sayLeft(cap);
      if (durable !== undefined) {
        // A run stopped ends at once: `flush` never throws, and `finish`, where the API is stopping, joins it.
        if (signal?.aborted === true) void Promise.all([durable.flush(), digestWritten(undefined, stopFlushMs)]);
        else await writeStore(durable, signal, writingAlong);
      }
      const count = (outcome: Outcome): number => outcomes.filter((each) => each === outcome).length;
      logger.info('audit.anchor_check_done', {
        chains: outcomes.length,
        anchored: count('anchored'),
        unchanged: count('unchanged'),
        unanchored: count('unanchored'),
        failed: count('failed'),
        unchecked: count('unchecked'),
        left: turns.left(),
      });
    },
  });
}

/**
 * Runs the check now and then `intervalMs` after each run ends (scheduleRuns):
 * runs never overlap, and `stop` ends a run in flight at once, waits for it,
 * then writes what moved (`finish`).
 */
export function scheduleAnchorCheck(
  check: Pick<AnchorCheck, 'run'>,
  intervalMs: number,
  finish: () => Promise<void> = () => Promise.resolve(),
): { stop(): Promise<void> } {
  const runs = scheduleRuns(check, intervalMs);
  return {
    stop: async () => {
      await runs.stop();
      await finish();
    },
  };
}
