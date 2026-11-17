// The security events' recorder (ADR-011 §7, SEC-AV-07; Phase 1 B2-5b):
// failed sign-ins and rate-limit hits, counted in memory and written to
// `security.events` (B2-5a) a batch at a time, so a flood is a count, not a
// row per request.
//
// - `note` counts one event under its kind, reason, address, person, agent,
//   organisation and minute. It never throws and never waits: it runs inside requests, the
//   rate limit's refusals included.
// - The address is the client's full address, a port or brackets taken off as
//   the rate limit does (`clientAddress`), never the rate limit's /64 key.
// - At most `mostCounts` counts are held. Past that, a new address's events
//   are counted without their address or person, so a flood from many
//   addresses still shows, and memory stays bounded. Such a count is tied to
//   no organisation either (6E1b): it goes to the global table.
// - The organisation (6E1b, CO7b) is one the API verified: a member's once
//   their membership was found active, an agent's by its accepted key. A
//   batch is one organisation's counts or none's: it is written in that one
//   organisation's tenant transaction, whose wall refuses any other's row.
// - `run` writes every count whose minute has ended (the API runs it each
//   minute); `flush` writes them all (the API runs it as it stops, once the
//   last request has been answered). The run begins no batch once the API is
//   stopping, and the flush none that could end past the deadline the API
//   gives it (the reviews of B2-5b: a flood's backlog to a slow database
//   would otherwise outlast the stop deadline and be lost unseen); what the
//   flush leaves is logged with its count.
// - A write the database couldn't take puts its counts back for the next run.
//   One the module refuses as malformed is a bug: it is logged and dropped,
//   never retried for ever.
import { MOST_EVENTS_A_BATCH, type SecurityEvent, type SecurityEventKind } from '@agentx/core/modules/security-events';
import type { Logger } from '@agentx/platform/observability';

import { clientAddress } from './rate-limit.ts';

/** Events are counted per minute. */
const WINDOW_MS = 60_000;

/**
 * The longest one batch's write may take: the module's 10-second statement
 * limit. The last write begins a batch only if it would end by its deadline
 * even taking this long.
 */
export const LONGEST_BATCH_MS = 10_000;

/** The most counts held at once, unless the API says otherwise. */
const MOST_COUNTS = 10_000;

export interface SecurityEventNote {
  readonly kind: SecurityEventKind;
  /** Why, in the kind's own words: lowercase letters and underscores. */
  readonly reason: string;
  /** The client's address as the request had it; undefined if it had none. */
  readonly ip: string | undefined;
  /** The person, when the event is about a signed-in one. */
  readonly userId?: string | undefined;
  /** The organisation the API verified the person or agent in (6E1b); none and no organisation ever sees it. */
  readonly orgId?: string | null | undefined;
  /** The agent refused, with its organisation. */
  readonly agentId?: string | undefined;
}

/** Where the API's routes and hooks note security events. */
export interface SecurityEventSink {
  /** Counts one event. Never throws. */
  note(event: SecurityEventNote): void;
}

/** A sink that counts nothing, for a server built without one. */
export const NO_SECURITY_EVENTS: SecurityEventSink = Object.freeze({ note: () => undefined });

export interface SecurityRecorder extends SecurityEventSink {
  /** Writes every count whose minute has ended, stopping between batches once `signal` aborts. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
  /**
   * Writes every count, the current minute's too, beginning no batch that
   * could end after `until` (a time in milliseconds), then logs and drops
   * whatever it couldn't write: the API calls it last, as it stops. Never throws.
   */
  flush(until: number): Promise<void>;
  /**
   * Logs and drops every count still held, writing none: the process is
   * ending at once (a crash), with no time to write (MO4). Never throws.
   */
  drop(): void;
}

export interface SecurityRecorderOptions {
  /** Writes a batch of at most MOST_EVENTS_A_BATCH events (SecurityEvents.record). */
  readonly write: (events: readonly SecurityEvent[]) => Promise<void>;
  /** The time now, in milliseconds. */
  readonly now: () => number;
  readonly logger: Logger;
  /** The most counts held at once; MOST_COUNTS when not given. */
  readonly mostCounts?: number;
}

interface Held {
  readonly event: Omit<SecurityEvent, 'count'>;
  count: number;
}

const keyOf = (event: Omit<SecurityEvent, 'count'>): string =>
  JSON.stringify([
    event.kind,
    event.reason,
    event.ip ?? null,
    event.userId ?? null,
    event.orgId ?? null,
    event.agentId ?? null,
    event.windowStart.getTime(),
  ]);

/** The counts as batches to write: each one organisation's or none's, and at most MOST_EVENTS_A_BATCH. */
function batchesOf(taken: readonly SecurityEvent[]): SecurityEvent[][] {
  const byOrg = new Map<string | undefined, SecurityEvent[]>();
  for (const event of taken) {
    const events = byOrg.get(event.orgId);
    if (events === undefined) byOrg.set(event.orgId, [event]);
    else events.push(event);
  }
  return [...byOrg.values()].flatMap((events) => {
    const batches: SecurityEvent[][] = [];
    for (let start = 0; start < events.length; start += MOST_EVENTS_A_BATCH) {
      batches.push(events.slice(start, start + MOST_EVENTS_A_BATCH));
    }
    return batches;
  });
}

export function createSecurityRecorder({
  write,
  now,
  logger,
  mostCounts = MOST_COUNTS,
}: SecurityRecorderOptions): SecurityRecorder {
  const held = new Map<string, Held>();
  /** How many events were counted without their address since the last write, because too many counts were held. */
  let unaddressed = 0;
  /** Writes one after another, so a flush never races the minute's run. */
  let writing: Promise<void> = Promise.resolve();
  /** Counts taken out for a write and not yet written or put back: what a crash mid-write would lose (MO4). */
  let inFlight: { batches: readonly (readonly SecurityEvent[])[]; from: number } = { batches: [], from: 0 };

  const add = (event: Omit<SecurityEvent, 'count'>, count: number): void => {
    let key = keyOf(event);
    let entry = held.get(key);
    if (entry === undefined && held.size >= mostCounts) {
      // Full: counted all the same, without what makes one count differ from another.
      unaddressed += count;
      event = { ...event, ip: undefined, userId: undefined, orgId: undefined, agentId: undefined };
      key = keyOf(event);
      entry = held.get(key);
    }
    if (entry === undefined) held.set(key, { event, count });
    else entry.count += count;
  };

  /** Takes the counts out whose window began before `before`, and reports any counted without address. */
  const takeBefore = (before: number): SecurityEvent[] => {
    const taken: SecurityEvent[] = [];
    for (const [key, entry] of held) {
      if (entry.event.windowStart.getTime() >= before) continue;
      held.delete(key);
      taken.push({ ...entry.event, count: entry.count });
    }
    if (unaddressed > 0) {
      logger.warn('security.events_unaddressed', { count: unaddressed, mostCounts });
      unaddressed = 0;
    }
    return taken;
  };

  /**
   * Takes the counts out whose window began before `before`, and writes them a
   * batch at a time. Once `stopNow` says so, the batches not yet begun are put
   * back; the one under way is left to finish, so no count is written twice.
   */
  const writeBefore = async (before: number, stopNow: () => boolean): Promise<void> => {
    const batches = batchesOf(takeBefore(before));
    /** Puts the batches from `index` on back to be written next run, and says how many events they held. */
    const putBack = (index: number): number => {
      let events = 0;
      for (const batch of batches.slice(index)) {
        for (const event of batch) add(event, event.count);
        events += batch.length;
      }
      return events;
    };
    // What a crash would lose: the batches from `from` on (a place, never a copy of the rest each batch).
    inFlight = { batches, from: 0 };
    try {
      for (const [index, batch] of batches.entries()) {
        if (stopNow()) {
          putBack(index);
          return;
        }
        try {
          await write(batch);
        } catch (error) {
          if (error instanceof RangeError) {
            // Malformed by our own hand: writing it again would fail again.
            logger.error('security.events_refused', { events: batch.length, err: error });
            inFlight.from = index + 1;
            continue;
          }
          const left = putBack(index);
          logger.warn('security.events_write_failed', { events: left, err: error });
          return;
        }
        inFlight.from = index + 1;
        logger.info('security.events_written', {
          events: batch.length,
          count: batch.reduce((sum, event) => sum + event.count, 0),
        });
      }
    } finally {
      // Written, refused or put back in held: none is in flight now.
      inFlight = { batches: [], from: 0 };
    }
  };

  const queued = (before: () => number, stopNow: () => boolean): Promise<void> => {
    writing = writing
      .then(() => writeBefore(before(), stopNow))
      .catch((error: unknown) => {
        // Only the logger could get here; the next run must still go ahead.
        logger.error('security.events_write_failed', { err: error });
      });
    return writing;
  };

  /** The start of the current minute: every window before it has ended. */
  const thisMinute = (): number => {
    const at = now();
    return at - (at % WINDOW_MS);
  };

  /** Whatever is still held is lost as the process ends: counted here, so the log says what the store never got. */
  const dropHeld = (): void => {
    // A crash mid-write: the batch under way may or may not have been written, and those after it never will be.
    const lost = inFlight.batches.slice(inFlight.from).flat();
    const flying = lost.reduce((sum, event) => sum + event.count, 0);
    if (held.size === 0 && flying === 0) return;
    let count = 0;
    for (const entry of held.values()) count += entry.count;
    logger.error('security.events_unwritten', {
      events: held.size,
      count,
      ...(flying > 0 && { inFlightEvents: lost.length, inFlightCount: flying }),
    });
    held.clear();
  };

  return Object.freeze({
    note(note: SecurityEventNote): void {
      add(
        {
          kind: note.kind,
          reason: note.reason,
          ip: clientAddress(note.ip),
          userId: note.userId,
          orgId: note.orgId?.toLowerCase(),
          agentId: note.agentId,
          windowStart: new Date(thisMinute()),
        },
        1,
      );
    },
    run: (signal?: AbortSignal) => queued(thisMinute, () => signal?.aborted === true),
    async flush(until: number): Promise<void> {
      await queued(
        () => Number.POSITIVE_INFINITY,
        () => now() + LONGEST_BATCH_MS > until,
      );
      // The process is stopping: whatever is still held is lost, so it is counted here.
      dropHeld();
    },
    drop: dropHeld,
  });
}
