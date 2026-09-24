// The security events' recorder (ADR-011 §7, SEC-AV-07; Phase 1 B2-5b):
// failed sign-ins and rate-limit hits, counted in memory and written to
// `security.events` (B2-5a) a batch at a time, so a flood is a count, not a
// row per request.
//
// - `note` counts one event under its kind, reason, address, person and
//   minute. It never throws and never waits: it runs inside requests, the
//   rate limit's refusals included.
// - The address is the client's full address, a port or brackets taken off as
//   the rate limit does (`clientAddress`), never the rate limit's /64 key.
// - At most `mostCounts` counts are held. Past that, a new address's events
//   are counted without their address or person, so a flood from many
//   addresses still shows, and memory stays bounded.
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
export const MOST_COUNTS = 10_000;

export interface SecurityEventNote {
  readonly kind: SecurityEventKind;
  /** Why, in the kind's own words: lowercase letters and underscores. */
  readonly reason: string;
  /** The client's address as the request had it; undefined if it had none. */
  readonly ip: string | undefined;
  /** The person, when the event is about a signed-in one. */
  readonly userId?: string | undefined;
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
  JSON.stringify([event.kind, event.reason, event.ip ?? null, event.userId ?? null, event.windowStart.getTime()]);

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

  const add = (event: Omit<SecurityEvent, 'count'>, count: number): void => {
    let key = keyOf(event);
    let entry = held.get(key);
    if (entry === undefined && held.size >= mostCounts) {
      // Full: counted all the same, without what makes one count differ from another.
      unaddressed += count;
      event = { ...event, ip: undefined, userId: undefined };
      key = keyOf(event);
      entry = held.get(key);
    }
    if (entry === undefined) held.set(key, { event, count });
    else entry.count += count;
  };

  /**
   * Takes the counts out whose window began before `before`, and writes them a
   * batch at a time. Once `stopNow` says so, the batches not yet begun are put
   * back; the one under way is left to finish, so no count is written twice.
   */
  const writeBefore = async (before: number, stopNow: () => boolean): Promise<void> => {
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
    for (let start = 0; start < taken.length; start += MOST_EVENTS_A_BATCH) {
      if (stopNow()) {
        for (const event of taken.slice(start)) add(event, event.count);
        return;
      }
      const batch = taken.slice(start, start + MOST_EVENTS_A_BATCH);
      try {
        await write(batch);
      } catch (error) {
        if (error instanceof RangeError) {
          // Malformed by our own hand: writing it again would fail again.
          logger.error('security.events_refused', { events: batch.length, err: error });
          continue;
        }
        const left = taken.slice(start);
        for (const event of left) add(event, event.count);
        logger.warn('security.events_write_failed', { events: left.length, err: error });
        return;
      }
      logger.info('security.events_written', {
        events: batch.length,
        count: batch.reduce((sum, event) => sum + event.count, 0),
      });
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

  return Object.freeze({
    note(note: SecurityEventNote): void {
      add(
        {
          kind: note.kind,
          reason: note.reason,
          ip: clientAddress(note.ip),
          userId: note.userId,
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
      if (held.size > 0) {
        let count = 0;
        for (const entry of held.values()) count += entry.count;
        logger.error('security.events_unwritten', { events: held.size, count });
        held.clear();
      }
    },
  });
}
