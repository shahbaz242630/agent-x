// Security events (ADR-005 §6, ADR-011 §7; Phase 1 B2-5): failed sign-ins and
// rate-limit hits, with the client's IP address, kept in-country in our own
// database and nowhere else.
//
// - `record` writes a batch of counts, each the events of one kind, reason,
//   address and person in one window (B2-5b gathers them in memory and writes
//   them a batch at a time, so a flood is a count, not a row per request).
//   What the API decides (the kind, the reason, the person, the window, the
//   count) must be well formed, or the whole batch is refused before any SQL:
//   a bug, never a partial write. The address is the one part that comes from
//   outside: one that isn't a plain IP address is kept as unknown, and the
//   event with it, so an odd proxy header can't lose a batch (the review of
//   B2-5a; the API strips a port or brackets first, as the rate limit does).
// - `sweep` deletes up to a batch of rows past the retention period, oldest
//   first (hourly, from the API).
//
// Each runs in a transaction of its own whose statements give up after 10
// seconds, a wait for a lock included.
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import type { SecurityEventsTables } from './tables.ts';

export const SECURITY_EVENT_KINDS = ['sign_in_failed', 'rate_limited'] as const;
export type SecurityEventKind = (typeof SECURITY_EVENT_KINDS)[number];

/** The least time a security event is kept: AGENTX_SECURITY_EVENT_RETENTION_DAYS's minimum. */
export const LEAST_RETENTION_DAYS = 30;

/** The most events one `record` writes. */
export const MOST_EVENTS_A_BATCH = 1_000;

export interface SecurityEvent {
  readonly kind: SecurityEventKind;
  /** Why, in the kind's own words: lowercase letters and underscores, at most 64. */
  readonly reason: string;
  /** The client's address as the API saw it; undefined if it had none it could read. Anything but a plain IP address is kept as unknown. */
  readonly ip: string | undefined;
  /** The person, when the event is about a signed-in one. */
  readonly userId: string | undefined;
  /** When the window these events were counted in began. */
  readonly windowStart: Date;
  /** How many there were: a whole number from 1. */
  readonly count: number;
}

export interface SecurityEvents {
  /** Writes these events, at most MOST_EVENTS_A_BATCH. Throws RangeError for anything malformed, writing nothing. */
  record(db: Kysely<SecurityEventsTables>, events: readonly SecurityEvent[]): Promise<void>;
  /** Deletes up to `most` events past the retention period, oldest first, and says how many. */
  sweep(db: Kysely<SecurityEventsTables>, most: number): Promise<number>;
}

const REASON = /^[a-z][a-z_]{0,63}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DAY_MS = 86_400_000;

const OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4 = new RegExp(`^${OCTET}(?:[.]${OCTET}){3}$`);

/**
 * An IPv4 address in dotted form, or an IPv6 address as a URL's host takes one
 * (no zone, no port). Checked here rather than with node:net, which the
 * boundary rules keep to the outbound fetch.
 */
const isIpAddress = (text: string): boolean => IPV4.test(text) || URL.canParse(`http://[${text}]/`);

/** Why an event can't be written, if it can't. */
function problemWith(event: SecurityEvent, now: Date): string | undefined {
  if (!SECURITY_EVENT_KINDS.includes(event.kind)) return 'its kind is not one we record';
  if (typeof event.reason !== 'string' || !REASON.test(event.reason)) return 'its reason is not a short lowercase name';
  if (event.userId !== undefined && !UUID.test(event.userId)) return 'its person is not a UUID';
  if (!(event.windowStart instanceof Date) || Number.isNaN(event.windowStart.getTime()))
    return 'its window has no start';
  if (event.windowStart > now) return 'its window starts in the future';
  if (!Number.isSafeInteger(event.count) || event.count < 1) return 'its count is not a whole number from 1';
  return undefined;
}

export function createSecurityEvents({
  ids,
  clock,
  retentionDays,
}: {
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** How long an event is kept: AGENTX_SECURITY_EVENT_RETENTION_DAYS. */
  readonly retentionDays: number;
}): SecurityEvents {
  if (!Number.isSafeInteger(retentionDays) || retentionDays < LEAST_RETENTION_DAYS) {
    throw new RangeError(`security events are kept at least ${String(LEAST_RETENTION_DAYS)} whole days`);
  }

  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(db: Kysely<SecurityEventsTables>, work: (tx: Kysely<SecurityEventsTables>) => Promise<T>) =>
    db.transaction().execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return work(tx);
    });

  return {
    async record(db, events) {
      if (events.length === 0) return;
      if (events.length > MOST_EVENTS_A_BATCH) {
        throw new RangeError(`at most ${String(MOST_EVENTS_A_BATCH)} security events are written at a time`);
      }
      const now = clock.now();
      for (const event of events) {
        const problem = problemWith(event, now);
        if (problem !== undefined) throw new RangeError(`a security event can't be written: ${problem}`);
      }
      await limited(db, (tx) =>
        tx
          .insertInto('security.events')
          .values(
            events.map((event) => ({
              id: ids.next(),
              kind: event.kind,
              reason: event.reason,
              ip: event.ip !== undefined && isIpAddress(event.ip) ? event.ip : null,
              user_id: event.userId ?? null,
              window_start: event.windowStart,
              count: event.count,
              created_at: now,
            })),
          )
          .execute(),
      );
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one event at a time');
      const past = new Date(clock.now().getTime() - retentionDays * DAY_MS);
      return limited(db, async (tx) => {
        const oldest = tx
          .selectFrom('security.events')
          .select('id')
          .where('created_at', '<=', past)
          .orderBy('created_at')
          .limit(most);
        // An event is never changed, so the rows found are still past their retention when deleted.
        const rows = await tx.deleteFrom('security.events').where('id', 'in', oldest).returning('id').execute();
        return rows.length;
      });
    },
  };
}
