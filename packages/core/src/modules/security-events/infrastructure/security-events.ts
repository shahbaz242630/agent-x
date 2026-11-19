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
// - An event tied to one organisation (6E1b, CO7b: a verified member's or an
//   agent's) is written to that organisation's own table (0091) inside its
//   transaction, never to the global one: a batch is one organisation's
//   events or none's, so each write is whole. `sweepOrganisation` deletes one
//   organisation's past their retention, inside its transaction too.
// - Each row is written with its MAC (0106, S206 V6; event-seals.ts), made
//   here: the write stays one INSERT, with no lock beyond its own rows.
//
// Each runs in a transaction of its own whose statements give up after 10
// seconds, a wait for a lock included.
import { limitStatements, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely } from 'kysely';

import { type Clock, DAY_MS, type IdGenerator, isIpAddress, UUID } from '../../../shared-kernel/index.ts';
import { eventMac } from './event-seals.ts';
import type { SecurityEventsTables } from './tables.ts';

export const SECURITY_EVENT_KINDS = [
  'sign_in_failed',
  'rate_limited',
  'partner_event_refused',
  // 0093 (6E3a): an OAuth client refused before any organisation is known.
  'oauth_refused',
  // 0093 (6E3a): an MCP connection's refresh token used twice, the connection revoked: its organisation's alone.
  'connection_token_reused',
] as const;
export type SecurityEventKind = (typeof SECURITY_EVENT_KINDS)[number];

/** The kinds an organisation's own events can be (0091): a partner's refused message, or an OAuth client's, never. */
export const ORG_EVENT_KINDS = [
  'sign_in_failed',
  'rate_limited',
  'connection_token_reused',
] as const satisfies readonly SecurityEventKind[];

/** The kinds only ever an organisation's (0093): never written where no organisation is named. */
const ONLY_AN_ORGANISATIONS: readonly SecurityEventKind[] = ['connection_token_reused'];

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
  /** The organisation it is tied to, when the API verified one (6E1b); none for an event no organisation may see. */
  readonly orgId?: string | undefined;
  /** The agent refused, with its organisation; never beside a person. */
  readonly agentId?: string | undefined;
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
  /** Deletes up to `most` of one organisation's own events past the retention period, oldest first, and says how many. */
  sweepOrganisation(db: Kysely<SecurityEventsTables>, orgId: string, most: number): Promise<number>;
}

const REASON = /^[a-z][a-z_]{0,63}$/;

/** Why who an event names can't be written, if it can't: its person, organisation and agent. */
function ownerProblem(event: SecurityEvent): string | undefined {
  if (event.userId !== undefined && !UUID.test(event.userId)) return 'its person is not a UUID';
  if (event.orgId !== undefined && !UUID.test(event.orgId)) return 'its organisation is not a UUID';
  if (event.agentId !== undefined && !UUID.test(event.agentId)) return 'its agent is not a UUID';
  if (event.agentId !== undefined && event.orgId === undefined) return 'its agent has no organisation';
  if (event.agentId !== undefined && event.userId !== undefined) return 'it names both a person and an agent';
  if (event.orgId !== undefined && !(ORG_EVENT_KINDS as readonly string[]).includes(event.kind))
    return "its kind is never an organisation's";
  if (event.orgId === undefined && ONLY_AN_ORGANISATIONS.includes(event.kind))
    return "its kind is only an organisation's";
  return undefined;
}

/** Why an event can't be written, if it can't. */
function problemWith(event: SecurityEvent, now: Date): string | undefined {
  if (!SECURITY_EVENT_KINDS.includes(event.kind)) return 'its kind is not one we record';
  if (typeof event.reason !== 'string' || !REASON.test(event.reason)) return 'its reason is not a short lowercase name';
  const owner = ownerProblem(event);
  if (owner !== undefined) return owner;
  if (!(event.windowStart instanceof Date) || Number.isNaN(event.windowStart.getTime()))
    return 'its window has no start';
  if (event.windowStart > now) return 'its window starts in the future';
  if (!Number.isSafeInteger(event.count) || event.count < 1) return 'its count is not a whole number from 1';
  return undefined;
}

export function createSecurityEvents({
  ids,
  clock,
  keys,
  retentionDays,
}: {
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** Holds `session-mac`, each row's MAC's key. */
  readonly keys: KeyProvider;
  /** How long an event is kept: AGENTX_SECURITY_EVENT_RETENTION_DAYS. */
  readonly retentionDays: number;
}): SecurityEvents {
  if (!Number.isSafeInteger(retentionDays) || retentionDays < LEAST_RETENTION_DAYS) {
    throw new RangeError(`security events are kept at least ${String(LEAST_RETENTION_DAYS)} whole days`);
  }

  /** The row of `event` as written at `now` for the organisation (null for none), with its MAC: all but its agent's. */
  const rowOf = (event: SecurityEvent, orgId: string | null, now: Date) => {
    const facts = {
      id: ids.next(),
      orgId,
      kind: event.kind,
      reason: event.reason,
      ip: event.ip !== undefined && isIpAddress(event.ip) ? event.ip : null,
      userId: event.userId ?? null,
      agentId: event.agentId ?? null,
      windowStart: event.windowStart,
      count: event.count,
      createdAt: now,
    };
    return {
      id: facts.id,
      kind: facts.kind,
      reason: facts.reason,
      ip: facts.ip,
      user_id: facts.userId,
      window_start: facts.windowStart,
      count: facts.count,
      created_at: now,
      ...eventMac(keys, facts),
    };
  };

  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(db: Kysely<SecurityEventsTables>, work: (tx: Kysely<SecurityEventsTables>) => Promise<T>) =>
    db.transaction().execute(async (tx) => {
      await limitStatements(tx);
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
      const orgId = events[0]?.orgId;
      if (events.some((event) => event.orgId?.toLowerCase() !== orgId?.toLowerCase())) {
        throw new RangeError("a batch of security events is one organisation's, or none's");
      }
      if (orgId !== undefined) {
        // Inside the organisation's own transaction: its wall is the database's, on the write too.
        await withTenant(
          db,
          orgId,
          (tx) =>
            tx
              .insertInto('security.org_events')
              .values(
                events.map((event) => ({
                  org_id: orgId.toLowerCase(),
                  agent_id: event.agentId ?? null,
                  ...rowOf(event, orgId, now),
                })),
              )
              .execute(),
          { limited: true },
        );
        return;
      }
      await limited(db, (tx) =>
        tx
          .insertInto('security.events')
          // The global table has no agent column: an agent is always an organisation's (ownerProblem).
          .values(events.map((event) => rowOf(event, null, now)))
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

    async sweepOrganisation(db, orgId, most) {
      if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one event at a time');
      const past = new Date(clock.now().getTime() - retentionDays * DAY_MS);
      return withTenant(
        db,
        orgId,
        async (tx) => {
          const oldest = tx
            .selectFrom('security.org_events')
            .select('id')
            .where('org_id', '=', orgId.toLowerCase())
            // Its window starts no later than it was written: the index finds them, the time written keeps each its days.
            .where('window_start', '<=', past)
            .where('created_at', '<=', past)
            .orderBy('window_start')
            .limit(most);
          // An event is never changed, so the rows found are still past their retention when deleted.
          const rows = await tx
            .deleteFrom('security.org_events')
            .where('org_id', '=', orgId.toLowerCase())
            .where('id', 'in', oldest)
            .returning('id')
            .execute();
          return rows.length;
        },
        { limited: true },
      );
    },
  };
}
