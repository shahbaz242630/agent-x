// The partner's messages as Agent X keeps them (Phase 4 E1b; ADR-007 §12;
// SEC-PTR-01, -03, -05; 0063), in two global tables: a message arrives before
// any organisation is known.
//
// - `takeIn`: a verified message, one row a message by its partner and dedupe
//   key, so a replay adds nothing (SEC-PTR-03); routed to the organisation its
//   reference found, or none, whose body alone is kept, encrypted, for
//   investigation (SEC-PTR-05). A message is a nudge: the row holds what it
//   names, never a status.
// - `waiting`, `tried` and `taken`: the bank check (E1a) takes each routed
//   row once, oldest first, and checks the payments it names with the bank;
//   one it couldn't take after MOST_TRIES is left for the regular check, so
//   it never holds up the messages behind it.
// - `keepRefused`: a refused message (a bad signature, a stale time, a
//   malformed body) kept as security evidence, encrypted, its first 16 KiB:
//   the first MOST_KEPT_AN_HOUR an hour from one network (an IPv6 /64, as the
//   rate limit keys it; an IPv4 address), at most MOST_KEPT_AN_HOUR_IN_ALL an
//   hour from everyone, counted and written under one lock (SEC-PTR-01). A
//   flood is counted in `security.events`, never stored.
// - `sweep`: both tables past the security events' retention.
//
// Each runs in a transaction of its own whose statements give up after 10
// seconds, a wait for a lock included.
import type { KeyProvider } from '@agentx/platform/keys';
import { limitStatements } from '@agentx/platform/db';
import { type Kysely, sql, type SqlBool } from 'kysely';

import { type Clock, DAY_MS, type IdGenerator, isIpAddress } from '../../../shared-kernel/index.ts';
import type { EventReference, EventRefusal, PartnerEvent } from '../../providers/index.ts';
import type { ProviderEventsTables } from './tables.ts';

/** How many refused messages from one network are kept an hour; the rest are only counted. */
export const MOST_KEPT_AN_HOUR = 5;

/** How many refused messages are kept an hour from every network together: a botnet's flood is counted, not stored. */
export const MOST_KEPT_AN_HOUR_IN_ALL = 50;

/** How many runs try to take a message before it is left to the regular check. */
export const MOST_TRIES = 5;

/** How much of a refused message's body is kept. */
export const MOST_KEPT_BYTES = 16 * 1024;

const HOUR_MS = 60 * 60_000;

/** A routed message the bank check hasn't taken yet. */
export interface Nudge {
  readonly id: string;
  readonly orgId: string;
  readonly reference: EventReference;
}

export interface ProviderEvents {
  /** Keeps a verified message, routed to `orgId` (null: its reference is unknown); `replay` where it was kept before. */
  takeIn(
    db: Kysely<ProviderEventsTables>,
    event: PartnerEvent,
    orgId: string | null,
    body: Uint8Array,
  ): Promise<'new' | 'replay'>;
  /** Up to `most` routed messages not yet taken nor tried MOST_TRIES times, oldest first. */
  waiting(db: Kysely<ProviderEventsTables>, most: number): Promise<Nudge[]>;
  /** One more try at the message counted; says how many it has had. */
  tried(db: Kysely<ProviderEventsTables>, id: string): Promise<number>;
  /** The message taken by the bank check. */
  taken(db: Kysely<ProviderEventsTables>, id: string): Promise<void>;
  /**
   * A refused message kept as evidence (`first`: the first from its network
   * this hour, the one to alert on), or only counted past the hour's caps.
   */
  keepRefused(
    db: Kysely<ProviderEventsTables>,
    refused: { readonly reason: EventRefusal; readonly ip: string | undefined; readonly body: Uint8Array },
  ): Promise<'first' | 'kept' | 'capped'>;
  /** An unknown message's kept body, opened (an investigation's read). */
  unknownBody(db: Kysely<ProviderEventsTables>, id: string): Promise<Buffer | undefined>;
  /** A refused message's kept body, opened (an investigation's read). */
  refusedBody(db: Kysely<ProviderEventsTables>, id: string): Promise<Buffer | undefined>;
  /** Deletes up to `most` rows of each table past the retention, oldest first, and says how many. */
  sweep(db: Kysely<ProviderEventsTables>, most: number): Promise<number>;
}

const inboxData = (id: string) => ['provider_events.inbox', id.toLowerCase()] as const;
const evidenceData = (id: string) => ['security.partner_event_evidence', id.toLowerCase()] as const;

export function createProviderEvents({
  keys,
  ids,
  clock,
  retentionDays,
}: {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** How long a message is kept: the security events' retention (AGENTX_SECURITY_EVENT_RETENTION_DAYS). */
  readonly retentionDays: number;
}): ProviderEvents {
  const limited = <T>(db: Kysely<ProviderEventsTables>, work: (tx: Kysely<ProviderEventsTables>) => Promise<T>) =>
    db.transaction().execute(async (tx) => {
      await limitStatements(tx);
      return work(tx);
    });

  return {
    takeIn: (db, event, orgId, body) =>
      limited(db, async (tx) => {
        const id = ids.next();
        const sealed = orgId === null ? keys.encrypt('field-encryption', body, inboxData(id)) : undefined;
        const added = await tx
          .insertInto('provider_events.inbox')
          .values({
            id,
            partner: event.partner,
            dedupe_key: event.dedupeKey,
            event_type: event.eventType,
            reference_kind: event.reference.kind,
            reference:
              event.reference.kind === 'instruction' ? event.reference.instructionId : event.reference.consentId,
            org_id: orgId,
            received_at: clock.now(),
            taken_at: null,
            attempts: 0,
            body_ciphertext: sealed?.ciphertext ?? null,
            body_key_version: sealed?.keyVersion ?? null,
          })
          .onConflict((conflict) => conflict.columns(['partner', 'dedupe_key']).doNothing())
          .executeTakeFirst();
        return added.numInsertedOrUpdatedRows === 1n ? 'new' : 'replay';
      }),

    waiting: (db, most) =>
      limited(db, async (tx) =>
        (
          await tx
            .selectFrom('provider_events.inbox')
            .select(['id', 'org_id', 'reference_kind', 'reference'])
            .where('taken_at', 'is', null)
            .where('org_id', 'is not', null)
            .where('attempts', '<', MOST_TRIES)
            .orderBy('received_at')
            .orderBy('id')
            .limit(most)
            .execute()
        ).map(({ id, org_id, reference_kind, reference }) => ({
          id,
          orgId: org_id ?? '',
          reference:
            reference_kind === 'instruction'
              ? { kind: 'instruction', instructionId: reference }
              : { kind: 'consent', consentId: reference },
        })),
      ),

    tried: (db, id) =>
      limited(db, async (tx) => {
        const row = await tx
          .updateTable('provider_events.inbox')
          .set((set) => ({ attempts: set('attempts', '+', 1) }))
          .where('id', '=', id)
          .returning('attempts')
          .executeTakeFirst();
        return row?.attempts ?? MOST_TRIES;
      }),

    taken: async (db, id) => {
      await limited(db, (tx) =>
        tx
          .updateTable('provider_events.inbox')
          .set({ taken_at: clock.now() })
          .where('id', '=', id)
          .where('taken_at', 'is', null)
          .execute(),
      );
    },

    keepRefused: (db, { reason, ip, body }) =>
      limited(db, async (tx) => {
        // One lock for every refused message: the counts below and the write after them never race (S102).
        await sql`select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('security.partner_event_evidence', 0))`.execute(
          tx,
        );
        const address = ip !== undefined && isIpAddress(ip) ? ip : null;
        const now = clock.now();
        const hourAgo = new Date(now.getTime() - HOUR_MS);
        // Its network as the rate limit keys it: an IPv6 /64 (one holder's), an IPv4 address alone.
        const network =
          address === null
            ? null
            : sql<string>`pg_catalog.network(pg_catalog.set_masklen(${address}::inet, case when pg_catalog.family(${address}::inet) = 6 then 64 else 32 end))`;
        const counts = await tx
          .selectFrom('security.partner_event_evidence')
          .select((select) => [
            select.fn.countAll<string>().as('all'),
            select.fn
              .count<string>('id')
              .filterWhere(network === null ? sql<SqlBool>`ip is null` : sql<SqlBool>`ip <<= ${network}`)
              .as('from_network'),
          ])
          .where('received_at', '>', hourAgo)
          .executeTakeFirstOrThrow();
        const fromNetwork = Number(counts.from_network);
        if (fromNetwork >= MOST_KEPT_AN_HOUR || Number(counts.all) >= MOST_KEPT_AN_HOUR_IN_ALL) return 'capped';
        const id = ids.next();
        const kept = body.subarray(0, MOST_KEPT_BYTES);
        const sealed = keys.encrypt('field-encryption', kept, evidenceData(id));
        await tx
          .insertInto('security.partner_event_evidence')
          .values({
            id,
            reason,
            ip: address,
            body_ciphertext: sealed.ciphertext,
            body_key_version: sealed.keyVersion,
            body_bytes: kept.length,
            received_at: now,
          })
          .execute();
        return fromNetwork === 0 ? 'first' : 'kept';
      }),

    unknownBody: async (db, id) => {
      const row = await db
        .selectFrom('provider_events.inbox')
        .select(['body_ciphertext', 'body_key_version'])
        .where('id', '=', id)
        .executeTakeFirst();
      if (row === undefined || row.body_ciphertext === null || row.body_key_version === null) return undefined;
      return keys.decrypt(
        'field-encryption',
        { ciphertext: row.body_ciphertext, keyVersion: row.body_key_version },
        inboxData(id),
      );
    },

    refusedBody: async (db, id) => {
      const row = await db
        .selectFrom('security.partner_event_evidence')
        .select(['body_ciphertext', 'body_key_version'])
        .where('id', '=', id)
        .executeTakeFirst();
      if (row === undefined) return undefined;
      return keys.decrypt(
        'field-encryption',
        { ciphertext: row.body_ciphertext, keyVersion: row.body_key_version },
        evidenceData(id),
      );
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one row at a time');
      const past = new Date(clock.now().getTime() - retentionDays * DAY_MS);
      return limited(db, async (tx) => {
        const inbox = await tx
          .deleteFrom('provider_events.inbox')
          .where(
            'id',
            'in',
            tx
              .selectFrom('provider_events.inbox')
              .select('id')
              .where('received_at', '<=', past)
              .orderBy('received_at')
              .limit(most),
          )
          .returning('id')
          .execute();
        const evidence = await tx
          .deleteFrom('security.partner_event_evidence')
          .where(
            'id',
            'in',
            tx
              .selectFrom('security.partner_event_evidence')
              .select('id')
              .where('received_at', '<=', past)
              .orderBy('received_at')
              .limit(most),
          )
          .returning('id')
          .execute();
        return inbox.length + evidence.length;
      });
    },
  };
}
