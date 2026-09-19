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
import {
  type AnchorPoint,
  appendEvent,
  type Chain,
  type ChainReader,
  type ChainReport,
  type ChainWriter,
  headFields,
  sealedFields,
  type StoredEntry,
  verifyChain,
} from '@agentx/platform/audit-chain';
import { assertTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { sql, type Transaction } from 'kysely';

import { canonicalDetails, type IdGenerator } from '../../../shared-kernel/index.ts';
import { type ActorType, type AuditEvent, AuditEventRefused, checkedEvent, eventContent } from '../domain/event.ts';
import type { AuditTables } from './tables.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A transaction on the audit tables, opened by withTenant for the organisation. */
export type AuditTransaction = Transaction<AuditTables>;

export interface RecordedAuditEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
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
}

/** The organisation's chain, named by its ID in lower case, as Postgres returns a uuid. */
function chainOf(orgId: string): Chain & { readonly kind: 'organisation' } {
  if (!UUID.test(orgId)) throw new AuditEventRefused(['the organisation ID must be a UUID']);
  return { kind: 'organisation', orgId: orgId.toLowerCase() };
}

const isText = (value: unknown): value is string => typeof value === 'string';

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

export function createAuditTrail({ keys, ids }: { readonly keys: KeyProvider; readonly ids: IdGenerator }): AuditTrail {
  return Object.freeze({
    async record(tx: AuditTransaction, orgId: string, input: AuditEvent): Promise<RecordedAuditEvent> {
      const event = checkedEvent(input, hidesField);
      const chain = chainOf(orgId);
      const details = canonicalDetails(event.details);
      const sealed = await appendEvent(keys, chain, writerFor(tx, chain.orgId, event, details), {
        nextId: () => ids.next(),
        content: eventContent(event, details),
      });
      return Object.freeze({ id: sealed.id, seq: sealed.seq, recordedAt: sealed.recordedAt });
    },

    async verify(tx: AuditTransaction, orgId: string, anchor: AnchorPoint | undefined): Promise<ChainReport> {
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      return verifyChain(keys, chain, readerFor(tx, chain.orgId), anchor);
    },
  });
}
