// The platform's own audit chain in Postgres (ADR-011 §3, ADR-014 §8):
// schema `platform_controls`, one chain for the whole platform. Recording and
// checking follow the steps in @agentx/platform/audit-chain, as the
// organisation chains do, given a store over these tables. They belong to no
// organisation, so they are global tables: no tenant is needed to reach them.
//
// The head is the table's only row by its key. Should someone with the owner's
// rights drop that key and add a second head, the chain counts as having no
// readable head: recording is refused and the check fails.
import {
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
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { sql, type Transaction } from 'kysely';

import { canonicalDetails, type IdGenerator } from '../../../shared-kernel/index.ts';
import { checkedPlatformEvent, type PlatformEvent, platformEventContent } from '../domain/event.ts';
import type { PlatformControlsTables } from './tables.ts';

/** A transaction on the platform-controls tables: any transaction, since they belong to no organisation. */
export type PlatformTransaction = Transaction<PlatformControlsTables>;

export interface RecordedPlatformEvent {
  readonly id: string;
  readonly seq: bigint;
  readonly recordedAt: Date;
}

export interface PlatformChain {
  /**
   * Adds the event to the platform chain, in the caller's transaction. Takes
   * the chain head's lock, which comes last (ADR-006 §6). Throws
   * PlatformEventRefused for an event that breaks the rules, and ChainBroken
   * if the chain fails its check at the head or holds events past it.
   */
  record(tx: PlatformTransaction, event: PlatformEvent): Promise<RecordedPlatformEvent>;
  /** Checks the platform chain up to its head (SEC-EVD-02). Reads only. */
  verify(tx: PlatformTransaction): Promise<ChainReport>;
}

const CHAIN: Chain = { kind: 'platform' };

const isText = (value: unknown): value is string => typeof value === 'string';

/** What the chain sealed for a stored event, from its own columns, or nothing if one can't be read. */
function contentOf(row: Readonly<Record<string, unknown>>): StoredEntry['content'] | undefined {
  const { actor_type: actorType, actor_id: actorId, action, details } = row;
  if (![actorType, actorId, action, details].every(isText)) return undefined;
  return platformEventContent(
    { actor: { type: actorType as 'system', id: actorId as string }, action: action as string },
    details as string,
  );
}

/** Recording's steps over the platform-controls tables, for one event. */
function writerFor(tx: PlatformTransaction, event: PlatformEvent, details: string): ChainWriter {
  return {
    async lockHead() {
      const rows = await tx
        .selectFrom('platform_controls.audit_head')
        .select(['seq', 'hash', 'mac', 'mac_key_version'])
        .forNoKeyUpdate()
        .execute();
      const [row, ...others] = rows;
      if (row === undefined) return undefined;
      // A second head row means someone went round the app: no head can be trusted.
      return { head: others.length > 0 ? undefined : headFields(row) };
    },

    async start(head) {
      await tx
        .insertInto('platform_controls.audit_head')
        .values({ seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .onConflict((conflict) => conflict.column('only_row').doNothing())
        .execute();
    },

    async hasEventsPast(seq) {
      const past = await tx
        .selectFrom('platform_controls.audit_events')
        .select('seq')
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
      await tx
        .insertInto('platform_controls.audit_events')
        .values({
          seq: sealed.seq,
          id: sealed.id,
          recorded_at: sealed.recordedAt,
          actor_type: event.actor.type,
          actor_id: event.actor.id,
          action: event.action,
          details,
          prev_hash: sealed.prevHash,
          hash: sealed.hash,
          mac: sealed.mac,
          mac_key_version: sealed.macKeyVersion,
        })
        .execute();
      const moved = await tx
        .updateTable('platform_controls.audit_head')
        .set({ seq: head.seq, hash: head.hash, mac: head.mac, mac_key_version: head.macKeyVersion })
        .where('seq', '=', previous.seq)
        .where('hash', '=', previous.hash)
        .executeTakeFirst();
      return moved.numUpdatedRows === 1n;
    },
  };
}

/** Checking's reads of the platform-controls tables. */
function readerFor(tx: PlatformTransaction): ChainReader {
  return {
    async state() {
      // One statement, so the head and the count of events come from the same moment.
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.count(*) from platform_controls.audit_events) as stored,
               (select pg_catalog.count(*) from platform_controls.audit_head) as heads,
               h.seq, h.hash, h.mac, h.mac_key_version
        from (values (1)) as one (x)
        left join (select * from platform_controls.audit_head limit 1) as h on true
      `.execute(tx);
      const state = rows[0] ?? {};
      const stored = typeof state.stored === 'bigint' ? state.stored : 0n;
      if (state.heads === 0n) return { head: 'none', stored };
      if (state.heads !== 1n) return { head: 'unreadable', stored };
      return { head: headFields(state) ?? 'unreadable', stored };
    },

    async events(after, upTo, limit) {
      const rows = await tx
        .selectFrom('platform_controls.audit_events')
        .selectAll()
        .select(sql<boolean>`recorded_at = pg_catalog.date_trunc('milliseconds', recorded_at)`.as('whole_ms'))
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

export function createPlatformChain({
  keys,
  ids,
}: {
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
}): PlatformChain {
  return Object.freeze({
    async record(tx: PlatformTransaction, input: PlatformEvent): Promise<RecordedPlatformEvent> {
      const event = checkedPlatformEvent(input, hidesField);
      const details = canonicalDetails(event.details);
      const sealed = await appendEvent(keys, CHAIN, writerFor(tx, event, details), {
        nextId: () => ids.next(),
        content: platformEventContent(event, details),
      });
      return Object.freeze({ id: sealed.id, seq: sealed.seq, recordedAt: sealed.recordedAt });
    },

    verify(tx: PlatformTransaction): Promise<ChainReport> {
      return verifyChain(keys, CHAIN, readerFor(tx));
    },
  });
}
