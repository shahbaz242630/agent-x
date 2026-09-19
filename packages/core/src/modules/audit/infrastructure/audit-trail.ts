// The organisation audit chains in Postgres (ADR-011 §3): schema `audit`, one
// chain per organisation, sealed and checked by @agentx/platform/audit-chain.
//
// Recording an event locks the organisation's chain head, and ADR-006 §6 puts
// that lock last of all: work that records an event takes its other locks
// first. The head lock is what keeps a chain in one line. Two transactions
// recording at once queue on it, so each event takes the next place and
// points at the one before it. The app role can only add events and read them
// (SEC-EVD-01); the head is the one row it changes.
//
// Everything read back is checked as untrusted: the database owner could have
// changed any of it, or its column types. Each event's details are stored as
// the exact JSON text that was sealed, so a change that keeps their meaning
// (a key moved, a number written another way) still shows.
import {
  type Chain,
  type ChainHead,
  type ChainReport,
  createChainVerifier,
  GENESIS_HASH,
  genesisHead,
  headIsSealed,
  sealNext,
  type StoredEntry,
} from '@agentx/platform/audit-chain';
import { assertTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { hidesField } from '@agentx/platform/observability';
import { sql, type Transaction } from 'kysely';

import type { IdGenerator } from '../../../shared-kernel/index.ts';
import {
  type ActorType,
  type AuditEvent,
  AuditEventRefused,
  canonicalDetails,
  checkedEvent,
  eventContent,
} from '../domain/event.ts';
import type { AuditTables } from './tables.ts';

/** How many events the check reads at a time. */
const BATCH = 500;

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
   * an event that breaks the rules, and AuditChainBroken if the chain fails its
   * check at the head or holds events past it, so nothing more is added to a
   * chain someone has tampered with.
   */
  record(tx: AuditTransaction, orgId: string, event: AuditEvent): Promise<RecordedAuditEvent>;
  /**
   * Checks the organisation's whole chain up to its head (SEC-EVD-02). Reads
   * only, and only in withTenant's transaction for that organisation: in any
   * other, row security would show its chain as empty.
   */
  verify(tx: AuditTransaction, orgId: string): Promise<ChainReport>;
}

/**
 * The chain fails its check at the head: tampered with, or sealed with a key
 * version this process doesn't hold (a new key made current before it was
 * installed everywhere). An event can't be added until someone has looked into it.
 */
export class AuditChainBroken extends Error {
  readonly orgId: string;

  constructor(orgId: string) {
    super(
      "The organisation's audit chain fails its check at the head (tampered with, or sealed with a key version this process doesn't hold), so no event can be added to it",
    );
    this.name = 'AuditChainBroken';
    this.orgId = orgId;
  }
}

/** The organisation's chain, named by its ID in lower case, as Postgres returns a uuid. */
function chainOf(orgId: string): Chain & { readonly kind: 'organisation' } {
  if (!UUID.test(orgId)) throw new AuditEventRefused(['the organisation ID must be a UUID']);
  return { kind: 'organisation', orgId: orgId.toLowerCase() };
}

/** Events with no usable head: the head row was removed, or can't be read. */
const NO_HEAD: ChainReport = Object.freeze({ ok: false, problem: Object.freeze({ reason: 'head', seq: 0n }) });

const isBytes = (value: unknown): value is Buffer => Buffer.isBuffer(value);
const isText = (value: unknown): value is string => typeof value === 'string';

/** A head row as a head, or nothing if a field is missing or of the wrong type. */
function headFrom(row: Readonly<Record<string, unknown>>): ChainHead | undefined {
  const { seq, hash, mac, mac_key_version: macKeyVersion } = row;
  if (typeof seq !== 'bigint' || !isBytes(hash) || !isBytes(mac) || typeof macKeyVersion !== 'number') {
    return undefined;
  }
  return { seq, hash, mac, macKeyVersion };
}

/**
 * An event row as the chain checks it, or nothing if a field is missing or of
 * the wrong type, or its time isn't one the app could have written: a real
 * time (one past JavaScript's range arrives as an Invalid Date, 'infinity' as
 * a number) and a whole millisecond, as `whole_ms` says.
 */
function storedEntry(row: Readonly<Record<string, unknown>>): StoredEntry | undefined {
  const { seq, id, recorded_at: recordedAt, whole_ms: wholeMs, action, details, prev_hash: prevHash } = row;
  const { actor_type: actorType, actor_id: actorId, subject_type: subjectType, subject_id: subjectId } = row;
  const { subject_version: subjectVersion, hash, mac, mac_key_version: macKeyVersion } = row;
  const readable =
    typeof seq === 'bigint' &&
    isText(id) &&
    recordedAt instanceof Date &&
    Number.isFinite(recordedAt.getTime()) &&
    wholeMs === true &&
    [actorType, actorId, action, subjectType, subjectId, details].every(isText) &&
    typeof subjectVersion === 'number' &&
    [prevHash, hash, mac].every(isBytes) &&
    typeof macKeyVersion === 'number';
  if (!readable) return undefined;
  const content = eventContent(
    {
      actor: { type: actorType as ActorType, id: actorId as string },
      action: action as string,
      subject: { type: subjectType as string, id: subjectId as string, version: subjectVersion },
    },
    details as string,
  );
  return {
    seq,
    id,
    recordedAt,
    content,
    prevHash: prevHash as Buffer,
    hash: hash as Buffer,
    mac: mac as Buffer,
    macKeyVersion,
  };
}

export function createAuditTrail({ keys, ids }: { readonly keys: KeyProvider; readonly ids: IdGenerator }): AuditTrail {
  /** Locks the head and reads it: nothing if the chain hasn't started, a head of undefined if its row can't be read. */
  const lockHead = async (
    tx: AuditTransaction,
    orgId: string,
  ): Promise<{ head: ChainHead | undefined } | undefined> => {
    const row = await tx
      .selectFrom('audit.heads')
      .select(['seq', 'hash', 'mac', 'mac_key_version'])
      .where('org_id', '=', orgId)
      .forNoKeyUpdate()
      .executeTakeFirst();
    return row === undefined ? undefined : { head: headFrom(row) };
  };

  /**
   * An organisation's first event starts its chain. If two first events race,
   * the second insert waits for the first to commit and then does nothing.
   */
  const startChain = async (tx: AuditTransaction, chain: Chain & { readonly orgId: string }): Promise<void> => {
    const head = genesisHead(keys, chain);
    await tx
      .insertInto('audit.heads')
      .values({
        org_id: chain.orgId,
        seq: head.seq,
        hash: head.hash,
        mac: head.mac,
        mac_key_version: head.macKeyVersion,
      })
      .onConflict((conflict) => conflict.column('org_id').doNothing())
      .execute();
  };

  /**
   * Whether the organisation has events past the head. Asked with the head
   * locked, so no one else can be adding one: any found were there before the
   * head was removed or wound back, and nothing more may be added on top.
   */
  const hasEventsPast = async (tx: AuditTransaction, orgId: string, seq: bigint): Promise<boolean> =>
    (await tx
      .selectFrom('audit.events')
      .select('seq')
      .where('org_id', '=', orgId)
      .where('seq', '>', seq)
      .limit(1)
      .executeTakeFirst()) !== undefined;

  /**
   * The time the event is recorded: the database's (ADR-006 §3), read once
   * the head's lock is held, so times rise with the events' numbers (unless
   * the server's clock is set back). Cut to the millisecond, as JavaScript
   * keeps it.
   */
  const recordedAt = async (tx: AuditTransaction): Promise<Date> => {
    const { now } = await tx
      .selectNoFrom(sql<Date>`pg_catalog.date_trunc('milliseconds', pg_catalog.clock_timestamp())`.as('now'))
      .executeTakeFirstOrThrow();
    return now;
  };

  /** The next event ID, in lower case as Postgres returns a uuid, so the stored row hashes the same. */
  const nextId = (): string => {
    const id = ids.next().toLowerCase();
    if (!UUID.test(id)) throw new RangeError('The ID generator gave an ID that is not a UUID');
    return id;
  };

  return Object.freeze({
    async record(tx: AuditTransaction, orgId: string, input: AuditEvent): Promise<RecordedAuditEvent> {
      const event = checkedEvent(input, hidesField);
      const chain = chainOf(orgId);
      let locked = await lockHead(tx, chain.orgId);
      if (locked === undefined) {
        await startChain(tx, chain);
        locked = await lockHead(tx, chain.orgId);
      }
      if (
        locked?.head === undefined ||
        !headIsSealed(keys, chain, locked.head) ||
        (await hasEventsPast(tx, chain.orgId, locked.head.seq))
      ) {
        throw new AuditChainBroken(chain.orgId);
      }
      const { head } = locked;

      const details = canonicalDetails(event.details);
      const entry = {
        seq: head.seq + 1n,
        id: nextId(),
        recordedAt: await recordedAt(tx),
        content: eventContent(event, details),
      };
      const { link, head: next } = sealNext(keys, chain, head, entry);
      await tx
        .insertInto('audit.events')
        .values({
          org_id: chain.orgId,
          seq: entry.seq,
          id: entry.id,
          recorded_at: entry.recordedAt,
          actor_type: event.actor.type,
          actor_id: event.actor.id,
          action: event.action,
          subject_type: event.subject.type,
          subject_id: event.subject.id,
          subject_version: event.subject.version,
          details,
          prev_hash: link.prevHash,
          hash: link.hash,
          mac: link.mac,
          mac_key_version: link.macKeyVersion,
        })
        .execute();
      await tx
        .updateTable('audit.heads')
        .set({ seq: next.seq, hash: next.hash, mac: next.mac, mac_key_version: next.macKeyVersion })
        .where('org_id', '=', chain.orgId)
        .execute();
      return Object.freeze({ id: entry.id, seq: entry.seq, recordedAt: entry.recordedAt });
    },

    async verify(tx: AuditTransaction, orgId: string): Promise<ChainReport> {
      await assertTenant(tx, orgId);
      const chain = chainOf(orgId);
      // One statement, so the head and the count of events come from the same moment.
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.count(*) from audit.events e where e.org_id = ${chain.orgId}) as stored,
               h.seq, h.hash, h.mac, h.mac_key_version, h.org_id is not null as has_head
        from (values (1)) as one (x)
        left join audit.heads h on h.org_id = ${chain.orgId}
      `.execute(tx);
      const state = rows[0] ?? {};
      const stored = typeof state.stored === 'bigint' ? state.stored : 0n;
      if (state.has_head !== true) {
        // A chain that was never started is empty; events with no head mean the head was removed.
        return stored === 0n ? { ok: true, seq: 0n, hash: GENESIS_HASH } : NO_HEAD;
      }
      const head = headFrom(state);
      if (head === undefined) return NO_HEAD;

      const verifier = createChainVerifier(keys, chain, { head, stored });
      // Each full batch moves `after` on, and a short or empty one ends the reading, so this always stops.
      let after = 0n;
      for (let full = true; full;) {
        const batch = await tx
          .selectFrom('audit.events')
          .selectAll()
          .select(sql<boolean>`recorded_at = pg_catalog.date_trunc('milliseconds', recorded_at)`.as('whole_ms'))
          .where('org_id', '=', chain.orgId)
          .where('seq', '>', after)
          .where('seq', '<=', head.seq)
          .orderBy('seq')
          .limit(BATCH)
          .execute();
        for (const row of batch) {
          const entry = storedEntry(row);
          const problem = entry === undefined ? verifier.unreadable() : verifier.check(entry);
          if (problem !== undefined) return { ok: false, problem };
          after = row.seq;
        }
        full = batch.length === BATCH;
      }
      return verifier.finish();
    },
  });
}
