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
// changed any of it, or its column types.
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
import type { KeyProvider } from '@agentx/platform/keys';
import { ruleForName } from '@agentx/platform/observability';
import { sql, type Transaction } from 'kysely';

import type { IdGenerator } from '../../../shared-kernel/index.ts';
import {
  type ActorType,
  type AuditDetails,
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
   * an event that breaks the rules, and AuditChainBroken if the head fails its
   * check, so nothing more is added to a chain someone has tampered with.
   */
  record(tx: AuditTransaction, orgId: string, event: AuditEvent): Promise<RecordedAuditEvent>;
  /** Checks the organisation's whole chain up to its head (SEC-EVD-02). Reads only. */
  verify(tx: AuditTransaction, orgId: string): Promise<ChainReport>;
}

/** The chain's head fails its check: an event can't be added until someone has looked into it. */
export class AuditChainBroken extends Error {
  readonly orgId: string;

  constructor(orgId: string) {
    super("The organisation's audit chain head fails its check, so no event can be added to it");
    this.name = 'AuditChainBroken';
    this.orgId = orgId;
  }
}

/** The organisation's chain, named by its ID in lower case, as Postgres returns a uuid. */
function chainOf(orgId: string): Chain & { readonly kind: 'organisation' } {
  if (!UUID.test(orgId)) throw new AuditEventRefused(['the organisation ID must be a UUID']);
  return { kind: 'organisation', orgId: orgId.toLowerCase() };
}

/** Events with no head: the head row was removed, or can't be read. */
const HEAD_MISSING: ChainReport = Object.freeze({ ok: false, problem: Object.freeze({ reason: 'head', seq: 0n }) });

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

/** An event row as the chain checks it, or nothing if a field is missing or of the wrong type. */
function storedEntry(row: Readonly<Record<string, unknown>>): StoredEntry | undefined {
  const { seq, id, recorded_at: recordedAt, action, details, prev_hash: prevHash, hash, mac } = row;
  const { actor_type: actorType, actor_id: actorId, subject_type: subjectType, subject_id: subjectId } = row;
  const { subject_version: subjectVersion, mac_key_version: macKeyVersion } = row;
  // A timestamp of 'infinity' arrives as a number, not a Date, so every Date here is a real time.
  const readable =
    typeof seq === 'bigint' &&
    isText(id) &&
    recordedAt instanceof Date &&
    [actorType, actorId, action, subjectType, subjectId].every(isText) &&
    typeof subjectVersion === 'number' &&
    typeof details === 'object' &&
    details !== null &&
    [prevHash, hash, mac].every(isBytes) &&
    typeof macKeyVersion === 'number';
  if (!readable) return undefined;
  const content = eventContent({
    actor: { type: actorType as ActorType, id: actorId as string },
    action: action as string,
    subject: { type: subjectType as string, id: subjectId as string, version: subjectVersion },
    details: details as AuditDetails,
  });
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
  /**
   * Locks the head and reads it, with the transaction's time to the
   * millisecond (ADR-006 §3: "recorded at" is the database's). Nothing if the
   * chain hasn't started; a head of undefined if its row can't be read.
   */
  const lockHead = async (
    tx: AuditTransaction,
    orgId: string,
  ): Promise<{ readonly head: ChainHead | undefined; readonly now: Date } | undefined> => {
    const row = await tx
      .selectFrom('audit.heads')
      .select(['seq', 'hash', 'mac', 'mac_key_version'])
      .select(sql<Date>`pg_catalog.date_trunc('milliseconds', pg_catalog.now())`.as('now'))
      .where('org_id', '=', orgId)
      .forNoKeyUpdate()
      .executeTakeFirst();
    return row === undefined ? undefined : { head: headFrom(row), now: row.now };
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

  return Object.freeze({
    async record(tx: AuditTransaction, orgId: string, input: AuditEvent): Promise<RecordedAuditEvent> {
      const event = checkedEvent(input, (name) => ruleForName(name) !== 'keep');
      const chain = chainOf(orgId);
      let locked = await lockHead(tx, chain.orgId);
      if (locked === undefined) {
        await startChain(tx, chain);
        locked = await lockHead(tx, chain.orgId);
      }
      if (locked?.head === undefined || !headIsSealed(keys, chain, locked.head)) {
        throw new AuditChainBroken(chain.orgId);
      }
      const { head, now } = locked;

      const entry = { seq: head.seq + 1n, id: ids.next(), recordedAt: now, content: eventContent(event) };
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
          details: canonicalDetails(event.details),
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
      const chain = chainOf(orgId);
      // One statement, so the head and the last event number come from the same moment.
      const { rows } = await sql<Record<string, unknown>>`
        select (select pg_catalog.max(e.seq) from audit.events e where e.org_id = ${chain.orgId}) as last_seq,
               h.seq, h.hash, h.mac, h.mac_key_version, h.org_id is not null as has_head
        from (values (1)) as one (x)
        left join audit.heads h on h.org_id = ${chain.orgId}
      `.execute(tx);
      const state = rows[0] ?? {};
      const lastSeq = typeof state.last_seq === 'bigint' ? state.last_seq : 0n;
      if (state.has_head !== true) {
        // A chain that was never started is empty; events with no head mean the head was removed.
        return lastSeq === 0n ? { ok: true, seq: 0n, hash: GENESIS_HASH } : HEAD_MISSING;
      }
      const head = headFrom(state);
      if (head === undefined) return HEAD_MISSING;

      const verifier = createChainVerifier(keys, chain, { head, lastSeq });
      // Each full batch moves `after` on, and a short or empty one ends the reading, so this always stops.
      let after = 0n;
      for (let full = true; full;) {
        const batch = await tx
          .selectFrom('audit.events')
          .selectAll()
          .where('org_id', '=', chain.orgId)
          .where('seq', '>', after)
          .where('seq', '<=', head.seq)
          .orderBy('seq')
          .limit(BATCH)
          .execute();
        for (const row of batch) {
          const stored = storedEntry(row);
          const problem = stored === undefined ? verifier.unreadable() : verifier.check(stored);
          if (problem !== undefined) return { ok: false, problem };
          after = row.seq;
        }
        full = batch.length === BATCH;
      }
      return verifier.finish();
    },
  });
}
