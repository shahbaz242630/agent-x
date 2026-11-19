// The notifications outbox (ADR-003 §10, ADR-007; Phase 1 B5-1a): notices to
// one person each, written in the change's own transaction, then sent by the
// API's sender (B5-1b).
//
// - `add` writes notices in the transaction it is given, the change's own,
//   so a notice commits or rolls back with what it tells of: it takes a
//   transaction and nothing else (review). Everything must be well formed, or
//   nothing is written: a bug, never a partial write.
// - `claimDue` takes up to a batch of due notices, soonest due first, and
//   starts a try of each: it counts the try and moves the next one on by the
//   lease, in one statement. A sender that dies mid-send leaves the notice to
//   be tried again once the lease runs out, and two senders never take the
//   same notice (`SKIP LOCKED`). A notice whose last try's lease ran out is
//   given up (`lease_expired`) rather than taken again, so one that brings its
//   sender down every time is still tried MOST_ATTEMPTS times at most
//   (review). A last try merely slow past its lease can so be given up while
//   it sends; `sent` still marks it sent (confirmation review). A remittance is
//   never given up there: `endRemittanceLeases` gives those up and says which,
//   so each is kept in its organisation's audit log (gate H2). A notice may
//   be sent twice after a crash; the provider is given its ID to tell (B5-3).
// - `fanOut` turns a notice to the organisation's admins (no recipient) into
//   one notice to each admin the sender found, and a notice to its registered
//   contacts (`to_contacts`, B6-1b) into one to each contact, and marks the
//   first sent, in one transaction: done once, and never a second set of
//   notices. A last try slow past its lease is rescued the same way as `sent`
//   (review).
// - LEASE_EXPIRED is the outbox's own reason, never a caller's: `failed`
//   refuses it, so only a lease run out can make a notice given up that a
//   late `sent` or `fanOut` may still complete (review).
// - `sent` marks a notice sent; `failed` records why a try failed and sets the
//   next one further off each time, or gives the notice up after its
//   MOST_ATTEMPTS-th try, or at once for a failure no retry can mend. Neither
//   touches a notice already sent or given up.
// - `sweep` deletes notices sent or given up past the retention, oldest first.
//
// Sealed (S206 V4, Threat-Model R-15; 0105, notice-seals.ts): every notice it
// writes carries a MAC over whom it tells of what, and `notice.queued` is
// recorded about it on its organisation's chain in the same statement, so a
// notice deleted leaves its signed record behind; every notice it ends, sent or
// given up, carries a MAC of that end. `claimDue` judges each notice's seal,
// for the sender to send only one the app queued; `fanOut` and `passOn` write
// from a notice only one whose seal holds. The notice check (notice-check.ts)
// holds the records to the rows.
//
// Each but `add` runs in a transaction of its own whose statements give up
// after 10 seconds, a wait for a lock included: `fanOut` and `passOn` under
// the organisation's wall, as their records need. The times are the Clock's.
import { limitStatements, readEachTenant, withTenant } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, type RawBuilder, sql, type Transaction } from 'kysely';

import { type AuditEvent, type AuditTables, createAuditTrail } from '../../audit/index.ts';

import { type Clock, DAY_MS, HOUR_MS, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import {
  type ClaimedNotice,
  isAboutAMembership,
  isNoticeKind,
  isNoticeRole,
  type Notice,
  type NoticeKind,
  REMITTANCE_KIND,
  RESET_LINK_KIND,
} from '../domain/notice.ts';
import {
  endSeal,
  type NoticeEnd,
  type QueuedColumns,
  queuedJudged,
  queuedSeal,
  type SealJudged,
} from './notice-seals.ts';
import type { NotificationsTables } from './tables.ts';

/** How many times a notice is tried before it is given up. */
export const MOST_ATTEMPTS = 8;

/** How long a claimed notice is left to its sender before it is due again. */
export const CLAIM_LEASE_MS = 10 * 60_000;

/**
 * The notices whose last try's lease ran out by `now`, locked to be given up; the caller picks which kinds. Read
 * first, as each is given up with its own end seal in the one write (0105 refuses an end with none).
 */
const leaseEnded = (tx: Kysely<NotificationsTables>, now: Date) =>
  tx
    .selectFrom('notifications.outbox')
    .select(['id', 'org_id', 'about_id'])
    .where('sent_at', 'is', null)
    .where('given_up_at', 'is', null)
    .where('next_attempt_at', '<=', now)
    .where('attempts', '>=', MOST_ATTEMPTS)
    .where('mac', 'is not', null)
    .forUpdate();

/** The waits after each failed try but the last: a minute, then longer, to six hours. */
const BACKOFF_MS = [60_000, 5 * 60_000, 15 * 60_000, HOUR_MS, 2 * HOUR_MS, 4 * HOUR_MS, 6 * HOUR_MS];

/** Why the outbox gave a notice up: its last try's lease ran out. The outbox's own; `failed` refuses it. */
export const LEASE_EXPIRED = 'lease_expired';

/** The most notices one `fanOut` writes: an organisation's admins are never near it. */
export const MOST_RECIPIENTS = 1_000;

/** How long a notice sent or given up is kept. */
export const OUTBOX_RETENTION_DAYS = 30;

/** The most notices one `add` writes, or one `claimDue` takes. */
export const MOST_NOTICES_A_BATCH = 100;

/** The record on the organisation's chain of each notice queued (S206 V4): the notice check reads them. */
export const NOTICE_QUEUED = 'notice.queued';

/** The type of object a notice's record is about. */
export const NOTICE_SUBJECT = 'notice';

/** Who records a notice queued: the outbox itself, whichever process writes it. */
const OUTBOX_ACTOR = { type: 'system', id: 'notifications' } as const;

/** The tables a notice is written to: the outbox, and its organisation's chain for its record. */
export type OutboxTables = NotificationsTables & AuditTables;

/** A notice claimed, with how its seal reads (notice-seals.ts): the sender sends only one the app queued. */
export interface SealedClaim extends ClaimedNotice {
  readonly seal: SealJudged;
}

/** A remittance given up because its last try's lease ran out. */
export interface LeaseEnded {
  readonly id: string;
  readonly orgId: string;
  readonly aboutId: string | null;
}

export interface Outbox {
  /**
   * Writes these notices in the change's own transaction, withTenant's for their one organisation, at most
   * MOST_NOTICES_A_BATCH, each sealed and recorded on the organisation's chain (`notice.queued`). Throws RangeError for
   * anything malformed, or notices of more than one organisation, writing nothing.
   */
  add(tx: Transaction<OutboxTables>, notices: readonly Notice[]): Promise<void>;
  /**
   * Starts a try of up to `most` due notices, soonest due first, each held for the lease, with how its seal reads;
   * gives up any whose last try's lease ran out.
   */
  claimDue(db: Kysely<NotificationsTables>, most: number): Promise<SealedClaim[]>;
  /** Gives up every remittance whose last try's lease ran out (claimDue leaves them), and says which (gate H2). */
  endRemittanceLeases(db: Kysely<NotificationsTables>): Promise<LeaseEnded[]>;
  /**
   * Turns a notice to the organisation's admins into one notice to each of
   * `recipients` (at most MOST_RECIPIENTS), user IDs, due at once, and marks
   * it sent; a notice to its registered contacts the same, `recipients` then
   * contact IDs (B6-1b). Says how many it wrote, or `not_open` if the notice
   * is not one to a group, or is already done; a notice given up because its
   * last try's lease ran out is done all the same (that try was only slow).
   * `id` is one claimDue handed out, in `orgId`; one whose seal no longer
   * holds is `not_open`, and nothing is written from it.
   */
  fanOut(
    db: Kysely<OutboxTables>,
    orgId: string,
    id: string,
    recipients: readonly string[],
  ): Promise<number | 'not_open'>;
  /**
   * Gives the notice up as `failure` (a short constant) and writes, in its
   * place and in the same transaction, one notice of `kind` to the
   * organisation's admins about the same thing, due at once (0062: a paid
   * supplier with no email, its admins told instead). False, writing nothing,
   * if it was already sent or given up; a notice given up because its last
   * try's lease ran out is passed on all the same. `id` is one claimDue
   * handed out, in `orgId`; one whose seal no longer holds is not passed on.
   */
  passOn(db: Kysely<OutboxTables>, orgId: string, id: string, kind: NoticeKind, failure: string): Promise<boolean>;
  /**
   * Marks the notice sent; false if it was already sent or given up. A notice
   * given up because its last try's lease ran out is marked sent all the
   * same: that try was only slow.
   */
  sent(db: Kysely<NotificationsTables>, id: string): Promise<boolean>;
  /**
   * Records why the notice's try failed, `failure` a short constant: the next
   * try is set further off, or the notice given up after its MOST_ATTEMPTS-th
   * try, or at once when `lasting`. Says what became of it; `done` if it was
   * already sent or given up.
   */
  failed(
    db: Kysely<NotificationsTables>,
    id: string,
    failure: string,
    lasting: boolean,
  ): Promise<'retry' | 'given_up' | 'done'>;
  /** Deletes up to `most` notices sent or given up past the retention, oldest first, and says how many. */
  sweep(db: Kysely<NotificationsTables>, most: number): Promise<number>;
}

const FAILURE = /^[a-z][a-z_]{0,63}$/;

const isId = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);

/** Why a notice can't be written, if it can't. */
function problemWith(notice: Notice): string | undefined {
  const contact = notice.recipientContactId ?? null;
  if (!isId(notice.orgId)) return 'its organisation is not a UUID';
  if (notice.recipientUserId !== null && !isId(notice.recipientUserId)) return 'its recipient is not a UUID';
  if (contact !== null && !isId(contact)) return 'its contact is not a UUID';
  const recipients = [notice.recipientUserId !== null, contact !== null, notice.toContacts === true];
  if (recipients.filter(Boolean).length > 1) return 'it names more than one recipient';
  if (!isNoticeKind(notice.kind)) return 'its kind is not one we send';
  // Its email carries one contact's own link: never to a group, nor to a person (0026).
  if (notice.kind === RESET_LINK_KIND && contact === null) return "a reset's link goes to one contact";
  // Its email goes to the paid supplier, whose address the sender reads (0062).
  if (notice.kind === REMITTANCE_KIND && recipients.some(Boolean)) return 'a remittance goes to its supplier alone';
  return subjectProblem(notice);
}

/** Why what a notice is about can't be written, if it can't: a membership, or something else. */
function subjectProblem(notice: Notice): string | undefined {
  if (isAboutAMembership(notice.kind)) {
    if (!isId(notice.membershipId)) return 'its membership is not a UUID';
    if (!isNoticeRole(notice.role)) return 'its role is not one of the four';
    if ((notice.aboutId ?? null) !== null) return 'a membership notice is about nothing else';
  } else {
    if (!isId(notice.aboutId)) return 'what it is about is not a UUID';
    if (notice.membershipId !== null || notice.role !== null) return 'it is not about a membership';
  }
  return undefined;
}

/** The wait after the `tries`-th try failed, `tries` from 1 to MOST_ATTEMPTS - 1. */
const backoffAfter = (tries: number): number => BACKOFF_MS[tries - 1] ?? 0;

/** Whom a notice's record names: a person, a contact, or a group found as it is sent (the contacts, or the admins). */
export function recipientOf(row: QueuedColumns): { readonly recipient: string; readonly recipientId: string | null } {
  if (row.recipient_user_id !== null) return { recipient: 'person', recipientId: row.recipient_user_id };
  if (row.recipient_contact_id !== null) return { recipient: 'contact', recipientId: row.recipient_contact_id };
  return { recipient: row.to_contacts ? 'contacts' : 'admins', recipientId: null };
}

/** A notice's columns its seal binds, and the seal, as read back for its judgement. */
const QUEUED_COLUMNS = [
  'id',
  'org_id',
  'recipient_user_id',
  'recipient_contact_id',
  'to_contacts',
  'kind',
  'membership_id',
  'role',
  'about_id',
  'created_at',
  'mac',
  'mac_key_version',
] as const;

/** Thrown inside a transaction to roll it back: the notice it read is not one the app queued there. */
class NotQueuedHere extends Error {}

/**
 * Seals, over what each says now, every notice still to be sent that has no seal and no `notice.queued` record, in
 * the caller's transaction, which must record that it was done, once ever (apps/api/src/notice-legacy.ts). A notice
 * with a record was queued sealed: one with no seal now had it taken out, and stays unsealed, to be refused. Its
 * organisations' records are read under each one's wall (readEachTenant, on `db`), one with a read that failed
 * counted as recorded, and the pass then not `complete`: its caller leaves it to be done again. Says how many it
 * sealed.
 *
 * TODO(S206 V4): delete this with sealLegacyNotices once a release has run it (Outstanding-Work AT10).
 */
export async function sealNoticesFromBefore(
  tx: Transaction<NotificationsTables>,
  db: Kysely<OutboxTables>,
  keys: KeyProvider,
): Promise<{ readonly sealed: number; readonly complete: boolean }> {
  const unsealed = await tx
    .selectFrom('notifications.outbox')
    .select(QUEUED_COLUMNS)
    .where('mac', 'is', null)
    .where('before_seals', '=', true)
    .where('sent_at', 'is', null)
    .where('given_up_at', 'is', null)
    .forUpdate()
    .execute();
  const { recorded, complete } = await recordedNotices(db, unsealed);
  const open = unsealed.filter((row) => !recorded.has(row.id.toLowerCase()));
  if (open.length === 0) return { sealed: 0, complete };
  const values = open.map((row) => {
    const { mac, keyVersion } = queuedSeal(keys, row);
    return sql`(${row.id}::uuid, ${mac}::bytea, ${keyVersion}::integer)`;
  });
  await sql`
    update notifications.outbox o set mac = v.mac, mac_key_version = v.version
    from (values ${sql.join(values)}) as v (id, mac, version)
    where o.id = v.id and o.mac is null
  `.execute(tx);
  return { sealed: open.length, complete };
}

/** Which of these notices their organisations' chains record as queued: one statement an organisation, one trip. */
async function recordedNotices(
  db: Kysely<OutboxTables>,
  rows: readonly { readonly id: string; readonly org_id: string }[],
): Promise<{ readonly recorded: ReadonlySet<string>; readonly complete: boolean }> {
  const byOrg = new Map<string, string[]>();
  for (const row of rows) byOrg.set(row.org_id.toLowerCase(), [...(byOrg.get(row.org_id.toLowerCase()) ?? []), row.id]);
  const reads = await readEachTenant(
    db,
    [...byOrg].map(([orgId, ids]) => ({ orgId, ids })),
    ({ orgId, ids }) =>
      db
        .selectFrom('audit.events')
        .select('subject_id')
        .where('org_id', '=', orgId)
        .where('subject_type', '=', NOTICE_SUBJECT)
        .where('subject_id', 'in', ids),
  );
  const recorded = new Set<string>();
  let complete = true;
  for (const { item, read } of reads) {
    // A read that failed can't say a notice has no record: none of its organisation's is sealed, this time.
    if (!('rows' in read)) complete = false;
    const found = 'rows' in read ? read.rows.map(({ subject_id: id }) => id) : item.ids;
    for (const id of found) recorded.add(id.toLowerCase());
  }
  return { recorded, complete };
}

export function createOutbox({
  ids,
  clock,
  keys,
}: {
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** Holds `audit-mac`, for each notice's seals and its record on the chain. */
  readonly keys: KeyProvider;
}): Outbox {
  const trail = createAuditTrail({ keys, ids });

  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(db: Kysely<NotificationsTables>, work: (tx: Kysely<NotificationsTables>) => Promise<T>) =>
    db.transaction().execute(async (tx) => {
      await limitStatements(tx);
      return work(tx);
    });

  /**
   * Runs the work under the organisation's wall, each statement limited; the NotQueuedHere it threw, if it found a
   * notice the app didn't queue there (and so wrote nothing).
   */
  const inOrg = async <T>(
    db: Kysely<OutboxTables>,
    orgId: string,
    work: (tx: Transaction<OutboxTables>) => Promise<T>,
  ): Promise<T | NotQueuedHere> => {
    try {
      return await withTenant(db, orgId, work, { limited: true });
    } catch (error) {
      if (error instanceof NotQueuedHere) return error;
      throw error;
    }
  };

  const atLeastOne = (most: number, what: string): void => {
    if (!Number.isSafeInteger(most) || most < 1 || most > MOST_NOTICES_A_BATCH) {
      throw new RangeError(`${what} 1 to ${String(MOST_NOTICES_A_BATCH)} notices at a time`);
    }
  };

  /** The notice's end seal, as its columns keep it. */
  const ended = (id: string, end: NoticeEnd) => {
    const { mac, keyVersion } = endSeal(keys, id, end);
    return { end_mac: mac, end_key_version: keyVersion };
  };

  /** Gives up these notices, each as its last try's lease ran out, with its end's seal: one statement. */
  const giveUpLeaseEnds = async <Row extends { readonly id: string }>(
    tx: Kysely<NotificationsTables>,
    given: readonly Row[],
    now: Date,
  ): Promise<readonly Row[]> => {
    if (given.length === 0) return given;
    const values = given.map(({ id }) => {
      const { end_mac: mac, end_key_version: version } = ended(id, { outcome: 'given_up', failure: LEASE_EXPIRED });
      return sql`(${id}::uuid, ${mac}::bytea, ${version}::integer)`;
    });
    await sql`
      update notifications.outbox o
      set given_up_at = ${now}, last_failure = ${LEASE_EXPIRED}, end_mac = v.mac, end_key_version = v.version
      from (values ${sql.join(values)}) as v (id, mac, version)
      where o.id = v.id
    `.execute(tx);
    return given;
  };

  /** Whether a notice read back is one the app queued in this organisation. */
  const queuedHere = (
    orgId: string,
    row: QueuedColumns & { readonly mac: unknown; readonly mac_key_version: unknown },
  ) => row.org_id.toLowerCase() === orgId.toLowerCase() && queuedJudged(keys, row) === 'sound';

  /** A new notice's row in the organisation, queued now. */
  const rowOf = (
    orgId: string,
    fields: Omit<QueuedColumns, 'id' | 'org_id' | 'created_at'>,
    now: Date,
  ): QueuedColumns => ({ id: ids.next(), org_id: orgId, ...fields, created_at: now });

  /**
   * Writes the notices, each sealed and due at once, in the one statement that records each on the organisation's
   * chain (recordAllAlong): a notice is written only with its record. A change that has recorded its own event holds
   * the chain head's lock already, and this takes no other: so a change queues its notices after its own event, and
   * the head's lock stays last (ADR-006 §6). One that records nothing else takes the head's lock here, last.
   */
  const queue = async (tx: Transaction<OutboxTables>, orgId: string, rows: readonly QueuedColumns[]) => {
    const events: AuditEvent[] = rows.map((row) => ({
      actor: OUTBOX_ACTOR,
      action: NOTICE_QUEUED,
      subject: { type: NOTICE_SUBJECT, id: row.id, version: 1 },
      details: { kind: row.kind, ...recipientOf(row) },
    }));
    const values = rows.map((row) => {
      const { mac, keyVersion } = queuedSeal(keys, row);
      return sql`(${row.id}::uuid, ${row.org_id}::uuid, ${row.recipient_user_id}::uuid,
        ${row.recipient_contact_id}::uuid, ${row.to_contacts}::boolean, ${row.kind}::text, ${row.membership_id}::uuid,
        ${row.role}::text, ${row.about_id}::uuid, ${row.created_at}::timestamptz, 0, ${row.created_at}::timestamptz,
        ${mac}::bytea, ${keyVersion}::integer)`;
    });
    // Each row written counted by `returning 1`, which needs no right to read the outbox: the operator's command has none.
    const insert = (_lastEventId: string, gate: RawBuilder<unknown>) => sql`
      insert into notifications.outbox (id, org_id, recipient_user_id, recipient_contact_id, to_contacts, kind,
        membership_id, role, about_id, created_at, attempts, next_attempt_at, mac, mac_key_version)
      select v.* from (values ${sql.join(values)}) as v where ${gate}
      returning 1 as written
    `;
    // After the change's own event, from the head it left: no read of the head again, so no trip more (S206 V4).
    const { along } = await trail.recordAllAlong(tx, orgId, events, insert, { headHeld: true });
    if (along?.length !== rows.length) throw new Error('the notices were not written with their records');
  };

  return {
    async add(tx, notices) {
      if (notices.length === 0) return;
      if (notices.length > MOST_NOTICES_A_BATCH) {
        throw new RangeError(`at most ${String(MOST_NOTICES_A_BATCH)} notices are written at a time`);
      }
      for (const notice of notices) {
        const problem = problemWith(notice);
        if (problem !== undefined) throw new RangeError(`a notice can't be written: ${problem}`);
      }
      const orgIds = new Set(notices.map((notice) => notice.orgId.toLowerCase()));
      // Each notice's record goes on its organisation's chain, and a change runs under one organisation's wall.
      if (orgIds.size > 1) throw new RangeError("a notice can't be written: notices of one organisation at a time");
      const [orgId = ''] = orgIds;
      const now = clock.now();
      await queue(
        tx,
        orgId,
        notices.map((notice) =>
          rowOf(
            orgId,
            {
              recipient_user_id: notice.recipientUserId?.toLowerCase() ?? null,
              recipient_contact_id: notice.recipientContactId?.toLowerCase() ?? null,
              to_contacts: notice.toContacts === true,
              kind: notice.kind,
              membership_id: notice.membershipId?.toLowerCase() ?? null,
              role: notice.role,
              about_id: notice.aboutId?.toLowerCase() ?? null,
            },
            now,
          ),
        ),
      );
    },

    async claimDue(db, most) {
      atLeastOne(most, 'a claim takes');
      const now = clock.now();
      return limited(db, async (tx) => {
        // A notice due again after its last try: that try's lease ran out, its sender gone.
        // A remittance is left to endRemittanceLeases, which says which it gave up (gate H2).
        await giveUpLeaseEnds(tx, await leaseEnded(tx, now).where('kind', '!=', REMITTANCE_KIND).execute(), now);
        const due = tx
          .selectFrom('notifications.outbox')
          .select('id')
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .where('next_attempt_at', '<=', now)
          .where('attempts', '<', MOST_ATTEMPTS)
          // Only a notice with a seal to judge: one with none is the owner's, never sent, and 0105 refuses its claim.
          .where('mac', 'is not', null)
          .orderBy('next_attempt_at')
          .orderBy('id')
          .limit(most)
          .forUpdate()
          .skipLocked();
        const rows = await tx
          .updateTable('notifications.outbox')
          .set((eb) => ({
            attempts: eb('attempts', '+', 1),
            next_attempt_at: new Date(now.getTime() + CLAIM_LEASE_MS),
          }))
          .where('id', 'in', due)
          .returning([...QUEUED_COLUMNS, 'attempts'])
          .execute();
        // Every row taken now has the same next try, the lease's end, so they go in the order they were written.
        return rows
          .map((row) => {
            if (!isNoticeKind(row.kind) || (row.role !== null && !isNoticeRole(row.role))) {
              throw new Error("a notice's kind or role is not one the table allows");
            }
            return {
              id: row.id,
              orgId: row.org_id,
              recipientUserId: row.recipient_user_id,
              recipientContactId: row.recipient_contact_id,
              toContacts: row.to_contacts,
              kind: row.kind,
              membershipId: row.membership_id,
              role: row.role,
              aboutId: row.about_id,
              createdAt: row.created_at,
              attempts: row.attempts - 1,
              seal: queuedJudged(keys, row),
            };
          })
          .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime() || a.id.localeCompare(b.id));
      });
    },

    async endRemittanceLeases(db) {
      const now = clock.now();
      const rows = await limited(db, async (tx) =>
        giveUpLeaseEnds(tx, await leaseEnded(tx, now).where('kind', '=', REMITTANCE_KIND).execute(), now),
      );
      return rows.map((row) => ({ id: row.id, orgId: row.org_id, aboutId: row.about_id }));
    },

    async fanOut(db, orgId, id, recipients) {
      if (recipients.length > MOST_RECIPIENTS) {
        throw new RangeError(`at most ${String(MOST_RECIPIENTS)} notices are written from one notice to a group`);
      }
      if (!recipients.every(isId)) throw new RangeError("a notice's recipient is not a UUID");
      if (!isId(orgId) || !isId(id)) return 'not_open';
      const now = clock.now();
      const done = await inOrg(db, orgId, async (tx) => {
        const notice = await tx
          .selectFrom('notifications.outbox')
          .select(QUEUED_COLUMNS)
          .where('id', '=', id)
          .where('recipient_user_id', 'is', null)
          .where('recipient_contact_id', 'is', null)
          .where('sent_at', 'is', null)
          .where((eb) => eb.or([eb('given_up_at', 'is', null), eb('last_failure', '=', LEASE_EXPIRED)]))
          .forUpdate()
          .executeTakeFirst();
        if (notice === undefined) return 'not_open';
        // Its group and what it tells of are copied to each notice written: only from one the app queued.
        if (!queuedHere(orgId, notice)) throw new NotQueuedHere();
        // Its end first, sealed: the chain head's lock, which the records take, comes last (ADR-006 §6).
        await tx
          .updateTable('notifications.outbox')
          .set({ sent_at: now, given_up_at: null, ...ended(id, { outcome: 'sent' }) })
          .where('id', '=', id)
          .execute();
        const unique = [...new Set(recipients.map((recipient) => recipient.toLowerCase()))];
        if (unique.length > 0) {
          await queue(
            tx,
            orgId,
            unique.map((recipient) =>
              rowOf(
                orgId,
                {
                  // One notice to each of the group it was to: the admins' user IDs, or the contacts' IDs.
                  recipient_user_id: notice.to_contacts ? null : recipient,
                  recipient_contact_id: notice.to_contacts ? recipient : null,
                  to_contacts: false,
                  kind: notice.kind,
                  membership_id: notice.membership_id,
                  role: notice.role,
                  about_id: notice.about_id,
                },
                now,
              ),
            ),
          );
        }
        return unique.length;
      });
      return done instanceof NotQueuedHere ? 'not_open' : done;
    },

    async passOn(db, orgId, id, kind, failure) {
      if (!FAILURE.test(failure) || failure === LEASE_EXPIRED) {
        throw new RangeError("a notice passed on gives a short lowercase reason of the caller's");
      }
      // To the admins, about what the notice was about: never a membership's kind, a remittance or a reset's link.
      if (!isNoticeKind(kind) || isAboutAMembership(kind) || kind === REMITTANCE_KIND || kind === RESET_LINK_KIND) {
        throw new RangeError('a notice is passed on to the admins as a kind about what it was about');
      }
      if (!isId(orgId) || !isId(id)) return false;
      const now = clock.now();
      const done = await inOrg(db, orgId, async (tx) => {
        const row = await tx
          .updateTable('notifications.outbox')
          .set({ given_up_at: now, last_failure: failure, ...ended(id, { outcome: 'given_up', failure }) })
          .where('id', '=', id)
          .where('sent_at', 'is', null)
          .where((eb) => eb.or([eb('given_up_at', 'is', null), eb('last_failure', '=', LEASE_EXPIRED)]))
          .returning(QUEUED_COLUMNS)
          .executeTakeFirst();
        if (row === undefined) return false;
        // What it was about goes to the admins' notice: only from one the app queued, or nothing of it stays.
        if (!queuedHere(orgId, row)) throw new NotQueuedHere();
        const toAdmins = { recipient_user_id: null, recipient_contact_id: null, to_contacts: false };
        await queue(tx, orgId, [
          rowOf(orgId, { ...toAdmins, kind, membership_id: null, role: null, about_id: row.about_id }, now),
        ]);
        return true;
      });
      return done === true;
    },

    async sent(db, id) {
      if (!isId(id)) return false;
      const now = clock.now();
      return limited(db, async (tx) => {
        const row = await tx
          .updateTable('notifications.outbox')
          .set({ sent_at: now, given_up_at: null, ...ended(id, { outcome: 'sent' }) })
          .where('id', '=', id)
          .where('sent_at', 'is', null)
          .where((eb) => eb.or([eb('given_up_at', 'is', null), eb('last_failure', '=', LEASE_EXPIRED)]))
          .returning('id')
          .executeTakeFirst();
        return row !== undefined;
      });
    },

    async failed(db, id, failure, lasting) {
      if (!FAILURE.test(failure)) throw new RangeError("a notice's failure is not a short lowercase name");
      if (failure === LEASE_EXPIRED)
        throw new RangeError(`${LEASE_EXPIRED} is the outbox's own reason, never a caller's`);
      if (!isId(id)) return 'done';
      const now = clock.now();
      return limited(db, async (tx) => {
        const row = await tx
          .selectFrom('notifications.outbox')
          .select('attempts')
          .where('id', '=', id)
          .where('sent_at', 'is', null)
          .where('given_up_at', 'is', null)
          .forUpdate()
          .executeTakeFirst();
        if (row === undefined) return 'done';
        // The try that failed was counted as it was taken.
        const givenUp = lasting || row.attempts >= MOST_ATTEMPTS;
        await tx
          .updateTable('notifications.outbox')
          .set({
            last_failure: failure,
            ...(givenUp
              ? { given_up_at: now, ...ended(id, { outcome: 'given_up', failure }) }
              : { next_attempt_at: new Date(now.getTime() + backoffAfter(row.attempts)) }),
          })
          .where('id', '=', id)
          .execute();
        return givenUp ? 'given_up' : 'retry';
      });
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1)
        throw new RangeError('a sweep deletes at least one notice at a time');
      const past = new Date(clock.now().getTime() - OUTBOX_RETENTION_DAYS * DAY_MS);
      return limited(db, async (tx) => {
        const oldest = tx
          .selectFrom('notifications.outbox')
          .select('id')
          .where((eb) => eb.or([eb('sent_at', 'is not', null), eb('given_up_at', 'is not', null)]))
          .where('created_at', '<=', past)
          .orderBy('created_at')
          .limit(most);
        // A notice done is never changed again, so the rows found are still done when deleted.
        const rows = await tx.deleteFrom('notifications.outbox').where('id', 'in', oldest).returning('id').execute();
        return rows.length;
      });
    },
  };
}
