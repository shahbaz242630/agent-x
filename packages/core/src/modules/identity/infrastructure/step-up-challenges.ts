// Step-up challenges (ADR-003 §8-§9, 0013; B3-1): a person's fresh sign-in,
// bound to one pending change in their own session.
//
// 1. `open`: the change's route opens a challenge for the session, naming the
//    action and the pending change's SHA-256, which the change's own module
//    keeps. The person is the session's. The challenge holds the nonce the
//    login service must echo, and lives five minutes.
// 2. `pending`: on the way back from the login service, the challenge as it
//    stands, for the checks (B3-2): only this session's, not yet verified,
//    still in time.
// 3. `recordEvidence`: once the checks pass, what the fresh sign-in proved is
//    recorded on it, once.
// 4. `hold`: the change's own transaction locks the session's challenges
//    first, at ADR-006 §6's level 0b, before any row the change decides on: a
//    demotion or deactivation of the same person locks their challenges there,
//    then their membership, so a change that read the membership first and its
//    challenge after would deadlock with it (S76). Every one of the session's
//    still in time, since some changes learn which only from a row they read;
//    one past its time is the sweep's, never consumed. `consume` takes only a
//    session held in its own transaction.
// 5. `consume`: the change's own transaction reads it and its evidence, then
//    deletes it, only for the same session, action and change hash, verified
//    and still in time: used once, and for nothing else (SEC-HA-03, 04). The
//    hold keeps anything else from moving it in between. The evidence goes to
//    the audit trail with the change.
//    A change an admin or a finance approver makes asks for a passkey too
//    (SEC-HA-12, ADR-012 §7; B3+-1): the fresh sign-in's `amr` must hold
//    `user`, and one proved with an authenticator app alone is left unused.
//
// Each challenge carries a MAC with `session-mac` (row-macs.ts, S205): over
// what it is for when it opens, and over that and the evidence once verified.
// `pending`, `recordEvidence` and `consume` take only a challenge whose MAC
// holds; one planted or edited by something without the app's key, such as
// the database's owner moving it to verified with a passkey, is none of them,
// and raises the integrity alarm. So does one whose MAC holds but whose use
// the organisation's audit trail already records (`usedBefore`): the owner
// put back, byte for byte, the row its change deleted (R-15, S206). That read
// believes the chain from before the challenge opened through its head, or
// refuses the change as a broken chain does (ChainBroken); `consume` so runs
// only in an organisation's transaction.
//
// Each runs on the handle it is given, so the caller decides the transaction:
// `hold` one statement, the rest a read and then a write of only the row as it
// was read. `sweep` deletes challenges past their time a batch at a time, in a
// transaction of its own with a statement timeout (hourly, from the API). A
// challenge goes with its session. The times are the Clock's (ADR-006 §3), so
// tests can move them.
import { createHash, randomBytes } from 'node:crypto';

import { limitStatements } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, sql, type Transaction } from 'kysely';

import { type Clock, type IdGenerator, UUID } from '../../../shared-kernel/index.ts';
import { type AuditTransaction, ChainBroken, type CheckedEventFacts, eventsSinceChecked } from '../../audit/index.ts';
import { PASSKEY_METHOD } from '../domain/step-up.ts';
import { SESSION_SEALED, sessionRowMessage } from './sessions.ts';
import {
  type ChallengeFacts,
  challengeMessage,
  macHolds,
  macOf,
  type RowMacs,
  rowForged,
  type VerifiedFacts,
} from './row-macs.ts';
import type { IdentityTables } from './tables.ts';

/** How long a person has to sign in again and confirm the change. */
export const STEP_UP_SECONDS = 300;

/** What a challenge is for: the session it binds to, the action, and the pending change's SHA-256. */
export interface StepUpBinding {
  readonly sessionId: string;
  /** In the same form as a write's operation: lower-case words joined by `.` or `-`, at most 64 characters. */
  readonly action: string;
  readonly changeHash: Buffer;
}

/** A challenge not yet verified, as the step-up's return reads it. */
export interface PendingChallenge extends StepUpBinding {
  readonly challengeId: string;
  readonly userId: string;
  /** The nonce the fresh sign-in's ID token must carry. */
  readonly nonce: string;
  readonly createdAt: Date;
  readonly endsAt: Date;
}

/** What the fresh sign-in proved (ADR-003 §9, step 6). */
export interface StepUpEvidence {
  readonly authTime: Date;
  readonly amr: readonly string[];
  /** Zitadel's session ID, as evidence only: it changes at every forced re-login. */
  readonly idpSessionId: string | null;
  /** SHA-256 of the ID token the login service returned. */
  readonly idTokenHash: Buffer;
}

declare const held: unique symbol;

/** A session whose challenges `hold` has locked in the change's transaction: the only kind `consume` takes. */
export interface HeldChallenges {
  readonly sessionId: string;
  /** The transaction holding them: a hold on any other handle has let go already. */
  readonly db: Handle;
  readonly [held]: true;
}

/** A challenge used by its change: what it was for, and the evidence, for the audit trail. */
export interface ConsumedStepUp extends PendingChallenge {
  readonly verifiedAt: Date;
  readonly evidence: StepUpEvidence;
}

export interface StepUpChallenges {
  /** Opens a challenge for a change in the session; undefined if the session is gone or past its absolute end. */
  open(db: Handle, binding: StepUpBinding): Promise<PendingChallenge | undefined>;
  /** The session's challenge, not yet verified and still in time; undefined for any other. */
  pending(db: Kysely<IdentityTables>, challengeId: string, sessionId: string): Promise<PendingChallenge | undefined>;
  /** Records what the fresh sign-in proved on the session's challenge, once and in time; false if it can't. */
  recordEvidence(
    db: Kysely<IdentityTables>,
    challengeId: string,
    sessionId: string,
    evidence: StepUpEvidence,
  ): Promise<boolean>;
  /**
   * Locks every challenge of the session still in time, in order of ID, for
   * the change's own transaction, first, at ADR-006 §6's level 0b: before the
   * change reads any row it decides on.
   */
  hold(db: Handle, sessionId: string): Promise<HeldChallenges>;
  /**
   * Uses the challenge for exactly this change, in the change's own
   * transaction: deleted and read in one statement, only if it binds this
   * session, action and change hash, is verified and still in time, and,
   * where `passkeyRequired`, was proved with a passkey. Undefined otherwise,
   * and the challenge is left as it was.
   */
  consume(
    db: Handle,
    session: HeldChallenges,
    challengeId: string,
    binding: StepUpBinding,
    need: { readonly passkeyRequired: boolean },
  ): Promise<ConsumedStepUp | undefined>;
  /** Deletes up to `most` challenges past their time, and says how many. */
  sweep(db: Kysely<IdentityTables>, most: number): Promise<number>;
}

/**
 * A pending change's SHA-256, as a challenge binds it: each fact in a fixed
 * order, as its length then its bytes, so no two lists of facts hash alike.
 * No label of its own: the challenge binds the action beside it.
 */
export function changeHashOf(parts: readonly string[]): Buffer {
  const hash = createHash('sha256');
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length).update(bytes);
  }
  return hash.digest();
}

/** A consumed step-up's evidence, as the change's audit event keeps it (ADR-003 §9 step 6): IDs, times and hashes only. */
export const stepUpDetails = (consumed: ConsumedStepUp) => ({
  stepUpChallengeId: consumed.challengeId,
  changeHash: consumed.changeHash.toString('hex'),
  signedInAt: consumed.evidence.authTime.toISOString(),
  methods: consumed.evidence.amr.join(' '),
  proofHash: consumed.evidence.idTokenHash.toString('hex'),
  verifiedAt: consumed.verifiedAt.toISOString(),
});

/**
 * Locks the people's challenges, in order of ID, in the caller's transaction:
 * a demotion's or deactivation's level 0b (ADR-006 §6), after their sessions,
 * so the challenges their sessions' end deletes are held before any
 * membership is, and a challenge being used at the same moment is waited
 * for, never waited on backwards. Found through their sessions, by the
 * session's index: a challenge is its session's person's (0013).
 */
export async function lockChallengesOf(tx: Transaction<IdentityTables>, userIds: readonly string[]): Promise<void> {
  await tx
    .selectFrom('identity.step_up_challenges')
    .select('id')
    .where('session_id', 'in', (eb) => eb.selectFrom('identity.sessions').select('id').where('user_id', 'in', userIds))
    .orderBy('id')
    .forUpdate()
    .execute();
}

/** A handle a challenge is opened or consumed on: the pool, or a change's own transaction, whatever else it can reach. */
type Handle = Kysely<IdentityTables> | Transaction<IdentityTables>;

const ACTION = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$/;
const ACTION_MAX = 64;
const HASH_BYTES = 32;
const MOST_AMR = 16;
const MOST_TEXT = 255;

const isId = (value: unknown): value is string => typeof value === 'string' && UUID.test(value);
const isHash = (value: unknown): value is Buffer => Buffer.isBuffer(value) && value.length === HASH_BYTES;
const isText = (value: unknown): value is string =>
  typeof value === 'string' && value.length >= 1 && value.length <= MOST_TEXT;

/** Why a binding can't be taken, if it can't: a caller the compiler can't see could pass anything. */
function bindingProblem({ sessionId, action, changeHash }: StepUpBinding): string | undefined {
  if (!isId(sessionId)) return 'the session ID is not a UUID';
  if (typeof action !== 'string' || !ACTION.test(action) || action.length > ACTION_MAX) {
    return `the action is not lower-case words joined by . or -, at most ${String(ACTION_MAX)} characters`;
  }
  if (!isHash(changeHash)) return "the change's hash is not 32 bytes";
  return undefined;
}

function evidenceProblem({ authTime, amr, idpSessionId, idTokenHash }: StepUpEvidence): string | undefined {
  if (!(authTime instanceof Date) || Number.isNaN(authTime.getTime())) return 'the authentication time is not a time';
  if (!Array.isArray(amr) || amr.length < 1 || amr.length > MOST_AMR || !amr.every(isText)) {
    return `the methods are not 1 to ${String(MOST_AMR)} names`;
  }
  if (idpSessionId !== null && !isText(idpSessionId)) return "Zitadel's session ID is not 1 to 255 characters";
  if (!isHash(idTokenHash)) return "the ID token's hash is not 32 bytes";
  return undefined;
}

const refuse = (problem: string | undefined): void => {
  if (problem !== undefined) throw new RangeError(`A step-up refused: ${problem}`);
};

/** The columns a challenge is read back by. */
const PENDING = ['id', 'session_id', 'user_id', 'action', 'change_hash', 'nonce', 'created_at', 'ends_at'] as const;

interface PendingRow {
  readonly id: string;
  readonly session_id: string;
  readonly user_id: string;
  readonly action: string;
  readonly change_hash: Buffer;
  readonly nonce: string;
  readonly created_at: Date;
  readonly ends_at: Date;
}

/** The columns a challenge's MAC is kept in. */
const MAC = ['mac', 'mac_key_version'] as const;
/** The columns its evidence is kept in, once verified. */
const EVIDENCE = ['verified_at', 'auth_time', 'amr', 'idp_session_id', 'id_token_hash'] as const;

interface MacRow {
  readonly mac: Buffer;
  readonly mac_key_version: number;
}

interface EvidenceRow {
  readonly verified_at: Date | null;
  readonly auth_time: Date | null;
  readonly amr: readonly string[] | null;
  readonly idp_session_id: string | null;
  readonly id_token_hash: Buffer | null;
}

const factsOf = (row: PendingRow, verified: VerifiedFacts | undefined): ChallengeFacts => ({
  id: row.id,
  sessionId: row.session_id,
  userId: row.user_id,
  action: row.action,
  changeHash: row.change_hash,
  nonce: row.nonce,
  createdAt: row.created_at,
  endsAt: row.ends_at,
  verified,
});

/** The evidence a verified row holds, or undefined where any part is missing: the app always writes it whole. */
function verifiedOf(row: EvidenceRow): VerifiedFacts | undefined {
  const { verified_at: verifiedAt, auth_time: authTime, amr, idp_session_id: idpSessionId, id_token_hash } = row;
  if (verifiedAt === null || authTime === null || amr === null || id_token_hash === null) return undefined;
  return { verifiedAt, authTime, amr, idpSessionId, idTokenHash: id_token_hash };
}

/**
 * How much earlier than a challenge's own creation `usedBefore` starts
 * reading: its first use can't come before it opened, but the time it holds
 * is the app's clock, and the events' the database's.
 */
const CLOCKS_APART_MS = 60_000;

/** A challenge's use as the audit trail tells it: `used` or `unused`, believed; or the chain can't be (its problem). */
type Use =
  | { readonly kind: 'used' | 'unused' }
  | { readonly kind: 'unbelieved'; readonly reason: string; readonly orgId?: string; readonly seq?: bigint };

/** An event of the challenge's person whose details name it: the change that used it. */
function namesChallenge(event: CheckedEventFacts, row: PendingRow): boolean {
  // Most events don't hold the ID at all: only those that do are read as JSON.
  if (event.actorType !== 'user' || event.actorId !== row.user_id || !event.details.includes(row.id)) return false;
  // The chain's check passed it, so its details are the app's own canonical JSON object.
  const details = JSON.parse(event.details) as Readonly<Record<string, unknown>>;
  return details.stepUpChallengeId === row.id;
}

/**
 * Whether the organisation's audit trail already holds a change made with
 * this challenge (R-15, S206): every change that consumes one records
 * `stepUpDetails` in an event of its own transaction, by the challenge's
 * person. Read only from events the chain's check believes, from the last one
 * before the challenge opened through the head (eventsSinceChecked): the owner
 * can't hide the change's event for the replay and put it back after, since a
 * chain with it gone, edited or moved fails the check, and fails closed. The
 * challenge's creation time is its MAC's, so the owner can't move the start.
 */
async function usedBefore(db: Handle, row: PendingRow, keys: KeyProvider): Promise<Use> {
  const since = new Date(row.created_at.getTime() - CLOCKS_APART_MS);
  // The audit trail's read runs raw SQL on the change's own transaction, whatever tables its type names.
  const checked = await eventsSinceChecked(db as unknown as AuditTransaction, keys, since);
  if (checked.kind === 'unbelieved') return checked;
  return { kind: checked.events.some((event) => namesChallenge(event, row)) ? 'used' : 'unused' };
}

const pendingOf = (row: PendingRow): PendingChallenge => ({
  challengeId: row.id,
  sessionId: row.session_id,
  userId: row.user_id,
  action: row.action,
  changeHash: row.change_hash,
  nonce: row.nonce,
  createdAt: row.created_at,
  endsAt: row.ends_at,
});

export function createStepUpChallenges({
  ids,
  clock,
  keys,
  logger,
}: RowMacs & {
  readonly ids: IdGenerator;
  readonly clock: Clock;
}): StepUpChallenges {
  /** Whether the row is the app's own, as it stands: a row whose MAC doesn't hold raises the alarm, and is no challenge. */
  const genuine = (row: PendingRow & MacRow, verified: VerifiedFacts | undefined): boolean => {
    if (macHolds(keys, challengeMessage(factsOf(row, verified)), row)) return true;
    rowForged(logger, 'step_up_challenge', row);
    return false;
  };

  /** The session's challenge not yet verified and still in time, whatever its MAC. */
  const unverified = (db: Kysely<IdentityTables>, challengeId: string, sessionId: string, now: Date) =>
    db
      .selectFrom('identity.step_up_challenges')
      .select([...PENDING, ...MAC])
      .where('id', '=', challengeId)
      .where('session_id', '=', sessionId)
      .where('verified_at', 'is', null)
      .where('ends_at', '>', now)
      .executeTakeFirst();

  return {
    async open(db, binding) {
      refuse(bindingProblem(binding));
      const now = clock.now();
      const id = ids.next();
      const nonce = randomBytes(32).toString('base64url');
      const endsAt = new Date(now.getTime() + STEP_UP_SECONDS * 1000);
      // The person is the session's: read first, for the MAC, and asked again of the session as the row is written.
      const session = await db
        .selectFrom('identity.sessions')
        .select(SESSION_SEALED)
        .where('id', '=', binding.sessionId)
        .where('ends_at', '>', now)
        .executeTakeFirst();
      if (session === undefined) return undefined;
      // Its person is bound to the challenge only from a session whose MAC holds.
      if (!macHolds(keys, sessionRowMessage(session), session)) {
        rowForged(logger, 'session', session);
        return undefined;
      }
      const { mac, mac_key_version: macKeyVersion } = macOf(
        keys,
        challengeMessage({
          id,
          sessionId: binding.sessionId,
          userId: session.user_id,
          action: binding.action,
          changeHash: binding.changeHash,
          nonce,
          createdAt: now,
          endsAt,
          verified: undefined,
        }),
      );
      // A session gone, ended or given to another person meanwhile opens nothing.
      const { rows } = await sql<PendingRow>`
        insert into identity.step_up_challenges
          (id, session_id, user_id, action, change_hash, nonce, created_at, ends_at, mac, mac_key_version)
        select ${id}::uuid, s.id, s.user_id, ${binding.action}, ${binding.changeHash}::bytea, ${nonce},
          ${now}::timestamptz, ${endsAt}::timestamptz, ${mac}::bytea, ${macKeyVersion}::integer
        from identity.sessions as s
        where s.id = ${binding.sessionId} and s.user_id = ${session.user_id} and s.ends_at > ${now}
        returning id, session_id, user_id, action, change_hash, nonce, created_at, ends_at
      `.execute(db);
      const [row] = rows;
      return row === undefined ? undefined : pendingOf(row);
    },

    async pending(db, challengeId, sessionId) {
      if (!isId(challengeId) || !isId(sessionId)) return undefined;
      const row = await unverified(db, challengeId, sessionId, clock.now());
      return row !== undefined && genuine(row, undefined) ? pendingOf(row) : undefined;
    },

    async recordEvidence(db, challengeId, sessionId, evidence) {
      refuse(evidenceProblem(evidence));
      if (!isId(challengeId) || !isId(sessionId)) return false;
      const now = clock.now();
      const row = await unverified(db, challengeId, sessionId, now);
      // Only a challenge whose MAC held is verified: the new MAC would make a forged one genuine.
      if (row === undefined || !genuine(row, undefined)) return false;
      const verified: VerifiedFacts = {
        verifiedAt: now,
        authTime: evidence.authTime,
        amr: [...evidence.amr],
        idpSessionId: evidence.idpSessionId,
        idTokenHash: evidence.idTokenHash,
      };
      const recorded = await db
        .updateTable('identity.step_up_challenges')
        .set({
          verified_at: now,
          auth_time: evidence.authTime,
          amr: [...evidence.amr],
          idp_session_id: evidence.idpSessionId,
          id_token_hash: evidence.idTokenHash,
          ...macOf(keys, challengeMessage(factsOf(row, verified))),
        })
        .where('id', '=', challengeId)
        .where('session_id', '=', sessionId)
        .where('verified_at', 'is', null)
        .where('ends_at', '>', now)
        // Only the row as it was checked: written meanwhile by anyone else, it is left as it is.
        .where('mac', '=', row.mac)
        .returning('id')
        .executeTakeFirst();
      return recorded !== undefined;
    },

    async hold(db, sessionId) {
      if (isId(sessionId)) {
        await db
          .selectFrom('identity.step_up_challenges')
          .select('id')
          .where('session_id', '=', sessionId)
          .where('ends_at', '>', clock.now())
          .orderBy('id')
          .forUpdate()
          .execute();
      }
      return { sessionId, db } as HeldChallenges;
    },

    async consume(db, session, challengeId, binding, { passkeyRequired }) {
      refuse(bindingProblem(binding));
      // Held for another session: a change that checked the wrong one, which nothing must let through.
      if (session.sessionId !== binding.sessionId) throw new RangeError("the challenges held are another session's");
      if (session.db !== db) throw new RangeError('the challenges were held in another transaction');
      if (!isId(challengeId)) return undefined;
      // Read, then deleted: `hold` locked it in this transaction, so nothing moves it in between.
      const row = await db
        .selectFrom('identity.step_up_challenges')
        .select([...PENDING, ...EVIDENCE, ...MAC])
        .where('id', '=', challengeId)
        .where('session_id', '=', binding.sessionId)
        .where('action', '=', binding.action)
        .where('change_hash', '=', binding.changeHash)
        .where('verified_at', 'is not', null)
        .where('ends_at', '>', clock.now())
        .$if(passkeyRequired, (query) => query.where((eb) => eb(eb.val(PASSKEY_METHOD), '=', eb.fn.any('amr'))))
        .executeTakeFirst();
      if (row === undefined) return undefined;
      // The app writes the evidence whole (0013), so a part missing is a row it never wrote, as is a MAC that fails.
      const verified = verifiedOf(row);
      if (verified === undefined) {
        rowForged(logger, 'step_up_challenge', row);
        return undefined;
      }
      if (!genuine(row, verified)) return undefined;
      // A genuine row already used: the owner put back the one its change deleted (R-15), to use it again.
      const use = await usedBefore(db, row, keys);
      if (use.kind === 'used') {
        rowForged(logger, 'step_up_challenge', row, 'already_used');
        return undefined;
      }
      if (use.kind === 'unbelieved') {
        if (use.orgId === undefined)
          throw new RangeError("a challenge is consumed only in an organisation's transaction");
        rowForged(logger, 'step_up_challenge', row, 'chain_unverified');
        // As a write finding its chain broken does: refused whole, and withSignedStates names the chain.
        throw new ChainBroken({ kind: 'organisation', orgId: use.orgId });
      }
      const deleted = await db
        .deleteFrom('identity.step_up_challenges')
        .where('id', '=', challengeId)
        .where('mac', '=', row.mac)
        .returning('id')
        .executeTakeFirst();
      if (deleted === undefined) return undefined;
      const { verifiedAt, authTime, amr, idpSessionId, idTokenHash } = verified;
      return {
        ...pendingOf(row),
        verifiedAt,
        evidence: { authTime, amr, idpSessionId, idTokenHash },
      };
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) {
        throw new RangeError('a sweep deletes at least one challenge at a time');
      }
      const now = clock.now();
      return db.transaction().execute(async (tx) => {
        await limitStatements(tx);
        // Never waits on a challenge locked by a change or a demotion: it takes the rest, and that one next time.
        const ended = tx
          .selectFrom('identity.step_up_challenges')
          .select('id')
          .where('ends_at', '<=', now)
          .orderBy('id')
          .limit(most)
          .forUpdate()
          .skipLocked();
        const rows = await tx
          .deleteFrom('identity.step_up_challenges')
          .where('id', 'in', ended)
          .returning('id')
          .execute();
        return rows.length;
      });
    },
  };
}
