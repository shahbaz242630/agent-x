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
// 4. `consume`: the change's own transaction deletes it and reads its
//    evidence in one statement, only for the same session, action and change
//    hash, verified and still in time: used once, and for nothing else
//    (SEC-HA-03, 04). The evidence goes to the audit trail with the change.
//
// Each runs one statement on the handle it is given, so the caller decides
// the transaction; `sweep` deletes challenges past their time a batch at a
// time, in a transaction of its own with a statement timeout (hourly, from the
// API). A challenge goes with its session. The times are the Clock's
// (ADR-006 §3), so tests can move them.
import { randomBytes } from 'node:crypto';

import { type Kysely, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
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
   * Uses the challenge for exactly this change, in the change's own
   * transaction: deleted and read in one statement, only if it binds this
   * session, action and change hash, is verified and still in time. Undefined
   * otherwise, and the challenge is left as it was.
   */
  consume(db: Handle, challengeId: string, binding: StepUpBinding): Promise<ConsumedStepUp | undefined>;
  /** Deletes up to `most` challenges past their time, and says how many. */
  sweep(db: Kysely<IdentityTables>, most: number): Promise<number>;
}

/** A handle a challenge is opened or consumed on: the pool, or a change's own transaction, whatever else it can reach. */
type Handle = Kysely<IdentityTables> | Transaction<IdentityTables>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
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
}: {
  readonly ids: IdGenerator;
  readonly clock: Clock;
}): StepUpChallenges {
  return {
    async open(db, binding) {
      refuse(bindingProblem(binding));
      const now = clock.now();
      const id = ids.next();
      const nonce = randomBytes(32).toString('base64url');
      const endsAt = new Date(now.getTime() + STEP_UP_SECONDS * 1000);
      // The person is the session's, read in the same statement; a session gone or ended opens nothing.
      const { rows } = await sql<PendingRow>`
        insert into identity.step_up_challenges
          (id, session_id, user_id, action, change_hash, nonce, created_at, ends_at)
        select ${id}::uuid, s.id, s.user_id, ${binding.action}, ${binding.changeHash}::bytea, ${nonce},
          ${now}::timestamptz, ${endsAt}::timestamptz
        from identity.sessions as s
        where s.id = ${binding.sessionId} and s.ends_at > ${now}
        returning id, session_id, user_id, action, change_hash, nonce, created_at, ends_at
      `.execute(db);
      const [row] = rows;
      return row === undefined ? undefined : pendingOf(row);
    },

    async pending(db, challengeId, sessionId) {
      if (!isId(challengeId) || !isId(sessionId)) return undefined;
      const row = await db
        .selectFrom('identity.step_up_challenges')
        .select(PENDING)
        .where('id', '=', challengeId)
        .where('session_id', '=', sessionId)
        .where('verified_at', 'is', null)
        .where('ends_at', '>', clock.now())
        .executeTakeFirst();
      return row === undefined ? undefined : pendingOf(row);
    },

    async recordEvidence(db, challengeId, sessionId, evidence) {
      refuse(evidenceProblem(evidence));
      if (!isId(challengeId) || !isId(sessionId)) return false;
      const now = clock.now();
      const recorded = await db
        .updateTable('identity.step_up_challenges')
        .set({
          verified_at: now,
          auth_time: evidence.authTime,
          amr: [...evidence.amr],
          idp_session_id: evidence.idpSessionId,
          id_token_hash: evidence.idTokenHash,
        })
        .where('id', '=', challengeId)
        .where('session_id', '=', sessionId)
        .where('verified_at', 'is', null)
        .where('ends_at', '>', now)
        .returning('id')
        .executeTakeFirst();
      return recorded !== undefined;
    },

    async consume(db, challengeId, binding) {
      refuse(bindingProblem(binding));
      if (!isId(challengeId)) return undefined;
      const row = await db
        .deleteFrom('identity.step_up_challenges')
        .where('id', '=', challengeId)
        .where('session_id', '=', binding.sessionId)
        .where('action', '=', binding.action)
        .where('change_hash', '=', binding.changeHash)
        .where('verified_at', 'is not', null)
        .where('ends_at', '>', clock.now())
        .returning([...PENDING, 'verified_at', 'auth_time', 'amr', 'idp_session_id', 'id_token_hash'])
        .executeTakeFirst();
      if (row === undefined) return undefined;
      const { verified_at: verifiedAt, auth_time: authTime, amr, id_token_hash: idTokenHash } = row;
      // The table holds the evidence whole or not at all (0013), and only a verified challenge is consumed.
      if (verifiedAt === null || authTime === null || amr === null || idTokenHash === null) {
        throw new Error("a consumed step-up challenge's evidence is incomplete, though the table holds it whole");
      }
      return {
        ...pendingOf(row),
        verifiedAt,
        evidence: { authTime, amr, idpSessionId: row.idp_session_id, idTokenHash },
      };
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) {
        throw new RangeError('a sweep deletes at least one challenge at a time');
      }
      const now = clock.now();
      return db.transaction().execute(async (tx) => {
        await sql`set local statement_timeout = '10s'`.execute(tx);
        const ended = tx.selectFrom('identity.step_up_challenges').select('id').where('ends_at', '<=', now).limit(most);
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
