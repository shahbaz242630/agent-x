// A sign-in from end to end (ADR-003 §5-§7), for the API's routes (B2-3a-2):
//
// - `begin` starts an OIDC flow and keeps it (login-flows.ts), giving the
//   address to send the browser to and the flow ID for its short-lived cookie.
// - `complete` takes the flow back once, before anything else, so a replayed
//   callback finds nothing; has the OIDC client trade the code and check the
//   ID token; then, in one transaction, finds or makes the user, ends the
//   session the browser brought (if any) and opens a new one. A sign-in never
//   keeps a session it didn't open (SEC-HA-07: rotated at login).
// - `signedIn` finds the live session a request's cookie names, its last use
//   moved on (B2-4b: every signed-in request).
//
// A step-up (B3-3a, ADR-003 §9):
// - `beginStepUp` starts one for a challenge of the person's own session: a
//   flow like a sign-in's, naming the challenge, with `prompt=login` and the
//   challenge's own nonce, so the login service asks them to sign in again
//   and its ID token must carry that nonce.
// - `complete` takes a step-up's flow back the same way. Then, instead of
//   opening a session: the session the browser brings must still be live and
//   the challenge still pending for it; the ID token is checked; its person
//   must be a user already (found, never made); and the fresh sign-in must
//   stand for the challenge (`stepUpRefusal`). Then, in one transaction, the
//   session is given a new cookie ID, keeping its record (SEC-HA-07: rotated
//   at step-up), and the evidence recorded on the challenge: the session's
//   lock before the challenge's, as a sign-out's and a deactivation's are
//   (ADR-006 §6 level 0b), so none of them waits on another backwards. Anything wrong is
//   StepUpFailed, and nothing is recorded; a login service that can't be
//   reached stays SignInFailed `provider_unavailable`.
//
// B4-4a: a sign-in's verified email address, if the login service gave one,
// is kept encrypted with the session it opens, in the same transaction
// (session-emails.ts); a step-up's is never taken, as the session keeps its
// own.
//
// Each database step gives up after 10 seconds, a wait for a lock included,
// so a hung statement can't hold a sign-in, or its connection, for good.
import type { KeyProvider } from '@agentx/platform/keys';
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { HOME_PATH, isReturnPath } from '../domain/sign-in.ts';
import { type StepUpRefusal, stepUpRefusal } from '../domain/step-up.ts';
import type { LoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed, type SignInFailure } from './oidc-client.ts';
import { recordSessionEmail } from './session-emails.ts';
import type { LiveSession, Sessions } from './sessions.ts';
import type { StepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { userForSubject } from './users.ts';

export interface SignInBegun {
  /** The login service's address to send the browser to. */
  readonly url: string;
  /** For the flow cookie; never kept. */
  readonly flowId: string;
}

export interface SignInCompleted {
  readonly userId: string;
  readonly sessionId: string;
  /** For the session cookie; never kept. */
  readonly cookie: string;
  /** Where to send the browser now: the path it asked for at the start. */
  readonly returnTo: string;
  /** The step-up challenge now verified, when the flow was a step-up; undefined for a sign-in. */
  readonly stepUpChallengeId: string | undefined;
}

export interface CallbackInput {
  /** The flow cookie's value, if the browser sent one. */
  readonly flowId: string | undefined;
  readonly code: string;
  readonly state: string;
  /** The session cookie the browser brought, if any: ended at a sign-in, never kept; a step-up's own. */
  readonly previousCookie: string | undefined;
}

/**
 * Why a step-up failed: the sign-in's own failures on the way back (but the
 * login service being unreachable, which stays SignInFailed), no live session
 * (`session_missing`), the challenge gone, used or out of time
 * (`challenge_missing`), or the fresh sign-in not standing for it.
 */
export type StepUpFailure =
  Exclude<SignInFailure, 'provider_unavailable'> | 'session_missing' | 'challenge_missing' | StepUpRefusal;

export class StepUpFailed extends Error {
  override readonly name = 'StepUpFailed';
  readonly failure: StepUpFailure;
  /** The session's person, where the failure came after the session was found. */
  readonly userId: string | undefined;
  constructor(failure: StepUpFailure, detail: string, userId?: string) {
    super(`step-up failed (${failure}): ${detail}`);
    this.failure = failure;
    this.userId = userId;
  }
}

export interface SignIn {
  /** Starts a sign-in that sends the browser back to `returnTo` (our home page if none). Throws RangeError for a path that isn't ours. */
  begin(returnTo?: string): Promise<SignInBegun>;
  /**
   * Starts a step-up for the session's own pending challenge, sending the
   * browser back to `returnTo` after. Throws StepUpFailed `challenge_missing`
   * for a challenge that isn't the session's or isn't pending, RangeError for
   * a path that isn't ours.
   */
  beginStepUp(sessionId: string, challengeId: string, returnTo?: string): Promise<SignInBegun>;
  /** Finishes the sign-in or step-up the flow cookie names. Throws SignInFailed, or StepUpFailed for a step-up. */
  complete(input: CallbackInput): Promise<SignInCompleted>;
  /** Ends the session this cookie belongs to, if any; true if there was one. */
  signOut(cookie: string | undefined): Promise<boolean>;
  /** The live session this cookie belongs to, its last use moved on; undefined if there is none. */
  signedIn(cookie: string): Promise<LiveSession | undefined>;
}

export function createSignIn({
  db,
  oidc,
  flows,
  sessions,
  challenges,
  ids,
  clock,
  keys,
}: {
  readonly db: Kysely<IdentityTables>;
  readonly oidc: OidcClient;
  readonly flows: LoginFlows;
  readonly sessions: Sessions;
  readonly challenges: StepUpChallenges;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** For the session's verified address (`field-encryption`). */
  readonly keys: KeyProvider;
}): SignIn {
  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(work: (tx: Kysely<IdentityTables>) => Promise<T>): Promise<T> =>
    db.transaction().execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return work(tx);
    });

  /** A step-up's way back: the session, the challenge, the ID token, the checks; then the evidence and a new cookie ID. */
  async function completeStepUp(
    challengeId: string,
    taken: { readonly flow: LoginFlow; readonly returnTo: string },
    returned: { readonly code: string; readonly state: string },
    cookie: string | undefined,
  ): Promise<SignInCompleted> {
    const session = cookie === undefined ? undefined : await limited((tx) => sessions.use(tx, cookie));
    if (session === undefined) throw new StepUpFailed('session_missing', 'the browser brought no live session');
    const { sessionId, userId } = session;
    const pending = await limited((tx) => challenges.pending(tx, challengeId, sessionId));
    if (pending === undefined) {
      throw new StepUpFailed('challenge_missing', 'the challenge is not pending for this session', userId);
    }
    let signedIn;
    try {
      signedIn = await oidc.finish(taken.flow, returned);
    } catch (error) {
      if (!(error instanceof SignInFailed) || error.failure === 'provider_unavailable') throw error;
      throw new StepUpFailed(error.failure, error.message, userId);
    }
    const { subject, evidence, idTokenHash } = signedIn;
    const person = await limited((tx) =>
      tx
        .selectFrom('identity.users')
        .select('id')
        .where('issuer', '=', subject.issuer)
        .where('subject', '=', subject.subject)
        .executeTakeFirst(),
    );
    // A passkey is asked for as the change consumes the challenge, where its role is known (B3+-1).
    const refusal =
      person === undefined
        ? 'other_person'
        : stepUpRefusal(pending, { userId: person.id, evidence }, { passkeyRequired: false });
    if (refusal !== undefined) {
      throw new StepUpFailed(refusal, 'the fresh sign-in does not stand for the challenge', userId);
    }
    return limited(async (tx) => {
      const rotated = await sessions.rotate(tx, sessionId);
      if (rotated === undefined) throw new StepUpFailed('session_missing', 'the session ended', userId);
      const recorded = await challenges.recordEvidence(tx, challengeId, sessionId, {
        authTime: evidence.authTime,
        amr: evidence.amr,
        idpSessionId: evidence.idpSessionId ?? null,
        idTokenHash,
      });
      if (!recorded) throw new StepUpFailed('challenge_missing', 'the challenge ran out of time', userId);
      return { userId, sessionId, cookie: rotated, returnTo: taken.returnTo, stepUpChallengeId: challengeId };
    });
  }

  return {
    async begin(returnTo = HOME_PATH) {
      if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
      const { url, flow } = await oidc.start();
      const flowId = await limited((tx) => flows.save(tx, flow, returnTo));
      return { url, flowId };
    },

    async beginStepUp(sessionId, challengeId, returnTo = HOME_PATH) {
      if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
      const pending = await limited((tx) => challenges.pending(tx, challengeId, sessionId));
      if (pending === undefined) {
        throw new StepUpFailed('challenge_missing', 'no challenge of this session is pending');
      }
      const { url, flow } = await oidc.start({ prompt: 'login', nonce: pending.nonce });
      const flowId = await limited((tx) => flows.save(tx, flow, returnTo, pending.challengeId));
      return { url, flowId };
    },

    async complete({ flowId, code, state, previousCookie }) {
      // Taken, and committed, before the login service is called: used once, whatever follows.
      const taken = flowId === undefined ? undefined : await limited((tx) => flows.take(tx, flowId));
      if (taken === undefined) throw new SignInFailed('flow_missing', 'no flow of ours is waiting for this browser');
      if (taken.stepUpChallengeId !== undefined) {
        return completeStepUp(taken.stepUpChallengeId, taken, { code, state }, previousCookie);
      }
      const { subject, evidence, verifiedEmail } = await oidc.finish(taken.flow, { code, state });
      return limited(async (tx) => {
        const userId = await userForSubject(tx, subject, { ids, clock });
        if (previousCookie !== undefined) await sessions.end(tx, previousCookie);
        const { sessionId, cookie } = await sessions.open(tx, userId, evidence);
        if (verifiedEmail !== undefined) await recordSessionEmail(tx, keys, sessionId, verifiedEmail);
        return { userId, sessionId, cookie, returnTo: taken.returnTo, stepUpChallengeId: undefined };
      });
    },

    signOut(cookie) {
      return cookie === undefined ? Promise.resolve(false) : limited((tx) => sessions.end(tx, cookie));
    },

    signedIn(cookie) {
      return limited((tx) => sessions.use(tx, cookie));
    },
  };
}
