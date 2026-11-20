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
// E10d (decision 25): a sign-in's name and verified address, as the login
// service gave them, are kept for the person too, in the same transaction
// (user-contacts.ts), for the audit log to say who did what.
//
// S206 V8: a sign-in starts only while its flows are under their caps
// (login-flows.ts): every network's together, and the network it comes from.
// Past either it is SignInBusy, and no flow is kept.
//
// S207 (R-15): a flow's return path is kept unsealed, so `complete` checks it
// again as it takes the flow. Only the app writes one, and only a path of our
// own, so one that isn't (an address on another site, `//evil.example`) was
// written past the app: the integrity alarm, and the browser goes home.
//
// S207 (R-15): a session a sign-out deletes, or a sign-in ends for the cookie
// the browser brought, is signed as ended on the platform chain in the same
// transaction, the platform head its last lock (ADR-006 §6): its row put back by
// the database's owner is no session (sessions.ts). A sign-out never fails
// closed: if its end can't be signed (the platform head locked past the limit,
// or unreadable, which the owner could cause), the session is deleted in a
// transaction of its own, with the integrity alarm, and the browser signed out.
//
// Each database step gives up after 10 seconds, a wait for a lock included,
// so a hung statement can't hold a sign-in, or its connection, for good.
import type { KeyProvider } from '@agentx/platform/keys';
import { limitStatements } from '@agentx/platform/db';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { createPlatformChain, type PlatformTransaction } from '../../platform-controls/index.ts';
import { HOME_PATH, isReturnPath, type Subject } from '../domain/sign-in.ts';
import { earliestAuthTime, type StepUpRefusal, stepUpRefusal } from '../domain/step-up.ts';
import type { LoginFlows } from './login-flows.ts';
import { type LoginFlow, type OidcClient, SignInFailed, type SignInFailure } from './oidc-client.ts';
import { recordSessionEmail } from './session-emails.ts';
import { type EndedSession, type LiveSession, type Sessions, sessionsEndedAt } from './sessions.ts';
import { createSignedEnds, sessionEndedEvent } from './signed-ends.ts';
import type { StepUpChallenges } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { keepUserContact } from './user-contacts.ts';
import { subjectOfUser, userForSubject, userOfSubject, UserUnbelieved } from './users.ts';

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

/**
 * What the browser brought back: the code and state to finish with, or, when
 * the login service sent it back without a sign-in, why (`refused`): its flow
 * is still taken, so a step-up's browser can go back to its page (CO2).
 */
export type CallbackInput = {
  /** The flow cookie's value, if the browser sent one. */
  readonly flowId: string | undefined;
  /** The session cookie the browser brought, if any: ended at a sign-in, never kept; a step-up's own. */
  readonly previousCookie: string | undefined;
} & (
  { readonly code: string; readonly state: string } | { readonly refused: 'provider_refused' | 'callback_incomplete' }
);

/**
 * Why a step-up failed: the sign-in's own failures on the way back (but the
 * login service being unreachable, which stays SignInFailed), no live session
 * (`session_missing`), the challenge gone, used or out of time
 * (`challenge_missing`), or the fresh sign-in not standing for it.
 */
export type StepUpFailure =
  Exclude<SignInFailure, 'provider_unavailable'> | 'session_missing' | 'challenge_missing' | StepUpRefusal;

/** Where a step-up's browser goes back to after a failure on the way back: the page it was asked on, and for which challenge. */
interface StepUpReturn {
  readonly returnTo: string;
  readonly challengeId: string;
}

export class StepUpFailed extends Error {
  override readonly name = 'StepUpFailed';
  readonly failure: StepUpFailure;
  /** The session's person, where the failure came after the session was found. */
  readonly userId: string | undefined;
  /** Where the browser came from, for a failure on the way back from the login service; none at the start. */
  readonly back: StepUpReturn | undefined;
  constructor(failure: StepUpFailure, detail: string, userId?: string, back?: StepUpReturn) {
    super(`step-up failed (${failure}): ${detail}`);
    this.failure = failure;
    this.userId = userId;
    this.back = back;
  }
}

/** A sign-in not started: too many are under way, every network's together (`full`) or this network's (S206 V8). */
export class SignInBusy extends Error {
  override readonly name = 'SignInBusy';
  readonly cap: 'full' | 'network_full';
  constructor(cap: 'full' | 'network_full') {
    super(`sign-in not started: too many under way (${cap})`);
    this.cap = cap;
  }
}

export interface SignIn {
  /**
   * Starts a sign-in from `network` (its client's, as login-flows.ts counts it) that sends the browser back to
   * `returnTo` (our home page if none). Throws RangeError for a path that isn't ours, SignInBusy past a cap.
   */
  begin(returnTo: string | undefined, network: string): Promise<SignInBegun>;
  /**
   * Starts a step-up for the session's own pending challenge, sending the
   * browser back to `returnTo` after. Throws StepUpFailed `challenge_missing`
   * for a challenge that isn't the session's or isn't pending, RangeError for
   * a path that isn't ours.
   */
  beginStepUp(sessionId: string, challengeId: string, returnTo?: string): Promise<SignInBegun>;
  /** Finishes the sign-in or step-up the flow cookie names. Throws SignInFailed, or StepUpFailed for a step-up. */
  complete(input: CallbackInput): Promise<SignInCompleted>;
  /** Ends the session this cookie belongs to, if any; who it was, as they sign in, undefined if there was none. */
  signOut(cookie: string | undefined): Promise<Subject | undefined>;
  /** The live session this cookie belongs to, its last use moved on; undefined if there is none. */
  signedIn(cookie: string): Promise<LiveSession | undefined>;
  /** Who holds the live session this cookie belongs to, its last use left as it was; undefined if there is none. */
  holderOf(cookie: string): Promise<string | undefined>;
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
  logger,
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
  /** For the integrity alarm of a person's row whose MAC fails (S205). */
  readonly logger: Logger;
}): SignIn {
  const macs = { keys, logger };
  /** The people's sessions' ends this process has checked on the platform chain, shared by its sign-ins (R-15). */
  const ends = { logger, signedEnds: createSignedEnds(keys) };
  const platform = createPlatformChain({ keys, ids });
  /** Signs the session's end on the platform chain, in the transaction that deleted it, last of its locks (R-15). */
  const signEnd = async (tx: Kysely<IdentityTables>, ended: EndedSession | undefined): Promise<void> => {
    // The platform chain's tables are in the same database, and belong to no organisation.
    if (ended !== undefined)
      await platform.record(tx as unknown as PlatformTransaction, sessionEndedEvent(ended, clock.now()));
  };
  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(work: (tx: Kysely<IdentityTables>) => Promise<T>): Promise<T> =>
    db.transaction().execute(async (tx) => {
      await limitStatements(tx);
      return work(tx);
    });

  /** The flow as taken, its return path checked again (S207): one that isn't ours raises the alarm and is home instead. */
  function ownReturn<T extends { readonly returnTo: string }>(taken: T | undefined): T | undefined {
    if (taken === undefined || isReturnPath(taken.returnTo)) return taken;
    logger.error('audit.integrity_failed', { check: 'login_flow', reason: 'return_to' });
    return { ...taken, returnTo: HOME_PATH };
  }

  /** A step-up's way back: the session, the challenge, the ID token, the checks; then the evidence and a new cookie ID. */
  async function completeStepUp(
    challengeId: string,
    taken: { readonly flow: LoginFlow; readonly returnTo: string },
    returned: { readonly code: string; readonly state: string },
    cookie: string | undefined,
  ): Promise<SignInCompleted> {
    // Each failure names the page the browser came from, so the API can send it back there to say so (CO2).
    const back = { returnTo: taken.returnTo, challengeId };
    const failed = (failure: StepUpFailure, detail: string, userId?: string) =>
      new StepUpFailed(failure, detail, userId, back);
    const session = cookie === undefined ? undefined : await limited((tx) => sessions.use(tx, cookie));
    if (session === undefined) throw failed('session_missing', 'the browser brought no live session');
    const { sessionId, userId } = session;
    const pending = await limited((tx) => challenges.pending(tx, challengeId, sessionId));
    if (pending === undefined) {
      throw failed('challenge_missing', 'the challenge is not pending for this session', userId);
    }
    let signedIn;
    try {
      signedIn = await oidc.finish(taken.flow, returned);
    } catch (error) {
      if (!(error instanceof SignInFailed) || error.failure === 'provider_unavailable') throw error;
      throw failed(error.failure, error.message, userId);
    }
    const { subject, evidence, idTokenHash } = signedIn;
    // A row whose MAC fails is no one (S205): refused as another person, with the alarm.
    const personId = await limited((tx) => userOfSubject(tx, subject, macs));
    // A passkey is asked for as the change consumes the challenge, where its role is known (B3+-1).
    const refusal =
      personId === undefined
        ? 'other_person'
        : stepUpRefusal(pending, { userId: personId, evidence }, { passkeyRequired: false });
    if (refusal !== undefined) {
      throw failed(refusal, 'the fresh sign-in does not stand for the challenge', userId);
    }
    return limited(async (tx) => {
      const rotated = await sessions.rotate(tx, sessionId);
      if (rotated === undefined) throw failed('session_missing', 'the session ended', userId);
      const recorded = await challenges.recordEvidence(tx, challengeId, sessionId, {
        authTime: evidence.authTime,
        amr: evidence.amr,
        idpSessionId: evidence.idpSessionId ?? null,
        idTokenHash,
      });
      if (!recorded) throw failed('challenge_missing', 'the challenge ran out of time', userId);
      return { userId, sessionId, cookie: rotated, returnTo: taken.returnTo, stepUpChallengeId: challengeId };
    });
  }

  return {
    async begin(returnTo = HOME_PATH, network) {
      if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
      // Always a fresh sign-in (the S68 audit): signing out of Agent X leaves the login service's own
      // session, and on a shared computer that would sign the next person straight back in.
      const { url, flow } = await oidc.start({ prompt: 'login' });
      const started = await limited((tx) => flows.start(tx, flow, returnTo, network));
      if (started.outcome !== 'started') throw new SignInBusy(started.outcome);
      return { url, flowId: started.flowId };
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

    async complete(input) {
      const { flowId, previousCookie } = input;
      // Taken, and committed, before the login service is called: used once, whatever follows.
      const taken = flowId === undefined ? undefined : ownReturn(await limited((tx) => flows.take(tx, flowId)));
      if ('refused' in input) {
        const detail = 'the login service sent the browser back without a sign-in';
        // A step-up's: back to the change's page to say so (CO2); a sign-in's, refused as it always was.
        if (taken?.stepUpChallengeId === undefined) throw new SignInFailed(input.refused, detail);
        throw new StepUpFailed(input.refused, detail, undefined, {
          returnTo: taken.returnTo,
          challengeId: taken.stepUpChallengeId,
        });
      }
      const { code, state } = input;
      if (taken === undefined) throw new SignInFailed('flow_missing', 'no flow of ours is waiting for this browser');
      if (taken.stepUpChallengeId !== undefined) {
        return completeStepUp(taken.stepUpChallengeId, taken, { code, state }, previousCookie);
      }
      const { subject, evidence, verifiedEmail, name } = await oidc.finish(taken.flow, { code, state });
      // The sign-in asked for was a fresh one: a login service that answered with one it kept is refused.
      if (evidence.authTime.getTime() < earliestAuthTime(taken.startedAt)) {
        throw new SignInFailed('stale_authentication', 'the sign-in was made before the flow began');
      }
      return limited(async (tx) => {
        let userId: string;
        try {
          userId = await userForSubject(tx, subject, { ids, clock, ...macs });
        } catch (error) {
          if (!(error instanceof UserUnbelieved)) throw error;
          throw new SignInFailed('account_unbelieved', error.message);
        }
        const previous = previousCookie === undefined ? undefined : await sessions.end(tx, previousCookie);
        // AG10: a sign-in made before the person's sessions were last all ended (a removal, a factor reset, a change
        // at the login service) opens none, though its flow began before that end.
        const ended = await sessionsEndedAt(tx, userId, ends, evidence.authTime);
        // R-15: the platform chain's record of the ends can't be believed (the alarm raised): no session.
        if (ended.kind === 'tampered') {
          throw new SignInFailed('account_unbelieved', "the person's sessions' ends can't be believed");
        }
        const { endedAt } = ended;
        if (endedAt !== null && evidence.authTime.getTime() < endedAt.getTime()) {
          throw new SignInFailed(
            'stale_authentication',
            "the sign-in was made before the person's sessions were ended",
          );
        }
        const { sessionId, cookie } = await sessions.open(tx, userId, evidence);
        if (verifiedEmail !== undefined) await recordSessionEmail(tx, keys, sessionId, verifiedEmail);
        await keepUserContact(tx, keys, userId, { name, verifiedEmail }, clock.now());
        await signEnd(tx, previous);
        return { userId, sessionId, cookie, returnTo: taken.returnTo, stepUpChallengeId: undefined };
      });
    },

    async signOut(cookie) {
      if (cookie === undefined) return undefined;
      // Set inside the transaction, as its end is signed: only a failure from there on is answered by the fallback.
      const reached = { signing: false };
      try {
        return await limited(async (tx) => {
          const ended = await sessions.end(tx, cookie);
          if (ended === undefined) return undefined;
          const subject = await subjectOfUser(tx, ended.userId, macs);
          reached.signing = true;
          await signEnd(tx, ended);
          return subject;
        });
      } catch (error) {
        if (!reached.signing) throw error;
        // The end couldn't be signed, and its transaction rolled back the delete: the session goes all the same, and
        // its end unsigned (a row put back would be believed) raises the alarm.
        return limited(async (tx) => {
          const ended = await sessions.end(tx, cookie);
          if (ended === undefined) return undefined;
          logger.error('audit.integrity_failed', {
            check: 'session',
            reason: 'end_unsigned',
            rowId: ended.sessionId,
            userId: ended.userId,
            error: error instanceof Error ? error.name : 'unknown',
          });
          return subjectOfUser(tx, ended.userId, macs);
        });
      }
    },

    signedIn(cookie) {
      return limited((tx) => sessions.use(tx, cookie));
    },

    holderOf(cookie) {
      return limited((tx) => sessions.holder(tx, cookie));
    },
  };
}
