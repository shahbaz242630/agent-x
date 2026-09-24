// A sign-in from end to end (ADR-003 §5-§7), for the API's routes (B2-3a-2):
//
// - `begin` starts an OIDC flow and keeps it (login-flows.ts), giving the
//   address to send the browser to and the flow ID for its short-lived cookie.
// - `complete` takes the flow back once, before anything else, so a replayed
//   callback finds nothing; has the OIDC client trade the code and check the
//   ID token; then, in one transaction, finds or makes the user, ends the
//   session the browser brought (if any) and opens a new one. A sign-in never
//   keeps a session it didn't open (SEC-HA-07: rotated at login).
//
// Each database step gives up after 10 seconds, a wait for a lock included,
// so a hung statement can't hold a sign-in, or its connection, for good.
import { type Kysely, sql } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { HOME_PATH, isReturnPath } from '../domain/sign-in.ts';
import type { LoginFlows } from './login-flows.ts';
import { type OidcClient, SignInFailed } from './oidc-client.ts';
import type { Sessions } from './sessions.ts';
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
}

export interface CallbackInput {
  /** The flow cookie's value, if the browser sent one. */
  readonly flowId: string | undefined;
  readonly code: string;
  readonly state: string;
  /** The session cookie the browser brought, if any: ended, never kept. */
  readonly previousCookie: string | undefined;
}

export interface SignIn {
  /** Starts a sign-in that sends the browser back to `returnTo` (our home page if none). Throws RangeError for a path that isn't ours. */
  begin(returnTo?: string): Promise<SignInBegun>;
  /** Finishes the sign-in the flow cookie names. Throws SignInFailed. */
  complete(input: CallbackInput): Promise<SignInCompleted>;
  /** Ends the session this cookie belongs to, if any; true if there was one. */
  signOut(cookie: string | undefined): Promise<boolean>;
}

export function createSignIn({
  db,
  oidc,
  flows,
  sessions,
  ids,
  clock,
}: {
  readonly db: Kysely<IdentityTables>;
  readonly oidc: OidcClient;
  readonly flows: LoginFlows;
  readonly sessions: Sessions;
  readonly ids: IdGenerator;
  readonly clock: Clock;
}): SignIn {
  /** Runs the work in a transaction of its own, each statement limited to 10 seconds, a wait for a lock included. */
  const limited = <T>(work: (tx: Kysely<IdentityTables>) => Promise<T>): Promise<T> =>
    db.transaction().execute(async (tx) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
      return work(tx);
    });

  return {
    async begin(returnTo = HOME_PATH) {
      if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
      const { url, flow } = await oidc.start();
      const flowId = await limited((tx) => flows.save(tx, flow, returnTo));
      return { url, flowId };
    },

    async complete({ flowId, code, state, previousCookie }) {
      // Taken, and committed, before the login service is called: used once, whatever follows.
      const taken = flowId === undefined ? undefined : await limited((tx) => flows.take(tx, flowId));
      if (taken === undefined) throw new SignInFailed('flow_missing', 'no flow of ours is waiting for this browser');
      const { subject, evidence } = await oidc.finish(taken.flow, { code, state });
      return limited(async (tx) => {
        const userId = await userForSubject(tx, subject, { ids, clock });
        if (previousCookie !== undefined) await sessions.end(tx, previousCookie);
        const { sessionId, cookie } = await sessions.open(tx, userId, evidence);
        return { userId, sessionId, cookie, returnTo: taken.returnTo };
      });
    },

    signOut(cookie) {
      return cookie === undefined ? Promise.resolve(false) : limited((tx) => sessions.end(tx, cookie));
    },
  };
}
