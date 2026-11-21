// The sign-in flows under way (0011): kept here, by the hash of a random flow
// ID the browser holds, from the moment the browser is sent to the login
// service until it comes back. A flow is taken once (deleted and read in one
// statement) and lives ten minutes; one left behind is swept after. The
// times are the Clock's (ADR-006 §3).
//
// S206 V8 (0106): anyone can start a sign-in with an anonymous GET, so a
// network holds at most MOST_OPEN_SIGN_INS_A_NETWORK under way. S208: a
// network at its share is never refused a fresh sign-in, as one caller filling
// it would lock everyone else behind the same address (an office, a carrier's
// NAT) out for ten minutes; instead the network's oldest unfinished sign-ins
// give way to the new one, so a flood must go on without pause to push others
// out, which the per-address rate limit bounds. A flow that gave way is gone:
// its callback finds no flow, a plain refusal to start again. Every network's
// together are held too, but never as a lockout (the review of S206 V8): once MOST_OPEN_SIGN_INS
// are under way, a network holding fewer than QUIET_NETWORK_SIGN_INS is still
// let in, and only the busy ones are refused, so a crowd of networks filling
// the table can't stop everyone else signing in, admins included; the table
// then grows only with each new network's few. A step-up's flow is never
// counted, and never gives way.
import { createHash, randomBytes } from 'node:crypto';

import { limitStatements } from '@agentx/platform/db';
import { type Kysely, sql } from 'kysely';

import { type Clock, UUID } from '../../../shared-kernel/index.ts';
import { isReturnPath } from '../domain/sign-in.ts';
import type { LoginFlow } from './oidc-client.ts';
import type { IdentityTables } from './tables.ts';

/** How long a browser has to come back from the login service. */
export const LOGIN_FLOW_SECONDS = 600;

/**
 * The sign-ins under way, every network together, past which only a quiet network's start (S206 V8): the table's
 * storage backstop, far above any real day (a flow lives ten minutes), never a lockout.
 */
export const MOST_OPEN_SIGN_INS = 1_000_000;

/** How few sign-ins under way make a network quiet: let in even when MOST_OPEN_SIGN_INS are under way. */
export const QUIET_NETWORK_SIGN_INS = 3;

/**
 * The most sign-ins under way at once from one network (S206 V8): an IPv4 address alone, or an IPv6 /48, as the OAuth
 * flows count theirs (AG8), so a few networks can't fill MOST_OPEN_SIGN_INS for everyone. An office signs in a few.
 * Past it the network's oldest give way (S208), never the new one.
 */
export const MOST_OPEN_SIGN_INS_A_NETWORK = 100;

/**
 * A sign-in's flow kept, with the ID for its cookie, and whether its network's oldest gave way to it (S208); or not:
 * every network's at their cap and this one not quiet.
 */
type SignInFlowStarted =
  { readonly outcome: 'started'; readonly flowId: string; readonly gaveWay: boolean } | { readonly outcome: 'full' };

/** A flow as the callback takes it back. */
interface TakenFlow {
  readonly flow: LoginFlow;
  readonly returnTo: string;
  /** The step-up challenge it was started for (0014), if it is a step-up. */
  readonly stepUpChallengeId: string | undefined;
  /** When it was started: a sign-in must have been made after it (the S68 audit). */
  readonly startedAt: Date;
}

export interface LoginFlows {
  /**
   * Keeps the flow, where to send the browser after and, for a step-up, its
   * challenge; gives the flow ID for its cookie, which is never kept.
   */
  save(db: Kysely<IdentityTables>, flow: LoginFlow, returnTo: string, stepUpChallengeId?: string): Promise<string>;
  /**
   * Keeps a sign-in's flow started from `network` (S206 V8), unless MOST_OPEN_SIGN_INS are under way and this network
   * holds QUIET_NETWORK_SIGN_INS or more; each count stopping at its cap (0106's indexes). A network holding
   * MOST_OPEN_SIGN_INS_A_NETWORK has its oldest sign-ins under way deleted first, all but its newest one fewer than
   * that, in one statement (S208). Best effort, with no lock, as the OAuth flows' caps: sign-ins started at once may
   * pass a cap by a few rows, which the network's next start trims back. In the caller's transaction.
   */
  start(db: Kysely<IdentityTables>, flow: LoginFlow, returnTo: string, network: string): Promise<SignInFlowStarted>;
  /** Takes the flow this ID names, once and within its ten minutes; undefined for any other. */
  take(db: Kysely<IdentityTables>, flowId: string): Promise<TakenFlow | undefined>;
  /**
   * Deletes up to `most` flows past their ten minutes, and says how many: a browser that never came back leaves its flow behind, and
   * anyone can start one (B2-3a-2 sweeps them hourly, a batch at a time). In
   * a transaction of its own, its statement limited to 10 seconds, a wait for
   * a lock included.
   */
  sweep(db: Kysely<IdentityTables>, most: number): Promise<number>;
}

/** The flow ID: 32 random bytes as base64url, like a session's cookie ID. */
const FLOW_ID = /^[A-Za-z0-9_-]{43}$/;
const hashOf = (flowId: string): Buffer => createHash('sha256').update(flowId, 'ascii').digest();

/**
 * The count of sign-ins not ended at `now` (a network's, when named), stopping at `most`: the statement itself, so a
 * test can read the plan of the very query the caps run (login-flows.db.test.ts).
 */
export const signInsUnderWay = (db: Kysely<IdentityTables>, most: number, now: Date, network?: string) =>
  db
    .selectFrom((inner) => {
      const open = inner
        .selectFrom('identity.login_flows')
        // A constant, so the count reads 0106's partial indexes alone, never the rows.
        .select(sql<number>`1`.as('one'))
        .where('ends_at', '>', now)
        .where('step_up_challenge_id', 'is', null);
      return (network === undefined ? open : open.where('network_key', '=', network)).limit(most).as('open');
    })
    .select(sql<number>`pg_catalog.count(*)::int`.as('flows'));

/** Whether the sign-ins not ended at `now` (a network's, when named) are at `most`, the count stopping there. */
async function signInsAt(db: Kysely<IdentityTables>, most: number, now: Date, network?: string): Promise<boolean> {
  const { flows } = await signInsUnderWay(db, most, now, network).executeTakeFirstOrThrow();
  return flows >= most;
}

/**
 * Deletes the network's sign-ins not ended at `now` but its newest MOST_OPEN_SIGN_INS_A_NETWORK - 1, in one statement
 * (S208): the oldest give way to the one about to start. A step-up's flow is never one of them.
 */
async function oldestGiveWay(db: Kysely<IdentityTables>, network: string, now: Date): Promise<void> {
  await db
    .deleteFrom('identity.login_flows')
    .where('step_up_challenge_id', 'is', null)
    .where('cookie_hash', 'in', (inner) =>
      inner
        .selectFrom('identity.login_flows')
        .select('cookie_hash')
        .where('network_key', '=', network)
        .where('step_up_challenge_id', 'is', null)
        .where('ends_at', '>', now)
        .orderBy('ends_at', 'desc')
        .offset(MOST_OPEN_SIGN_INS_A_NETWORK - 1),
    )
    .execute();
}

export function createLoginFlows({
  clock,
  mostOpen = MOST_OPEN_SIGN_INS,
}: {
  readonly clock: Clock;
  /** Every network's backstop (MOST_OPEN_SIGN_INS unless a test names fewer, rather than add a million rows). */
  readonly mostOpen?: number;
}): LoginFlows {
  /** Keeps the flow from `now` for its ten minutes: a step-up's with its challenge, a sign-in's with its network. */
  async function kept(
    db: Kysely<IdentityTables>,
    flow: LoginFlow,
    returnTo: string,
    now: Date,
    from: { readonly stepUpChallengeId?: string; readonly network?: string },
  ): Promise<string> {
    if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
    const flowId = randomBytes(32).toString('base64url');
    await db
      .insertInto('identity.login_flows')
      .values({
        cookie_hash: hashOf(flowId),
        state: flow.state,
        nonce: flow.nonce,
        verifier: flow.verifier,
        return_to: returnTo,
        created_at: now,
        ends_at: new Date(now.getTime() + LOGIN_FLOW_SECONDS * 1000),
        step_up_challenge_id: from.stepUpChallengeId ?? null,
        network_key: from.network ?? null,
      })
      .execute();
    return flowId;
  }

  return {
    save(db, flow, returnTo, stepUpChallengeId) {
      if (stepUpChallengeId !== undefined && !UUID.test(stepUpChallengeId)) {
        return Promise.reject(new RangeError('the step-up challenge ID is not a UUID'));
      }
      return kept(db, flow, returnTo, clock.now(), stepUpChallengeId === undefined ? {} : { stepUpChallengeId });
    },

    async start(db, flow, returnTo, network) {
      const now = clock.now();
      // A quiet network gets in on its own count of a few: a flood across many networks never makes each start count
      // every network's. Only a busy one is counted further, against its own cap and then the backstop.
      let gaveWay = false;
      if (await signInsAt(db, QUIET_NETWORK_SIGN_INS, now, network)) {
        gaveWay = await signInsAt(db, MOST_OPEN_SIGN_INS_A_NETWORK, now, network);
        // At its share, the network's oldest give way: its count is no higher after, so the backstop needs no count.
        if (gaveWay) await oldestGiveWay(db, network, now);
        else if (await signInsAt(db, mostOpen, now)) return { outcome: 'full' };
      }
      return { outcome: 'started', flowId: await kept(db, flow, returnTo, now, { network }), gaveWay };
    },

    async take(db, flowId) {
      if (typeof flowId !== 'string' || !FLOW_ID.test(flowId)) return undefined;
      // Deleted whether or not it is still in time: a flow is used once, or not at all.
      const row = await db
        .deleteFrom('identity.login_flows')
        .where('cookie_hash', '=', hashOf(flowId))
        .returning(['state', 'nonce', 'verifier', 'return_to', 'ends_at', 'step_up_challenge_id', 'created_at'])
        .executeTakeFirst();
      if (row === undefined || row.ends_at <= clock.now()) return undefined;
      return {
        flow: { state: row.state, nonce: row.nonce, verifier: row.verifier },
        returnTo: row.return_to,
        stepUpChallengeId: row.step_up_challenge_id ?? undefined,
        startedAt: row.created_at,
      };
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one flow at a time');
      const now = clock.now();
      return db.transaction().execute(async (tx) => {
        await limitStatements(tx);
        const ended = tx
          .selectFrom('identity.login_flows')
          .select('cookie_hash')
          .where('ends_at', '<=', now)
          .limit(most);
        const rows = await tx
          .deleteFrom('identity.login_flows')
          .where('cookie_hash', 'in', ended)
          .returning('cookie_hash')
          .execute();
        return rows.length;
      });
    },
  };
}
