// The sign-in flows under way (0011): kept here, by the hash of a random flow
// ID the browser holds, from the moment the browser is sent to the login
// service until it comes back. A flow is taken once (deleted and read in one
// statement) and lives ten minutes; one left behind is swept after. The
// times are the Clock's (ADR-006 §3).
import { createHash, randomBytes } from 'node:crypto';

import type { Kysely } from 'kysely';

import type { Clock } from '../../../shared-kernel/index.ts';
import { isReturnPath } from '../domain/sign-in.ts';
import type { LoginFlow } from './oidc-client.ts';
import type { IdentityTables } from './tables.ts';

/** How long a browser has to come back from the login service. */
export const LOGIN_FLOW_SECONDS = 600;

/** A flow as the callback takes it back. */
interface TakenFlow {
  readonly flow: LoginFlow;
  readonly returnTo: string;
}

export interface LoginFlows {
  /** Keeps the flow and where to send the browser after; gives the flow ID for its cookie, which is never kept. */
  save(db: Kysely<IdentityTables>, flow: LoginFlow, returnTo: string): Promise<string>;
  /** Takes the flow this ID names, once and within its ten minutes; undefined for any other. */
  take(db: Kysely<IdentityTables>, flowId: string): Promise<TakenFlow | undefined>;
  /**
   * Deletes up to `most` flows past their ten minutes, and says how many: a browser that never came back leaves its flow behind, and
   * anyone can start one (B2-3a-2 sweeps them hourly, a batch at a time).
   */
  sweep(db: Kysely<IdentityTables>, most: number): Promise<number>;
}

/** The flow ID: 32 random bytes as base64url, like a session's cookie ID. */
const FLOW_ID = /^[A-Za-z0-9_-]{43}$/;
const hashOf = (flowId: string): Buffer => createHash('sha256').update(flowId, 'ascii').digest();

export function createLoginFlows({ clock }: { readonly clock: Clock }): LoginFlows {
  return {
    async save(db, flow, returnTo) {
      if (!isReturnPath(returnTo)) throw new RangeError('the return path is not a path on our own origin');
      const now = clock.now();
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
        })
        .execute();
      return flowId;
    },

    async take(db, flowId) {
      if (typeof flowId !== 'string' || !FLOW_ID.test(flowId)) return undefined;
      // Deleted whether or not it is still in time: a flow is used once, or not at all.
      const row = await db
        .deleteFrom('identity.login_flows')
        .where('cookie_hash', '=', hashOf(flowId))
        .returning(['state', 'nonce', 'verifier', 'return_to', 'ends_at'])
        .executeTakeFirst();
      if (row === undefined || row.ends_at <= clock.now()) return undefined;
      return {
        flow: { state: row.state, nonce: row.nonce, verifier: row.verifier },
        returnTo: row.return_to,
      };
    },

    async sweep(db, most) {
      if (!Number.isSafeInteger(most) || most < 1) throw new RangeError('a sweep deletes at least one flow at a time');
      const ended = db
        .selectFrom('identity.login_flows')
        .select('cookie_hash')
        .where('ends_at', '<=', clock.now())
        .limit(most);
      const rows = await db
        .deleteFrom('identity.login_flows')
        .where('cookie_hash', 'in', ended)
        .returning('cookie_hash')
        .execute();
      return rows.length;
    },
  };
}
