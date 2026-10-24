// The load test's clean-up (D2c): a run's organisations made inert for good,
// once its checks are done. On staging they stay (audit chains are
// append-only), so each is put where nothing it holds can move again, through
// the same signed steps the product's own changes take, by the load test as
// a part of Agent X (`load-test`), never as a person:
// 1. its waiting, approved and ready requests voided (ORG_FROZEN), their
//    reservations and order claims released, then the organisation frozen,
//    as an admin's freeze choosing "cancel" does (decision 14): nothing is
//    asked for, approved or handed off in it again
// 2. its agents' keys revoked
// 3. every membership deactivated, so a notice still queued for its admins
//    and approvers fans out to nobody, quietly (email is off for the run:
//    on the laptop the stack has none, on Azure the run's apps switch turns
//    it off, so no notice has been split per person yet)
// The use cases' own notices are left out: no one is there to tell. The
// people's sessions are left to expire: no one holds their cookies (the
// seed never kept them), and a deactivated membership acts in nothing.
// Run again, it finds the work done and changes nothing. The laptop's run
// (cleanup.load.test.ts) proves it before Azure runs it.
import { AGENT_KEYS } from '../../packages/core/src/modules/agents/index.ts';
import { withSignedStates } from '../../packages/core/src/modules/audit/index.ts';
import { MEMBERSHIPS } from '../../packages/core/src/modules/identity/index.ts';
import { ORGANIZATIONS } from '../../packages/core/src/modules/organizations/index.ts';
import { PENDING_STATUSES, voidPendingOf } from '../../packages/core/src/modules/spend-requests/index.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { type Database, type DatabaseTransaction, withTenant } from '../../packages/platform/src/db/index.ts';
import type { KeyProvider } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { freezeChoiceDetails } from '../../apps/api/src/suspensions.ts';

/** The load test, as the audit log names it: a part of Agent X, by its process name. */
const LOAD_TEST = { type: 'system' as const, id: 'load-test' };

/** Requests voided a transaction: each void is a dozen statements, so a batch holds the organisation's lock and the chain head for seconds, not minutes. */
const VOIDED_A_BATCH = 200;

/** The IDs of the organisation's rows of `table` in `status`, through its tenant wall. */
async function idsIn(
  tx: DatabaseTransaction<MandateWorldTables>,
  table: 'agents.agent_keys' | 'identity.memberships',
  status: string,
) {
  // The IDs alone: each is moved through its signed state, verified there, by the caller.
  const rows = await tx.selectFrom(table).select('id').where('status', '=', status).orderBy('id').execute();
  return rows.map(({ id }) => id);
}

/** A signed move that didn't happen (refused, or a row that can't be believed) stops the clean-up, loudly. */
function moved({ outcome }: { readonly outcome: string }, what: string): void {
  if (outcome !== 'changed') throw new Error(`${what} did not move: ${outcome}.`);
}

/** Makes one organisation inert, as the file's head says. */
async function cleanUpOrg(database: Database<MandateWorldTables>, keyring: KeyProvider, orgId: string) {
  const quiet = { keys: keyring, ids: uuidV7Ids, logger: testLogger() };
  const key = { orgId, id: orgId };
  // 1. Voided in batches, each under the organisation's lock as a freeze holds it, until a batch finds none
  // (never "fewer than a batch": a request whose alarm is raised is skipped, not counted), then frozen in that one.
  for (;;) {
    const done = await withSignedStates(database, orgId, quiet, async (tx, states) => {
      const read = await states.verifiedState(tx, ORGANIZATIONS, key, 'change');
      if (read.outcome !== 'verified') throw new Error(`Organisation ${orgId} can't be believed: ${read.outcome}.`);
      const voided = await voidPendingOf(
        tx,
        states,
        keyring,
        orgId,
        { organizationId: orgId },
        'ORG_FROZEN',
        new Date(),
        VOIDED_A_BATCH,
      );
      if (voided > 0) return false;
      if (read.fields.get('status') !== 'FROZEN') {
        moved(
          await states.changeStatus(tx, ORGANIZATIONS, key, 'freeze', {
            actor: LOAD_TEST,
            action: 'organization.freeze',
            details: freezeChoiceDetails('cancel'),
          }),
          `Organisation ${orgId}`,
        );
      }
      return true;
    });
    if (done) break;
  }
  // 2 and 3: every key revoked, every membership deactivated.
  await withSignedStates(database, orgId, quiet, async (tx, states) => {
    for (const id of await idsIn(tx, 'agents.agent_keys', 'ACTIVE')) {
      moved(
        await states.changeStatus(tx, AGENT_KEYS, { orgId, id }, 'revoke', {
          actor: LOAD_TEST,
          action: 'agent_key.revoked',
          details: {},
        }),
        `Key ${id}`,
      );
    }
  });
  await withSignedStates(database, orgId, quiet, async (tx, states) => {
    for (const id of await idsIn(tx, 'identity.memberships', 'ACTIVE')) {
      moved(
        await states.changeStatus(tx, MEMBERSHIPS, { orgId, id }, 'deactivate', {
          actor: LOAD_TEST,
          action: 'membership.deactivated',
          details: {},
        }),
        `Membership ${id}`,
      );
    }
  });
}

/**
 * Organisations cleaned up at once. Voiding runs ~7 requests a second within
 * one organisation (its lock and chain head serialise it), so the laptop's
 * ~6,800 took 16 minutes one after another; organisations share neither, and
 * four keep well inside the pool's ten connections and staging's database.
 */
const ORGS_AT_ONCE = 4;

/**
 * Cleans up each of the run's organisations, ORGS_AT_ONCE at a time. The
 * first failure stops new organisations being taken; it throws once those
 * under way have finished, so nothing is still running when it answers.
 */
export async function cleanUpRun(
  database: Database<MandateWorldTables>,
  keyring: KeyProvider,
  orgIds: readonly string[],
): Promise<void> {
  const queue = [...orgIds];
  const worker = async (): Promise<void> => {
    for (let orgId = queue.shift(); orgId !== undefined; orgId = queue.shift()) {
      try {
        await cleanUpOrg(database, keyring, orgId);
      } catch (error) {
        queue.length = 0;
        throw error;
      }
    }
  };
  const ends = await Promise.allSettled(Array.from({ length: Math.min(ORGS_AT_ONCE, queue.length) }, worker));
  const failed = ends.flatMap((end) => (end.status === 'rejected' ? [end.reason as unknown] : []));
  if (failed.length === 1) throw failed[0];
  if (failed.length > 1) throw new AggregateError(failed, `${String(failed.length)} organisations' clean-up failed.`);
}

/** What the clean-up left undone, in plain words: none when every organisation is inert. */
export async function cleanUpFailures(
  database: Database<MandateWorldTables>,
  orgIds: readonly string[],
): Promise<string[]> {
  const found: string[] = [];
  for (const orgId of orgIds) {
    const left = await withTenant(database, orgId, async (tx) => ({
      org: await tx.selectFrom('organizations.organizations').select('status').executeTakeFirstOrThrow(),
      pending: await tx
        .selectFrom('spend_requests.requests')
        .select('id')
        .where('status', 'in', PENDING_STATUSES)
        .execute(),
      held: await tx.selectFrom('limit_reservations.reservations').select('id').where('state', '=', 'HELD').execute(),
      keys: await tx.selectFrom('agents.agent_keys').select('id').where('status', '=', 'ACTIVE').execute(),
      members: await tx.selectFrom('identity.memberships').select('id').where('status', '=', 'ACTIVE').execute(),
    }));
    const wrong = [
      left.org.status === 'FROZEN' ? undefined : `is ${left.org.status}, not FROZEN`,
      left.pending.length === 0 ? undefined : `has ${String(left.pending.length)} request(s) still pending`,
      left.held.length === 0 ? undefined : `holds ${String(left.held.length)} reservation(s)`,
      left.keys.length === 0 ? undefined : `has ${String(left.keys.length)} key(s) still active`,
      left.members.length === 0 ? undefined : `has ${String(left.members.length)} membership(s) still active`,
    ].filter((one) => one !== undefined);
    if (wrong.length > 0) found.push(`Organisation ${orgId} ${wrong.join(', ')}.`);
  }
  return found;
}
