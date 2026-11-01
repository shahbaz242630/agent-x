// An admin's brake under trouble (PL-63 item 3, 4D2e C): near phase 5's end, the
// product's own freeze is asked of the stuck organisation, as its admin's click
// asks it, and how long it took and what it was answered go in the report. A
// freeze can wait behind decisions holding the organisation's row, so this says
// whether the brake holds while the trouble lasts; nothing here fails a run.
//
// It pauses the organisation's requests rather than cancelling them: the database
// checks still compare what each holds, and the clean-up voids them after, finding
// the organisation frozen already. The stuck agents' later requests are then
// answered 409 ORG_FROZEN, which k6 doesn't check of them. The laptop's run
// (run.ts) and, on Azure, the second job (job.ts) both call this.
import { createStepUpChallenges } from '../../packages/core/src/modules/identity/index.ts';
import { createOutbox } from '../../packages/core/src/modules/notifications/index.ts';
import { systemClock, uuidV7Ids } from '../../packages/core/src/shared-kernel/index.ts';
import { type Database, withTenant } from '../../packages/platform/src/db/index.ts';
import type { KeyProvider } from '../../packages/platform/src/keys/index.ts';
import { testLogger } from '../../packages/testing/src/index.ts';

import { canonicalJson } from '../../apps/api/src/idempotent-writes.ts';
import type { MandateWorldTables } from '../../apps/api/src/mandate-world.helper.test.ts';
import { createOrganizationChanges, FREEZE_OPERATION } from '../../apps/api/src/organization-changes.ts';
import type { SeededAgent } from './plan.ts';

/** What a freeze was answered, in plain words, and how long the answer took. */
export interface FreezeProbed {
  readonly ms: number;
  readonly answer: string;
}

/** How a failed freeze reads: Postgres's own codes in words, anything else as it says. */
function failure(error: unknown): string {
  const code = typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined;
  if (code === '55P03') return "not frozen: its wait for the organisation's lock ran out";
  if (code === '57014') return 'not frozen: it ran past the limit on a statement';
  return `not frozen: ${error instanceof Error ? error.message : String(error)}`;
}

/** The stuck organisation's admin, as an admin's session would name them. */
async function adminOf(database: Database<MandateWorldTables>, orgId: string): Promise<string> {
  const { user_id: userId } = await withTenant(database, orgId, (tx) =>
    tx
      .selectFrom('identity.memberships')
      .select('user_id')
      .where('role', '=', 'admin')
      .where('status', '=', 'ACTIVE')
      .executeTakeFirstOrThrow(),
  );
  return userId;
}

/** Freezes the stuck organisation as its admin would. It answers whatever happens: a failure is what it came to find. */
export async function probeFreeze(
  database: Database<MandateWorldTables>,
  keys: KeyProvider,
  agents: readonly Pick<SeededAgent, 'kind' | 'orgId'>[],
): Promise<FreezeProbed> {
  const clock = systemClock;
  const ids = uuidV7Ids;
  const changes = createOrganizationChanges({
    database,
    keys,
    ids,
    clock,
    challenges: createStepUpChallenges({ ids, clock }),
    outbox: createOutbox({ ids, clock }),
    logger: testLogger(),
  });
  let started = performance.now();
  try {
    const orgId = agents.find(({ kind }) => kind === 'neighbour-stuck')?.orgId;
    if (orgId === undefined) throw new Error('the run has no stuck organisation');
    const userId = await adminOf(database, orgId);
    started = performance.now();
    const answer = await changes.freeze(
      { orgId, userId, sessionId: 'load-freeze-probe' },
      {
        orgId,
        client: { kind: 'user', id: userId },
        operation: FREEZE_OPERATION,
        key: 'load-freeze-probe',
        payload: canonicalJson({ params: {}, query: {}, body: { pendingRequests: 'pause' } }),
      },
      'pause',
      ids.next(),
    );
    const words = answer.outcome === 'changed' ? 'frozen' : `not frozen: ${answer.outcome} ${codeOf(answer)}`;
    return { ms: Math.round(performance.now() - started), answer: words.trimEnd() };
  } catch (error) {
    return { ms: Math.round(performance.now() - started), answer: failure(error) };
  }
}

const codeOf = (answer: object): string => ('code' in answer ? String(answer.code) : '');

/**
 * Runs `phase` with `probe` asked `afterMs` into it, its answer waiting for the
 * probe's. A phase ending first asks nothing and says so with none. Around the
 * trouble's hold, never inside it: the probe's transactions can't begin inside the
 * hold's (withTenant refuses, seeing its own, which a timer set in it inherits).
 */
export async function withFreezeProbe<T, P>(
  afterMs: number,
  probe: () => Promise<P>,
  phase: () => Promise<T>,
): Promise<{ readonly ran: T; readonly probed: P | undefined }> {
  let probing: Promise<P> | undefined;
  const timer = setTimeout(() => {
    probing = probe();
  }, afterMs);
  try {
    const ran = await phase();
    return { ran, probed: await probing };
  } finally {
    clearTimeout(timer);
  }
}
