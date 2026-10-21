// The rest of the waiting requests an admin chose to reject with a policy
// change (PRD §5; BR-06, BR-09; partner decision 33b, S134; Phase 3 F1 G8):
// the API's job, on a timer of its own. A change's confirm rejects at most 20
// (policy-waiting.ts); the others its plan weighed are bound into its step-up
// and kept on the new version's event (WAITING_LEFTOVER_KEYS), and this
// rejects each as its approver's confirm would (decision 18), while that
// version stays in force. Past the oldest 100 its confirm weighed, the
// younger waiting when it was confirmed are this job's too ("the rest",
// decision 33b; G8b): weighed 100 at a time as the confirm's plan weighs them
// (waitingPlan), under the rules the change replaced and its own in their
// place, so one is rejected only if the change alone would reject it, then
// each as a leftover is; none once any other policy has a new version since,
// as no confirm weighed them under the policies then in force.
//
// For each organisation the directory lists, the candidates are its policies
// whose version in force names leftovers still waiting, or the youngest its
// confirm weighed with any request waiting, found by their rows and that
// event's details, unverified: a filter alone. Each policy is then
// read through its signed state, and its version's event believed only whole
// (eventOf); then each leftover in a transaction of its own, in the approval's
// lock order (ADR-006 §6): the organisation (2, not frozen), then levels 3–8
// as its approver's confirm weighs it (`weighedAgain`). It is rejected only
// when nothing it was decided against moved, its supplier's details are those
// it was decided under, it was decided before the change, the policy's
// version in force is still the one that named it, and the engine now
// refuses it only under rules the team set; as
// the admin's who confirmed, with those rules as `causes`, its holdings
// released. Anything else leaves it with its approver: one approved, rejected,
// expired or voided meanwhile, or one the rules in force let stand. A later
// change of the policy ends its leftovers, that change's own choice governing.
//
// A run never throws: each failure is logged, naming the organisation and
// request, and the run goes on to the next.
import {
  namedInDetails,
  type SignedStates,
  type SignedStatesServices,
  withDetail,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { POLICIES, POLICY_VERSIONS, policyOf, policyVersionOf, type PolicyRules } from '@agentx/core/modules/mandates';
import { rejectRequest, SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import type { Clock, IdGenerator } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { rejectionNote } from './approval-rejections.ts';
import { eachOrganisation } from './expiry-pages.ts';
import { MandateRefused, VERSION_MADE } from './mandate-reads.ts';
import {
  leftoverOf,
  WAITING_LEFTOVER_KEYS,
  WAITING_YOUNGER_KEY,
  waitingPlan,
  type Younger,
  youngerAfterOf,
} from './policy-waiting.ts';
import { weighedAgain } from './spend-request-approvals.ts';
import {
  type DecisionTables,
  notFrozen,
  organizationWeighed,
  type PoliciesWeighed,
  versionRules,
} from './spend-request-decisions.ts';

/** How often the leftovers are looked over, once the last run has ended: the rest are rejected within this. */
export const WAITING_REJECTIONS_EVERY_MS = 5 * 60_000;

/** How many of an organisation's leftovers one run rejects: the rest wait for the next run. */
const MOST_REJECTED_A_RUN = 100;

/** How many of an organisation's candidate policies a page holds, each page after the last (expiry-pages.ts' reason). */
const POLICIES_A_PAGE = 50;

type RejectionTx = DatabaseTransaction<DecisionTables>;

/**
 * One policy's leftovers, as its version's event names them: which version,
 * where in the chain, who confirmed, and the requests; and the younger, past
 * the oldest 100 its confirm weighed, when there were any (G8b).
 */
interface Leftovers {
  readonly policyId: string;
  readonly versionId: string;
  readonly versionSeq: bigint;
  readonly mandateId: string | null;
  readonly userId: string;
  readonly requestIds: readonly string[];
  readonly younger: Weighed | null;
}

/** Where the younger are taken up, with the change's rules and those it replaced, as its confirm's plan weighed them. */
interface Weighed extends Younger {
  readonly rules: PolicyRules;
  readonly before: (inForce: PoliciesWeighed) => PoliciesWeighed;
}

/** The policy's version in force's event, as the candidates' filters name it. */
const MADE = {
  type: POLICY_VERSIONS.subject,
  idColumn: 'p.current_version_id',
  orgColumn: 'p.org_id',
  action: VERSION_MADE,
} as const;

/**
 * The organisation's policies whose version in force names leftovers still
 * waiting, by their rows and that version's event, unverified, in order of
 * ID, after `after` when given, at most `most`: each then read through its
 * signed state.
 */
async function withLeftovers(
  tx: RejectionTx,
  orgId: string,
  most: number,
  after: string | undefined,
): Promise<readonly string[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each read through its signed state before anything moves
    .selectFrom('mandates.policies as p')
    .select('p.id')
    .where('p.org_id', '=', orgId)
    .where((where) => (after === undefined ? where.lit(true) : where('p.id', '>', after)))
    .where((where) =>
      where.exists(
        where
          // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a filter alone; each leftover is weighed through its signed states
          .selectFrom('spend_requests.requests as r')
          .select('r.id')
          .whereRef('r.org_id', '=', 'p.org_id')
          .where('r.status', '=', 'APPROVAL_REQUIRED')
          .where((named) =>
            named.or([
              namedInDetails({ ...MADE, keys: WAITING_LEFTOVER_KEYS, named: 'r.id' }),
              withDetail({ ...MADE, key: WAITING_YOUNGER_KEY }),
            ]),
          ),
      ),
    )
    .orderBy('p.id')
    .limit(most)
    .execute();
  return rows.map(({ id }) => id);
}

/**
 * The policy's leftovers whose rows still wait, and the younger's start, its
 * row and its version's event believed: undefined for neither (another
 * version in force since the candidates were read). One that can't be
 * believed throws, its alarm raised.
 */
async function leftoversOf(
  tx: RejectionTx,
  states: SignedStates,
  orgId: string,
  policyId: string,
): Promise<Leftovers | undefined> {
  const policy = await policyOf(tx, states, { orgId, id: policyId }, 'share');
  if (policy.outcome !== 'found') throw new Error(`A policy with leftovers can't be believed: ${policyId}`);
  const versionId = policy.policy.currentVersionId;
  const found = await states.eventOf(tx, orgId, { onlyAbout: { type: POLICY_VERSIONS.subject, id: versionId } });
  if (found.outcome !== 'read' || found.event === undefined) {
    throw new Error(`A policy's version in force has no event to believe: ${versionId}`);
  }
  const { event, seq } = found.event;
  const made = event.action === VERSION_MADE;
  const requestIds = made ? leftoverOf(event.details) : undefined;
  const after = made ? youngerAfterOf(event.details) : undefined;
  if (requestIds === undefined || after === undefined) {
    throw new Error(`A policy version's leftovers can't be believed: ${versionId}`);
  }
  if (requestIds.length === 0 && after === null) return undefined;
  // Leftovers are a person's choice (an admin's confirm): any other actor can't be believed.
  if (event.actor.type !== 'user') throw new Error(`A policy version's leftovers name no person: ${versionId}`);
  const { mandateId } = policy.policy;
  const at = { orgId, policyId, mandateId, versionId };
  return {
    policyId,
    versionId,
    versionSeq: seq,
    mandateId,
    userId: event.actor.id,
    requestIds: await stillWaiting(tx, orgId, requestIds),
    younger: after === null ? null : await youngerOf(tx, states, at, after),
  };
}

/** Which policy version, of which policy. */
interface VersionAt {
  readonly orgId: string;
  readonly policyId: string;
  readonly mandateId: string | null;
  readonly versionId: string;
}

/** Where the younger are taken up, past `after`, with the version's rules and those it replaced, believed. */
async function youngerOf(tx: RejectionTx, states: SignedStates, at: VersionAt, after: string): Promise<Weighed> {
  const read = await policyVersionOf(tx, states, { orgId: at.orgId, id: at.versionId }, at.policyId);
  if (read.outcome !== 'found') throw new Error(`A policy's version can't be believed: ${at.versionId}`);
  return {
    after,
    // When the version was made, by the app's clock as each request's row is: one made since was decided under it.
    until: read.version.madeAt,
    rules: read.version,
    before: await rulesBefore(tx, states, at),
  };
}

/**
 * The policies as they stood before the change that made the version, as its
 * confirm's plan weighed them: the version it replaced in place of its own
 * (with that version's choices, for the organisation's), or none for a
 * policy's first; from the policy's newest event, which must be the change
 * that made the version in force.
 */
async function rulesBefore(
  tx: RejectionTx,
  states: SignedStates,
  { orgId, policyId, mandateId, versionId }: VersionAt,
): Promise<(inForce: PoliciesWeighed) => PoliciesWeighed> {
  const history = await states.historyOf(tx, orgId, {
    subjectTypes: [POLICIES.subject],
    subjectId: policyId,
    actions: ['policy.set', 'policy.changed'],
    limit: 1,
    newest: true,
  });
  const newest = history.outcome === 'read' ? history.events.at(-1)?.event : undefined;
  const replaced = newest?.action === 'policy.changed' ? newest.details.replaced : null;
  if (newest?.details.versionId !== versionId || (replaced !== null && typeof replaced !== 'string')) {
    throw new Error(`A policy's change can't be believed: ${policyId}`);
  }
  const was = replaced === null ? null : await policyVersionOf(tx, states, { orgId, id: replaced }, policyId);
  if (was !== null && was.outcome !== 'found') throw new Error(`A policy's version can't be believed: ${replaced}`);
  const version = was?.version ?? null;
  if (mandateId !== null) return (inForce) => ({ ...inForce, mandatePolicy: versionRules(version) });
  const organization = await organizationWeighed(tx, states, orgId, version);
  return (inForce) => ({ ...inForce, ...organization });
}

/**
 * Whether any other policy version of the organisation was made since the
 * change, by the rows, unverified: then the younger are left with their
 * approvers, as no confirm weighed them under the policies now in force
 * (G8b review). A filter that only ever rejects fewer.
 */
async function otherChangedSince(tx: RejectionTx, orgId: string, versionId: string, since: Date): Promise<boolean> {
  const row = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a filter alone, which only leaves requests with their approvers
    .selectFrom('mandates.policy_versions')
    .select('id')
    .where('org_id', '=', orgId)
    .where('id', '!=', versionId)
    .where('made_at', '>=', since)
    .limit(1)
    .executeTakeFirst();
  return row !== undefined;
}

/** Of the leftovers, those whose rows still wait, oldest first, unverified: each then weighed through its signed states. */
async function stillWaiting(tx: RejectionTx, orgId: string, ids: readonly string[]): Promise<readonly string[]> {
  // None named past the 20 (the younger alone): no statement.
  if (ids.length === 0) return [];
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- IDs alone, each weighed through its signed states before anything moves
    .selectFrom(SPEND_REQUESTS.table)
    .select('id')
    .where('org_id', '=', orgId)
    .where('id', 'in', ids)
    .where('status', '=', 'APPROVAL_REQUIRED')
    .execute();
  const waiting = new Set(rows.map(({ id }) => id));
  return ids.filter((id) => waiting.has(id));
}

export interface WaitingRejections {
  /** Rejects the leftovers the rules in force refuse, up to MOST_REJECTED_A_RUN an organisation, until the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

export function createWaitingRejections({
  list,
  database,
  keys,
  ids,
  clock,
  logger,
  most = MOST_REJECTED_A_RUN,
  page = POLICIES_A_PAGE,
}: {
  /** The organisations to look in: the directory's list, which main.ts passes. */
  readonly list: () => Promise<readonly string[]>;
  readonly database: Database<DecisionTables>;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  readonly logger: Logger;
  /** MOST_REJECTED_A_RUN, but for the tests. */
  readonly most?: number;
  /** POLICIES_A_PAGE, but for the tests. */
  readonly page?: number;
}): WaitingRejections {
  const services = (log: Logger): SignedStatesServices => ({ keys, ids, logger: log });

  /** The leftover weighed as its approver's confirm weighs it, and rejected if the rules in force refuse it; whether it was. */
  const rejected = async (
    tx: RejectionTx,
    states: SignedStates,
    orgId: string,
    requestId: string,
    from: Leftovers,
  ): Promise<boolean> => {
    // Read before the lock waits below, as a decision's: the instant it is weighed at.
    const now = clock.now();
    await notFrozen(tx, states, orgId);
    const { made, supplierNow, unchanged, rejection, decidedSeq } = await weighedAgain(tx, states, {
      orgId,
      requestId,
      now,
      decides: true,
    });
    const inForce = from.mandateId === null ? made.versions.organizationPolicy : made.versions.mandatePolicy;
    if (!unchanged || supplierNow.move !== 'same' || inForce !== from.versionId || rejection === null) return false;
    // Waiting when the change was confirmed: one decided since was decided under its rules (null: weighedAgain refuses it first).
    if (decidedSeq === null || decidedSeq > from.versionSeq) return false;
    await rejectRequest(
      tx,
      states,
      keys,
      { orgId, id: requestId },
      {
        userId: from.userId,
        reason: rejectionNote(rejection, 'policy'),
        stepUp: { policyVersionId: from.versionId, via: 'waiting_rejections', causes: rejection.join(',') },
      },
      now,
    );
    return true;
  };

  /** The leftover rejected if it should be, logging what came of it; whether it was. Never throws. */
  const rejectedLogged = async (log: Logger, orgId: string, requestId: string, from: Leftovers): Promise<boolean> => {
    try {
      return await withSignedStates(database, orgId, services(log), (tx, states) =>
        rejected(tx, states, orgId, requestId, from),
      );
    } catch (error) {
      // Settled or frozen meanwhile, or refused as no longer waiting: left with its approver.
      if (error instanceof MandateRefused && error.code !== 'INTEGRITY_FAILED') return false;
      // A history that can't be believed (its alarm raised), or a write that failed.
      log.error('waiting_rejection.failed', { requestId, policyVersionId: from.versionId, err: error });
      return false;
    }
  };

  /** The policy's leftovers still waiting, read in a transaction of their own; none for one that can't be read, logged. */
  const leftoversLogged = async (log: Logger, orgId: string, policyId: string): Promise<Leftovers | undefined> => {
    try {
      return await withSignedStates(database, orgId, services(log), (tx, states) =>
        leftoversOf(tx, states, orgId, policyId),
      );
    } catch (error) {
      log.error('waiting_rejection.unreadable', { policyId, err: error });
      return undefined;
    }
  };

  /** A page of the organisation's candidate policies, after `after`; undefined for one that can't be read, logged. */
  const pageOf = async (log: Logger, orgId: string, after: string | undefined) => {
    try {
      return await withSignedStates(database, orgId, services(log), (tx) => withLeftovers(tx, orgId, page, after));
    } catch (error) {
      log.error('waiting_rejection.unreadable', { err: error });
      return undefined;
    }
  };

  /** The requests rejected in turn while `left` and the signal allow: how many, or null once the signal stops it. */
  const rejectedOf = async (
    log: Logger,
    orgId: string,
    from: Leftovers,
    requestIds: readonly string[],
    left: number,
    aborted: () => boolean,
  ): Promise<number | null> => {
    let done = 0;
    for (const requestId of requestIds) {
      if (aborted()) return null;
      if (done >= left) return done;
      if (await rejectedLogged(log, orgId, requestId, from)) {
        done += 1;
        log.info('waiting_rejection.rejected', { requestId, policyVersionId: from.versionId });
      }
    }
    return done;
  };

  /**
   * The next 100 younger waiting past `after` as the change's confirm would
   * have weighed them, in a transaction of their own (FOR SHARE): those it
   * would reject, and where the next 100 start (null: none wait past them);
   * undefined for a plan that can't be read, logged.
   */
  const youngerPlanned = async (log: Logger, orgId: string, from: Leftovers, younger: Weighed, after: string) => {
    try {
      return await withSignedStates(database, orgId, services(log), async (tx, states) => {
        if (await otherChangedSince(tx, orgId, from.versionId, younger.until)) return { requestIds: [], next: null };
        const scope = { orgId, now: clock.now(), mandateId: from.mandateId, rules: younger.rules };
        const plan = await waitingPlan(tx, states, scope, {
          decides: false,
          before: younger.before,
          younger: { after, until: younger.until },
        });
        return { requestIds: [...plan.rejected.map(({ id }) => id), ...plan.leftover], next: plan.weighedTo };
      });
    } catch (error) {
      log.error('waiting_rejection.unreadable', { policyId: from.policyId, err: error });
      return undefined;
    }
  };

  /** The policy's younger rejected, 100 weighed at a time, while `left` and the signal allow: how many, or null once the signal stops it. */
  const youngerRejected = async (
    log: Logger,
    orgId: string,
    from: Leftovers,
    left: number,
    aborted: () => boolean,
  ): Promise<number | null> => {
    const { younger } = from;
    if (younger === null) return 0;
    let done = 0;
    let after = younger.after;
    for (;;) {
      if (done >= left) return done;
      const planned = await youngerPlanned(log, orgId, from, younger, after);
      if (planned === undefined) return done;
      const rejected = await rejectedOf(log, orgId, from, planned.requestIds, left - done, aborted);
      if (rejected === null) return null;
      done += rejected;
      if (planned.next === null) return done;
      after = planned.next;
    }
  };

  /** One policy's leftovers, then its younger, rejected while `left` and the signal allow: how many, or null once the signal stops it. */
  const rejectedFor = async (
    log: Logger,
    orgId: string,
    from: Leftovers,
    left: number,
    aborted: () => boolean,
  ): Promise<number | null> => {
    const listed = await rejectedOf(log, orgId, from, from.requestIds, left, aborted);
    if (listed === null) return null;
    const younger = await youngerRejected(log, orgId, from, left - listed, aborted);
    return younger === null ? null : listed + younger;
  };

  /** A page's policies' leftovers rejected while `left` and the signal allow: how many, or null once the signal stops it. */
  const rejectedInPage = async (
    log: Logger,
    orgId: string,
    policies: readonly string[],
    left: number,
    aborted: () => boolean,
  ): Promise<number | null> => {
    let done = 0;
    for (const policyId of policies) {
      if (done >= left) return done;
      const from = await leftoversLogged(log, orgId, policyId);
      const rejected = from === undefined ? 0 : await rejectedFor(log, orgId, from, left - done, aborted);
      if (rejected === null) return null;
      done += rejected;
    }
    return done;
  };

  /** Rejects the organisation's leftovers, up to its share, a page of policies at a time; false if the signal stopped it. */
  const rejectIn = async (orgId: string, signal: AbortSignal | undefined): Promise<boolean> => {
    const log = logger.child({ orgId });
    // A call, read afresh after each await (a property check would stay narrowed).
    const aborted = () => signal?.aborted === true;
    let done = 0;
    let after: string | undefined;
    for (;;) {
      const policies = await pageOf(log, orgId, after);
      if (policies === undefined) return true;
      const rejected = await rejectedInPage(log, orgId, policies, most - done, aborted);
      if (rejected === null) return false;
      done += rejected;
      if (done >= most || policies.length < page) return true;
      after = policies.at(-1);
    }
  };

  return {
    run: (signal) =>
      eachOrganisation(
        list,
        (error) => {
          logger.error('waiting_rejection.run_failed', { err: error });
        },
        (orgId) => rejectIn(orgId, signal),
      ),
  };
}
