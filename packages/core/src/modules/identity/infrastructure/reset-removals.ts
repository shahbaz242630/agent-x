// Carrying out the resets of lost second factors (ADR-003 §4, ADR-012 §8;
// SEC-OPS-04; B6-3c): the API's job, on a timer of its own, finding each
// reset whose cooling-off has passed (`isDue`) and removing the person's
// second factors at the login service (idp-factors.ts).
//
// For each organisation the directory lists, its resets are read and
// verified (`resetsOf`: one that can't be believed raises the alarm and holds
// the organisation, and the job leaves them all); then each due reset:
// 1. read and judged, in a transaction of its own that holds nothing after:
//    the person the reset's row names, and whom the directory lists with that
//    membership (where to look, never whose it is); their membership (2a),
//    naming the same person; the reset (2c), due still;
// 2. unless it is to be cancelled, every second factor removed at the login
//    service, outside any transaction: nothing of the organisation is held
//    while the login service answers, so an admin's cancel, list or ask is
//    never kept waiting on it (review: they would pass their 10 s);
// 3. read and judged again in one transaction, with their sessions and step-up
//    challenges locked first (ADR-006 §6 level 0b, as a deactivation does) and
//    the reset read for the change: a person deactivated since, or listed in
//    another organisation since (their login signs in to each, and one
//    organisation can't reset it for the others: the runbook), is not reset:
//    CANCELLED by the job, told. Otherwise every session of the person ended,
//    their challenges with them; the reset COMPLETED, with how many factors
//    were removed; the person, the admins and the contacts told. Either way
//    (the factors are gone), last, the platform chain's
//    `person.second_factors_removed` about the person, from which their 7
//    days without an admin's or approver's powers count (B6-3d;
//    removal-restriction.ts). A session opened between the removal and this
//    commit is ended with the others (a completed reset), and any opened
//    after it is restricted.
//
// A cancel committed before step 1 reads the reset stops it: any cancel made
// within the cooling-off does. One made in the moments after it ended, while
// the factors were being removed, leaves the reset CANCELLED with its factors
// gone: logged as an error (`factor_resets.removed_after_cancel`), and on the
// record by the login service's own events, which the copier copies and tells
// (B6-2b), as it does a factor removed before a removal failed part-way.
//
// A removal the login service refuses, or one that leaves a factor, throws:
// nothing is written and the reset stays due, tried again at the next run. A
// commit that fails after the removal leaves the same: the next run finds none
// left and completes it.
//
// A run never throws: each failure is logged, naming the organisation and
// reset, and the run goes on to the next. Each statement is limited to 10
// seconds; the login service's calls to 10 seconds each.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { limitStatements } from '@agentx/platform/db';
import { type Kysely, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, type SignedStatesServices, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedElsewhere, listedMember, listedOrganizations } from '../../directory/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import { createPlatformChain, type PlatformControlsTables } from '../../platform-controls/index.ts';
import { isDue } from '../domain/factor-reset.ts';
import { listedPersonOf, moveReset, resetForChange, resetRecord, resetsOf } from './factor-resets.ts';
import type { SecondFactorRemover } from './idp-factors.ts';
import { memberOf } from './memberships.ts';
import { SECOND_FACTORS_REMOVED } from './removal-restriction.ts';
import { toldOfReset } from './reset-changes.ts';
import { endSessionsOf, lockSessionsOf } from './sessions.ts';
import { lockChallengesOf } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { subjectOfUser } from './users.ts';

/** Who carries a reset out: the API's own job. */
const ACTOR = { type: 'system', id: 'api' } as const;

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables & PlatformControlsTables;

/** What became of one due reset. */
type RemovalOutcome = 'completed' | 'cancelled' | 'not_due' | 'removed_after_cancel';

/**
 * Why a reset read now isn't carried out: done (by another run), not due
 * (cancelled or lapsed since), or its person can't be reset.
 */
type NotCarriedOut = 'done' | 'not_due' | 'member_deactivated' | 'member_elsewhere';

export interface ResetRemovals {
  /** Carries out every due reset, until none is left or the signal is aborted. Never throws. */
  run(signal?: AbortSignal): Promise<void>;
}

/** A reset or person that can't be believed as its rows read: the alarm is raised where it was read. */
class RemovalRefused extends Error {
  constructor(what: string) {
    super(`a reset's removal refused: ${what}`);
    this.name = 'RemovalRefused';
  }
}

export function createResetRemovals({
  database,
  factors,
  keys,
  ids,
  clock,
  issuer,
  outbox,
  logger,
}: {
  readonly database: Kysely<Tables>;
  readonly factors: SecondFactorRemover;
  readonly keys: KeyProvider;
  readonly ids: IdGenerator;
  readonly clock: Clock;
  /** The login service the factors are removed at: its subjects are its user IDs. */
  readonly issuer: string;
  readonly outbox: Outbox;
  readonly logger: Logger;
}): ResetRemovals {
  const platform = createPlatformChain({ keys, ids });

  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  const inOrganization = <T>(
    orgId: string,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>,
  ): Promise<T> => {
    const services: SignedStatesServices = { keys, ids, logger: logger.child({ orgId }) };
    return withSignedStates(database, orgId, services, async (tx, states) => {
      await limitStatements(tx);
      return work(tx, states);
    });
  };

  /** The IDs of the organisation's resets due now. Throws for resets that can't be believed, or more than are read. */
  const dueIn = async (orgId: string): Promise<string[]> => {
    const listed = await inOrganization(orgId, (tx, states) => resetsOf(tx, states, orgId));
    if (listed.outcome === 'tampered') throw new RemovalRefused("the organisation's resets can't be believed");
    const now = clock.now();
    return listed.resets.filter((reset) => isDue(reset, now)).map((reset) => reset.id);
  };

  /**
   * The reset's person, and why it isn't carried out now, if it isn't: read
   * for a decision, or (`change`) with the person's sessions and challenges
   * locked first and the reset read for the change. Throws for a person or
   * reset that can't be believed.
   */
  const judged = async (
    tx: Transaction<Tables>,
    states: SignedStates,
    orgId: string,
    id: string,
    lock: 'share' | 'change',
  ): Promise<{ readonly userId: string; readonly not: NotCarriedOut | undefined }> => {
    const personId = await listedPersonOf(tx, orgId, id);
    const userId = personId === undefined ? undefined : await listedMember(tx, orgId, personId);
    if (personId === undefined || userId === undefined) throw new RemovalRefused('its person is not listed');
    if (lock === 'change') {
      // Level 0b, before any membership: the person's sessions, then their challenges.
      await lockSessionsOf(tx, [userId]);
      await lockChallengesOf(tx, [userId]);
    }
    // Each read that can't be believed has raised the alarm and held the organisation.
    const person = await memberOf(tx, states, { orgId, id: personId }, 'share');
    if (person.outcome !== 'found' || person.member.userId !== userId) {
      throw new RemovalRefused("the person's membership can't be believed");
    }
    // The reset's person is sealed, and verified from the row listedPersonOf read.
    const read =
      lock === 'change' ? await resetForChange(tx, states, { orgId, id }) : await resetRecord(tx, states, orgId, id);
    if (read.outcome !== 'found') throw new RemovalRefused("the reset can't be believed");
    if (read.reset.status === 'COMPLETED') return { userId, not: 'done' };
    if (!isDue(read.reset, clock.now())) return { userId, not: 'not_due' };
    if (person.member.status !== 'ACTIVE') return { userId, not: 'member_deactivated' };
    if (await listedElsewhere(tx, orgId, userId)) return { userId, not: 'member_elsewhere' };
    return { userId, not: undefined };
  };

  /** Cancels the reset, which the job judged not to be carried out, and tells everyone, in the caller's transaction. */
  const cancel = async (
    tx: Transaction<Tables>,
    states: SignedStates,
    {
      orgId,
      id,
      userId,
      reason,
    }: { orgId: string; id: string; userId: string; reason: Exclude<NotCarriedOut, 'done' | 'not_due'> },
  ): Promise<void> => {
    await moveReset(tx, states, { orgId, id, event: 'cancel', actor: ACTOR, details: { reason } });
    await outbox.add(tx, toldOfReset(orgId, 'factor_reset_cancelled', userId, true));
  };

  /** Carries out one due reset; what became of it. */
  const carryOut = async (orgId: string, id: string): Promise<RemovalOutcome> => {
    const { userId, not: first } = await inOrganization(orgId, (tx, states) => judged(tx, states, orgId, id, 'share'));
    if (first === 'done' || first === 'not_due') return 'not_due';
    // Judged again with the person's sessions and challenges locked: the person is the membership's,
    // which is sealed, so the same one.
    const again = (tx: Transaction<Tables>, states: SignedStates) =>
      judged(tx, states, orgId, id, 'change').then(({ not }) => not);
    const key = { orgId, id, userId };
    if (first !== undefined) {
      // Not to be reset: cancelled, unless cancelled or done since.
      return inOrganization(orgId, async (tx, states) => {
        const not = await again(tx, states);
        if (not === 'done' || not === 'not_due') return 'not_due';
        await cancel(tx, states, { ...key, reason: first });
        return 'cancelled';
      });
    }
    const signsInAs = await subjectOfUser(database, userId);
    if (signsInAs?.issuer !== issuer) throw new RemovalRefused('the person signs in with another login service');
    const factorsRemoved = await factors.removeAll(signsInAs.subject);
    return inOrganization(orgId, async (tx, states) => {
      const not = await again(tx, states);
      // Completed by another run (a second replica, or two revisions at a release): the same removal, benign.
      if (not === 'done') return 'not_due';
      let outcome: RemovalOutcome = 'removed_after_cancel';
      if (not === undefined) {
        const signInsEnded = await endSessionsOf(tx, userId);
        await moveReset(tx, states, {
          orgId,
          id,
          event: 'complete',
          actor: ACTOR,
          details: { factorsRemoved, signInsEnded },
        });
        await outbox.add(tx, toldOfReset(orgId, 'factor_reset_completed', userId, true));
        outcome = 'completed';
      } else if (not !== 'not_due') {
        // The person deactivated or listed elsewhere while the factors were being removed.
        await cancel(tx, states, { ...key, reason: not });
      }
      // Cancelled or not, the factors are gone, so the restriction counts from now. The platform head last of all
      // (ADR-006 §6).
      await platform.record(tx, {
        actor: ACTOR,
        action: SECOND_FACTORS_REMOVED,
        details: { person: userId, org: orgId, reset: id, at: clock.now().toISOString() },
      });
      return outcome;
    });
  };

  /** Carries out one due reset and logs how it ended, or that it failed. */
  const carryOutLogged = async (log: Logger, orgId: string, resetId: string): Promise<void> => {
    try {
      const outcome = await carryOut(orgId, resetId);
      if (outcome === 'removed_after_cancel') log.error('factor_resets.removed_after_cancel', { resetId });
      else if (outcome !== 'not_due') log.info(`factor_resets.${outcome}`, { resetId });
    } catch (error) {
      log.error('factor_resets.removal_failed', { resetId, err: error });
    }
  };

  return {
    async run(signal) {
      let orgs: string[];
      try {
        orgs = await listedOrganizations(database);
      } catch (error) {
        logger.warn('factor_resets.run_failed', { err: error });
        return;
      }
      for (const orgId of orgs) {
        let due: string[];
        const log = logger.child({ orgId });
        try {
          due = await dueIn(orgId);
        } catch (error) {
          // Resets that can't be believed, more than are read (TooManyResets), or a read that failed.
          log.error('factor_resets.unreadable', { err: error });
          continue;
        }
        for (const resetId of due) {
          if (signal?.aborted === true) return;
          await carryOutLogged(log, orgId, resetId);
        }
      }
    },
  };
}
