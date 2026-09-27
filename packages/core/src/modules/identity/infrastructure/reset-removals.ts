// Carrying out the resets of lost second factors (ADR-003 §4, ADR-012 §8;
// SEC-OPS-04; B6-3c): the API's job, on a timer of its own, finding each
// reset whose cooling-off has passed (`isDue`) and removing the person's
// second factors at the login service (idp-factors.ts).
//
// For each organisation the directory lists, its resets are read and
// verified (`resetsOf`: one that can't be believed raises the alarm and holds
// the organisation, and the job leaves them all); then each due reset in one
// transaction of its own, withSignedStates' for the organisation:
// 1. the person the reset's row names, and whom the directory lists with that
//    membership: where to look, never whose it is;
// 2. their sessions and step-up challenges locked (ADR-006 §6 level 0b, as a
//    deactivation does), then their membership read (2a), naming the same
//    person, then the reset read for the change (2c), naming the same
//    membership, and due still: an admin's cancel waits on this lock, or was
//    first and the reset is left;
// 3. a person deactivated since, or listed in another organisation since
//    (their login signs in to each, and one organisation can't reset it for
//    the others: the runbook), is not reset: CANCELLED by the job, told;
// 4. otherwise every second factor removed at the login service, while the
//    reset is held, so no cancel can come between the removal and its record;
//    every session of the person ended, their challenges with them; the reset
//    COMPLETED, with how many were removed; the person, the admins and the
//    contacts told, in the same transaction.
//
// A removal the login service refuses, or one that leaves a factor, throws:
// the transaction rolls back and the reset stays due, tried again at the next
// run (a factor removed before the failure is on the login service's own
// record, which the copier copies and tells, B6-2b). A commit that fails after
// the removal leaves the same: the next run finds none left and completes it.
//
// A run never throws: each failure is logged, naming the organisation and
// reset, and the run goes on to the next. Each statement is limited to 10
// seconds; the login service's calls to 10 seconds each.
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type Kysely, sql, type Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import { type AuditTables, type SignedStates, type SignedStatesServices, withSignedStates } from '../../audit/index.ts';
import { type DirectoryTables, listedElsewhere, listedMember, listedOrganizations } from '../../directory/index.ts';
import type { NotificationsTables, Outbox } from '../../notifications/index.ts';
import { isDue } from '../domain/factor-reset.ts';
import { listedPersonOf, moveReset, resetForChange, resetsOf } from './factor-resets.ts';
import type { SecondFactorRemover } from './idp-factors.ts';
import { memberOf } from './memberships.ts';
import { toldOfReset } from './reset-changes.ts';
import { endSessionsOf, lockSessionsOf } from './sessions.ts';
import { lockChallengesOf } from './step-up-challenges.ts';
import type { IdentityTables } from './tables.ts';
import { subjectOfUser } from './users.ts';

/** Who carries a reset out: the API's own job. */
const ACTOR = { type: 'system', id: 'api' } as const;

type Tables = IdentityTables & DirectoryTables & AuditTables & NotificationsTables;

/** What became of one due reset. */
type RemovalOutcome = 'completed' | 'cancelled' | 'not_due';

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
  /** Runs the work in the organisation's transaction, each statement limited to 10 seconds. */
  const inOrganization = <T>(
    orgId: string,
    work: (tx: Transaction<Tables>, states: SignedStates) => Promise<T>,
  ): Promise<T> => {
    const services: SignedStatesServices = { keys, ids, logger: logger.child({ orgId }) };
    return withSignedStates(database, orgId, services, async (tx, states) => {
      await sql`set local statement_timeout = '10s'`.execute(tx);
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

  /** Carries out one due reset, in one transaction; what became of it. */
  const carryOut = (orgId: string, id: string): Promise<RemovalOutcome> =>
    inOrganization(orgId, async (tx, states) => {
      const personId = await listedPersonOf(tx, orgId, id);
      const userId = personId === undefined ? undefined : await listedMember(tx, orgId, personId);
      if (personId === undefined || userId === undefined) throw new RemovalRefused('its person is not listed');
      // Level 0b, before any membership: the person's sessions, then their challenges.
      await lockSessionsOf(tx, [userId]);
      await lockChallengesOf(tx, [userId]);
      // Each read that can't be believed has raised the alarm and held the organisation.
      const person = await memberOf(tx, states, { orgId, id: personId }, 'share');
      if (person.outcome !== 'found' || person.member.userId !== userId) {
        throw new RemovalRefused("the person's membership can't be believed");
      }
      // The reset's person is sealed and the app never deletes one: anything else is the row changed past it.
      const read = await resetForChange(tx, states, { orgId, id });
      if (read.outcome !== 'found' || read.reset.person !== personId.toLowerCase()) {
        throw new RemovalRefused("the reset can't be believed");
      }
      // Cancelled, or carried out, since the list was read.
      if (!isDue(read.reset, clock.now())) return 'not_due';

      const reason =
        person.member.status !== 'ACTIVE'
          ? 'member_deactivated'
          : (await listedElsewhere(tx, orgId, userId))
            ? 'member_elsewhere'
            : undefined;
      if (reason !== undefined) {
        await moveReset(tx, states, { orgId, id, event: 'cancel', actor: ACTOR, details: { reason } });
        await outbox.add(tx, toldOfReset(orgId, 'factor_reset_cancelled', userId, true));
        return 'cancelled';
      }

      const signsInAs = await subjectOfUser(tx, userId);
      if (signsInAs?.issuer !== issuer) throw new RemovalRefused('the person signs in with another login service');
      const factorsRemoved = await factors.removeAll(signsInAs.subject);
      const signInsEnded = await endSessionsOf(tx, userId);
      await moveReset(tx, states, {
        orgId,
        id,
        event: 'complete',
        actor: ACTOR,
        details: { factorsRemoved, signInsEnded },
      });
      await outbox.add(tx, toldOfReset(orgId, 'factor_reset_completed', userId, true));
      return 'completed';
    });

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
          try {
            const outcome = await carryOut(orgId, resetId);
            if (outcome !== 'not_due') log.info(`factor_resets.${outcome}`, { resetId });
          } catch (error) {
            log.error('factor_resets.removal_failed', { resetId, err: error });
          }
        }
      }
    },
  };
}
