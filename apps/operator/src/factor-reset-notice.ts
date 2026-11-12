// OR2 (playbook K; CF Before production "The only-admin runbook's tools"):
// before our team removes a person's second factor at the login service, as no
// admin can ask the product's own reset (the organisation's only admin lost
// theirs, or the person is in more than one organisation: ADR-003 §4, ADR-012
// §8, SEC-OPS-04), the operator tells every member of the organisation that it
// is under way, and its registered contacts that count now, each at the address
// Agent X holds, never one the requester gives. Anyone may stop it within the
// 24 hours the team then waits. One organisation a run: a person in several is
// told of in each, and the run names the others the directory lists them in.
//
// In one transaction, withSignedStates' for the organisation (ADR-006 §6: its
// chain's head at 12, then the platform's at 13):
// 1. the organisation must exist and be verified, and the directory must list
//    the person in it (directory.members, IDs alone: where a membership is,
//    never what it says; the reset reaches their login whatever its state);
// 2. `support.factor_reset_notified` on its own chain (actor system:operator,
//    its ID the request's, naming the person and the incident's reference);
// 3. two notices of `factor_reset_by_support` (0087) about the person: one to
//    every active member, one to the contacts that count now, each group found
//    by the API's sender as it sends (as for a notice about a supplier);
// 4. `operator.factor_reset_notified` on the platform chain.
// Both chains and the notices, or none.
//
// The record's ID is made where the request was written, so a request run
// again finds its record and records and tells nothing twice; one that names
// any other record, here or another organisation's on the platform chain, is
// refused. The reference is sealed on the chains alone, never logged.
import {
  createAuditTrail,
  type SignedStates,
  type SignedStatesServices,
  withSignedStates,
} from '@agentx/core/modules/audit';
import { listedMembership, organizationsOf } from '@agentx/core/modules/directory';
import { createOutbox, type Notice, type NotificationsTables } from '@agentx/core/modules/notifications';
import { ORGANIZATIONS } from '@agentx/core/modules/organizations';
import { createPlatformChain, platformEventWith } from '@agentx/core/modules/platform-controls';
import { type IdGenerator, systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import type { Database, DatabaseTransaction } from '@agentx/platform/db';

import { OPERATOR, type OperatorTables } from './create-organization.ts';

/** Every table the record and its notices reach: both chains, the directory, and the outbox. */
export type FactorResetNoticeTables = OperatorTables & NotificationsTables;

/** The organisation's own record of the notice: what its audit log shows. */
export const NOTIFIED = 'support.factor_reset_notified';

/** The platform's own record of it, naming the organisation and the record. */
export const PLATFORM_NOTIFIED = 'operator.factor_reset_notified';

/** The notice's kind (0087): to every member, and to the contacts that count now. */
const KIND = 'factor_reset_by_support';

/** A reset's notice, as its request asks it. */
export interface FactorResetNoticeRequest {
  readonly orgId: string;
  readonly userId: string;
  /** The incident's reference: sealed on both chains, never logged. */
  readonly reason: string;
  /** Its record's ID on the organisation's chain, made where the request was written. */
  readonly noticeId: string;
  readonly release: string;
  readonly run: string | null;
}

/** Why the notice can't be written: never naming the reference. */
class NoticeRefused extends Error {
  readonly problem: string;

  constructor(problem: string) {
    super(`The notice refused: ${problem}`);
    this.name = 'NoticeRefused';
    this.problem = problem;
  }
}

/** Refused for a record ID that names any other record. */
const ANOTHER_RECORD = 'the ID names another record: write a new request';

/** Whether an earlier run of this very request recorded it: refused for an ID that names anything else. */
async function recordedBefore(
  tx: DatabaseTransaction<FactorResetNoticeTables>,
  states: SignedStates,
  { orgId, userId, reason, noticeId }: FactorResetNoticeRequest,
): Promise<boolean> {
  const organization = await states.verifiedState(tx, ORGANIZATIONS, { orgId, id: orgId }, 'share');
  if (organization.outcome === 'missing') throw new NoticeRefused('no organisation has this ID');
  if (organization.outcome === 'tampered') throw new NoticeRefused("the organisation's records can't be verified");
  // Through the signed states: a record that can't be believed raises the alarm and the hold.
  const found = await states.eventOf(tx, orgId, { eventId: noticeId });
  if (found.outcome === 'tampered') throw new NoticeRefused("the organisation's audit log can't be verified");
  if (found.event !== undefined) {
    const { event } = found.event;
    const same =
      event.action === NOTIFIED &&
      event.actor.type === OPERATOR.type &&
      event.actor.id === OPERATOR.id &&
      event.details.userId === userId &&
      event.details.reason === reason;
    if (!same) throw new NoticeRefused(ANOTHER_RECORD);
    return true;
  }
  // Another organisation's record of this ID: one ID names one notice.
  if (await platformEventWith(tx, PLATFORM_NOTIFIED, { noticeId })) throw new NoticeRefused(ANOTHER_RECORD);
  return false;
}

/** The one ID the organisation's record takes: the request's. */
const theNoticeId = (noticeId: string): IdGenerator => ({ next: () => noticeId });

/** Records the notice on both chains and writes it to the outbox, or finds an earlier run's record: whether it did now. */
function record(
  database: Database<FactorResetNoticeTables>,
  services: SignedStatesServices,
  request: FactorResetNoticeRequest,
): Promise<boolean> {
  const { orgId, userId, reason, noticeId, release, run } = request;
  const trail = createAuditTrail({ keys: services.keys, ids: theNoticeId(noticeId) });
  const platform = createPlatformChain({ keys: services.keys, ids: services.ids });
  const outbox = createOutbox({ ids: uuidV7Ids, clock: systemClock });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    if (await recordedBefore(tx, states, request)) return false;
    if ((await listedMembership(tx, orgId, userId)) === undefined) {
      throw new NoticeRefused('the directory lists no such person in this organisation');
    }
    await trail.record(tx, orgId, {
      actor: OPERATOR,
      action: NOTIFIED,
      subject: { type: 'support_factor_reset', id: noticeId, version: 1 },
      details: { userId, reason },
    });
    const notice: Notice = {
      orgId,
      recipientUserId: null,
      kind: KIND,
      membershipId: null,
      role: null,
      aboutId: userId,
    };
    await outbox.add(tx, [notice, { ...notice, toContacts: true }]);
    await platform.record(tx, {
      actor: OPERATOR,
      action: PLATFORM_NOTIFIED,
      details: { orgId, noticeId, userId, reason, release, run },
    });
    return true;
  });
}

/** Tells the organisation of the reset under way: the exit code, 0 once recorded and its notices written. */
export async function noticeFactorReset(
  database: Database<FactorResetNoticeTables>,
  services: SignedStatesServices,
  request: FactorResetNoticeRequest,
): Promise<number> {
  const { noticeId } = request;
  // Every line names the record, so the deploy tool reads this run's lines alone.
  const log = services.logger.child({ orgId: request.orgId });
  try {
    const recordedNow = await record(database, services, request);
    // Where else the reset reaches: the runbook tells each of those organisations too, a request each.
    const elsewhere = (await organizationsOf(database, request.userId)).filter((orgId) => orgId !== request.orgId);
    log.info('operator.factor_reset_notified', { noticeId, recordedBefore: !recordedNow, elsewhere });
    return 0;
  } catch (error) {
    if (error instanceof NoticeRefused) {
      log.error('operator.refused', { noticeId, problems: [error.problem] });
    } else {
      // The record is one transaction, and the directory's read after it only reads: the same request run again
      // finds out which, recording and telling nothing twice.
      log.error('operator.failed', { command: 'factor-reset-notice', noticeId, err: error });
    }
    return 1;
  }
}
