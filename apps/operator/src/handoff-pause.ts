// Phase 4 B1: the operator pauses or resumes every hand-off of an approved
// payment to the bank, for every organisation at once (BR-11; SEC-OPS-03;
// partner decision 4, S135: operator only, a reason required, signed on the
// platform chain, every organisation's admins emailed on pause and resume).
//
// 1. The change, in one transaction on the platform tables
//    (platform-controls' changeHandoffPause): the pause row locked first
//    (ADR-006 §6 level 1), then `platform.handoff_paused` or
//    `platform.handoff_resumed` on the platform chain (actor system:operator,
//    its ID the request's, its reason, the release and the job's run), the
//    head's lock last (13), and the row pointed at it. A row that can't be
//    believed is refused, changing nothing (the alarm raised); one already as
//    asked records nothing.
// 2. Then every organisation the directory lists is told, each in a
//    transaction of its own, withSignedStates' for it: `handoff.paused` or
//    `handoff.resumed` on its own chain (about the platform event, naming it
//    and the reason), and a notice to every admin about that entry (0056).
//    One told already by an earlier run (its chain holds an event about the
//    platform event) is passed over; one that fails is logged and the rest
//    are still told, and the run then exits 1, to be run again, telling only
//    those left.
//
// The platform event's ID is made where the request was written, so a
// request run again finds its own change in force, records nothing, and
// tells those not told yet. Should the pause have moved on since (another
// request's change in force now), the request is refused: its ID names an
// event overtaken, or one that isn't its own. A request found already as
// asked by another's change records and tells nothing: telling is that
// change's own request's to finish. The reason is sealed on the chains
// alone, never logged, as a case reference is.
import { createAuditTrail, type SignedStatesServices, withSignedStates } from '@agentx/core/modules/audit';
import { listedOrganizations } from '@agentx/core/modules/directory';
import { createOutbox, type NotificationsTables } from '@agentx/core/modules/notifications';
import {
  changeHandoffPause,
  createPlatformChain,
  type HandoffPauseChanged,
} from '@agentx/core/modules/platform-controls';
import { type IdGenerator, systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { type Database, limitStatements } from '@agentx/platform/db';

import { OPERATOR, type OperatorTables } from './create-organization.ts';

/** Every table the change and its telling reach: the platform's, each organisation's chain, and its admins' notices. */
export type HandoffPauseTables = OperatorTables & NotificationsTables;

/** A pause or resume, as its request asks it. */
export interface HandoffPauseRequest {
  /** True to pause every hand-off, false to resume them. */
  readonly paused: boolean;
  /** A case reference: sealed on the chains, never logged. */
  readonly reason: string;
  /** The platform event's ID, made where the request was written. */
  readonly eventId: string;
  readonly release: string;
  readonly run: string | null;
}

/** What each organisation's chain names the platform event's subject as. */
const SUBJECT_TYPE = 'handoff_pause';

/** Why the request is refused when the row can't be believed: the alarm is raised already. */
const TAMPERED = "the hand-off pause's record can't be verified, so nothing was changed";

/** Why it is refused when its ID is on the platform chain but its change isn't the one in force. */
const ANOTHER_EVENT = 'the ID names another platform event, or a change overtaken since: write a new request';

/** The one ID the platform event takes: the request's. */
const theEventId = (eventId: string): IdGenerator => ({ next: () => eventId });

/** Whether an error is the platform chain refusing an event ID it holds already. */
const heldAlready = (error: unknown): boolean =>
  error instanceof Error && 'constraint' in error && error.constraint === 'audit_events_id_key';

/** The change, in a transaction of its own: its event's ID the request's. */
function change(
  database: Database<HandoffPauseTables>,
  services: SignedStatesServices,
  { paused, reason, eventId, release, run }: HandoffPauseRequest,
): Promise<HandoffPauseChanged> {
  const chain = createPlatformChain({ keys: services.keys, ids: theEventId(eventId) });
  return database
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await limitStatements(tx);
      return changeHandoffPause(
        tx,
        { chain, logger: services.logger },
        { paused, reason, actor: OPERATOR, release, run },
      );
    });
}

/** Tells one organisation, unless an earlier run did: whether it was told now. */
function tell(
  database: Database<HandoffPauseTables>,
  services: SignedStatesServices,
  orgId: string,
  { paused, reason, eventId }: HandoffPauseRequest,
): Promise<boolean> {
  const trail = createAuditTrail({ keys: services.keys, ids: services.ids });
  const outbox = createOutbox({ ids: uuidV7Ids, clock: systemClock });
  return withSignedStates(database, orgId, services, async (tx, states) => {
    const subject = { type: SUBJECT_TYPE, id: eventId };
    // Through the signed states: a record that can't be believed raises the alarm and the hold, and fails this one.
    const before = await states.eventOf(tx, orgId, { onlyAbout: subject });
    if (before.outcome === 'tampered') throw new Error("the organisation's audit log can't be verified");
    if (before.event !== undefined) return false;
    const recorded = await trail.record(tx, orgId, {
      actor: OPERATOR,
      action: paused ? 'handoff.paused' : 'handoff.resumed',
      subject: { ...subject, version: 1 },
      details: { reason, platformEventId: eventId },
    });
    await outbox.add(tx, [
      {
        orgId,
        recipientUserId: null,
        kind: paused ? 'handoff_paused' : 'handoff_resumed',
        membershipId: null,
        role: null,
        aboutId: recorded.id,
      },
    ]);
    return true;
  });
}

/** Tells every organisation the directory lists, each on its own: the exit code, 0 once all are told. */
async function tellEvery(
  database: Database<HandoffPauseTables>,
  services: SignedStatesServices,
  request: HandoffPauseRequest,
): Promise<number> {
  const log = services.logger;
  const platformEventId = request.eventId;
  const organizations = await listedOrganizations(database);
  let told = 0;
  let failed = 0;
  for (const orgId of organizations) {
    try {
      if (await tell(database, services, orgId, request)) told += 1;
    } catch (error) {
      failed += 1;
      log.child({ orgId }).error('operator.handoff_notice_failed', { platformEventId, err: error });
    }
  }
  const toldBefore = organizations.length - told - failed;
  log.info('operator.handoff_told', {
    platformEventId,
    organizations: organizations.length,
    told,
    toldBefore,
    failed,
  });
  return failed === 0 ? 0 : 1;
}

/** Pauses or resumes every hand-off and tells every organisation: the exit code, 0 once done and all are told. */
export async function changeHandoffPauseAsOperator(
  database: Database<HandoffPauseTables>,
  services: SignedStatesServices,
  request: HandoffPauseRequest,
): Promise<number> {
  const log = services.logger;
  // Every line names the request's platform event, so the deploy tool reads this run's lines alone.
  const platformEventId = request.eventId;
  const command = request.paused ? 'handoff-pause' : 'handoff-resume';
  let changed: HandoffPauseChanged;
  try {
    changed = await change(database, services, request);
  } catch (error) {
    if (heldAlready(error)) {
      log.error('operator.refused', { platformEventId, problems: [ANOTHER_EVENT] });
    } else {
      // One transaction: nothing was changed, unless the connection was lost as it committed. Run again to find out.
      log.error('operator.failed', { command, platformEventId, err: error });
    }
    return 1;
  }
  if (changed.outcome === 'tampered') {
    log.error('operator.refused', { platformEventId, problems: [TAMPERED] });
    return 1;
  }
  if (changed.outcome === 'changed') {
    log.info(request.paused ? 'operator.handoff_paused' : 'operator.handoff_resumed', {
      platformEventId,
      platformSeq: changed.seq,
    });
  } else {
    log.info('operator.handoff_unchanged', {
      platformEventId,
      paused: changed.paused,
      inForce: changed.eventId,
      since: changed.since?.toISOString() ?? null,
    });
    // As asked by another request's change, or as born: telling is that change's own, or there is nothing to tell.
    if (changed.eventId !== platformEventId) return 0;
  }
  try {
    return await tellEvery(database, services, request);
  } catch (error) {
    // The organisations couldn't be listed: none told this run. The change stands; run the same request again.
    log.error('operator.failed', { command, platformEventId, err: error });
    return 1;
  }
}
