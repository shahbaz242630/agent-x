// Every background job of the API (4D2e D), each on a timer of its own, so one
// never holds up another: the `jobs` side's, and what every process runs for
// itself (the counts it holds in memory, and how a trip feels from there).
//
// The `jobs` side's run only while this process holds the lease (background.ts).
// Nothing here starts until start-jobs.ts starts it: the anchor check's order
// (it must start before the hand-off's first run) is this list's.
import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import { createAuditTrail, holdOrganisation } from '@agentx/core/modules/audit';
import { listedOrganizations } from '@agentx/core/modules/directory';
import {
  activeContactsFor,
  contactAddressFor,
  countingContactsFor,
  membersFor,
  resetLinkFor,
} from '@agentx/core/modules/identity';
import { createPlatformChain } from '@agentx/core/modules/platform-controls';
import { checkSchemaOnSchedule, createFullServerWatch, createReleaseDriftWatch } from '@agentx/core/schema-check';
import { HOUR_MS, systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { createMemoryAnchorStore } from '@agentx/platform/audit-chain';
import { sweepExpiredKeys, timedRoundTrips } from '@agentx/platform/db';
import { createOutboundFetch } from '@agentx/platform/outbound';

import { ACTIVITY_EXPORTS_EVERY_MS } from './activity-export-builder.ts';
import { ACTIVITY_SEAL_CHECK_EVERY_MS, createActivitySealCheck } from './activity-seal-check.ts';
import { ACTIVITY_SEAL_EVERY_MS, createActivitySeal } from './activity-seal.ts';
import { createZoneSealing, ZONE_SEALING_EVERY_MS } from './agent-zone-seals.ts';
import { createAnchorCheck, scheduleAnchorCheck } from './anchor-check.ts';
import { type Leadership, scheduleRuns } from './background.ts';
import type { Booted, SharedParts } from './boot.ts';
import { FACTOR_REMOVALS_EVERY_MS, resetRemovalsFrom } from './factor-removals.ts';
import { createHandoff, HANDOFF_EVERY_MS } from './handoff.ts';
import { createHoldHistoryCheck, HOLD_HISTORY_EVERY_MS } from './hold-history-check.ts';
import { createHoldingsCheck, HOLDINGS_CHECK_EVERY_MS } from './holdings-check.ts';
import { IDP_EVENTS_EVERY_MS, idpEventCopierFrom } from './idp-events.ts';
import { contactFillFrom } from './kept-names.ts';
import { CARRY_REST_EVERY_MS, createCarryRest } from './mandate-carry-rest.ts';
import { createMandateExpiry, MANDATE_EXPIRY_EVERY_MS } from './mandate-expiry.ts';
import { PULSE_EVERY_MS, type JobWatch, type WatchedWork, type Work } from './job-watch.ts';
import { NOTICES_EVERY_MS, noticeSenderFrom } from './notices.ts';
import { createPaymentChecks, PAYMENT_CHECKS_EVERY_MS } from './payment-checks.ts';
import { createRemittances } from './remittances.ts';
import { createRequestExpiry, REQUEST_EXPIRY_EVERY_MS } from './request-expiry.ts';
import { createRequestVoids, REQUEST_VOIDS_EVERY_MS } from './request-voids.ts';
import { createRetentionSweep, scheduleRetentionSweep } from './retention-sweep.ts';
import { createRoundTripTiming, ROUND_TRIP_EVERY_MS, ROUND_TRIPS_A_RUN } from './round-trip-timing.ts';
import { createRowSweep, scheduleRowSweep, type SweptRows } from './row-sweep.ts';
import { createWaitingRequests } from './waiting-requests.ts';
import { createWaitingRejections, WAITING_REJECTIONS_EVERY_MS } from './waiting-rejections.ts';

/**
 * How long the anchor check of one chain may take before it counts as not
 * completed (anchor-check.ts). Each of its statements has 10 seconds at most
 * (verifyAlone); this bounds the whole check, whatever the database does.
 */
const ANCHOR_CHECK_DEADLINE_MS = 120_000;

/**
 * The idempotency keys' retention sweep (B1e-3): at each start, then an hour
 * after each sweep ends; a batch of 1,000 keys at a time, at most 100 batches
 * an organisation a run, each within the anchor check's deadline.
 */
const SWEEP = { batch: 1_000, mostBatches: 100 } as const;
const SWEEP_EVERY_MS = HOUR_MS;

/**
 * The global tables' sweeps: the sign-in flows' (B2-3a-2), the ended
 * sessions' (B2-4a) and the security events' past their retention (B2-5a),
 * each a batch of 1,000 rows at a time, at most 100 batches a run.
 */
const ROW_SWEEP = { batch: 1_000, mostBatches: 100 } as const;

/** How often people with no kept name are looked up at the login service (decision 25, E10d-4): at the start, then hourly, so a run the login service failed is soon tried again. */
const CONTACT_FILL_EVERY_MS = HOUR_MS;

/** How often the recorder writes the security events' counts whose minute has ended (B2-5b). */
const RECORD_EVERY_MS = 60_000;

interface Handle {
  stop(): Promise<void>;
}

/** One job as the list keeps it: what it is, and how it starts. */
export interface Job {
  readonly name: string;
  /** Starts its timer, or runs nothing where a config left it off. */
  start(): Handle;
}

/**
 * How long a run may take before it counts as stalled (job-watch.ts). Far past
 * any run seen, and an error, which reaches the partner: each is what a job at
 * 10k organisations could take on a slow day, not what it should.
 */
const QUICK_MS = 15 * 60_000;
const HALF_HOUR_MS = 30 * 60_000;
const LONG_MS = 2 * HOUR_MS;

/** Makes the list's entries, each one's runs recorded by the watch. */
function jobsWatchedBy(watch: JobWatch, gate: (work: WatchedWork) => WatchedWork = (work) => work) {
  return function job(
    name: string,
    work: Work | undefined,
    everyMs: number,
    stalledAfterMs: number,
    /** A job the config can leave off says whether it is on, as it starts. */
    says?: (running: boolean) => void,
    schedule: (work: WatchedWork, everyMs: number) => Handle = scheduleRuns,
  ): Job {
    return {
      name,
      start: () => {
        const handle =
          work === undefined
            ? { stop: () => Promise.resolve() }
            : // The gate outside the watch: a run waiting for the lease isn't a run stalled.
              schedule(gate(watch.watching(name, work, stalledAfterMs)), everyMs);
        says?.(work !== undefined);
        return handle;
      },
    };
  };
}

/** What every process runs for itself: the counts it holds in memory, and how a trip feels from it. */
export function eachProcessJobs({ logger, database }: Booted, { recorder, watch }: SharedParts): readonly Job[] {
  const job = jobsWatchedBy(watch);
  return [
    // The minute's counts, on a timer of their own (B2-5b); the last are written as the API stops.
    job('recorder', recorder, RECORD_EVERY_MS, QUICK_MS),
    // A trip's time through the API's life (4D2d): what its decisions' times are read against.
    job(
      'round_trips',
      createRoundTripTiming({ timed: () => timedRoundTrips(database, ROUND_TRIPS_A_RUN), logger }),
      ROUND_TRIP_EVERY_MS,
      QUICK_MS,
    ),
    // What sees the rest (job-watch.ts): not watched itself, and each minute whatever the others do.
    { name: 'pulse', start: () => scheduleRuns(watch, PULSE_EVERY_MS) },
  ];
}

/**
 * The `jobs` side, made but not started. The hand-off and the payment checks
 * come back too, for /health; the zones' sealing, whose first pass comes before
 * a process at `all` answers.
 */
export function oneCopyJobs({ config, keys, logger, database }: Booted, parts: SharedParts, leadership: Leadership) {
  const { flows, sessions, challenges, securityEvents, outbox, downloads, rail, providerEvents, watch } = parts;
  const job = jobsWatchedBy(watch, leadership.onlyWhileLeading.bind(leadership));
  const list = () => listedOrganizations(database);
  const organisationJob = { list, database, keys, ids: uuidV7Ids, logger };
  const clocked = { ...organisationJob, clock: systemClock };
  // The audit chains' last anchors, in this process's memory (ADR-012 §2): the anchor check keeps them, Tx A reads them.
  const anchorStore = createMemoryAnchorStore();
  const platform = createPlatformChain({ keys, ids: uuidV7Ids });
  const trail = createAuditTrail({ keys, ids: uuidV7Ids });
  const anchors = createAnchorCheck({
    chains: [{ chain: { kind: 'platform' }, verify: (anchor) => platform.verifyAlone(database, anchor) }],
    organizations: {
      list,
      recorded: () => platform.createdOrganizations(database),
      verify: (orgId, anchor) => trail.verifyAlone(database, orgId, anchor),
      // The run's own logger: the hold's lines name the organisation themselves.
      hold: (orgId, failure) => holdOrganisation(database, orgId, { keys, ids: uuidV7Ids, logger }, failure),
    },
    keys,
    clock: systemClock,
    logger,
    // Three missed checks in a row are the alarm, not just a warning.
    staleAfterMs: config.audit.anchorSeconds * 3 * 1000,
    deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
    anchors: anchorStore,
  });
  // Every approved request handed to the partner once, its authority checked again first (Phase 4 B4, PL-46); only
  // where the partner's rail is built (ADR-014 §4; the fake alone, until Phase 5). Its heartbeat is /health's first check (B5, ADR-013).
  const handoff =
    rail &&
    createHandoff({
      ...clocked,
      rail,
      outbox,
      // The anchor check starts before the hand-off's first run: this list's order.
      anchoring: { anchors: anchorStore, anchorFirst: (orgId, signal) => anchors.anchorOrganisation(orgId, signal) },
    });
  // Each payment under way checked with the bank, its transaction moved to match (Phase 4 E1a); beside the hand-off,
  // the payments the partner's messages name first (E1b).
  const paymentChecks = rail && createPaymentChecks({ ...clocked, rail, outbox, events: providerEvents });
  // The agents' zones kept before 0054 sealed before any decision reads one (PL-40); then on a timer of its own.
  const zoneSealing = createZoneSealing(organisationJob);
  // A server with every connection in use is the alarm only past the time a chain may go unchecked (decision 3).
  const fullServer = createFullServerWatch(config.audit.anchorSeconds * 3 * 1000, () => systemClock.now().getTime());
  const releaseDrift = createReleaseDriftWatch();
  // The one allowlisted fetch the notices, the login service's events and the resets send with.
  const outboundFetch = createOutboundFetch(config.outbound.allowedOrigins);
  const logged = { keys, ids: uuidV7Ids, logger };
  // A table's own sweep on a timer of its own, each batch within the anchor check's deadline.
  const sweepRows = (rows: SweptRows, sweep: (most: number) => Promise<number>): Job =>
    job(
      rows,
      createRowSweep({ rows, sweep, logger, deadlineMs: ANCHOR_CHECK_DEADLINE_MS, ...ROW_SWEEP }),
      SWEEP_EVERY_MS,
      HOUR_MS,
      undefined,
      scheduleRowSweep,
    );
  const jobs: readonly Job[] = [
    // The schema has a timer of its own: the chains' run grows with the organisations, and walls rewritten must not
    // wait for it (S168 review). Within its own deadline and ending at once when the API stops, so a database that
    // accepts a read and never answers cannot hold the schedule open.
    job(
      'schema_check',
      {
        run: (signal?: AbortSignal) =>
          checkSchemaOnSchedule({ database, appRole: config.db.user, logger, signal }, fullServer, releaseDrift),
      },
      config.audit.anchorSeconds * 1000,
      QUICK_MS,
    ),
    job('anchor_check', anchors, config.audit.anchorSeconds * 1000, HOUR_MS, undefined, scheduleAnchorCheck),
    // On a timer of its own (B1e-3): a long sweep must never hold up the anchor
    // check. The two share the pool, and both start at once: each statement is
    // bounded, and a pool at its limit queues rather than refuses. Nothing orders
    // the sweep after a schema check: 0009's `retention` policy is its wall.
    job(
      'idempotency_sweep',
      createRetentionSweep({
        list,
        sweep: (orgId, most) => sweepExpiredKeys(database, orgId, most),
        logger,
        deadlineMs: ANCHOR_CHECK_DEADLINE_MS,
        ...SWEEP,
      }),
      SWEEP_EVERY_MS,
      LONG_MS,
      undefined,
      scheduleRetentionSweep,
    ),
    // The sign-in flows' and the ended sessions' own sweeps, whether or not sign-in is on: rows left from when it was
    // on still go (B2-3a-2, B2-4a).
    sweepRows('identity.flow', (most) => flows.sweep(database, most)),
    sweepRows('identity.session', (most) => sessions.sweep(database, most)),
    // Step-up challenges past their five minutes (B3-1).
    sweepRows('identity.step_up_challenge', (most) => challenges.sweep(database, most)),
    // The security events past the retention the config names (B2-5a).
    sweepRows('security.event', (most) => securityEvents.sweep(database, most)),
    // The partner's messages and the refused ones kept as evidence, past the same retention (E1b).
    sweepRows('provider_events.message', (most) => providerEvents.sweep(database, most)),
    // Notices sent or given up, past their retention (B5-1b).
    sweepRows('notifications.notice', (most) => outbox.sweep(database, most)),
    // The notices, once the config names email (B5-3).
    job(
      'notices',
      noticeSenderFrom({
        config,
        db: database,
        outbox,
        // The organisation's verified members, as the members route lists them.
        listMembers: membersFor.bind(undefined, database, logged),
        // Its registered contacts, and each one's address, from their verified rows (B6-1b).
        listContacts: activeContactsFor.bind(undefined, database, logged),
        listCountingContacts: countingContactsFor.bind(undefined, database, { ...logged, clock: systemClock }),
        contactAddress: contactAddressFor.bind(undefined, database, logged),
        // A contact's link to confirm a reset, on the console's origin (B6-3b).
        resetLink: resetLinkFor.bind(undefined, database, logged, {
          publicOrigin: config.http.publicOrigin,
          clock: systemClock,
        }),
        // A spend request waiting for approval, from its verified records, Agent X's address its link (Phase 3 B2).
        waitingRequests: createWaitingRequests({ database, ...logged, publicOrigin: config.http.publicOrigin }),
        // A paid supplier's email, from the payment's verified records (Phase 4 C2b).
        remittances: createRemittances({ database, ...logged }),
        fetch: outboundFetch,
        logger,
      }),
      NOTICES_EVERY_MS,
      HALF_HOUR_MS,
      (running) => {
        logger.info('api.notices', { sending: running });
      },
    ),
    // The login service's admin events, copied into the audit trail and told (B6-2b).
    job(
      'idp_events',
      idpEventCopierFrom({ config, database, ...logged, clock: systemClock, outbox, fetch: outboundFetch }),
      IDP_EVENTS_EVERY_MS,
      HALF_HOUR_MS,
      (running) => {
        logger.info('api.idp_events', { copying: running });
      },
    ),
    // The kept names of people who signed in before they were kept (decision 25), once the login service can be asked.
    job(
      'contact_fill',
      contactFillFrom({ config, fetch: outboundFetch, database, keys, clock: systemClock, logger }),
      CONTACT_FILL_EVERY_MS,
      HOUR_MS,
      (running) => {
        logger.info('api.contact_fill', { filling: running });
      },
    ),
    // Resets of lost second factors carried out once cooled off (B6-3c).
    job(
      'factor_resets',
      resetRemovalsFrom({ config, database, ...logged, clock: systemClock, outbox, fetch: outboundFetch }),
      FACTOR_REMOVALS_EVERY_MS,
      HOUR_MS,
      (running) => {
        logger.info('api.factor_resets', { removing: running });
      },
    ),
    // Mandates past their end expired (Phase 2 B4).
    job('mandate_expiry', createMandateExpiry({ ...clocked, outbox }), MANDATE_EXPIRY_EVERY_MS, HOUR_MS),
    // A held organisation's whole history checked in batches before its clearing is confirmed (Phase 2 D1c).
    job(
      'hold_history',
      createHoldHistoryCheck({ ...organisationJob, tables: AUTHORITY_TABLES }),
      HOLD_HISTORY_EVERY_MS,
      HOUR_MS,
    ),
    job('zone_sealing', zoneSealing, ZONE_SEALING_EVERY_MS, HOUR_MS),
    // Every request's reservation and order claim checked against its signed state (Phase 2 E1).
    job('holdings_check', createHoldingsCheck(organisationJob), HOLDINGS_CHECK_EVERY_MS, LONG_MS),
    // Spend requests waiting for approval past their wait expired, their holdings released (Phase 2 D7).
    job('request_expiry', createRequestExpiry(clocked), REQUEST_EXPIRY_EVERY_MS, HOUR_MS),
    // Pending spend requests whose authority no longer stands voided, their holdings released (Phase 3 C1).
    job('request_voids', createRequestVoids(clocked), REQUEST_VOIDS_EVERY_MS, HOUR_MS),
    // The hand-off, where there is one.
    job('handoff', handoff, HANDOFF_EVERY_MS, HALF_HOUR_MS, (running) => {
      logger.info('api.handoff', { running });
    }),
    job('payment_checks', paymentChecks, PAYMENT_CHECKS_EVERY_MS, HALF_HOUR_MS, (running) => {
      logger.info('api.payment_checks', { running });
    }),
    // The rest of the waiting requests an admin chose to reject with a policy change (decision 33b).
    job('waiting_rejections', createWaitingRejections(clocked), WAITING_REJECTIONS_EVERY_MS, HOUR_MS),
    // A carry past 20's rest weighed and carried onto the version in force (Phase 4 A3, PL-47).
    job('carry_rest', createCarryRest(clocked), CARRY_REST_EVERY_MS, HOUR_MS),
    // Each closed day of every organisation's activity log sealed on its audit chain (Phase 3 L6).
    job('activity_seal', createActivitySeal(clocked), ACTIVITY_SEAL_EVERY_MS, LONG_MS),
    // The activity log's background downloads built, a month a file (Phase 3 L5c).
    job('background_downloads', downloads.builder, ACTIVITY_EXPORTS_EVERY_MS, HOUR_MS, (running) => {
      logger.info('api.background_downloads', { building: running });
    }),
    // Each sealed day digested again and held to its seal, a few a run (Phase 3 L6c).
    job('activity_seal_check', createActivitySealCheck(organisationJob), ACTIVITY_SEAL_CHECK_EVERY_MS, LONG_MS),
  ];
  return { jobs, handoff, paymentChecks, zoneSealing };
}
