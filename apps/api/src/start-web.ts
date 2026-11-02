// The API's `web` side (one of the roles, 4D2e D): the server and every route's use case, built and listening.
// It runs at `all` beside the jobs and at `web` without them. Nothing here starts a timer.
import { AUTHORITY_TABLES } from '@agentx/core/authority-tables';
import { createAgentKeyCheck } from '@agentx/core/modules/agents';
import {
  createOidcClient,
  createSignIn,
  createAcceptanceConfirmations,
  createInvitationAcceptance,
  createInvitationWrites,
  createHoldClearings,
  createHoldInvestigations,
  createMembershipChanges,
  createContactChanges,
  createContactConfirmations,
  createResetChanges,
  createRemovalRestriction,
  registeredContactsFor,
  type LoginFlows,
  membersFor,
  membershipFor,
  type Sessions,
  type StepUpChallenges,
  type SignIn,
} from '@agentx/core/modules/identity';
import { createActivityLog } from '@agentx/core/modules/activity';
import { paymentHoldsOf } from '@agentx/core/modules/outcomes';
import { holdingsRecordChecks } from '@agentx/core/modules/spend-requests';
import { systemClock, uuidV7Ids } from '@agentx/core/shared-kernel';
import { type Config, partnerName } from '@agentx/platform/config';
import { type Database, type DatabaseTransaction } from '@agentx/platform/db';
import { type KeyProvider } from '@agentx/platform/keys';
import { createOutboundFetch } from '@agentx/platform/outbound';
import type { FastifyInstance } from 'fastify';

import { createAgentChanges } from './agent-changes.ts';
import { createAgentKeyChanges } from './agent-key-changes.ts';
import { createAgentRegistrations } from './agent-registering.ts';
import { createActivityPages } from './activity-log.ts';
import { createActivityLogExports } from './activity-log-exports.ts';
import { createAuditLog } from './audit-log.ts';
import { createAuditLogExports } from './audit-log-exports.ts';
import { createFundingSourceChanges } from './funding-source-changes.ts';
import { createFundingSourceLinks } from './funding-source-links.ts';
import { createFundingSourceReads } from './funding-source-reads.ts';
import { createAgentMandates } from './agent-mandate.ts';
import { createPolicySimulations } from './policy-simulations.ts';
import { createSpendRequestCancels } from './spend-request-cancels.ts';
import { createSpendRequestReads } from './spend-request-reads.ts';
import { createSpendRequestRejects } from './spend-request-rejects.ts';
import { createSpendRequestApprovals } from './spend-request-approvals.ts';
import { createDecisionEntry } from './decision-entry.ts';
import { createDecisionGate, gateLimitsOf } from './decision-gate.ts';
import { createSpendRequestDecisions } from './spend-request-decisions.ts';
import { createMandateAcceptance } from './mandate-acceptance.ts';
import { createMandateMoves } from './mandate-moves.ts';
import { createPolicyChanges } from './policy-changes.ts';
import { createMandateRegistry } from './mandate-registry.ts';
import { createPaymentMarks } from './payment-marks.ts';
import { createPartnerEventIntake } from './partner-events.ts';
import { activitySinkOf } from './activity-recorder.ts';
import { loadPlaces } from './client-clues.ts';
import { loadConsoleFiles } from './console-files.ts';
import { loginSessionsFrom } from './login-sessions.ts';
import { createMyOrganizations } from './my-organizations.ts';
import { createLogSample } from './log-sample.ts';
import { buildServer } from './server.ts';
import { createOrganizationChanges } from './organization-changes.ts';
import { createSupplierChanges } from './supplier-changes.ts';
import { createSupplierDetailsChanges } from './supplier-details.ts';
import { createSupplierRemittance } from './supplier-remittance.ts';
import { createSupplierPayeeChanges } from './supplier-payee-changes.ts';
import { createSupplierVerifications } from './supplier-verifications.ts';
import { createSupplierPayees } from './supplier-payees.ts';
import { createSupplierRegistry } from './supplier-registry.ts';
import type { ApiTables, Booted, SharedParts } from './boot.ts';
import type { HealthCheck } from './health.ts';

/**
 * The console's sign-in (ADR-003 §5), when the config names a login service;
 * off otherwise (B2-6 switches it on for staging).
 */
function signInFrom(
  config: Config,
  database: Database<ApiTables>,
  flows: LoginFlows,
  sessions: Sessions,
  challenges: StepUpChallenges,
  keys: KeyProvider,
): SignIn | undefined {
  if (config.signIn === undefined) return undefined;
  const { issuer, clientId, clientSecret, internalOrigin } = config.signIn;
  return createSignIn({
    db: database,
    oidc: createOidcClient({
      settings: {
        issuer,
        clientId,
        clientSecret,
        redirectUri: `${config.http.publicOrigin}/v1/auth/callback`,
        internalOrigin,
      },
      fetch: createOutboundFetch(config.outbound.allowedOrigins),
      clock: systemClock,
    }),
    flows,
    sessions,
    challenges,
    ids: uuidV7Ids,
    clock: systemClock,
    keys,
  });
}

/**
 * Builds the server and listens. Returns nothing, the failure logged and everything closed, when it can't listen.
 * `beforeListen` runs between the two: what must be true before a request is answered.
 */
export async function startWeb(
  { host, config, keys, logger, database }: Booted,
  { flows, sessions, challenges, outbox, directory, downloads, recorder, rail, providerEvents }: SharedParts,
  healthChecks: readonly HealthCheck[],
  beforeListen: () => Promise<void>,
  /** What must end while the pool is open when it can't listen. */
  whenRefused: () => Promise<void>,
): Promise<FastifyInstance | undefined> {
  const signIn = signInFrom(config, database, flows, sessions, challenges, keys);
  // An agent's key, checked before its request goes on (C2-1).
  const keyCheck = createAgentKeyCheck({ database, keys, ids: uuidV7Ids, clock: systemClock, logger });
  // One a process, so a request's line and its decision's timers are in or out together.
  const logSample = createLogSample(config.logSuccessSampleOneIn);
  // A failure to build the server is a bug, so it goes to the crash handler (boot.ts).
  const server = await buildServer({
    config,
    logger,
    logSample,
    ids: uuidV7Ids,
    healthChecks,
    signIn:
      signIn === undefined
        ? undefined
        : {
            service: signIn,
            sessionSeconds: config.sessions.absoluteSeconds,
            loginSessions: loginSessionsFrom(config),
          },
    securityEvents: recorder,
    activity: activitySinkOf(createActivityLog({ ids: uuidV7Ids }), database),
    placeOf: await loadPlaces(config.environment, logger),
    consoleFiles: await loadConsoleFiles(config.environment, logger),
    findMembership: (orgId, userId, correlationId) =>
      membershipFor(
        database,
        { keys, ids: uuidV7Ids, logger: logger.child({ correlationId }), correlationId },
        orgId,
        userId,
      ),
    restrictedUntil: createRemovalRestriction({ database, clock: systemClock }),
    myOrganizations: createMyOrganizations({ database, keys, ids: uuidV7Ids, logger }),
    listMembers: (orgId, correlationId) =>
      membersFor(database, { keys, ids: uuidV7Ids, logger: logger.child({ correlationId }), correlationId }, orgId),
    acceptanceConfirmations: createAcceptanceConfirmations({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    invitationAcceptance: createInvitationAcceptance({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      outbox,
      logger,
    }),
    invitationWrites: createInvitationWrites({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      logger,
    }),
    membershipChanges: createMembershipChanges({ database, keys, ids: uuidV7Ids, challenges, outbox, logger }),
    listContacts: registeredContactsFor.bind(undefined, database, { keys, ids: uuidV7Ids, logger }),
    contactChanges: createContactChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    resetChanges: createResetChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    contactConfirmations: createContactConfirmations({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      outbox,
      logger,
    }),
    holdInvestigations: createHoldInvestigations({ database, keys, ids: uuidV7Ids, logger }),
    auditLog: createAuditLog({ database, keys, ids: uuidV7Ids, logger, directory }),
    auditLogExports: createAuditLogExports({ database, keys, ids: uuidV7Ids, clock: systemClock, logger, directory }),
    activityPages: createActivityPages({ database, keys, ids: uuidV7Ids, logger, directory }),
    backgroundExports: downloads.exports,
    downloadFiles: downloads.files,
    activityLogExports: createActivityLogExports({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      logger,
      directory,
    }),
    holdClearings: createHoldClearings({
      database,
      keys,
      ids: uuidV7Ids,
      challenges,
      logger,
      authorityTables: AUTHORITY_TABLES,
      // A held request's reservation and claim match its decision again before the hold clears (G1).
      namedRecordChecks: holdingsRecordChecks<DatabaseTransaction<ApiTables>>(keys, paymentHoldsOf),
    }),
    agentRegistrations: createAgentRegistrations({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      logger,
    }),
    agentChanges: createAgentChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    agentKeyChanges: createAgentKeyChanges({ database, keys, ids: uuidV7Ids, clock: systemClock, challenges, logger }),
    checkAgentKey: keyCheck.check.bind(keyCheck),
    fundingSourceLinks: createFundingSourceLinks({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      rail,
      partner: partnerName(config.partner),
      logger,
    }),
    fundingSourceReads: createFundingSourceReads({ database, keys, ids: uuidV7Ids, logger }),
    fundingSourceChanges: createFundingSourceChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      rail,
      challenges,
      logger,
    }),
    mandateRegistry: createMandateRegistry({ database, keys, ids: uuidV7Ids, clock: systemClock, logger }),
    mandateAcceptance: createMandateAcceptance({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    agentMandates: createAgentMandates({ database, keys, ids: uuidV7Ids, clock: systemClock, logger }),
    spendRequestDecisions: createSpendRequestDecisions({
      database,
      outbox,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      logger,
      logSample,
      entry: createDecisionEntry({
        gate: createDecisionGate(gateLimitsOf(config.db.poolMax, config.decisionGate)),
      }),
    }),
    spendRequestCancels: createSpendRequestCancels({ database, keys, ids: uuidV7Ids, clock: systemClock, logger }),
    spendRequestReads: createSpendRequestReads({ database, keys, ids: uuidV7Ids, logger }),
    spendRequestRejects: createSpendRequestRejects({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      logger,
    }),
    spendRequestApprovals: createSpendRequestApprovals({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      logger,
    }),
    paymentMarks: createPaymentMarks({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    policySimulations: createPolicySimulations({ database, keys, ids: uuidV7Ids, clock: systemClock, logger }),
    mandateMoves: createMandateMoves({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    policyChanges: createPolicyChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    supplierRegistry: createSupplierRegistry({ database, keys, ids: uuidV7Ids, clock: systemClock, logger }),
    supplierChanges: createSupplierChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    organizationChanges: createOrganizationChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    supplierDetailsChanges: createSupplierDetailsChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    supplierRemittance: createSupplierRemittance({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    supplierPayees: createSupplierPayees({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      rail,
      partner: partnerName(config.partner),
      logger,
    }),
    supplierPayeeChanges: createSupplierPayeeChanges({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    supplierVerifications: createSupplierVerifications({
      database,
      keys,
      ids: uuidV7Ids,
      clock: systemClock,
      challenges,
      outbox,
      logger,
    }),
    // D2-3c: the fake bank's steps, for the staging demo; only where the partner is the fake.
    fakeBank: rail?.bank,
    // The partner's messages, where its rail is built (E1b): checked by its signature, kept, then checked with the bank.
    partnerEvents:
      rail &&
      createPartnerEventIntake({
        database,
        rail,
        events: providerEvents,
        securityEvents: recorder,
        clock: systemClock,
      }),
  });
  await beforeListen();
  try {
    await server.listen({ host: config.http.host, port: config.http.port });
  } catch (error) {
    logger.error('api.listen_failed', { err: error });
    // Closed, so nothing it opened keeps the process running.
    await server.close();
    await whenRefused();
    await database.destroy();
    logger.flush();
    host.exitCode = 1;
    return undefined;
  }
  logger.info('api.listening', { ports: server.addresses().map((address) => address.port) });
  return server;
}
