// The chain repair's command (4D2e E10, PL-29; playbook H): its own job
// (`chain-restore`), the one process that holds the owner's login outside a
// migration, run by a person from a request file alone:
//
//   node apps/operator/src/chain-restore-main.ts --request <file>
//
// the file holding, as a JSON list, `chain-restore --org <organisation ID>
// --plan <plan ID> --digest <the plan's digest> --id <new repair ID>`, and
// `--discard-fork` last where the plan was made with it. The digest is the
// one the plan's command logged and wrote in the plan's file (planDigest).
//
// It holds the audit chains' MAC key, to check with, and the operator's
// signing key's public half; never the operator's own key, and it makes no
// MAC: it writes only the copy's original rows (chain-restore.ts). It logs in
// as agentx_owner on the live server, so the "login by the owner role outside
// a deploy" SEV-1 alert (playbook I) fires for each run, by design: the run
// says so in its first lines, to be matched in the incident log.
//
// It:
// 1. guards stdout and stderr, reads its settings and its keys, or refuses
// 2. reads the request, from the file alone, before it connects
// 3. reads the plan's own file in the evidence store, and refuses unless it is
//    this organisation's plan, made, with the digest asked: the repair is tied
//    to the plan the operator read, kept as evidence, not to a copied number
// 4. connects to the drill's copy read-only, and to the live server, each as
//    the owner, and refuses any other role, or one that can bypass the walls
// 5. reads the anchors' store whole and checks the live schema
// 6. writes the repair's start to the evidence store, once: a request run
//    again is refused there, before anything is read or written
// 7. repairs (chain-restore.ts) and writes the outcome beside its start
// It exits 0 once the chain is repaired; 1 when anything is refused or fails.
// The integrity hold stays: the organisation's admin clears it with a step-up.
import { type AuditTables, REPAIR_ROLE, repairRoleProblems } from '@agentx/core/modules/audit';
import { schemaSoundAtStart } from '@agentx/core/schema-check';
import { ConfigError, loadOperatorConfig, type OperatorConfig } from '@agentx/platform/config';
import { APP_ROLE, createDatabase, type Database, transactionsReadOnly } from '@agentx/platform/db';
import { type KeyProvider, loadKeys } from '@agentx/platform/keys';
import { createLogger, createStartupLogger, guardOutputs, type Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureWriteOnceStore, BlobStoreFailed, folderWriteOnceStore } from '@agentx/platform/storage';

import { outcomeLine, type RestoreFacts, restoreChain, restoreFile } from './chain-restore.ts';
import type { EvidenceStore } from './evidence-store.ts';
import {
  anchorLogOf,
  evidenceStoreOf,
  flagAlone,
  type OperatorOptions,
  type OperatorProcess,
  type Problems,
  problem,
  REQUEST_FLAG,
  requestWords,
} from './main.ts';
import {
  CHAIN_RESTORE,
  CHAIN_RESTORE_USAGE,
  NO_ANCHORS_PROBLEM,
  NO_STORE_PROBLEM,
  PLAN_DIGEST_HEX,
  UUID_V7,
} from './request.ts';

const SERVICE = 'chain-restore';

/** How the repair's connections are named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-chain-restore';

/** The one key the repair holds, to check the chain with; the operator's own it checks with its public half alone. */
const RESTORE_HELD_KEYS = ['audit-mac'] as const;
const RESTORE_CHECKED_KEYS = ['operator-signing'] as const;

/** What the owner's login sets off (playbook I), said in every run's first lines. */
export const OWNER_LOGIN_NOTE =
  'this run logs in as agentx_owner, so the "login by the owner role outside a deploy" SEV-1 alert fires for it by design: note this run in the incident log';

/** What the repair was asked, once read and checked. */
interface Asked {
  readonly orgId: string;
  readonly planId: string;
  readonly digest: string;
  readonly restoreId: string;
  readonly discardFork: boolean;
}

/** The repair's request, from its file alone, or the problems: none repeats what the file holds. */
function restoreAsked(argv: readonly string[]): Asked | Problems {
  if (argv[0] !== REQUEST_FLAG)
    return problem(`${CHAIN_RESTORE} runs only from a request file: ${CHAIN_RESTORE_USAGE}`);
  const read = requestWords(argv);
  if ('problems' in read) return read;
  const [command, orgFlag, orgId, planFlag, planId, digestFlag, digest, idFlag, id, ...more] = read.words;
  const flag = flagAlone(more);
  const shaped =
    command === CHAIN_RESTORE &&
    orgFlag === '--org' &&
    planFlag === '--plan' &&
    digestFlag === '--digest' &&
    idFlag === '--id' &&
    id !== undefined &&
    flag !== undefined;
  if (!shaped) return problem(`the request file holds ${CHAIN_RESTORE_USAGE} as a JSON list, and nothing else`);
  const problems = [
    ...(UUID_V7.test(String(orgId)) ? [] : ["the organisation's ID must be a UUIDv7, in lower case"]),
    ...(UUID_V7.test(String(planId)) ? [] : ["the plan's ID must be a UUIDv7, in lower case"]),
    ...(PLAN_DIGEST_HEX.test(String(digest)) ? [] : ["the plan's digest must be 64 lower-case hex digits"]),
    ...(UUID_V7.test(id) ? [] : ["the repair's ID must be a UUIDv7, in lower case"]),
  ];
  if (problems.length > 0) return { problems };
  return { orgId: String(orgId), planId: String(planId), digest: String(digest), restoreId: id, ...flag };
}

/** The settings' problems for a repair, before anything connects. */
function settingsProblems(config: OperatorConfig, store: unknown, anchors: unknown): string[] {
  const { user, drillHost, host } = config.db;
  return [
    ...(user === REPAIR_ROLE ? [] : [`AGENTX_DB_USER must be ${REPAIR_ROLE}: only the owner may repair a chain`]),
    ...(store === undefined ? [NO_STORE_PROBLEM] : []),
    ...(anchors === undefined ? [NO_ANCHORS_PROBLEM] : []),
    // Both are lower case (the config refuses a host that isn't), so one comparison tells them apart.
    ...(drillHost === null || drillHost === host
      ? ["AGENTX_DB_DRILL_HOST must name the drill's copy, a server other than AGENTX_DB_HOST"]
      : []),
  ];
}

/**
 * Why the plan asked for can't be applied, from its own file in the evidence
 * store (chain-recovery-plan's): none there, not this organisation's plan of
 * that ID, a plan that was refused, or another digest than the one asked. Its
 * first line is its summary; the rows after it are what the repair makes again.
 */
async function storedPlanProblems({ evidence }: OperatorConfig, asked: Asked): Promise<string[]> {
  const { container, directory } = evidence;
  let reader;
  if (container !== null) {
    reader = azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  } else if (directory === null) {
    return [];
  } else {
    reader = folderWriteOnceStore(directory);
  }
  const name = `${asked.orgId}/chain-recovery-${asked.planId}.ndjson`;
  let summary: Readonly<Record<string, unknown>>;
  try {
    const text = (await reader.get(name)).toString('utf8');
    const parsed: unknown = JSON.parse(text.slice(0, text.indexOf('\n')));
    summary = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch (error) {
    // None there, a folder's own refusal (development and test), or a first line that isn't JSON; anything else is a bug.
    const unreadable =
      error instanceof BlobStoreFailed || error instanceof SyntaxError || (error instanceof Error && 'code' in error);
    if (!unreadable) throw error;
    return [
      `the plan ${asked.planId} has no readable file in the evidence store (${name}): make the plan first, or check its ID`,
    ];
  }
  if (summary.k !== 'plan' || summary.planId !== asked.planId || summary.orgId !== asked.orgId) {
    return [`the file ${name} is not this organisation's plan ${asked.planId}`];
  }
  if (summary.ok !== true) {
    return [`the plan ${asked.planId} was refused (${String(summary.reason)}): there is nothing to apply`];
  }
  return summary.digest === asked.digest
    ? []
    : [`the digest asked is not the plan ${asked.planId}'s: copy it again from the plan's line`];
}

/** Opens one connection to a server as the owner. */
const ownerOn = (config: OperatorConfig, logger: Logger, to: { host: string; readOnly: boolean }) =>
  createDatabase<AuditTables>({ ...config.db, ...to, maxConnections: 1, applicationName: APPLICATION_NAME }, logger);

/** Why either connection can't be used: the copy read-only, both the owner and unable to bypass the walls. */
async function connectionProblems(copy: Database<AuditTables>, live: Database<AuditTables>): Promise<string[]> {
  const [copyRole, liveRole] = await Promise.all([repairRoleProblems(copy), repairRoleProblems(live)]);
  return [
    ...((await transactionsReadOnly(copy)) ? [] : ["the drill's copy is not read-only, so nothing was read"]),
    ...copyRole.map((text) => `the drill's copy: ${text}`),
    ...liveRole.map((text) => `the live server: ${text}`),
  ];
}

/** Repairs as asked: the exit code. */
async function restoreRun(config: OperatorConfig, keys: KeyProvider, argv: readonly string[], logger: Logger) {
  const asked = restoreAsked(argv);
  if ('problems' in asked) {
    logger.error('operator.refused', { problems: asked.problems });
    return 1;
  }
  const { orgId, planId, digest, restoreId, discardFork } = asked;
  const log = logger.child({ orgId });
  log.info('operator.starting', { command: CHAIN_RESTORE, role: config.db.user, keys: keys.describe() });
  log.info('operator.chain_restore_owner_login', { restoreId, note: OWNER_LOGIN_NOTE });
  const store = evidenceStoreOf(config);
  const anchors = anchorLogOf(config, logger);
  const refused = settingsProblems(config, store, anchors);
  if (store === undefined || anchors === undefined || config.db.drillHost === null || refused.length > 0) {
    log.error('operator.refused', { problems: refused });
    return 1;
  }
  const planProblems = await storedPlanProblems(config, asked);
  if (planProblems.length > 0) {
    log.error('operator.refused', { restoreId, problems: planProblems });
    return 1;
  }
  const copy = ownerOn(config, logger, { host: config.db.drillHost, readOnly: true });
  const live = ownerOn(config, logger, { host: config.db.host, readOnly: false });
  const facts = { restoreId, planId, orgId, digest, discardFork, release: config.release, run: config.run };
  try {
    const problems = await connectionProblems(copy, live);
    if (problems.length > 0) {
      log.error('operator.refused', { problems });
      return 1;
    }
    await anchors.read();
    if (anchors.state() !== 'read') {
      log.error('operator.refused', {
        problems: ["the chains' anchors' store couldn't be read whole, so no repair can be checked against it"],
      });
      return 1;
    }
    if (!(await schemaSoundAtStart({ database: live, appRole: APP_ROLE, logger }))) return 1;
    return await repaired(store, facts, log, () =>
      restoreChain({
        copy,
        live,
        keys,
        orgId,
        anchor: anchors.latest({ kind: 'organisation', orgId }),
        digest,
        discardFork,
      }),
    );
  } catch (error) {
    log.error('operator.failed', { command: CHAIN_RESTORE, restoreId, err: error });
    return 1;
  } finally {
    await copy.destroy();
    await live.destroy();
  }
}

/**
 * The repair between its two records in the evidence store: its start, once
 * (a request run again stops there), then its outcome. The exit code.
 */
async function repaired(
  store: EvidenceStore,
  facts: RestoreFacts,
  log: Logger,
  repair: () => ReturnType<typeof restoreChain>,
): Promise<number> {
  const name = `${facts.orgId}/chain-restore-${facts.restoreId}`;
  const start = Buffer.from(`${JSON.stringify({ k: 'restore_start', ...facts })}\n`);
  if ((await store.put(`${name}-start.ndjson`, start)) === 'there_already') {
    log.error('operator.done_before', { command: CHAIN_RESTORE, restoreId: facts.restoreId });
    return 1;
  }
  const outcome = await repair();
  const line = { restoreId: facts.restoreId, planId: facts.planId, ...outcomeLine(outcome) };
  // The outcome is in this line whether or not its record is written: a failed write is an error of its own.
  if (outcome.ok) log.info('operator.chain_restored', { ...line, holdKept: true });
  else log.error('operator.chain_restore_refused', line);
  if ((await store.put(`${name}-outcome.ndjson`, restoreFile(outcome, facts))) === 'there_already') {
    log.error('operator.done_before', { command: CHAIN_RESTORE, restoreId: facts.restoreId });
    return 1;
  }
  return outcome.ok ? 0 : 1;
}

/** Runs the repair, sets the process's exit code and returns it: 0 once the chain is repaired. */
export async function runChainRestore(host: OperatorProcess, options: OperatorOptions): Promise<number> {
  guardOutputs(host);
  const { destination } = options;
  let config: OperatorConfig;
  let keys: KeyProvider;
  try {
    config = loadOperatorConfig(options.env);
    keys = loadKeys(config.keys, RESTORE_HELD_KEYS, RESTORE_CHECKED_KEYS);
  } catch (error) {
    // A ConfigError's problems name each variable, key file and rule, never a value.
    const startup = createStartupLogger({ service: SERVICE, destination });
    startup.error(
      'operator.start_refused',
      error instanceof ConfigError ? { problems: error.problems } : { err: error },
    );
    startup.flush();
    host.exitCode = 1;
    return 1;
  }
  const logger = createLogger({ service: SERVICE, config, destination });
  const code = await restoreRun(config, keys, options.argv, logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process coverage can't see.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runChainRestore(process, { argv: process.argv.slice(2) });
