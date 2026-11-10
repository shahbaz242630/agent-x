// What the chain repair's job (`chain-restore`) shares across its commands:
// the chain's repair (chain-restore-main.ts) and the authority rows' plan and
// repair (state-restore-main.ts, PL-29 follow-up). Each logs in as the owner,
// reads the drill's copy read-only, checks its settings and both connections
// before anything is read, and applies only a plan kept as evidence.
import { type AuditTables, REPAIR_ROLE, repairRoleProblems } from '@agentx/core/modules/audit';
import { schemaSoundAtStart } from '@agentx/core/schema-check';
import type { OperatorConfig } from '@agentx/platform/config';
import type { AnchorLog } from '@agentx/platform/audit-chain';
import { APP_ROLE, createDatabase, type Database, transactionsReadOnly } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { createOutboundFetch } from '@agentx/platform/outbound';
import { azureBlobOrigins, azureWriteOnceStore, BlobStoreFailed, folderWriteOnceStore } from '@agentx/platform/storage';

import type { EvidenceStore } from './evidence-store.ts';
import { anchorLogOf, evidenceStoreOf } from './main.ts';
import { NO_ANCHORS_PROBLEM, NO_STORE_PROBLEM } from './request.ts';

/** How the repair's connections are named in Postgres's own views. */
const APPLICATION_NAME = 'agentx-chain-restore';

/** What the owner's login sets off (playbook I), said in every run's first lines. */
export const OWNER_LOGIN_NOTE =
  'this run logs in as agentx_owner, so the "login by the owner role outside a deploy" SEV-1 alert fires for it by design: note this run in the incident log';

/** The settings' problems for a run of the job, before anything connects. */
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
 * Whether the store said the file isn't there: Azure's 404, or the folder's
 * own refusal (development and test). BlobStoreFailed carries its answer in
 * these fixed words alone (packages/platform/src/storage/write-once.ts).
 */
const missingFile = (error: unknown): boolean =>
  error instanceof BlobStoreFailed &&
  (error.message.includes('the blob service answered 404 ') || error.message.endsWith('no file of that name'));

/** A plan's kind: the file its command keeps it in, by name, and its summary line's `k`. */
export interface PlanKind {
  readonly file: 'chain-recovery' | 'state-recovery';
  readonly line: 'plan' | 'state_plan';
}

/** The plan a repair is asked for: this organisation's, by its ID and digest. */
export interface PlanAsked {
  readonly orgId: string;
  readonly planId: string;
  readonly digest: string;
}

/**
 * Why the plan asked for can't be applied, from its own file in the evidence
 * store (its plan command's): none there, not this organisation's plan of
 * that ID, a plan that was refused, or another digest than the one asked. Its
 * first line is its summary; the rows after it are what the repair makes again.
 */
export async function storedPlanProblems(
  { evidence }: OperatorConfig,
  asked: PlanAsked,
  kind: PlanKind,
): Promise<string[]> {
  const { container, directory } = evidence;
  let reader;
  if (container !== null) {
    reader = azureWriteOnceStore({ settings: container, fetch: createOutboundFetch(azureBlobOrigins(container)) });
  } else if (directory === null) {
    return [];
  } else {
    reader = folderWriteOnceStore(directory);
  }
  const name = `${asked.orgId}/${kind.file}-${asked.planId}.ndjson`;
  let summary: Readonly<Record<string, unknown>>;
  try {
    const text = (await reader.get(name)).toString('utf8');
    const parsed: unknown = JSON.parse(text.slice(0, text.indexOf('\n')));
    summary = typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : {};
  } catch (error) {
    // No such file, or a first line that isn't JSON. Anything else (the network, a timeout) is the caller's failure.
    if (!(missingFile(error) || error instanceof SyntaxError)) throw error;
    return [
      `the plan ${asked.planId} has no readable file in the evidence store (${name}): make the plan first, or check its ID`,
    ];
  }
  if (summary.k !== kind.line || summary.planId !== asked.planId || summary.orgId !== asked.orgId) {
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

/** Why either connection can't be used: the copy read-only (the live server too, for `liveReadOnly`), both the owner. */
async function connectionProblems(
  copy: Database<AuditTables>,
  live: Database<AuditTables>,
  liveReadOnly: boolean,
): Promise<string[]> {
  const [copyRole, liveRole] = await Promise.all([repairRoleProblems(copy), repairRoleProblems(live)]);
  return [
    ...((await transactionsReadOnly(copy)) ? [] : ["the drill's copy is not read-only, so nothing was read"]),
    ...(!liveReadOnly || (await transactionsReadOnly(live))
      ? []
      : ['the live server is not read-only for a plan, so nothing was read']),
    ...copyRole.map((text) => `the drill's copy: ${text}`),
    ...liveRole.map((text) => `the live server: ${text}`),
  ];
}

/** What a run of the job works with, once its settings and connections are checked. */
export interface RestoreSidesOpen {
  readonly copy: Database<AuditTables>;
  readonly live: Database<AuditTables>;
  readonly store: EvidenceStore;
  readonly anchors: AnchorLog;
}

/**
 * Runs `work` on the drill's copy, read-only, and the live server, read-only
 * for a plan (`liveReadOnly`), each as the owner: the settings checked, then
 * `before` (what a repair checks before either connection is used), then both
 * connections, the anchors' store read whole and the live schema. The exit
 * code: `work`'s, or 1 when anything is refused or fails.
 */
export async function onRestoreSides(
  config: OperatorConfig,
  keys: KeyProvider,
  log: Logger,
  run: {
    readonly command: string;
    readonly liveReadOnly: boolean;
    readonly before?: () => Promise<readonly string[]>;
    readonly said?: Readonly<Record<string, unknown>>;
  },
  work: (open: RestoreSidesOpen) => Promise<number>,
): Promise<number> {
  const store = evidenceStoreOf(config);
  // A chain's rebase line is checked with `audit-rebase`'s public half (E11), as the planner checks it with the key.
  const anchors = anchorLogOf(config, keys, log);
  const refused = settingsProblems(config, store, anchors);
  if (store === undefined || anchors === undefined || config.db.drillHost === null || refused.length > 0) {
    log.error('operator.refused', { problems: refused });
    return 1;
  }
  const copy = ownerOn(config, log, { host: config.db.drillHost, readOnly: true });
  const live = ownerOn(config, log, { host: config.db.host, readOnly: run.liveReadOnly });
  try {
    // Before either connection is used: a repair applies only the plan kept as evidence.
    const planProblems = (await run.before?.()) ?? [];
    if (planProblems.length > 0) {
      log.error('operator.refused', { ...run.said, problems: planProblems });
      return 1;
    }
    const problems = await connectionProblems(copy, live, run.liveReadOnly);
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
    if (!(await schemaSoundAtStart({ database: live, appRole: APP_ROLE, logger: log }))) return 1;
    return await work({ copy, live, store, anchors });
  } catch (error) {
    log.error('operator.failed', { command: run.command, ...run.said, err: error });
    return 1;
  } finally {
    await copy.destroy();
    await live.destroy();
  }
}
