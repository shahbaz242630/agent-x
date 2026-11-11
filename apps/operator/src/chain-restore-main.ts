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
//
// The same job plans and repairs an organisation's authority rows from the
// drill's copy too (PL-29 follow-up, state-restore-main.ts): a request file
// whose first word is `state-recovery-plan` or `state-restore` goes there.
import { ConfigError, loadOperatorConfig, type OperatorConfig } from '@agentx/platform/config';
import { type KeyProvider, loadKeys } from '@agentx/platform/keys';
import { createLogger, createStartupLogger, guardOutputs, type Logger } from '@agentx/platform/observability';

import { outcomeLine, type RestoreFacts, restoreChain, restoreFile } from './chain-restore.ts';
import type { EvidenceStore } from './evidence-store.ts';
import {
  flagAlone,
  type OperatorOptions,
  type OperatorProcess,
  type Problems,
  problem,
  REQUEST_FLAG,
  requestWords,
} from './main.ts';
import { CHAIN_RESTORE, CHAIN_RESTORE_USAGE, PLAN_DIGEST_HEX, UUID_V7 } from './request.ts';
import { onRestoreSides, OWNER_LOGIN_NOTE, storedPlanProblems } from './restore-job.ts';
import { isStateCommand, stateRun } from './state-restore-main.ts';

const SERVICE = 'chain-restore';

/**
 * The one key the repair holds, to check the chain with; the operator's own signature and its rebases (E11) it checks
 * with their public halves alone, so the anchors it checks against are the planner's.
 */
const RESTORE_HELD_KEYS = ['audit-mac'] as const;
const RESTORE_CHECKED_KEYS = ['operator-signing', 'audit-rebase'] as const;

/** What the repair was asked, once read and checked. */
interface Asked {
  readonly orgId: string;
  readonly planId: string;
  readonly digest: string;
  readonly restoreId: string;
  readonly discardFork: boolean;
}

/** The chain repair's request, from its file's words, or the problems: none repeats what the file holds. */
function restoreAsked(words: readonly string[]): Asked | Problems {
  const [command, orgFlag, orgId, planFlag, planId, digestFlag, digest, idFlag, id, ...more] = words;
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

/** The command a request file asks the job for, by its first word: the chain's repair, or the authority rows' plan or repair. */
async function jobRun(config: OperatorConfig, keys: KeyProvider, argv: readonly string[], logger: Logger) {
  if (argv[0] !== REQUEST_FLAG) {
    logger.error('operator.refused', {
      problems: [`${CHAIN_RESTORE} runs only from a request file: ${CHAIN_RESTORE_USAGE}`],
    });
    return 1;
  }
  const read = requestWords(argv);
  if ('problems' in read) {
    logger.error('operator.refused', { problems: read.problems });
    return 1;
  }
  if (isStateCommand(read.words[0])) return stateRun(config, keys, read.words, logger);
  return restoreRun(config, keys, read.words, logger);
}

/** The chain's plan: the file chain-recovery-plan keeps it in, and its summary's `k`. */
const CHAIN_PLAN = { file: 'chain-recovery', line: 'plan' } as const;

/** Repairs as asked: the exit code. */
async function restoreRun(config: OperatorConfig, keys: KeyProvider, words: readonly string[], logger: Logger) {
  const asked = restoreAsked(words);
  if ('problems' in asked) {
    logger.error('operator.refused', { problems: asked.problems });
    return 1;
  }
  const { orgId, planId, digest, restoreId, discardFork } = asked;
  const log = logger.child({ orgId });
  log.info('operator.starting', { command: CHAIN_RESTORE, role: config.db.user, keys: keys.describe() });
  log.info('operator.chain_restore_owner_login', { restoreId, note: OWNER_LOGIN_NOTE });
  const facts = { restoreId, planId, orgId, digest, discardFork, release: config.release, run: config.run };
  return onRestoreSides(
    config,
    keys,
    log,
    {
      command: CHAIN_RESTORE,
      liveReadOnly: false,
      before: () => storedPlanProblems(config, asked, CHAIN_PLAN),
      said: { restoreId },
    },
    ({ copy, live, store, anchors }) =>
      repaired(store, facts, log, () =>
        restoreChain({
          copy,
          live,
          keys,
          orgId,
          anchor: anchors.latest({ kind: 'organisation', orgId }),
          digest,
          discardFork,
        }),
      ),
  );
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
  const code = await jobRun(config, keys, options.argv, logger);
  logger.flush();
  host.exitCode = code;
  return code;
}

// Only when Node runs this file itself: a real process, which in-process coverage can't see.
/* v8 ignore next -- @preserve */
if (import.meta.main) await runChainRestore(process, { argv: process.argv.slice(2) });
