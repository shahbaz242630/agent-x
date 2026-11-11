// The authority rows' plan and repair (PL-29 follow-up, Carry-Forward S175;
// playbook H), run on the chain repair's job (`chain-restore`) from a request
// file alone, as its chain repair is (chain-restore-main.ts hands these on):
//
//   ["state-recovery-plan", "--org", <organisation ID>, "--id", <new plan ID>]
//   ["state-restore", "--org", <organisation ID>, "--plan", <plan ID>,
//    "--digest", <the plan's digest>, "--id", <new repair ID>]
//
// Both log in as agentx_owner, the one role that reads every authority table
// whatever its grants and may write past their guards, so the "login by the
// owner role outside a deploy" SEV-1 alert (playbook I) fires for each run, by
// design. The plan reads the drill's copy and the live server read-only, and
// writes its file to the evidence store alone (state-recovery.ts). The repair
// applies only the plan kept there, made again with the same digest, in one
// transaction (state-restore.ts), between its start and outcome records, the
// start written once so a request run again does nothing. Each holds the
// audit chains' MAC key alone, to check with, as the chain's repair does.
// The integrity hold stays: the organisation's admin clears it with a step-up.
import type { OperatorConfig } from '@agentx/platform/config';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';

import { type Problems, problem } from './main.ts';
import {
  PLAN_DIGEST_HEX,
  STATE_RECOVERY,
  STATE_RECOVERY_USAGE,
  STATE_RESTORE,
  STATE_RESTORE_USAGE,
  UUID_V7,
} from './request.ts';
import { onRestoreSides, OWNER_LOGIN_NOTE, storedPlanProblems } from './restore-job.ts';
import { planStateRecovery, stateCounts, statePlanDigest, statePlanFile } from './state-recovery.ts';
import { restoreStates, stateOutcomeLine, stateRestoreFile } from './state-restore.ts';

/** Whether a request's first word is one of these commands'. */
export const isStateCommand = (word: string | undefined): boolean => word === STATE_RECOVERY || word === STATE_RESTORE;

/** The authority rows' plan: the file state-recovery-plan keeps it in, and its summary's `k`. */
const STATE_PLAN = { file: 'state-recovery', line: 'state_plan' } as const;

/** Problems with an organisation's and a new ID's form, each named. */
const idProblems = (orgId: unknown, id: unknown, idNoun: string): string[] => [
  ...(UUID_V7.test(String(orgId)) ? [] : ["the organisation's ID must be a UUIDv7, in lower case"]),
  ...(UUID_V7.test(String(id)) ? [] : [`${idNoun} must be a UUIDv7, in lower case`]),
];

/** A plan's request, from its file's words, or the problems: none repeats what the file holds. */
function planAsked(words: readonly string[]): { readonly orgId: string; readonly planId: string } | Problems {
  const [command, orgFlag, orgId, idFlag, id, ...more] = words;
  const shaped = command === STATE_RECOVERY && orgFlag === '--org' && idFlag === '--id' && more.length === 0;
  if (!shaped) return problem(`the request file holds ${STATE_RECOVERY_USAGE} as a JSON list, and nothing else`);
  const problems = idProblems(orgId, id, "the plan's ID");
  return problems.length > 0 ? { problems } : { orgId: String(orgId), planId: String(id) };
}

interface RestoreAsked {
  readonly orgId: string;
  readonly planId: string;
  readonly digest: string;
  readonly restoreId: string;
}

/** A repair's request, from its file's words, or the problems. */
function restoreAsked(words: readonly string[]): RestoreAsked | Problems {
  const [command, orgFlag, orgId, planFlag, planId, digestFlag, digest, idFlag, id, ...more] = words;
  const shaped =
    command === STATE_RESTORE &&
    orgFlag === '--org' &&
    planFlag === '--plan' &&
    digestFlag === '--digest' &&
    idFlag === '--id' &&
    more.length === 0;
  if (!shaped) return problem(`the request file holds ${STATE_RESTORE_USAGE} as a JSON list, and nothing else`);
  const problems = [
    ...idProblems(orgId, id, "the repair's ID"),
    ...(UUID_V7.test(String(planId)) ? [] : ["the plan's ID must be a UUIDv7, in lower case"]),
    ...(PLAN_DIGEST_HEX.test(String(digest)) ? [] : ["the plan's digest must be 64 lower-case hex digits"]),
  ];
  if (problems.length > 0) return { problems };
  return { orgId: String(orgId), planId: String(planId), digest: String(digest), restoreId: String(id) };
}

/** Runs the command a request file's words ask for: the exit code. */
export function stateRun(
  config: OperatorConfig,
  keys: KeyProvider,
  words: readonly string[],
  logger: Logger,
): Promise<number> {
  return words[0] === STATE_RECOVERY ? planRun(config, keys, words, logger) : restoreRun(config, keys, words, logger);
}

/** Plans as asked, read-only on both sides, the plan's file to the evidence store: the exit code, 0 once planned. */
async function planRun(config: OperatorConfig, keys: KeyProvider, words: readonly string[], logger: Logger) {
  const asked = planAsked(words);
  if ('problems' in asked) {
    logger.error('operator.refused', { problems: asked.problems });
    return 1;
  }
  const { orgId, planId } = asked;
  const log = logger.child({ orgId });
  log.info('operator.starting', { command: STATE_RECOVERY, role: config.db.user, keys: keys.describe() });
  log.info('operator.state_owner_login', { planId, note: OWNER_LOGIN_NOTE });
  const run = { command: STATE_RECOVERY, liveReadOnly: true, said: { planId } };
  return onRestoreSides(config, keys, log, run, async ({ copy, live, store, anchors }) => {
    const anchor = anchors.latest({ kind: 'organisation', orgId });
    const plan = await planStateRecovery({ copy, live, keys, orgId, anchor });
    const file = statePlanFile(plan, { planId, orgId, release: config.release, run: config.run, anchor });
    if ((await store.put(`${orgId}/state-recovery-${planId}.ndjson`, file)) === 'there_already') {
      log.error('operator.done_before', { command: STATE_RECOVERY, planId });
      return 1;
    }
    if (!plan.ok) {
      const { reason, subjectType, objectId, sign, problem: why } = plan;
      log.error('operator.state_recovery_refused', {
        planId,
        reason,
        subjectType: subjectType ?? null,
        objectId: objectId ?? null,
        sign: sign ?? null,
        problem: why ?? null,
      });
      return 1;
    }
    log.info('operator.state_recovery_planned', {
      planId,
      // What a repair is asked with (state-restore): the plan as read, by its digest alone.
      digest: statePlanDigest(plan, orgId, anchor),
      ...stateCounts(plan.rows),
      objects: plan.objects,
      copySeq: plan.copyHead.seq,
      liveSeq: plan.liveHead.seq,
      anchorSeq: anchor?.seq ?? null,
    });
    return 0;
  });
}

/** Repairs as asked, between its start and outcome records in the evidence store: the exit code, 0 once repaired. */
async function restoreRun(config: OperatorConfig, keys: KeyProvider, words: readonly string[], logger: Logger) {
  const asked = restoreAsked(words);
  if ('problems' in asked) {
    logger.error('operator.refused', { problems: asked.problems });
    return 1;
  }
  const { orgId, planId, digest, restoreId } = asked;
  const log = logger.child({ orgId });
  log.info('operator.starting', { command: STATE_RESTORE, role: config.db.user, keys: keys.describe() });
  log.info('operator.state_owner_login', { restoreId, note: OWNER_LOGIN_NOTE });
  const facts = { restoreId, planId, orgId, digest, release: config.release, run: config.run };
  const run = {
    command: STATE_RESTORE,
    liveReadOnly: false,
    before: () => storedPlanProblems(config, asked, STATE_PLAN),
    said: { restoreId },
  };
  return onRestoreSides(config, keys, log, run, async ({ copy, live, store, anchors }) => {
    const name = `${orgId}/state-restore-${restoreId}`;
    const start = Buffer.from(`${JSON.stringify({ k: 'state_restore_start', ...facts })}\n`);
    if ((await store.put(`${name}-start.ndjson`, start)) === 'there_already') {
      log.error('operator.done_before', { command: STATE_RESTORE, restoreId });
      return 1;
    }
    const anchor = anchors.latest({ kind: 'organisation', orgId });
    const outcome = await restoreStates({ copy, live, keys, orgId, anchor, digest, logger: log });
    const line = { restoreId, planId, ...stateOutcomeLine(outcome) };
    // The outcome is in this line whether or not its record is written: a failed write is an error of its own.
    if (outcome.ok) log.info('operator.states_restored', { ...line, holdKept: true });
    else log.error('operator.state_restore_refused', line);
    if ((await store.put(`${name}-outcome.ndjson`, stateRestoreFile(outcome, facts))) === 'there_already') {
      log.error('operator.done_before', { command: STATE_RESTORE, restoreId });
      return 1;
    }
    return outcome.ok ? 0 : 1;
  });
}
