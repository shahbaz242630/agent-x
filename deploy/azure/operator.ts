// Runs the operator's command on its job (B1c-2b; ADR-011 §3, ADR-005 §6):
//
//   node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
//   node deploy/azure/operator.ts invite-first-admin --org <organisation ID> --email <address> [--id <ID>]
//   node deploy/azure/operator.ts restore-check
//   node deploy/azure/operator.ts audit-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>]
//   node deploy/azure/operator.ts activity-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>]
//   node deploy/azure/operator.ts handoff-pause --reason <case reference> [--id <ID>]
//   node deploy/azure/operator.ts handoff-resume --reason <case reference> [--id <ID>]
//   node deploy/azure/operator.ts chain-recovery-plan --org <organisation ID> [--discard-fork]
//   node deploy/azure/operator.ts chain-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>] [--discard-fork]
//   node deploy/azure/operator.ts chain-rebase --chain <platform | organisation ID> --seq <head number> --hash <head hash> --reason <repaired | recovered> --evidence <incident reference> [--id <ID>]
//   node deploy/azure/operator.ts state-recovery-plan --org <organisation ID>
//   node deploy/azure/operator.ts state-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>]
//
// state-recovery-plan and state-restore (PL-29 follow-up, Carry-Forward S175;
// playbook H) put an organisation's tampered authority rows (its members,
// agents, keys, mandates, policies, suppliers and the like) back from the
// restore drill's copy, once its chain checks whole: the first plans it,
// read-only, and says the plan's ID and digest; the second applies that plan
// only if it is still the same. Both run on the chain repair's job, as the
// database's owner, so each sets off the owner-login SEV-1 alert, by design.
//
// chain-recovery-plan and chain-restore (4D2e E9, E10; PL-29; playbook H) mend an organisation's audit
// chain from the restore drill's copy: the first plans it, read-only, and says
// the plan's ID and digest; the second runs on the chain repair's own job, as
// the database's owner, and applies that plan only if it is still the same. A
// repair's every run sets off the owner-login SEV-1 alert, by design: it says
// so before it starts. --discard-fork, given to both, lets a plan throw away
// what the app wrote on a wound-back chain; it is never assumed. A repair says
// the rebase's command with its head's number and hash.
//
// chain-rebase (4D2e E11) moves a chain's anchor on to its checked head after a
// sanctioned change (a repair, or the platform chain begun again), signed with
// the operator's rebase key on the operator's job: the API then trusts that head,
// and the anchor alarm for the chain stops. Its --id is the rebase's: the same
// command with it writes nothing twice, and finishes a run that stopped between
// the rebase's file and its event on the chain.
//
// (An UNKNOWN payment is marked failed by the customer's admin, not by our
// team: partner decision 38.)
//
// The last two (Phase 4 B1, SEC-OPS-03) pause or resume every hand-off of an
// approved payment to the bank, for every organisation: the run records it
// on the platform chain, then tells every organisation on its own chain and
// its admins. Its --id is the platform event's: the same command with it
// records nothing twice and tells only the organisations not told yet.
//
// The fourth (Phase 3 E10c, ADR-005 §6) exports an organisation's audit log
// for a case, the fifth (L7) its activity log: the run records it on both
// chains and tells the organisation's admins, then writes the file to the
// write-once store, once. Its --id, like an organisation's, repeats an
// earlier run's export: it records nothing twice and writes a file not yet
// written.
//
// The third (S78) is the restore drill's check: run once the drill's copy of
// the database is up, it reads the copy and the live server, read-only, and
// says whether the copy holds (apps/operator restore-check.ts).
//
// The second (B4-6b) invites a new organisation's first admin. Its link's
// token is made here, on the partner's own machine: the job is sent only the
// token's SHA-256, and the link is shown here once, after the run says the
// invitation exists, and kept nowhere. The link's address is the API's own
// public origin, read from Azure, so no domain is written in the repository.
//
// The job holds its request as a secret of its own (B1c-2a), since a run
// started with containers of its own loses every mounted file, its login and
// key among them. So this:
// 1. reads the job and the API, and refuses a job that isn't the operator's as
//    apps.bicep deploys it, one still settling an earlier change, or one with
//    a run still going
// 2. makes the new organisation's ID, or takes --id: the ID an earlier run
//    gave whose end was unclear, which can never make a second organisation
// 3. writes the request onto the job in one PATCH of its secrets, every vault
//    reference sent back as it was read, and in the same PATCH brings the
//    job's container to the image and build the API runs (CI's release moves
//    the API and migrate alone), then waits until Azure has taken it
// 4. starts the job as it is, never with containers of its own, and waits
// 5. puts [] back whatever happened, once no change to the job is still
//    going, and waits until Azure has taken that
// 6. reads the run's log and says what the run did for this request's ID:
//    created the organisation, found it done already (nothing changed), or
//    neither; a line about another ID is never taken for this one's
// One run at a time: Azure can't say whose change it took. A run stopped
// part-way (the terminal closed, say) leaves the request on the job, which
// can't make a second organisation, since it names its ID; the same command
// again with that --id takes it off at its end, as does deploy.ts apps.
// The request is never printed, nor put on a command line: it goes to Azure in
// a file in this user's own temporary folder, removed straight after, with
// every character past ASCII escaped so the CLI can't misread its encoding. A
// read of the job never shows it back. Starting the job is the partner's
// (ADR-005 §6: the right to start it is the API's own authority), so this runs
// from their `!`.
import { createHash, randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

import {
  activityExportRequest,
  auditExportOf,
  auditExportRequest,
  createOrganizationRequest,
  firstAdminRequest,
  type HandoffCommand,
  handoffAskedOf,
  handoffRequest,
  NO_REQUEST_PROBLEM,
  NO_STORE_PROBLEM,
  REQUEST_LIMIT_BYTES,
  RESTORE_CHECK,
  chainRebaseRequest,
  chainRecoveryRequest,
  chainRestoreRequest,
  DISCARD_FORK,
  stateRecoveryRequest,
  stateRestoreRequest,
  HEAD_HASH,
  HEAD_SEQ,
  PLAN_DIGEST_HEX,
  restoreCheckRequest,
  UUID_V7,
} from '../../apps/operator/src/request.ts';
import { MOST_EXPORT_DAYS } from '../../packages/core/src/modules/evidence/domain/exports.ts';
import { EVIDENCE_REFERENCE, REBASE_REASONS } from '../../packages/platform/src/audit-chain/rebase.ts';
import { invitationEmail } from '../../packages/core/src/modules/identity/domain/invitation.ts';
import { uuidV7Ids } from '../../packages/core/src/shared-kernel/ids.ts';
import { realAz, signedIn, text } from './deploy.ts';
import { asciiJson, lastModified, reason, sendPatch, type VaultReference, vaultReferences } from './held-request.ts';
import {
  type Ended,
  jobName,
  type JobSteps,
  type LogLine,
  POLL_MS,
  readLog,
  runCli,
  start,
  type Target,
  unfinishedRuns,
  UsageError,
  waitFor,
} from './jobs.ts';
import {
  changes,
  type Container,
  get,
  readWorkload,
  record,
  released,
  resourceUrl,
  type Running,
  runningAs,
  same,
  settingValue,
  type WorkloadSpec,
} from './release.ts';

/** The operator's job, as apps.bicep deploys it; a test holds the two equal. */
export const OPERATOR_JOB: WorkloadSpec = { path: `jobs/${jobName('operator')}`, container: 'operator' };

/** The secret the job holds its request in (apps.bicep `operatorRequest`); a test holds the two equal. */
export const REQUEST_SECRET = 'operator-request';

/** The chain repair's job (4D2e E10), as apps.bicep deploys it, and the secret it holds its request in (`restoreRequest`). */
export const RESTORE_JOB: WorkloadSpec = { path: `jobs/${jobName('chain-restore')}`, container: 'chain-restore' };
export const RESTORE_REQUEST_SECRET = 'chain-restore-request';

/** What the job holds between runs: no request, which the command refuses (B1c-2a). */
export const NO_REQUEST = '[]';

/** The jobs a request is written onto: the operator's and the chain repair's. */
type RequestJob = 'operator' | 'chain-restore';

/** A job a request is written onto, by its name: what it is, the secret its request is in, and what it runs. */
interface RequestJobSpec {
  readonly spec: WorkloadSpec;
  readonly secret: string;
  /** The command, reading its request from the file the secret is mounted as (policy.ts `HELD`). */
  readonly runs: readonly string[];
  /** What a refusal calls it. */
  readonly known: string;
}

const REQUEST_JOBS: Readonly<Record<RequestJob, RequestJobSpec>> = {
  operator: {
    spec: OPERATOR_JOB,
    secret: REQUEST_SECRET,
    runs: ['node', 'apps/operator/src/main.ts', '--request', `/mnt/secrets/${REQUEST_SECRET}`],
    known: "the operator's job this tool knows",
  },
  'chain-restore': {
    spec: RESTORE_JOB,
    secret: RESTORE_REQUEST_SECRET,
    runs: ['node', 'apps/operator/src/chain-restore-main.ts', '--request', `/mnt/secrets/${RESTORE_REQUEST_SECRET}`],
    known: "the chain repair's job this tool knows",
  },
};

/** Where a request is written: the subscription and one of the jobs that runs one. */
interface HeldTarget extends Target {
  readonly job: RequestJob;
}

/** How long a change to the job may take to settle: as long as a release gives one (release.ts). */
const SETTLE_MS = 10 * 60_000;

/** Any ID, for the size of a request before its own is made: every ID is as long. */
const SOME_ID = '00000000-0000-7000-8000-000000000000';

/** What may now hold the request when [] couldn't be put back, and what takes it off. */
const mayStillHold = (id: string, noun: string): string =>
  `The request may still be on ${jobName('operator')}. It names ${id}, so it can't make a second ${noun}. Take it off by running the same command again with --id ${id}, or by deploying the apps (deploy.ts apps).`;

/**
 * The last word on any failure once the ID is made: what the run did may be
 * unknown, and the same command with the same ID both finds out and finishes
 * it, making none twice.
 */
const tryAgain = (id: string, noun: string): string =>
  `To find out what happened, and finish it if it didn't: run the same command again with --id ${id}. If the ${noun} exists, that run ends "Already done"; none is made twice.`;

export const USAGE = `Usage:
  node deploy/azure/operator.ts create-organization --name <name> [--id <ID>]
  node deploy/azure/operator.ts invite-first-admin --org <organisation ID> --email <address> [--id <ID>]
  node deploy/azure/operator.ts restore-check
  node deploy/azure/operator.ts audit-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>]
  node deploy/azure/operator.ts activity-export --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>]
  node deploy/azure/operator.ts handoff-pause --reason <case reference> [--id <ID>]
  node deploy/azure/operator.ts handoff-resume --reason <case reference> [--id <ID>]
  node deploy/azure/operator.ts chain-recovery-plan --org <organisation ID> [--discard-fork]
  node deploy/azure/operator.ts chain-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>] [--discard-fork]
  node deploy/azure/operator.ts chain-rebase --chain <platform | organisation ID> --seq <head number> --hash <head hash> --reason <repaired | recovered> --evidence <incident reference> [--id <ID>]
  node deploy/azure/operator.ts state-recovery-plan --org <organisation ID>
  node deploy/azure/operator.ts state-restore --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>]
The name is one argument: quote it if it holds a space. --id repeats the ID an earlier run gave when its end was unclear; the same ID can never make a second organisation, invitation, export, pause or resume. An export's times are UTC, such as 2026-10-01T00:00:00Z, ${String(MOST_EXPORT_DAYS)} days at most; its case reference, and a pause's or resume's, is the dispute's, the incident's or the regulator's: 3 to 64 letters, digits and . _ / -.`;

/** What the partner asked for: a new organisation's name, and the ID of an earlier try if this is one. */
export interface Request {
  readonly name: string;
  readonly id: string | undefined;
}

/** What was asked for, or a UsageError saying why it can't be done. Nothing typed is repeated in one. */
export function parseArguments(argv: readonly string[]): Request {
  const [command, flag, name, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if (command !== 'create-organization' || flag !== '--name' || name === undefined || name === '' || !ided) {
    throw new UsageError(
      'say create-organization --name <name> [--id <ID>], the name as one argument, and nothing else',
    );
  }
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  if (Buffer.byteLength(createOrganizationRequest(name, SOME_ID)) > REQUEST_LIMIT_BYTES) {
    throw new UsageError(
      `the name makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
    );
  }
  return { name, id };
}

/** The first admin's invitation the partner asked for (B4-6b). */
export interface FirstAdminArguments {
  readonly orgId: string;
  /** In lower case, as the invitation keeps it. */
  readonly email: string;
  /** The ID of an earlier try, if this is one. */
  readonly id: string | undefined;
}

/** What was asked for, or a UsageError saying why it can't be done. The address is never repeated in one. */
export function parseFirstAdmin(argv: readonly string[]): FirstAdminArguments {
  const [command, orgFlag, orgId, emailFlag, email, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if (
    command !== 'invite-first-admin' ||
    orgFlag !== '--org' ||
    emailFlag !== '--email' ||
    email === undefined ||
    !ided
  ) {
    throw new UsageError(
      'say invite-first-admin --org <organisation ID> --email <address> [--id <ID>], and nothing else',
    );
  }
  if (!UUID_V7.test(String(orgId))) throw new UsageError("--org takes the organisation's ID: a UUIDv7, in lower case");
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  const address = invitationEmail(email);
  if (address === undefined) throw new UsageError("--email takes the address to invite, and this isn't one");
  if (Buffer.byteLength(firstAdminRequest(String(orgId), address, SOME_ID, '0'.repeat(64))) > REQUEST_LIMIT_BYTES) {
    throw new UsageError(
      `the address makes the request longer than the ${String(REQUEST_LIMIT_BYTES)} bytes the operator reads`,
    );
  }
  return { orgId: String(orgId), email: address, id };
}

/** The audit export the partner asked for (E10c): its words as typed, and the ID of an earlier try if this is one. */
export interface AuditExportArguments {
  readonly orgId: string;
  readonly from: string;
  readonly to: string;
  readonly caseRef: string;
  readonly id: string | undefined;
}

/**
 * What was asked for, or a UsageError saying why it can't be done, by the
 * operator's own rules (request.ts `auditExportOf`), so a request it would
 * refuse is never written. The case reference is never repeated in one.
 */
export function parseAuditExport(argv: readonly string[], kind: CaseExportKind = 'audit-export'): AuditExportArguments {
  const [command, orgFlag, orgId, fromFlag, from, toFlag, to, reasonFlag, caseRef, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if (
    command !== kind ||
    orgFlag !== '--org' ||
    fromFlag !== '--from' ||
    toFlag !== '--to' ||
    reasonFlag !== '--reason' ||
    orgId === undefined ||
    from === undefined ||
    to === undefined ||
    caseRef === undefined ||
    !ided
  ) {
    throw new UsageError(
      `say ${kind} --org <organisation ID> --from <time> --to <time> --reason <case reference> [--id <ID>], and nothing else`,
    );
  }
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  const asked = auditExportOf({ orgId, from, to, caseRef, id: id ?? SOME_ID }, MOST_EXPORT_DAYS);
  if ('problems' in asked) throw new UsageError(asked.problems.join('; '));
  return { orgId, from, to, caseRef, id };
}

/** The pause or resume of every hand-off the partner asked for (Phase 4 B1). */
export interface HandoffArguments {
  readonly command: HandoffCommand;
  /** A case reference, never repeated in a problem. */
  readonly reason: string;
  /** The ID of an earlier try, if this is one. */
  readonly id: string | undefined;
}

/**
 * What was asked for, or a UsageError saying why it can't be done, by the
 * operator's own rules (request.ts `handoffAskedOf`), so a request it would
 * refuse is never written. The reason is never repeated in one.
 */
export function parseHandoff(argv: readonly string[]): HandoffArguments {
  const [command, reasonFlag, reason, ...rest] = argv;
  const [idFlag, id, ...more] = rest;
  const ided = rest.length === 0 || (idFlag === '--id' && id !== undefined && more.length === 0);
  if ((command !== 'handoff-pause' && command !== 'handoff-resume') || reasonFlag !== '--reason' || !ided) {
    throw new UsageError(`say ${String(command)} --reason <case reference> [--id <ID>], and nothing else`);
  }
  if (id !== undefined && !UUID_V7.test(id)) {
    throw new UsageError('--id takes the ID an earlier run gave: a UUIDv7, in lower case');
  }
  const asked = handoffAskedOf({ reason, id: id ?? SOME_ID });
  if ('problems' in asked) throw new UsageError(asked.problems.join('; '));
  return { command, reason: asked.reason, id };
}

/** A request's job as Azure has it, checked: what a change sends back of it, and where it stands. */
interface OperatorJob {
  /** The secret its request is in. */
  readonly secret: string;
  readonly running: Running;
  readonly references: readonly VaultReference[];
  /** How long one run may take, in seconds. */
  readonly limit: number;
  readonly state: string;
  /** When Azure last took a change to it: a change of ours has settled only once this moves on. */
  readonly modified: string;
}

/**
 * The job, read from Azure, or an error saying why it isn't the operator's job
 * as apps.bicep deploys it: its container as a release knows one, running the
 * command on its request's file and nothing else; its request held once, with
 * nothing shown of it; every other secret a reference to the vault; a time
 * limit; and the time of its last change, which tells a change of ours apart.
 */
function readOperatorJob(steps: JobSteps, target: HeldTarget): OperatorJob {
  const { spec, secret, runs, known } = REQUEST_JOBS[target.job];
  const refuse = (why: string): never => {
    throw new Error(`${spec.path} isn't ${known} (${why}): deploy it by hand.`);
  };
  const found = get(steps.az, resourceUrl(target.subscription, spec), jobName(target.job));
  const properties = record(found.properties);
  const configuration = record(properties.configuration);
  const running = runningAs(spec, known, record(properties.template).containers);
  if (JSON.stringify([...running.container.command, ...running.container.args]) !== JSON.stringify(runs)) {
    refuse(`it must run ${runs.join(' ')}`);
  }
  const references = vaultReferences(configuration.secrets, secret, refuse);
  const limit = configuration.replicaTimeout;
  if (typeof limit !== 'number' || !Number.isInteger(limit) || limit <= 0) return refuse('it has no time limit');
  const modified = lastModified(found);
  if (modified === '') return refuse("Azure gave no time of its last change, so one of ours can't be told apart");
  return { secret, running, references, limit, state: text(properties.provisioningState), modified };
}

/**
 * The PATCH that sets the job's request to `value`: the secrets list whole,
 * since Azure's PATCH replaces a list whole, every vault reference as it was
 * read; and the container, when it is given.
 */
const patchBody = (job: OperatorJob, value: string, container?: Container): string =>
  asciiJson(
    JSON.stringify({
      properties: {
        configuration: { secrets: [...job.references, { name: job.secret, value }] },
        ...(container === undefined ? {} : { template: { containers: [container] } }),
      },
    }),
  );

/** Sends a PATCH to the request's job (held-request.ts `sendPatch`). */
const patch = (steps: JobSteps, target: HeldTarget, body: string, what: string): void => {
  sendPatch(steps, resourceUrl(target.subscription, REQUEST_JOBS[target.job].spec), body, what);
};

/**
 * Waits until Azure has taken a change sent after `before` (the time of the
 * job's last change then), holding `container`, marked Succeeded. Just after
 * the PATCH the job can still show the state its earlier change left, so only
 * a state after that time counts.
 */
async function settled(
  steps: JobSteps,
  target: HeldTarget,
  before: string,
  container: Container,
  what: string,
): Promise<OperatorJob> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    const job = readOperatorJob(steps, target);
    const taken = job.modified !== before && same(job.running.container, container);
    if (taken && job.state === 'Succeeded') return job;
    if (taken && (job.state === 'Failed' || job.state === 'Canceled')) {
      throw new Error(`Azure's change to ${jobName(target.job)} for ${what} ended ${job.state}.`);
    }
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `Azure hadn't settled ${what} on ${jobName(target.job)} after ${String(SETTLE_MS / 60_000)} minutes (${job.state}${taken ? '' : ', not yet taken'}).`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/** Waits until no change to the job is still going, so the next is taken rather than refused: the job then. */
async function idle(steps: JobSteps, target: HeldTarget): Promise<OperatorJob> {
  const deadline = steps.now().getTime() + SETTLE_MS;
  for (;;) {
    const job = readOperatorJob(steps, target);
    if (job.state !== 'InProgress') return job;
    if (steps.now().getTime() >= deadline) {
      throw new Error(
        `${jobName(target.job)} was still taking a change after ${String(SETTLE_MS / 60_000)} minutes, so nothing more was sent.`,
      );
    }
    await steps.sleep(POLL_MS);
  }
}

/**
 * Puts [] back as the job's request, every vault reference as it is now, once
 * no change is still going (Azure may refuse one made during another), and
 * waits until Azure has taken it.
 */
async function clearRequest(steps: JobSteps, target: HeldTarget): Promise<void> {
  const job = await idle(steps, target);
  const what = `putting ${NO_REQUEST} back`;
  patch(steps, target, patchBody(job, NO_REQUEST), what);
  await settled(steps, target, job.modified, job.running.container, what);
  steps.say(`Put ${NO_REQUEST} back on ${jobName(target.job)}: its next run holds no request until one is written.`);
}

/** The command's own lines in a run: its JSON ones, since neither Azure's lines nor Node's own are JSON. */
function commandLines(lines: readonly LogLine[]): Readonly<Record<string, unknown>>[] {
  return lines.flatMap((line) => {
    try {
      return [record(JSON.parse(line.text))];
    } catch (error) {
      // A line that isn't JSON is shown above and read as none of the command's own.
      if (error instanceof SyntaxError) return [];
      throw error;
    }
  });
}

/** A line's problems as said, or undefined when it holds none. */
function problemsSaid(line: Readonly<Record<string, unknown>> | undefined): string | undefined {
  return Array.isArray(line?.problems) ? line.problems.map(String).join('; ') : undefined;
}

/** Whether a refusal line gives this problem among its own. */
const refusedFor = (refused: Readonly<Record<string, unknown>> | undefined, problem: string): boolean =>
  Array.isArray(refused?.problems) && refused.problems.includes(problem);

/** Whether a refusal line is about this request's ID, read from its own field. */
const refusedAbout = (refused: Readonly<Record<string, unknown>> | undefined, field: string, id: string): boolean =>
  Array.isArray(refused?.problems) && refused[field] === id;

/** Said when the run found no request: Azure hadn't put it in place when the run started. */
const noRequestFound = (id: string): string =>
  `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. Run the same command again with --id ${id}.`;

/** A request for the job: its file's text, what is said around its run, and how the run is judged. */
interface JobRequest {
  /** The request file's text. */
  readonly text: string;
  /** Said before anything is written. */
  readonly intro: string;
  /** Said after any failure: how to find out what happened, and finish it. */
  readonly tryAgain: string;
  /** Said when [] couldn't be put back: what may still hold the request, and what takes it off. */
  readonly mayStillHold: string;
  /** What the run did, from its lines and Azure's end of it: 0 once done. */
  readonly judge: (run: Ended, lines: readonly LogLine[]) => number;
}

/** A request that makes something named by its ID, which a second run of it can never make twice. */
interface MakingRequest {
  readonly id: string;
  readonly text: string;
  /** What it makes, as said: `organisation` or `invitation`. */
  readonly noun: string;
  /** The field the command's lines name it by. */
  readonly field: 'orgId' | 'invitationId';
  /** The command's line once it is made. */
  readonly made: string;
  /** Says it was made. */
  readonly sayMade: () => void;
  /** Said after "Already done", if anything. */
  readonly doneBeforeNote: string;
}

/** A making request as the job runner takes one. */
function making(steps: JobSteps, asked: MakingRequest): JobRequest {
  const { id, noun } = asked;
  return {
    text: asked.text,
    intro: `The new ${noun}'s ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it can't make a second ${noun}, and it takes the request off the job at its end.`,
    tryAgain: tryAgain(id, noun),
    mayStillHold: mayStillHold(id, noun),
    judge: (run, lines) => outcome(steps, run, lines, asked),
  };
}

/**
 * What the run did, from the command's own lines about this request's ID and
 * Azure's end of the run: 0 once what it makes exists, made now or by an
 * earlier run of the same request, and 1 otherwise, saying what to do next. A
 * line about another ID (another request run in this one's place) is never
 * taken for this one's.
 */
function outcome(steps: JobSteps, run: Ended, lines: readonly LogLine[], asked: MakingRequest): number {
  const { id, noun, field } = asked;
  const said = commandLines(lines);
  const about = (event: string): boolean => said.some((line) => line.event === event && line[field] === id);
  if (about(asked.made)) {
    asked.sayMade();
    return 0;
  }
  if (about('operator.done_before')) {
    steps.say(
      `Already done: the ${noun} ${id} exists from an earlier run of this request, and nothing changed.${asked.doneBeforeNote}`,
    );
    return 0;
  }
  const refused = said.find((line) => line.event === 'operator.refused');
  if (refusedFor(refused, NO_REQUEST_PROBLEM)) {
    steps.say(noRequestFound(id));
    return 1;
  }
  if (refusedAbout(refused, field, id)) {
    steps.say(`The operator's command refused it, and nothing changed: ${String(problemsSaid(refused))}.`);
    return 1;
  }
  steps.say(
    run.status === 'Succeeded'
      ? `The run succeeded, but its lines don't show the ${noun} ${id} made: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${id}, which can't make a second one.`
      : `The ${noun} may not have been created: read the lines above. If they leave it unclear, run the same command again with --id ${id}, which can't make a second one.`,
  );
  return 1;
}

/** Writes the request, runs it, puts [] back, and says what the run did: 0 once the organisation exists. */
export function createOrganization(request: Request, steps: JobSteps): Promise<number> {
  const id = request.id ?? uuidV7Ids.next();
  return runRequest(steps, () =>
    making(steps, {
      id,
      text: createOrganizationRequest(request.name, id),
      noun: 'organisation',
      field: 'orgId',
      made: 'operator.organization_created',
      sayMade: () => {
        steps.say(`Created the organisation ${id}.`);
      },
      doneBeforeNote: '',
    }),
  );
}

/**
 * Invites a new organisation's first admin (B4-6b): the token made here, only
 * its SHA-256 sent, and the link shown here once the run says the invitation
 * exists. 0 once it does.
 */
export function inviteFirstAdmin(request: FirstAdminArguments, steps: JobSteps): Promise<number> {
  const token = randomBytes(32).toString('base64url');
  const hash = createHash('sha256').update(token, 'ascii').digest('hex');
  const id = request.id ?? uuidV7Ids.next();
  return runRequest(steps, (api) => {
    const value = settingValue(api.container, 'AGENTX_PUBLIC_ORIGIN');
    if (!/^https:\/\/[a-z0-9.-]+$/.test(value)) {
      throw new Error('The API holds no https AGENTX_PUBLIC_ORIGIN, so no link could be made: nothing was written.');
    }
    return making(steps, {
      id,
      text: firstAdminRequest(request.orgId, request.email, id, hash),
      noun: 'invitation',
      field: 'invitationId',
      made: 'operator.first_admin_invited',
      sayMade: () => {
        steps.say(
          `Invited the first admin of ${request.orgId} (invitation ${id}). Send them this link, shown this once and kept nowhere. It works for 72 hours, signed in with the invited address:\n${value}/invitations/accept#token=${token}\nTell them to register a passkey as their first second factor: a passkey added after any other second factor holds back an admin's powers for 7 days.`,
        );
      },
      doneBeforeNote:
        ' Its link was shown by that run alone. If it was lost, run the command again without --id: a new invitation, with a new link.',
    });
  });
}

/**
 * The restore drill's check (S78): what the run found, from the command's own
 * line. 0 only when it says the copy holds; the problems are said otherwise.
 */
function restoreCheckOutcome(steps: JobSteps, run: Ended, lines: readonly LogLine[]): number {
  const said = commandLines(lines);
  const done = said.find((line) => line.event === 'operator.restore_check_done');
  const failed = said.find((line) => line.event === 'operator.restore_check_failed');
  // The command logs one of the two, never both.
  if (done !== undefined) {
    steps.say(
      `The copy holds: all ${String(done.chainsChecked)} chains on it checked whole, and each leads to the live one (${String(done.copyOrganizations)} organisations on the copy, ${String(done.newSinceCopy)} made since; the platform chain at ${String(done.platformCopySeq)} on the copy, ${String(done.platformLiveSeq)} live).`,
    );
    return 0;
  }
  const failedSaid = problemsSaid(failed);
  if (failedSaid !== undefined) {
    // The line names the first problems only (a log line's list is capped): the count is all of them.
    const shown = Array.isArray(failed?.problems) ? failed.problems.length : 0;
    const more = Number(failed?.problemCount) - shown;
    const rest = more > 0 ? '; and ' + String(more) + ' more' : '';
    steps.say(`The copy does not hold: ${failedSaid}${rest}.`);
    return 1;
  }
  const refusedSaid = problemsSaid(said.find((line) => line.event === 'operator.refused'));
  if (refusedSaid !== undefined) {
    steps.say(`The check was refused, and read nothing: ${refusedSaid}.`);
    return 1;
  }
  steps.say(
    run.status === 'Succeeded'
      ? "The run succeeded, but its lines don't say what it found: they may not all have arrived. Run the same command again: it only reads."
      : "The check didn't finish: read the lines above (is the drill's copy up, in the same subnet and private zone?). Run it again once it is: it only reads.",
  );
  return 1;
}

/** Runs the restore drill's check on the job (S78): 0 once the copy is shown to hold. */
export function restoreCheck(steps: JobSteps): Promise<number> {
  const again = 'Run the same command again: it only reads, so nothing is done twice.';
  return runRequest(steps, () => ({
    text: restoreCheckRequest(),
    intro: "Checking the drill's copy against the live server, read-only.",
    tryAgain: again,
    mayStillHold: `The request may still be on ${jobName('operator')}: it only reads. ${again} It takes the request off at its end, as does deploy.ts apps.`,
    judge: (run, lines) => restoreCheckOutcome(steps, run, lines),
  }));
}

/**
 * What an export's run did (E10c's audit log, L7's activity log), from the command's own lines about
 * this export's ID: 0 once its file is in the store, written now or by an
 * earlier run of the same export; 1 otherwise, saying what to do next. A run
 * that recorded the export but couldn't write its file says so, and the same
 * --id writes it without recording it twice.
 */
function auditExportOutcome(
  steps: JobSteps,
  run: Ended,
  lines: readonly LogLine[],
  id: string,
  kind: CaseExportKind,
): number {
  const said = commandLines(lines);
  const about = (event: string): Readonly<Record<string, unknown>> | undefined =>
    said.find((line) => line.event === event && line.exportId === id);
  const { done, counted } = CASE_EXPORTS[kind];
  const exported = about(done);
  if (exported !== undefined) {
    steps.say(
      exported.write === 'written'
        ? `Exported ${String(exported[counted])} ${counted} for the case to the store as ${String(exported.file)} (${String(exported.bytes)} bytes, SHA-256 ${String(exported.sha256)}). It is recorded on both chains, and the organisation's admins were told.`
        : `Already done: ${String(exported.file)} is in the store from an earlier run of this export, and nothing was written again.`,
    );
    return 0;
  }
  const unwritten = about('operator.export_unwritten');
  if (unwritten !== undefined) {
    const problems = problemsSaid(unwritten);
    const why = problems === undefined ? '' : ': ' + problems;
    steps.say(
      `The export ${id} is recorded on both chains and the organisation's admins were told, but its file wasn't written${why}. Run the same command again with --id ${id}: it records nothing twice, and writes the file once.`,
    );
    return 1;
  }
  const refused = said.find((line) => line.event === 'operator.refused');
  if (refusedFor(refused, NO_REQUEST_PROBLEM)) {
    steps.say(noRequestFound(id));
    return 1;
  }
  if (refusedFor(refused, NO_STORE_PROBLEM)) {
    steps.say(
      `The job has no store for an export set, so nothing was recorded: deploy the apps (deploy.ts apps), then run the same command again with --id ${id}.`,
    );
    return 1;
  }
  if (refusedAbout(refused, 'exportId', id)) {
    steps.say(`The operator's command refused it, and nothing was recorded: ${String(problemsSaid(refused))}.`);
    return 1;
  }
  steps.say(
    run.status === 'Succeeded'
      ? `The run succeeded, but its lines don't show the export ${id} written: they may not all have arrived, or another request ran in this one's place. Run the same command again with --id ${id}, which records nothing twice.`
      : `The export may not have been recorded or written: read the lines above. If they leave it unclear, run the same command again with --id ${id}, which records nothing twice.`,
  );
  return 1;
}

/** The exports for a case the job runs: the line a written one ends with, what it counts, and its request. */
const CASE_EXPORTS = {
  'audit-export': { done: 'operator.audit_exported', counted: 'events', request: auditExportRequest },
  'activity-export': { done: 'operator.activity_exported', counted: 'requests', request: activityExportRequest },
} as const;

type CaseExportKind = keyof typeof CASE_EXPORTS;

/** Exports an organisation's audit log (E10c) or activity log (L7) for a case on the job: 0 once its file is in the store. */
export function auditExport(
  request: AuditExportArguments,
  steps: JobSteps,
  kind: CaseExportKind = 'audit-export',
): Promise<number> {
  const id = request.id ?? uuidV7Ids.next();
  return runRequest(steps, () => ({
    text: CASE_EXPORTS[kind].request(request.orgId, request.from, request.to, request.caseRef, id),
    intro: `The export's ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it records nothing twice, and it takes the request off the job at its end.`,
    tryAgain: `To find out what happened, and finish it if it didn't: run the same command again with --id ${id}. If the file is in the store, that run ends "Already done"; nothing is recorded twice.`,
    mayStillHold: mayStillHold(id, 'export'),
    judge: (ended, lines) => auditExportOutcome(steps, ended, lines, id, kind),
  }));
}

/**
 * What a pause's or resume's run did (Phase 4 B1), from the command's own
 * lines about this request's platform event: 0 once it is in force and every
 * organisation is told, by this run or an earlier one of the same request,
 * or once hand-offs were found as asked by another change (that change's own
 * request tells); 1 otherwise, saying what to do next.
 */
function handoffOutcome(steps: JobSteps, run: Ended, lines: readonly LogLine[], id: string, verb: string): number {
  const said = commandLines(lines);
  const about = (event: string): Readonly<Record<string, unknown>> | undefined =>
    said.find((line) => line.event === event && line.platformEventId === id);
  const unchanged = about('operator.handoff_unchanged');
  if (unchanged !== undefined && unchanged.inForce !== id) {
    const inForce = typeof unchanged.inForce === 'string' ? unchanged.inForce : null;
    steps.say(
      inForce === null
        ? `Hand-offs to the bank are already ${verb}, as a new environment starts: nothing was recorded, and nobody was told.`
        : `Hand-offs to the bank are already ${verb}, by the platform event ${inForce}: nothing was recorded, and nobody was told by this request. That change's own request, run again with its --id, tells any organisation it didn't.`,
    );
    return 0;
  }
  const done =
    unchanged === undefined
      ? `Hand-offs to the bank are ${verb} (platform event ${id})`
      : `Hand-offs to the bank were already ${verb} by this request (platform event ${id}), and nothing was recorded again`;
  const told = about('operator.handoff_told');
  const again = `Run the same command again with --id ${id}: it records nothing twice, and tells only the organisations not told yet.`;
  if (told !== undefined) {
    const counts = `${String(told.told)} organisations told now, ${String(told.toldBefore)} by an earlier run`;
    if (told.failed === 0) {
      steps.say(`${done}; ${counts}.`);
      return 0;
    }
    steps.say(`${done}; ${counts}, but ${String(told.failed)} couldn't be told: their lines are above. ${again}`);
    return 1;
  }
  if (about(`operator.handoff_${verb}`) !== undefined || unchanged !== undefined) {
    steps.say(`${done}, but the run's lines don't show every organisation told. ${again}`);
    return 1;
  }
  const refused = said.find((line) => line.event === 'operator.refused');
  if (refusedFor(refused, NO_REQUEST_PROBLEM)) {
    steps.say(noRequestFound(id));
    return 1;
  }
  if (refusedAbout(refused, 'platformEventId', id)) {
    steps.say(`The operator's command refused it, and nothing was recorded: ${String(problemsSaid(refused))}.`);
    return 1;
  }
  steps.say(
    run.status === 'Succeeded'
      ? `The run succeeded, but its lines don't show hand-offs ${verb} by ${id}: they may not all have arrived, or another request ran in this one's place. ${again}`
      : `Hand-offs may not have been ${verb}: read the lines above. If they leave it unclear: ${again}`,
  );
  return 1;
}

/** Pauses or resumes every hand-off to the bank on the job (Phase 4 B1): 0 once in force and every organisation is told. */
export function handoffChange(request: HandoffArguments, steps: JobSteps): Promise<number> {
  const id = request.id ?? uuidV7Ids.next();
  const [noun, verb] = request.command === 'handoff-pause' ? ['pause', 'paused'] : ['resume', 'resumed'];
  return runRequest(steps, () => ({
    text: handoffRequest(request.command, request.reason, id),
    intro: `The ${noun}'s platform event ID is ${id}. If this run's end is unclear, run the same command again with --id ${id}: it records nothing twice, tells only the organisations not told yet, and takes the request off the job at its end.`,
    tryAgain: `To find out what happened, and finish it if it didn't: run the same command again with --id ${id}. Nothing is recorded twice, and no organisation is told twice.`,
    mayStillHold: mayStillHold(id, noun),
    judge: (ended, lines) => handoffOutcome(steps, ended, lines, id, verb),
  }));
}

/** A chain recovery plan the partner asked for (4D2e E9): the organisation, and whether a fork may be planned away. */
export interface RecoveryPlanArguments {
  readonly orgId: string;
  readonly discardFork: boolean;
}

/** Whether the words after a command's own are nothing, or the named flag alone; undefined for anything else. */
const forkFlag = (rest: readonly string[]): boolean | undefined => {
  if (rest.length === 0) return false;
  return rest.length === 1 && rest[0] === DISCARD_FORK ? true : undefined;
};

const ORG_PROBLEM = "--org takes the organisation's ID: a UUIDv7, in lower case";

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseRecoveryPlan(argv: readonly string[]): RecoveryPlanArguments {
  const [command, orgFlag, orgId, ...rest] = argv;
  const discardFork = forkFlag(rest);
  if (command !== 'chain-recovery-plan' || orgFlag !== '--org' || orgId === undefined || discardFork === undefined) {
    throw new UsageError(`say chain-recovery-plan --org <organisation ID> [${DISCARD_FORK}], and nothing else`);
  }
  if (!UUID_V7.test(orgId)) throw new UsageError(ORG_PROBLEM);
  return { orgId, discardFork };
}

/** A chain repair the partner asked for (4D2e E10): the plan by its ID and digest, and the repair's ID if one ran before. */
export interface RestoreArguments {
  readonly orgId: string;
  readonly planId: string;
  readonly digest: string;
  readonly id: string | undefined;
  readonly discardFork: boolean;
}

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseRestore(argv: readonly string[]): RestoreArguments {
  return repairAsked(argv, 'chain-restore', ` [${DISCARD_FORK}]`);
}

/**
 * A repair's words, the chain's (`chain-restore`, which may take the named flag
 * last) or the authority rows' (`state-restore`, which never does): the plan by
 * its ID and digest, and the repair's ID if one ran before.
 */
function repairAsked(argv: readonly string[], named: string, forkWords: string): RestoreArguments {
  const [command, orgFlag, orgId, planFlag, planId, digestFlag, digest, ...rest] = argv;
  const ided = rest[0] === '--id';
  const id = ided ? rest[1] : undefined;
  const afterId = rest.slice(ided ? 2 : 0);
  const discardFork = forkWords === '' && afterId.length > 0 ? undefined : forkFlag(afterId);
  const shaped =
    command === named &&
    orgFlag === '--org' &&
    planFlag === '--plan' &&
    digestFlag === '--digest' &&
    digest !== undefined &&
    (!ided || id !== undefined) &&
    discardFork !== undefined;
  if (!shaped) {
    throw new UsageError(
      `say ${named} --org <organisation ID> --plan <plan ID> --digest <digest> [--id <ID>]${forkWords}, and nothing else`,
    );
  }
  const problems = [
    ...(UUID_V7.test(String(orgId)) ? [] : [ORG_PROBLEM]),
    ...(UUID_V7.test(String(planId)) ? [] : ["--plan takes the plan's ID: a UUIDv7, in lower case"]),
    ...(PLAN_DIGEST_HEX.test(digest) ? [] : ["--digest takes the plan's digest: 64 lower-case hex digits"]),
    ...(id === undefined || UUID_V7.test(id) ? [] : ['--id takes the ID an earlier run gave: a UUIDv7, in lower case']),
  ];
  if (problems.length > 0) throw new UsageError(problems.join('; '));
  return { orgId: String(orgId), planId: String(planId), digest, id, discardFork };
}

/** A chain's rebase the partner asked for (4D2e E11): the chain, its checked head, why, the incident, and an earlier ID. */
export interface RebaseArguments {
  /** `platform`, or an organisation's ID. */
  readonly chain: string;
  readonly seq: string;
  readonly hash: string;
  readonly reason: string;
  readonly evidence: string;
  readonly id: string | undefined;
}

const REBASE_SHAPE = `say chain-rebase --chain <platform | organisation ID> --seq <head number> --hash <head hash> --reason <${REBASE_REASONS.join(' | ')}> --evidence <incident reference> [--id <ID>], and nothing else`;

/** What was asked for, or a UsageError saying why it can't be done. The incident's reference is repeated in none. */
export function parseRebase(argv: readonly string[]): RebaseArguments {
  const [command, chainFlag, chain, seqFlag, seq, hashFlag, hash, reasonFlag, reason, evidenceFlag, evidence, ...rest] =
    argv;
  const ided = rest.length === 2 && rest[0] === '--id';
  const shaped =
    command === 'chain-rebase' &&
    chainFlag === '--chain' &&
    seqFlag === '--seq' &&
    hashFlag === '--hash' &&
    reasonFlag === '--reason' &&
    evidenceFlag === '--evidence' &&
    evidence !== undefined &&
    (rest.length === 0 || ided);
  if (!shaped) throw new UsageError(REBASE_SHAPE);
  const id = ided ? rest[1] : undefined;
  const problems = [
    ...(chain === 'platform' || UUID_V7.test(String(chain))
      ? []
      : ["--chain takes platform, or the organisation's ID: a UUIDv7, in lower case"]),
    ...(HEAD_SEQ.test(String(seq)) ? [] : ["--seq takes the checked head's number: a whole number from 1"]),
    ...(HEAD_HASH.test(String(hash)) ? [] : ["--hash takes the checked head's hash: 64 lower-case hex digits"]),
    ...(REBASE_REASONS.some((each) => each === reason) ? [] : [`--reason takes ${REBASE_REASONS.join(' or ')}`]),
    ...(EVIDENCE_REFERENCE.test(evidence)
      ? []
      : [
          "--evidence takes the incident's reference: 3 to 64 letters, digits and . _ / -, starting with a letter or digit",
        ]),
    ...(id === undefined || UUID_V7.test(id) ? [] : ['--id takes the ID an earlier run gave: a UUIDv7, in lower case']),
  ];
  if (problems.length > 0) throw new UsageError(problems.join('; '));
  return { chain: String(chain), seq: String(seq), hash: String(hash), reason: String(reason), evidence, id };
}

/** A chain, as said to the partner. */
const chainSaid = (chain: string): string => (chain === 'platform' ? "the platform's chain" : `${chain}'s chain`);

/** What each refused rebase means, in plain words, by its reason. */
const REBASE_REFUSALS: Readonly<Record<string, (line: Readonly<Record<string, unknown>>) => string>> = {
  store: () => "the anchors' store couldn't be read, so nothing was checked: read the lines above",
  not_needed: (line) => {
    const at = typeof line.seq === 'string' ? ' (at ' + line.seq + ')' : '';
    return `the chain already meets its anchor${at}: there is nothing to move on`;
  },
  broken: (line) =>
    `the chain fails its own check (${String(line.problem)} at ${String(line.seq)}), and a rebase never blesses a chain the app didn't write: repair it first (chain-recovery-plan, then chain-restore)`,
  head_differs: (line) =>
    `the chain's head is at ${String(line.seq)}, not the place named: check the head again and ask for that one`,
};

/** What a rebase's run did: 0 once the rebase is in the anchors' store and its event on the chain. */
function rebaseOutcome(steps: JobSteps, lines: readonly LogLine[], asked: RebaseArguments, id: string): number {
  const said = commandLines(lines);
  const about = (event: string) => said.find((line) => line.event === event && line.rebaseId === id);
  const again = `Run the same command again with --id ${id}: a rebase is written once, and a run that stopped between its file and its event on the chain finishes the event.`;
  const rebased = about('operator.chain_rebased');
  if (rebased !== undefined) {
    if (rebased.recorded === 'failed') {
      steps.say(`The rebase ${id} is in the anchors' store, but its event on the chain wasn't written. ${again}`);
      return 1;
    }
    const shorter =
      Number(rebased.shorterBy) > 0
        ? `; the chain is ${String(rebased.shorterBy)} events shorter than its old anchor, and those are given up`
        : '';
    steps.say(
      `Rebased: ${chainSaid(asked.chain)}'s anchor moves on from ${String(rebased.anchorSeq)} to ${String(rebased.seq)} (head ${String(rebased.headHash)})${shorter}. The rebase ${id} is in the anchors' store and its event on the chain. The API takes it in on its next read of the store: the anchor alarm for this chain stops, and it logs the warning audit.rebased, by design.`,
    );
    return 0;
  }
  if (about('operator.rebase_recorded') !== undefined) {
    steps.say(`The rebase ${id} was written by an earlier run; its event on the chain is written now. It is done.`);
    return 0;
  }
  const before = about('operator.done_before');
  if (before !== undefined) {
    if (before.recorded === 'already') {
      steps.say(`Already done: the rebase ${id} and its event on the chain were written by an earlier run.`);
      return 0;
    }
    steps.say(
      before.recorded === 'failed'
        ? `The rebase ${id} is in the anchors' store, but its event on the chain still couldn't be written. ${again}`
        : `A rebase named ${id} is already in the anchors' store for another chain or another head, or can't be read as one: nothing was done, and the head named isn't rebased. A new rebase needs no --id.`,
    );
    return 1;
  }
  const refusedRebase = about('operator.chain_rebase_refused');
  if (refusedRebase !== undefined) {
    const why = REBASE_REFUSALS[String(refusedRebase.reason)]?.(refusedRebase) ?? String(refusedRebase.reason);
    steps.say(`Not rebased, and nothing changed: ${why}.`);
    return 1;
  }
  return refusedOrUnclear(steps, said, again);
}

/** Moves a chain's anchor on to its checked head on the operator's job (4D2e E11): 0 once rebased. */
export function chainRebase(asked: RebaseArguments, steps: JobSteps): Promise<number> {
  const id = asked.id ?? uuidV7Ids.next();
  const again = `Run the same command again with --id ${id}: a rebase is written once.`;
  return runRequest(steps, () => ({
    text: chainRebaseRequest({ ...asked, id }),
    intro: `Rebasing ${chainSaid(asked.chain)} on to its head at ${asked.seq}, as rebase ${id}, signed with the operator's rebase key. The API trusts that head from then on: name only a head checked after a sanctioned change.`,
    tryAgain: again,
    mayStillHold: `The request may still be on ${jobName('operator')}. It names ${id}, so it can't rebase twice. ${again} It takes the request off at its end, as does deploy.ts apps.`,
    judge: (_run, lines) => rebaseOutcome(steps, lines, asked, id),
  }));
}

/** An authority rows' recovery plan the partner asked for (PL-29 follow-up): the organisation alone. */
export interface StatePlanArguments {
  readonly orgId: string;
}

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseStatePlan(argv: readonly string[]): StatePlanArguments {
  const [command, orgFlag, orgId, ...rest] = argv;
  if (command !== 'state-recovery-plan' || orgFlag !== '--org' || orgId === undefined || rest.length > 0) {
    throw new UsageError('say state-recovery-plan --org <organisation ID>, and nothing else');
  }
  if (!UUID_V7.test(orgId)) throw new UsageError(ORG_PROBLEM);
  return { orgId };
}

/** An authority rows' repair the partner asked for: the plan by its ID and digest, and the repair's ID if one ran before. */
export type StateRestoreArguments = Omit<RestoreArguments, 'discardFork'>;

/** What was asked for, or a UsageError saying why it can't be done. */
export function parseStateRestore(argv: readonly string[]): StateRestoreArguments {
  const { orgId, planId, digest, id } = repairAsked(argv, 'state-restore', '');
  return { orgId, planId, digest, id };
}

/** What a plan's run did: 0 once a plan is made, saying its digest and the repair's command. */
function planOutcome(steps: JobSteps, lines: readonly LogLine[], asked: RecoveryPlanArguments, planId: string): number {
  const said = commandLines(lines);
  const about = (event: string) => said.find((line) => line.event === event && line.planId === planId);
  const planned = about('operator.chain_recovery_planned');
  if (planned !== undefined) {
    const fork = asked.discardFork ? ` ${DISCARD_FORK}` : '';
    steps.say(
      `Planned ${planId}: ${String(planned.putBack)} rows to put back, ${String(planned.replaced)} to replace, ${String(planned.removed)} to remove; the head ${planned.headReplaced === true ? 'put back' : 'left as it is'}${planned.forkDiscarded === true ? "; the app's events on a fork thrown away" : ''}. Nothing was changed. The plan and its rows are in the evidence store as ${asked.orgId}/chain-recovery-${planId}.ndjson.`,
    );
    steps.say(
      `Once read, the repair is: node deploy/azure/operator.ts chain-restore --org ${asked.orgId} --plan ${planId} --digest ${String(planned.digest)}${fork}`,
    );
    return 0;
  }
  const refusedPlan = about('operator.chain_recovery_refused');
  if (refusedPlan !== undefined) {
    const problem = typeof refusedPlan.problem === 'string' ? ` (${refusedPlan.problem})` : '';
    steps.say(
      `No plan: refused as ${String(refusedPlan.reason)} at ${String(refusedPlan.seq)}${problem}. Nothing was changed; the refusal is kept in the evidence store. Playbook H says what each reason means.`,
    );
    return 1;
  }
  return refusedOrUnclear(steps, said, 'Run the same command again: a plan only reads.');
}

/** A refusal the run said, or an unclear end: what to do next. Always 1. */
function refusedOrUnclear(steps: JobSteps, said: readonly Readonly<Record<string, unknown>>[], again: string): number {
  const refused = said.find((line) => line.event === 'operator.refused');
  if (refusedFor(refused, NO_REQUEST_PROBLEM)) {
    steps.say(
      `The run found no request, so nothing changed: Azure hadn't put it in place when the run started. ${again}`,
    );
    return 1;
  }
  const refusedSaid = problemsSaid(refused);
  steps.say(
    refusedSaid === undefined
      ? `The run's lines don't say what it did: they may not all have arrived. Read the lines above. ${again}`
      : `Refused, and nothing changed: ${refusedSaid}.`,
  );
  return 1;
}

/** What each refused repair means, in plain words, by its reason. */
const RESTORE_REFUSALS: Readonly<Record<string, (line: Readonly<Record<string, unknown>>) => string>> = {
  plan: (line) =>
    `the plan made now is refused (${String(line.planRefused)} at ${String(line.seq)}): make a new plan and read why`,
  stale: () => 'the plan made now is not the one asked for: something changed since it was read. Make a new plan',
  signing_start: () =>
    "where the operator's signing starts on the live chain changed after the plan read it: treat it as tampering (playbook B)",
  moved: () => 'the live chain changed as the repair began: make a new plan',
  unverified: (line) =>
    `the chain as written failed its check (${String(line.problem)} at ${String(line.seq)}), so every write was rolled back`,
};

/** What a repair's run did: 0 once the chain is repaired. */
function restoreOutcome(steps: JobSteps, lines: readonly LogLine[], asked: RestoreArguments, id: string): number {
  const said = commandLines(lines);
  const about = (event: string) => said.find((line) => line.event === event && line.restoreId === id);
  const records = `${asked.orgId}/chain-restore-${id}-start.ndjson and -outcome.ndjson`;
  const restored = about('operator.chain_restored');
  if (restored !== undefined) {
    steps.say(
      `Repaired: ${String(restored.putBack)} rows put back, ${String(restored.replaced)} replaced, ${String(restored.removed)} removed; the chain checks whole to ${String(restored.endsAt)}. The records are in the evidence store as ${records}. The organisation stays on hold: its admin clears it with a step-up once the investigation is recorded.`,
    );
    // The head a rebase names (4D2e E11), said only by a repair that logs its hash.
    if (typeof restored.endsAtHash === 'string') {
      steps.say(
        `If the anchor check then alarms "anchor" for this chain, the rebase, once its head is checked: node deploy/azure/operator.ts chain-rebase --chain ${asked.orgId} --seq ${String(restored.endsAt)} --hash ${restored.endsAtHash} --reason repaired --evidence <incident reference>`,
      );
    }
    return 0;
  }
  const refusedRepair = about('operator.chain_restore_refused');
  if (refusedRepair !== undefined) {
    const why = RESTORE_REFUSALS[String(refusedRepair.reason)]?.(refusedRepair) ?? String(refusedRepair.reason);
    steps.say(`Not repaired, and nothing changed: ${why}. The records are in the evidence store as ${records}.`);
    return 1;
  }
  if (about('operator.done_before') !== undefined) {
    steps.say(
      `This repair's ID ran before, so nothing was done now: its records in the evidence store (${records}) say how it ended. A new repair needs no --id.`,
    );
    return 1;
  }
  return refusedOrUnclear(
    steps,
    said,
    `Run the same command again with --id ${id}: a repair that ran stops at its first record and does nothing twice.`,
  );
}

/** What a repair's every run sets off, said before it starts (playbook I). */
const OWNER_LOGIN_SAID =
  'This run logs in as the database\'s owner, so the "login by the owner role outside a deploy" SEV-1 alert fires for it about 20 to 35 minutes later, by design. Note this run in the incident log.';

/** Plans an organisation's chain recovery on the operator's job (4D2e E9): 0 once a plan is made. Read-only. */
export function recoveryPlan(asked: RecoveryPlanArguments, steps: JobSteps): Promise<number> {
  const planId = uuidV7Ids.next();
  const again = 'Run the same command again: a plan only reads, so nothing is done twice.';
  return runRequest(steps, () => ({
    text: chainRecoveryRequest(asked.orgId, planId, asked.discardFork),
    intro: `Planning ${planId} for ${asked.orgId} from the drill's copy, read-only on both servers.`,
    tryAgain: again,
    mayStillHold: `The request may still be on ${jobName('operator')}: it only reads. ${again} It takes the request off at its end, as does deploy.ts apps.`,
    judge: (_run, lines) => planOutcome(steps, lines, asked, planId),
  }));
}

/** Repairs an organisation's chain from its plan on the chain repair's job (4D2e E10): 0 once repaired. */
export function chainRestore(asked: RestoreArguments, steps: JobSteps): Promise<number> {
  const id = asked.id ?? uuidV7Ids.next();
  const again = `Run the same command again with --id ${id}: a repair that ran stops at its first record and does nothing twice.`;
  return runRequest(
    steps,
    () => ({
      text: chainRestoreRequest(
        { orgId: asked.orgId, planId: asked.planId, digest: asked.digest, id },
        asked.discardFork,
      ),
      intro: `Repairing ${asked.orgId}'s chain from plan ${asked.planId}, as repair ${id}. ${OWNER_LOGIN_SAID}`,
      tryAgain: again,
      mayStillHold: `The request may still be on ${jobName('chain-restore')}. It names ${id}, so it can't repair twice. ${again} It takes the request off at its end, as does deploy.ts apps.`,
      judge: (_run, lines) => restoreOutcome(steps, lines, asked, id),
    }),
    'chain-restore',
  );
}

/** What an authority rows' plan's run did: 0 once a plan is made, saying its digest and the repair's command. */
function statePlanOutcome(steps: JobSteps, lines: readonly LogLine[], asked: StatePlanArguments, planId: string) {
  const said = commandLines(lines);
  const about = (event: string) => said.find((line) => line.event === event && line.planId === planId);
  const planned = about('operator.state_recovery_planned');
  if (planned !== undefined) {
    steps.say(
      `Planned ${planId}: ${String(planned.putBack)} records to put back, ${String(planned.removed)} planted ones to remove, of ${String(planned.objects)} checked. Nothing was changed. The plan and its rows are in the evidence store as ${asked.orgId}/state-recovery-${planId}.ndjson.`,
    );
    steps.say(
      `Once read, the repair is: node deploy/azure/operator.ts state-restore --org ${asked.orgId} --plan ${planId} --digest ${String(planned.digest)}`,
    );
    return 0;
  }
  const refusedPlan = about('operator.state_recovery_refused');
  if (refusedPlan !== undefined) {
    const where =
      typeof refusedPlan.objectId === 'string' ? ` on ${String(refusedPlan.subjectType)} ${refusedPlan.objectId}` : '';
    const problem = typeof refusedPlan.problem === 'string' ? ` (${refusedPlan.problem})` : '';
    steps.say(
      `No plan: refused as ${String(refusedPlan.reason)}${where}${problem}. Nothing was changed; the refusal is kept in the evidence store. Playbook H says what each reason means.`,
    );
    return 1;
  }
  return refusedOrUnclear(steps, said, 'Run the same command again: a plan only reads.');
}

/** What each refused authority rows' repair means, in plain words, by its reason. */
const STATE_RESTORE_REFUSALS: Readonly<Record<string, (line: Readonly<Record<string, unknown>>) => string>> = {
  plan: (line) => `the plan made now is refused (${String(line.planRefused)}): make a new plan and read why`,
  stale: () => 'the plan made now is not the one asked for: something changed since it was read. Make a new plan',
  moved: (line) => `${String(line.subjectType)} ${String(line.objectId)} changed as the repair began: make a new plan`,
  write_refused: (line) =>
    `the database refused a write (code ${String(line.code)}), so every write was rolled back: read playbook H`,
  unverified: (line) =>
    `what was written did not check out (${String(line.check)}), so every write was rolled back: treat it as tampering (playbook B)`,
};

/** What an authority rows' repair's run did: 0 once repaired. */
function stateRestoreOutcome(steps: JobSteps, lines: readonly LogLine[], asked: StateRestoreArguments, id: string) {
  const said = commandLines(lines);
  const about = (event: string) => said.find((line) => line.event === event && line.restoreId === id);
  const records = `${asked.orgId}/state-restore-${id}-start.ndjson and -outcome.ndjson`;
  const restored = about('operator.states_restored');
  if (restored !== undefined) {
    steps.say(
      `Repaired: ${String(restored.putBack)} records put back, ${String(restored.removed)} planted ones removed; every record checks whole. The records are in the evidence store as ${records}. The organisation stays on hold: its admin clears it with a step-up once the investigation is recorded.`,
    );
    return 0;
  }
  const refusedRepair = about('operator.state_restore_refused');
  if (refusedRepair !== undefined) {
    const why = STATE_RESTORE_REFUSALS[String(refusedRepair.reason)]?.(refusedRepair) ?? String(refusedRepair.reason);
    steps.say(`Not repaired, and nothing changed: ${why}. The records are in the evidence store as ${records}.`);
    return 1;
  }
  if (about('operator.done_before') !== undefined) {
    steps.say(
      `This repair's ID ran before, so nothing was done now: its records in the evidence store (${records}) say how it ended. A new repair needs no --id.`,
    );
    return 1;
  }
  return refusedOrUnclear(
    steps,
    said,
    `Run the same command again with --id ${id}: a repair that ran stops at its first record and does nothing twice.`,
  );
}

/** Plans an organisation's authority rows' recovery on the chain repair's job (PL-29 follow-up): 0 once planned. */
export function stateRecoveryPlan(asked: StatePlanArguments, steps: JobSteps): Promise<number> {
  const planId = uuidV7Ids.next();
  const again = 'Run the same command again: a plan only reads, so nothing is done twice.';
  return runRequest(
    steps,
    () => ({
      text: stateRecoveryRequest(asked.orgId, planId),
      intro: `Planning ${planId} for ${asked.orgId}'s records from the drill's copy, read-only on both servers. ${OWNER_LOGIN_SAID}`,
      tryAgain: again,
      mayStillHold: `The request may still be on ${jobName('chain-restore')}: it only reads. ${again} It takes the request off at its end, as does deploy.ts apps.`,
      judge: (_run, lines) => statePlanOutcome(steps, lines, asked, planId),
    }),
    'chain-restore',
  );
}

/** Repairs an organisation's authority rows from their plan on the chain repair's job: 0 once repaired. */
export function stateRestore(asked: StateRestoreArguments, steps: JobSteps): Promise<number> {
  const id = asked.id ?? uuidV7Ids.next();
  const again = `Run the same command again with --id ${id}: a repair that ran stops at its first record and does nothing twice.`;
  return runRequest(
    steps,
    () => ({
      text: stateRestoreRequest({ orgId: asked.orgId, planId: asked.planId, digest: asked.digest, id }),
      intro: `Repairing ${asked.orgId}'s records from plan ${asked.planId}, as repair ${id}. ${OWNER_LOGIN_SAID}`,
      tryAgain: again,
      mayStillHold: `The request may still be on ${jobName('chain-restore')}. It names ${id}, so it can't repair twice. ${again} It takes the request off at its end, as does deploy.ts apps.`,
      judge: (_run, lines) => stateRestoreOutcome(steps, lines, asked, id),
    }),
    'chain-restore',
  );
}

/** Writes a request, runs it, puts [] back, and says what the run did: 0 once what it makes exists. */
async function runRequest(
  steps: JobSteps,
  prepare: (api: Running) => JobRequest,
  on: RequestJob = 'operator',
): Promise<number> {
  const subscription = signedIn(steps.az, steps.say);
  const target: HeldTarget = { subscription, job: on };
  const job = readOperatorJob(steps, target);
  const name = jobName(on);
  if (job.state !== 'Succeeded') {
    throw new Error(`${name} is ${job.state} from an earlier change, so nothing was written: look at it first.`);
  }
  const api = readWorkload(steps.az, subscription, 'api').running;
  const going = unfinishedRuns(steps, target);
  if (going.length > 0) {
    throw new Error(`${name} has runs that haven't ended, so nothing was written: ${going.join(', ')}.`);
  }
  const synced = released(job.running, api.image, api.release);
  const moved = !same(job.running.container, synced);
  const asked = prepare(api);
  steps.say(asked.intro);
  let execution: string;
  let run: Ended | undefined;
  try {
    const what = moved ? "writing the request and bringing the job to the API's build" : 'writing the request';
    if (moved) steps.say(`Bringing ${name} to the API's build: ${changes(job.running.container, synced).join('; ')}.`);
    patch(steps, target, patchBody(job, asked.text, moved ? synced : undefined), what);
    await settled(steps, target, job.modified, synced, what);
    steps.say(`Wrote the request onto ${name}.`);
    execution = start(steps, target);
    run = await waitFor(steps, target, execution, job.limit);
  } catch (error) {
    // Whatever stopped it, the request comes off the job; a failure to take it off is said, and the first error stands.
    await clearRequest(steps, target).catch((failure: unknown) => {
      steps.say(`Putting ${NO_REQUEST} back failed too: ${reason(failure)} ${asked.mayStillHold}`);
    });
    steps.say(asked.tryAgain);
    throw error;
  }
  // The request comes off before the log is read; a failure to take it off still lets the run's outcome be said first.
  const left = await clearRequest(steps, target).then(
    () => undefined,
    (failure: unknown) => failure,
  );
  try {
    if (run === undefined) return 1;
    const said = asked.judge(run, await readLog(steps, target, execution, run));
    return left === undefined ? said : 1;
  } catch (error) {
    // The run ended, but what it did couldn't be read.
    steps.say(asked.tryAgain);
    throw error;
  } finally {
    if (left !== undefined) steps.say(`Putting ${NO_REQUEST} back failed: ${reason(left)} ${asked.mayStillHold}`);
  }
}

export function main(
  argv: readonly string[],
  say: (line: string) => void = console.log,
  az: () => ReturnType<typeof realAz> = realAz,
): Promise<number> {
  return runCli(
    USAGE,
    say,
    (): ((steps: JobSteps) => Promise<number>) => {
      if (argv[0] === RESTORE_CHECK) {
        if (argv.length !== 1) throw new UsageError(`say ${RESTORE_CHECK}, and nothing else`);
        return restoreCheck;
      }
      if (argv[0] === 'audit-export' || argv[0] === 'activity-export') {
        const kind = argv[0];
        const request = parseAuditExport(argv, kind);
        return (steps) => auditExport(request, steps, kind);
      }
      if (argv[0] === 'handoff-pause' || argv[0] === 'handoff-resume') {
        const request = parseHandoff(argv);
        return (steps) => handoffChange(request, steps);
      }
      if (argv[0] === 'chain-recovery-plan') {
        const asked = parseRecoveryPlan(argv);
        return (steps) => recoveryPlan(asked, steps);
      }
      if (argv[0] === 'chain-restore') {
        const asked = parseRestore(argv);
        return (steps) => chainRestore(asked, steps);
      }
      if (argv[0] === 'state-recovery-plan') {
        const asked = parseStatePlan(argv);
        return (steps) => stateRecoveryPlan(asked, steps);
      }
      if (argv[0] === 'state-restore') {
        const asked = parseStateRestore(argv);
        return (steps) => stateRestore(asked, steps);
      }
      if (argv[0] === 'chain-rebase') {
        const asked = parseRebase(argv);
        return (steps) => chainRebase(asked, steps);
      }
      if (argv[0] === 'invite-first-admin') {
        const request = parseFirstAdmin(argv);
        return (steps) => inviteFirstAdmin(request, steps);
      }
      const request = parseArguments(argv);
      return (steps) => createOrganization(request, steps);
    },
    (work) => work({ az: az(), say, now: () => new Date(), sleep: (ms) => sleep(ms) }),
  );
}

if (import.meta.main) process.exitCode = await main(process.argv.slice(2));
