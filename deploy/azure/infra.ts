// CI's approved infrastructure deploy (AZ5, decision 40): the hand deploys a
// merge needs run from GitHub once the partner taps Approve, never from a
// standing right. In the release workflow, after CI's image of the commit:
//
//   node deploy/azure/infra.ts plan <commit> <digest>   # staging-whatif: read-only
//   node deploy/azure/infra.ts deploy <step> <commit>   # staging-infra: after Approve
//   node deploy/azure/infra.ts deployers                # the partner's own terminal, once
//
// `plan` reads what staging runs and, as the release's gate does
// (release.ts decide), which hand deploys the merge needs: foundation, secrets
// (its machine part alone, `--keys`), apps and then the set-up job. For each it
// runs deploy.ts's own steps unattended up to Azure's what-if, under an
// identity that can only read, and says what each would change, in names and
// paths, never values (CI's log is public). Each what-if is reduced to its
// changes and hashed; the plan is the steps and the hashes.
//
// `deploy` runs one planned step after the partner's Approve, as an identity
// Azure trusts only in GitHub's `staging-infra` environment: deploy.ts's same
// steps, the what-if asked again and its hash held to the plan's, so what is
// sent is what was approved; any other change since (Azure's or a later
// merge's) stops it, red, nothing sent. The set-up job (jobs.ts run db-setup)
// is the workflow's own step. Then the release runs, as before.
//
// What stays a person's: anything plan can't answer from a GitHub secret (the
// database admin's and Zitadel's admin's passwords, an issued secret, a
// rotation), the certificates (issued only while the apps keep running), a
// first foundation, a log alert to delete (S172), the partner's `access`
// deployment (every custom role, the guardrails, the activity log and the
// budget: review S190) and deployers.bicep itself. Each of those leaves the plan
// empty and the release red, as before AZ5.
import { createHash } from 'node:crypto';
import { appendFileSync } from 'node:fs';

import { fileReferences } from '../../tooling/bicep/references.ts';
import { IMAGE_REPOSITORY } from '../image/verify.ts';
import {
  type Answer,
  type Az,
  azJson,
  deploy,
  type Deployment,
  DEPLOYMENTS,
  deploymentName,
  realAz,
  realSteps,
  realTerminal,
  type Request,
  type Steps,
  type Terminal,
  text,
} from './deploy.ts';
import { type History, realHistory } from './git.ts';
import {
  azureRefusal,
  behindRecords,
  decide,
  handDeployed,
  ORDER,
  PARAMS_PATHS,
  type Readers,
  readersFrom,
  readWorkload,
  recordsIn,
  settingValue,
} from './release.ts';

/** What an approved run may do, in the order it does them; db-setup is the workflow's own step (jobs.ts). */
export const STEPS = ['foundation', 'secrets', 'apps', 'db-setup'] as const;
export type Step = (typeof STEPS)[number];

/** The steps that are deployments, each with a what-if. */
export type Sent = Exclude<Step, 'db-setup'>;

/** The plan the partner approves: the steps, and each deployment's what-if by its hash. */
export interface Plan {
  readonly steps: readonly Step[];
  readonly whatIf: Readonly<Partial<Record<Sent, string>>>;
}

/** The area of hand-deployed.json that is Azure's own set-up: a file in it no deployment reads is a person's. */
const AZURE_AREA = 'deploy/azure/';

/** What GitHub's environment gives for each prompt, by the variable deploy.ts sends it as. */
export const ANSWER_VARIABLES: Readonly<Record<Answer, string>> = {
  alertEmail: 'AGENTX_AZURE_ALERT_EMAIL',
  authHost: 'AGENTX_AZURE_AUTH_HOST',
  appHost: 'AGENTX_AZURE_APP_HOST',
  adminEmail: 'AGENTX_AZURE_ZITADEL_ADMIN_EMAIL',
  apiClientId: 'AGENTX_AZURE_API_OIDC_CLIENT_ID',
};

/** One value a what-if says changes: where, and what it was and becomes. */
export interface Leaf {
  readonly path: string;
  readonly before: unknown;
  readonly after: unknown;
}

/** One resource a what-if says changes, by its ID and Azure's word for the change. */
export interface Changed {
  readonly resource: string;
  readonly change: string;
  readonly leaves: readonly Leaf[];
}

/** Where a workload names its image, and a setting's value, as a what-if's paths name them. */
const IMAGE_PATH = /^properties\.template\.(?:initContainers|containers)\.\d+\.image$/;
const SETTING_PATH = /^properties\.template\.containers\.(\d+)\.env\.(\d+)\.value$/;

/** Our own image by digest, the one every release moves (and nothing else's). */
const ourImage = (value: unknown): boolean =>
  typeof value === 'string' &&
  value.startsWith(`${IMAGE_REPOSITORY}@sha256:`) &&
  /^[0-9a-f]{64}$/.test(value.slice(-64));

const absentOr = (value: unknown, test: (value: unknown) => boolean): boolean =>
  value === undefined || value === null || test(value);

/** The name of the setting a path's value is, read from the resource's own body before or after. */
function settingName(bodies: readonly unknown[], container: string, setting: string): unknown {
  for (const body of bodies) {
    const containers = (body as { properties?: { template?: { containers?: unknown } } } | null)?.properties?.template
      ?.containers;
    const env = Array.isArray(containers) ? (containers[Number(container)] as { env?: unknown } | undefined)?.env : [];
    const name = Array.isArray(env) ? (env[Number(setting)] as { name?: unknown } | undefined)?.name : undefined;
    if (name !== undefined) return name;
  }
  return undefined;
}

/** A commit, as git writes it in full. */
const commit = (value: unknown): boolean => typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);

/**
 * A value every release moves, so never a change of the set-up: our own image at a workload's image path, and a
 * commit in AGENTX_RELEASE. Anything else, an image of anyone else's, any tag, or a commit-shaped value elsewhere,
 * counts. The hand deploys' records (`tags.agentx-deployed-<part>`) count too: apps carries them (S191), so they show
 * no change in the plan or the deploy, and a record lost or moved is shown to the partner before Approve.
 */
function movedByReleases(leaf: Leaf, bodies: readonly unknown[]): boolean {
  if (IMAGE_PATH.test(leaf.path)) return absentOr(leaf.before, ourImage) && absentOr(leaf.after, ourImage);
  const setting = SETTING_PATH.exec(leaf.path);
  if (setting === null || settingName(bodies, String(setting[1]), String(setting[2])) !== 'AGENTX_RELEASE')
    return false;
  return absentOr(leaf.before, commit) && absentOr(leaf.after, commit);
}

/** A what-if's property changes as leaves, each under its whole path (an array's items by index). */
function deltaLeaves(deltas: unknown, prefix: string): Leaf[] {
  if (!Array.isArray(deltas)) return [];
  return deltas.flatMap((item: { path?: unknown; before?: unknown; after?: unknown; children?: unknown }) => {
    const path = prefix === '' ? text(item.path) : `${prefix}.${text(item.path)}`;
    return Array.isArray(item.children) && item.children.length > 0
      ? deltaLeaves(item.children, path)
      : [{ path, before: item.before, after: item.after }];
  });
}

/** A new resource's whole body as leaves, nothing before. */
function bodyLeaves(value: unknown, path: string): Leaf[] {
  if (typeof value !== 'object' || value === null) return [{ path, before: null, after: value }];
  return Object.entries(value).flatMap(([key, child]) => bodyLeaves(child, path === '' ? key : `${path}.${key}`));
}

const byText = (one: string, other: string): number => (one < other ? -1 : Number(one > other));

/**
 * What a what-if (az deployment … what-if --no-pretty-print) says changes, in a fixed order: each resource that
 * changes and each value with it. Unchanged and ignored resources drop out, and so does a value every release moves
 * (movedByReleases), and a resource whose only change that is: the plan runs before the deploy's own migration, so
 * neither may make the two differ.
 */
export function whatIfShape(result: unknown): Changed[] {
  const read = result as { status?: unknown; changes?: unknown } | null;
  if (read?.status !== 'Succeeded' || !Array.isArray(read.changes)) {
    throw new Error(`Azure's what-if didn't succeed (${text(read?.status) || 'no status'}): this step was not sent.`);
  }
  return read.changes
    .flatMap(
      (item: { resourceId?: unknown; changeType?: unknown; before?: unknown; after?: unknown; delta?: unknown }) => {
        const change = text(item.changeType);
        if (change === 'NoChange' || change === 'Ignore') return [];
        const all = change === 'Create' ? bodyLeaves(item.after, '') : deltaLeaves(item.delta, '');
        const leaves = all.filter((leaf) => !movedByReleases(leaf, [item.after, item.before]));
        if (change === 'Modify' && leaves.length === 0 && all.length > 0) return [];
        return [{ resource: text(item.resourceId), change, leaves: leaves.toSorted((a, b) => byText(a.path, b.path)) }];
      },
    )
    .toSorted((a, b) => byText(a.resource.toLowerCase(), b.resource.toLowerCase()));
}

/** A what-if's changes as one hash: the same changes, values included, give the same one. */
export const shapeHash = (shape: readonly Changed[]): string =>
  createHash('sha256')
    .update(JSON.stringify(shape.map((changed) => ({ ...changed, resource: changed.resource.toLowerCase() }))))
    .digest('hex');

/** A resource by its type and name alone: the subscription's ID stays out of CI's public log. */
const local = (resource: string): string =>
  resource
    .replace(/^\/subscriptions\/[^/]+/i, '')
    .replace(/^\/resourceGroups\/[^/]+/i, '')
    .replace(/^\/providers\//i, '');

/** Built-in roles by their IDs, so a grant of one reads as what it is. */
const BUILT_IN_ROLES: Readonly<Record<string, string>> = {
  '8e3af657-a8ff-443c-a75c-2fe8c4bcb635': 'Owner',
  '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9': 'User Access Administrator',
  'f58310d9-a9f6-439a-9e8d-f62e7b41a168': 'Role Based Access Control Administrator',
  'b24988ac-6180-42a0-ab88-20f7382dd24c': 'Contributor',
  'acdd72a7-3385-48ef-bd42-f606fba81ae7': 'Reader',
  '4633458b-17de-408a-b874-0445c86b69e6': 'Key Vault Secrets User',
};

const GUID_TEXT = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * Whether a change is one a reviewer must see the values of before Approve (review S190): a grant or a role, a policy
 * rule, a trust, the network's rules and the ways in (ingress, a door, a firewall, an allow-list).
 */
const securityRelevant = (resource: string, path: string): boolean =>
  /\/Microsoft\.(?:Authorization|Network)\/|\/federatedIdentityCredentials\/|\/httpRouteConfigs\/|\/firewallRules\//i.test(
    resource,
  ) ||
  /ingress|networkAcls|ipRules|ipSecurityRestrictions|publicNetworkAccess|allowedIps|virtualNetworkRules/i.test(path);

/**
 * A value as the plan shows it. Numbers and switches always; a text only where the change is security-relevant, its
 * GUIDs out (a built-in role by its name), at most 200 characters: a text elsewhere can name the domain or a person.
 */
function shown(value: unknown, relevant: boolean): string | undefined {
  if (typeof value === 'number' || typeof value === 'boolean' || value === null || value === undefined) {
    return String(value);
  }
  if (!relevant) return undefined;
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  const clean = raw.replace(GUID_TEXT, (guid) => BUILT_IN_ROLES[guid.toLowerCase()] ?? '<id>');
  return clean.length > 200 ? `${clean.slice(0, 200)}…` : clean;
}

/** One value's line: its path, and what it was and becomes where both may be shown. */
function leafLine(resource: string, leaf: Leaf): string {
  const relevant = securityRelevant(resource, leaf.path);
  const before = shown(leaf.before, relevant);
  const after = shown(leaf.after, relevant);
  return before === undefined || after === undefined ? `    ${leaf.path}` : `    ${leaf.path}: ${before} -> ${after}`;
}

/** At most this many values a resource are named, with how many more. */
const SHOWN_LEAVES = 12;

/**
 * What a what-if changes, in words: each resource, and the paths of its values, with the values themselves where a
 * reviewer must see them (leafLine). A new security-relevant resource is shown value by value too.
 */
/** A what-if's resource as it reads it: its ID, Azure's word for the change, and its body after or before. */
interface WhatIfChange {
  readonly resourceId?: unknown;
  readonly changeType?: unknown;
  readonly before?: unknown;
  readonly after?: unknown;
}

const IDENTITY = /\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/([^/]+)$/i;
const TRUST = /\/userAssignedIdentities\/([^/]+)\/federatedIdentityCredentials\/[^/]+$/i;
const GRANT = /\/providers\/Microsoft\.Authorization\/roleAssignments\/[^/]+$/i;

/** A body's `properties.<field>`, as text. */
const propertyOf = (body: unknown, field: string): string =>
  text((body as { properties?: Record<string, unknown> } | null)?.properties?.[field]);

/** Who a grant is to, in words: an identity of this deployment by name, one it makes, or an existing principal. */
function grantee(change: WhatIfChange, ours: ReadonlyMap<string, string>): string {
  const principal = propertyOf(change.after, 'principalId') || propertyOf(change.before, 'principalId');
  const known = ours.get(principal);
  if (known !== undefined) return `grant to ${known}, an identity of this deployment`;
  // An identity made by this same deployment has no ID until it exists, and what-if leaves the expression; it says no more.
  if (principal.startsWith('[')) return "grant to a principal the what-if can't resolve yet";
  return "grant to an existing principal this deployment doesn't make (<id>)";
}

/**
 * Who each changed grant and trust is for (review S190), so the partner sees it before Approve: a grant to an identity
 * this deployment holds is named; any other is flagged as a grant to an existing principal, which the deployment
 * doesn't make. A trust on an identity this deployment doesn't hold is flagged the same way. Unchanged ones are none.
 */
export function describeGrants(result: unknown): string[] {
  const changes = (result as { changes?: unknown } | null)?.changes;
  const all: readonly WhatIfChange[] = Array.isArray(changes) ? (changes as WhatIfChange[]) : [];
  const ours = new Map<string, string>();
  // Ignore (in the group, not in the template) and Delete are identities the deployment doesn't hold.
  for (const change of all.filter((each) => !['Ignore', 'Delete'].includes(text(each.changeType)))) {
    const name = IDENTITY.exec(text(change.resourceId))?.[1];
    const principal = propertyOf(change.after, 'principalId') || propertyOf(change.before, 'principalId');
    if (name === undefined) continue;
    ours.set(`name:${name.toLowerCase()}`, name);
    if (principal !== '') ours.set(principal, name);
  }
  const lines: string[] = [];
  for (const change of all.filter((each) => !['NoChange', 'Ignore'].includes(text(each.changeType)))) {
    const id = text(change.resourceId);
    if (GRANT.test(id)) lines.push(`  ${text(change.changeType)} ${grantee(change, ours)}: ${local(id)}`);
    const trusted = TRUST.exec(id)?.[1];
    if (trusted !== undefined && !ours.has(`name:${trusted.toLowerCase()}`)) {
      lines.push(`  ${text(change.changeType)} trust on an existing identity this deployment doesn't make: ${trusted}`);
    }
  }
  return lines.length === 0 ? [] : ['Who the changed grants and trusts are for:', ...lines];
}

export function describeShape(part: Sent, shape: readonly Changed[]): string[] {
  if (shape.length === 0) return [`${part}: Azure's what-if shows no change.`];
  const lines = [`${part}: Azure's what-if shows ${String(shape.length)} resource(s) changing:`];
  for (const changed of shape) {
    const listed = changed.change !== 'Create' || securityRelevant(changed.resource, '');
    lines.push(
      listed
        ? `  ${changed.change} ${local(changed.resource)}`
        : `  Create ${local(changed.resource)} (${String(changed.leaves.length)} values)`,
    );
    if (!listed) continue;
    for (const leaf of changed.leaves.slice(0, SHOWN_LEAVES)) lines.push(leafLine(changed.resource, leaf));
    if (changed.leaves.length > SHOWN_LEAVES) {
      lines.push(`    and ${String(changed.leaves.length - SHOWN_LEAVES)} more`);
    }
  }
  return lines;
}

/** A plan run's end once Azure's what-if is read: nothing was sent, and the hash is what an approval holds to. */
export class Planned extends Error {
  readonly part: Sent;
  readonly hash: string;

  constructor(part: Sent, hash: string) {
    super(`${part} planned: nothing was sent.`);
    this.name = 'Planned';
    this.part = part;
    this.hash = hash;
  }
}

/** The deployment a deploy.ts command sends, by its parameters file; the certificates and access stay a person's. */
function partOf(args: readonly string[]): Sent {
  const file = args[args.indexOf('--parameters') + 1];
  const part = (Object.keys(DEPLOYMENTS) as Deployment[]).find((each) => DEPLOYMENTS[each] === file);
  if (part === undefined || BY_HAND.has(part)) {
    throw new Error(`An unattended run sends foundation, secrets or apps, not ${file ?? 'nothing'}: it was not sent.`);
  }
  return part as Sent;
}

/** The deployments only a person runs: the certificates (issued only while the apps keep running) and access (AZ5). */
const BY_HAND: ReadonlySet<Deployment> = new Set(['certificates', 'access']);

/**
 * The CLI for an unattended run (AZ5): deploy.ts's what-if-and-send (`--confirm-with-what-if`, which waits for a
 * person's y) becomes the what-if alone, read as JSON and said in words; a plan ends there (Planned), a deploy sends
 * only when the what-if is the one approved. deploy.ts's check alone (`what-if` in the command's place, asked before
 * a migration) answers 0 only when it is, sending nothing. Everything else runs as deploy.ts runs it.
 */
export function unattendedAz(
  base: Az,
  mode: 'plan' | 'deploy',
  approved: Plan['whatIf'],
  say: (line: string) => void,
): Az {
  return {
    run: (args, values) => base.run(args, values),
    interactive: (args, values) => {
      const checking = args[2] === 'what-if';
      if ((args[2] !== 'create' && !checking) || !args.includes('--confirm-with-what-if')) {
        throw new Error(`An unattended run can't answer az ${args.slice(0, 3).join(' ')}: it was not sent.`);
      }
      const part = partOf(args);
      const sent = args.filter((arg) => arg !== '--confirm-with-what-if').with(2, 'create');
      const asked = base.run([...sent.with(2, 'what-if'), '--no-pretty-print', '--output', 'json'], values);
      if (asked.status !== 0) {
        say(`Azure's what-if of ${part} failed (${azureRefusal(asked.stderr)}): ${part} was not sent.`);
        return 1;
      }
      const result: unknown = JSON.parse(asked.stdout);
      const shape = whatIfShape(result);
      for (const line of [...describeShape(part, shape), ...describeGrants(result)]) say(line);
      const hash = shapeHash(shape);
      if (mode === 'plan') throw new Planned(part, hash);
      if (approved[part] !== hash) {
        say(
          `${part}'s what-if isn't the one the partner approved: Azure or a later merge changed something since the plan, so ${part} was not sent (any step before it in this job was). Re-run this workflow's jobs, read the new plan, and approve that.`,
        );
        return 1;
      }
      if (checking) return 0;
      const done = base.run([...sent, '--output', 'none'], values);
      if (done.status !== 0) {
        say(
          `Azure didn't finish the ${part} deployment (${azureRefusal(done.stderr)}): what it did is in the resource group's deployments. Read why there, fix it, and run the release workflow again.`,
        );
      }
      return done.status;
    },
  };
}

/** A terminal with nobody at it: it prints, and any question fails the run, since none may be answered by chance. */
export function unattendedTerminal(say: (line: string) => void): Terminal {
  const refuse = (question: string): Promise<string> =>
    Promise.reject(
      new Error(
        `An unattended run can't answer "${question.trim()}": this step stays a hand deploy (deploy.ts), and was not sent.`,
      ),
    );
  return { say, ask: refuse, askHidden: refuse };
}

/** What a merge needs: the steps CI may run, and anything only a person may (each said why). */
export interface Needs {
  readonly steps: readonly Step[];
  readonly byHand: readonly string[];
}

/**
 * The steps for the files changed since what staging runs, as the release's gate reads them: a file a deployment
 * reads needs that deployment unless its record has it (`recorded`); a file of the set-up job's own areas needs apps,
 * for the image, then the job; a file the certificates or access read (every custom role, the guardrails, the budget:
 * AZ5), and any other file under deploy/azure, the deployers' among them, is a person's.
 */
export function needsOf(
  changed: readonly string[],
  readers: Readers,
  recorded: (deployment: Deployment, file: string) => boolean,
): Needs {
  const each = changed.map((file) => fileNeeds(file, readers, recorded));
  const steps = new Set(each.flatMap((needs) => needs.steps));
  return { steps: STEPS.filter((step) => steps.has(step)), byHand: each.flatMap((needs) => needs.byHand) };
}

/** What one changed file needs (needsOf). */
function fileNeeds(file: string, readers: Readers, recorded: (deployment: Deployment, file: string) => boolean): Needs {
  const area = handDeployed(file);
  if (area === undefined) return { steps: [], byHand: [] };
  const read = readers.get(file.toLowerCase());
  if (read === undefined) {
    return area.prefix === AZURE_AREA
      ? { steps: [], byHand: [`${file}: no deployment CI makes reads it (${area.why})`] }
      : { steps: ['apps', 'db-setup'], byHand: [] };
  }
  const unrecorded = read.filter((deployment) => !recorded(deployment, file));
  return {
    steps: unrecorded.filter((deployment): deployment is Sent => !BY_HAND.has(deployment)),
    byHand: unrecorded
      .filter((deployment) => BY_HAND.has(deployment))
      .map((deployment) => `${file}: ${deployment} reads it, which only the partner runs (deploy.ts ${deployment})`),
  };
}

/** What an unattended run is given: Azure's CLI signed in, the history, Bicep's references and deploy.ts. */
export interface InfraSteps {
  readonly az: Az;
  readonly history: History;
  readonly references: (paramsFiles: readonly string[]) => Promise<ReadonlyMap<string, readonly string[]>>;
  readonly say: (line: string) => void;
  readonly answers: Readonly<Record<Answer, string>>;
  readonly deploy: (request: Request, steps: Steps) => Promise<number>;
  readonly steps: (terminal: Terminal, az: Az) => Steps;
}

/** The subscription the CLI is signed in to, by its ID, which CI's log masks. */
const subscriptionOf = (az: Az): string => text((azJson(az, ['account', 'show']) as { id?: unknown }).id);

/** What a merge to `commit` needs, read from what staging runs, as the release's gate would. */
export async function needsAt(infra: InfraSteps, commit: string, digest: string): Promise<Needs> {
  const subscription = subscriptionOf(infra.az);
  const reads = new Map(ORDER.map((workload) => [workload, readWorkload(infra.az, subscription, workload)] as const));
  const running = new Map([...reads].map(([workload, read]) => [workload, read.running] as const));
  const api = running.get('api');
  if (api !== undefined && settingValue(api.container, 'AGENTX_ROLE') === 'web') {
    return { steps: [], byHand: ['a load run is up: a person ends it (load.ts finish, then apps) first'] };
  }
  const readers = readersFrom(await infra.references([...PARAMS_PATHS.values()]));
  const records = recordsIn(reads.get('migrate')?.tags ?? {}, infra.say);
  const decision = decide(running, commit, `${IMAGE_REPOSITORY}@${digest}`, infra.history, readers, records);
  if (decision.kind !== 'by-hand') return { steps: [], byHand: [] };
  const releases = new Set([...running.values()].map((each) => each.release));
  const outside = [...releases].filter((release) => !infra.history.isAncestor(release, commit));
  if (outside.length > 0) return { steps: [], byHand: [`staging runs ${outside.join(', ')}, outside this history`] };
  const changed = new Set([...releases].flatMap((release) => infra.history.changedFiles(release, commit)));
  const recorded = (deployment: Deployment, file: string): boolean => {
    const sent = deployment === 'apps' ? undefined : records.get(deployment);
    return (
      sent !== undefined &&
      infra.history.isAncestor(sent, commit) &&
      !infra.history.changedFiles(sent, commit).some((each) => each.toLowerCase() === file.toLowerCase())
    );
  };
  // AZ5c: each recorded deployment behind its own files, which a hand apps moved the workloads past, is needed too.
  const behind = behindRecords(commit, infra.history, readers, records).map(({ deployment, file }) =>
    fileNeeds(file, new Map([[file.toLowerCase(), [deployment]]]), () => false),
  );
  const fromWorkloads = needsOf([...changed], readers, recorded);
  const steps = new Set([...fromWorkloads.steps, ...behind.flatMap((needs) => needs.steps)]);
  return {
    steps: STEPS.filter((step) => steps.has(step)),
    byHand: [...new Set([...fromWorkloads.byHand, ...behind.flatMap((needs) => needs.byHand)])],
  };
}

/** The deploy.ts request each step makes: the plain foundation, secrets' machine part, apps migrating first. */
export function requestFor(step: Sent, commit: string): Request {
  if (step === 'foundation') return { command: 'foundation', loadSize: false, alwaysOn: false };
  if (step === 'secrets') return { command: 'secrets', plan: { kind: 'keys' } };
  return { command: 'apps', commit, keepRunning: false, loadRun: false, migrateFirst: true };
}

/** deploy.ts's steps for an unattended run, its CLI and terminal swapped for CI's. */
function stepsFor(infra: InfraSteps, mode: 'plan' | 'deploy', approved: Plan['whatIf']): Steps {
  const real = infra.steps(unattendedTerminal(infra.say), unattendedAz(infra.az, mode, approved, infra.say));
  return { ...real, unattended: { mode, answers: infra.answers } };
}

/** One step planned: its what-if's hash, or an error saying why it ended before Azure was asked. */
async function planStep(infra: InfraSteps, step: Sent, commit: string): Promise<string> {
  try {
    await infra.deploy(requestFor(step, commit), stepsFor(infra, 'plan', {}));
  } catch (error) {
    if (error instanceof Planned) return error.hash;
    throw error;
  }
  throw new Error(
    `${step} stopped before Azure's what-if, for the reason above, so nothing can be approved. Fix that, or run it by hand, then run the release workflow again.`,
  );
}

/** The plan for a merge: nothing when it needs no hand deploy, or one only a person may run. */
export async function plan(infra: InfraSteps, commit: string, digest: string): Promise<Plan> {
  const needs = await needsAt(infra, commit, digest);
  if (needs.byHand.length > 0) {
    infra.say('This merge needs a hand deploy CI does not make, so nothing is planned:');
    for (const line of needs.byHand) infra.say(`  ${line}`);
    infra.say('The release says what to run by hand (deploy.ts), and stays red until it has.');
    return { steps: [], whatIf: {} };
  }
  if (needs.steps.length === 0) {
    infra.say('This merge needs no infrastructure deploy: the release goes on by itself.');
    return { steps: [], whatIf: {} };
  }
  infra.say(`This merge needs: ${needs.steps.join(', ')}. Each what-if follows; nothing is changed until Approve.`);
  infra.say(
    "If a newer merge's run plans too, it covers this one: approve the newest, and this run's wait may be cancelled (its last job, release-landed, says whether staging got main's newest).",
  );
  const whatIf: Partial<Record<Sent, string>> = {};
  for (const step of needs.steps) {
    if (step === 'db-setup') infra.say('db-setup: then the set-up job runs (jobs.ts run db-setup), with its log.');
    else whatIf[step] = await planStep(infra, step, commit);
  }
  return { steps: needs.steps, whatIf };
}

/** A plan as the plan job left it, or an error: only the shape it writes, each hash a SHA-256. */
export function planFrom(json: string): Plan {
  const read = JSON.parse(json) as { steps?: unknown; whatIf?: unknown };
  const steps = Array.isArray(read.steps) ? read.steps : [];
  const whatIf = typeof read.whatIf === 'object' && read.whatIf !== null ? read.whatIf : {};
  const hashes = Object.entries(whatIf);
  // Every step a known one, and every deployment among them with its what-if's hash, and no other hash.
  const sound =
    steps.every((step) => (STEPS as readonly unknown[]).includes(step)) &&
    hashes.length === steps.filter((step) => step !== 'db-setup').length &&
    hashes.every(([part, hash]) => steps.includes(part) && /^[0-9a-f]{64}$/.test(String(hash)));
  if (!Array.isArray(read.steps) || !sound)
    throw new Error("The plan job's output isn't a plan: nothing was deployed.");
  return { steps: steps as Step[], whatIf };
}

/** One approved step: deploy.ts's own, with the what-if held to the plan's. */
export async function deployStep(infra: InfraSteps, step: Sent, commit: string, approved: Plan): Promise<number> {
  if (!approved.steps.includes(step) || approved.whatIf[step] === undefined) {
    infra.say(`The approved plan has no ${step}: nothing was deployed.`);
    return 1;
  }
  return infra.deploy(requestFor(step, commit), stepsFor(infra, 'deploy', approved.whatIf));
}

/** Each prompt's answer from GitHub's environment, or an error naming the secret not set (never a value). */
export function answersFrom(env: Readonly<Record<string, string | undefined>>): Record<Answer, string> {
  const missing = Object.values(ANSWER_VARIABLES).filter((variable) => (env[variable] ?? '') === '');
  if (missing.length > 0) {
    throw new Error(
      `GitHub's environment doesn't give ${missing.join(', ')}: set each as a secret of staging-whatif and staging-infra (Settings, Environments). Nothing was deployed.`,
    );
  }
  return Object.fromEntries(
    Object.entries(ANSWER_VARIABLES).map(([which, variable]) => [which, String(env[variable])]),
  ) as Record<Answer, string>;
}

const COMMIT = /^[0-9a-f]{40}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

export const USAGE = `Usage:
  node deploy/azure/infra.ts plan <commit> <digest>     (CI, staging-whatif)
  node deploy/azure/infra.ts deploy foundation|secrets|apps <commit>   (CI, staging-infra, PLAN from the plan job)
  node deploy/azure/infra.ts deployers                  (the partner's own terminal, once)`;

/** Where the plan job leaves its plan and words (GitHub's step output and summary files), and the environment. */
export interface Outlets {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly append: (file: string, text: string) => void;
}

/** The plan job: the plan as its output, and every line said as its summary too. */
async function runPlan(infra: InfraSteps, args: readonly string[], outlets: Outlets): Promise<number> {
  const [commit = '', digest = ''] = args;
  if (!COMMIT.test(commit) || !DIGEST.test(digest)) {
    infra.say(USAGE);
    return 2;
  }
  const planned = await plan(infra, commit, digest);
  const output = outlets.env.GITHUB_OUTPUT;
  // `needed` alone decides whether the approval job runs at all: a merge needing none never waits for the partner.
  if (output !== undefined) {
    outlets.append(output, `plan=${JSON.stringify(planned)}\nneeded=${String(planned.steps.length > 0)}\n`);
  }
  return 0;
}

/** One deploy job step, with the plan the job was approved on. */
async function runDeploy(infra: InfraSteps, args: readonly string[], outlets: Outlets): Promise<number> {
  const [step = '', commit = ''] = args;
  if (!['foundation', 'secrets', 'apps'].includes(step) || !COMMIT.test(commit)) {
    infra.say(USAGE);
    return 2;
  }
  return deployStep(infra, step as Sent, commit, planFrom(outlets.env.PLAN ?? ''));
}

/**
 * The deployers (deployers/deployers.bicep), from the partner's own terminal: Azure's what-if read and answered
 * there, as every hand deploy is, then the two client IDs GitHub's environments take.
 */
export async function deployDeployers(terminal: Terminal, az: Az, now: () => Date): Promise<number> {
  const account = azJson(az, ['account', 'show']) as { id?: unknown; name?: unknown };
  const subscription = text(account.id);
  terminal.say(`Signed in to the subscription "${text(account.name)}" (${subscription}).`);
  if (!/^y(?:es)?$/i.test(await terminal.ask("Deploy staging's deployers into it? [y/N] "))) return 1;
  const name = deploymentName('deployers', now());
  const where = ['--subscription', subscription, '--name', name];
  terminal.say(`Azure's what-if follows. Read it, then answer y to deploy (${name}).`);
  const status = az.interactive(
    [
      'deployment',
      'sub',
      'create',
      ...where,
      '--location',
      'uaenorth',
      '--parameters',
      'deployers/staging.bicepparam',
      '--confirm-with-what-if',
    ],
    {},
  );
  const shown =
    status === 0
      ? az.run(['deployment', 'sub', 'show', ...where, '--query', 'properties', '--output', 'json'])
      : undefined;
  const ended =
    shown?.status === 0
      ? (JSON.parse(shown.stdout) as { provisioningState?: unknown; outputs?: Record<string, { value?: unknown }> })
      : undefined;
  if (ended?.provisioningState !== 'Succeeded') {
    terminal.say(
      `The deployers weren't deployed (${text(ended?.provisioningState) || 'declined or not read'}): nothing more was done.`,
    );
    return 1;
  }
  terminal.say(
    'Deployed. Put each client ID into its GitHub environment as the variable AZURE_CLIENT_ID (not a secret):',
  );
  terminal.say(`  staging-infra: ${text(ended.outputs?.infraClientId?.value)}`);
  terminal.say(`  staging-whatif: ${text(ended.outputs?.whatIfClientId?.value)}`);
  return 0;
}

/** The command asked for, with the real CLI, history, Bicep and deploy.ts unless given (tests). */
export async function main(
  argv: readonly string[],
  outlets: Outlets = {
    env: process.env,
    append: (file, text) => {
      appendFileSync(file, text);
    },
  },
  make: (say: (line: string) => void) => InfraSteps = (say) => realInfra(say, outlets.env),
): Promise<number> {
  const said: string[] = [];
  const say = (line: string): void => {
    said.push(line);
    console.log(line);
  };
  const [command, ...args] = argv;
  try {
    if (command === 'deployers') return await deployDeployers(realTerminal(), realAz(), () => new Date());
    if (command !== 'plan' && command !== 'deploy') {
      say(USAGE);
      return 2;
    }
    const infra = make(say);
    return await (command === 'plan' ? runPlan(infra, args, outlets) : runDeploy(infra, args, outlets));
  } catch (error) {
    if (!(error instanceof Error)) throw error;
    say(error.message);
    return 1;
  } finally {
    const summary = outlets.env.GITHUB_STEP_SUMMARY;
    if (summary !== undefined && said.length > 0) {
      outlets.append(summary, `\`\`\`\n${said.map((line) => scrubbed(line, outlets.env)).join('\n')}\n\`\`\`\n`);
    }
  }
}

const ANY_GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

/**
 * A line for the job's summary page, which the log's masking may not reach: each answer (a host, an address, the
 * API's client ID) by its variable's name, and every GUID (the subscription's, the tenant's) as one.
 */
export function scrubbed(line: string, env: Readonly<Record<string, string | undefined>>): string {
  let clean = line.replace(ANY_GUID, '<id>');
  for (const variable of Object.values(ANSWER_VARIABLES)) {
    const value = env[variable];
    if (value !== undefined && value !== '') clean = clean.split(value).join(`<${variable}>`);
  }
  return clean;
}

/** The real pieces: Azure's CLI as the workflow signed it in, the clone's history, the pinned Bicep, deploy.ts. */
function realInfra(say: (line: string) => void, env: Readonly<Record<string, string | undefined>>): InfraSteps {
  // First, so a secret the environment lacks is said before anything else is started.
  const answers = answersFrom(env);
  return {
    az: realAz(),
    history: realHistory(),
    references: (files) => fileReferences(files),
    say,
    answers,
    deploy,
    steps: realSteps,
  };
}

if (import.meta.main) {
  void main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
