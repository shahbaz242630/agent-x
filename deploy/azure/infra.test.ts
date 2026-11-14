// CI's approved infrastructure deploy (AZ5): what a merge needs, the what-if
// reduced and hashed, the plan held to on deploy, and the deployers' Bicep.
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { IMAGE_REPOSITORY } from '../image/verify.ts';
import type { Az, AzResult, Request, Steps, Terminal } from './deploy.ts';
import type { History } from './git.ts';
import {
  ANSWER_VARIABLES,
  answersFrom,
  type Changed,
  deployDeployers,
  deployStep,
  describeGrants,
  describeShape,
  type InfraSteps,
  main,
  needsAt,
  needsOf,
  plan,
  Planned,
  planFrom,
  requestFor,
  scrubbed,
  shapeHash,
  unattendedAz,
  unattendedTerminal,
  whatIfShape,
} from './infra.ts';
import { PARAMS_PATHS } from './release.ts';
import { build, deploymentSnapshot, inCopy, lint } from './snapshot.ts';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const AZURE_DIR = import.meta.dirname;
const full = (file: string): string => path.join(ROOT, file);
const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000a';
const OLD = 'a'.repeat(40);
const NEW = 'b'.repeat(40);
const DIGEST = `sha256:${'c'.repeat(64)}`;
const IMAGE = `${IMAGE_REPOSITORY}@${DIGEST}`;
const API = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/containerApps/ca-agentx-stg-api`;
const ok = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

describe('whatIfShape and shapeHash', () => {
  const modify = (delta: unknown, resourceId = API) => ({ resourceId, changeType: 'Modify', delta });
  const result = (...changes: unknown[]) => ({ status: 'Succeeded', changes });

  it('keeps each changed value under its whole path, and drops what does not change', () => {
    const shape = whatIfShape(
      result(
        { resourceId: '/x/unchanged', changeType: 'NoChange' },
        { resourceId: '/x/ignored', changeType: 'Ignore' },
        modify([
          {
            path: 'properties.template',
            propertyChangeType: 'Modify',
            children: [{ path: 'scale.minReplicas', propertyChangeType: 'Modify', before: 0, after: 1 }],
          },
        ]),
        { resourceId: '/x/new', changeType: 'Create', after: { properties: { size: 'B1ms', tags: [1] } } },
      ),
    );
    // In order of ID: `/subscriptions/…` before `/x/…`.
    expect(shape).toEqual([
      {
        resource: API,
        change: 'Modify',
        leaves: [{ path: 'properties.template.scale.minReplicas', before: 0, after: 1 }],
      },
      {
        resource: '/x/new',
        change: 'Create',
        leaves: [
          { path: 'properties.size', before: null, after: 'B1ms' },
          { path: 'properties.tags.0', before: null, after: 1 },
        ],
      },
    ]);
  });

  it('drops an image of ours and a commit, and a resource whose only change they are: every release moves them', () => {
    const image = {
      path: 'properties.template.containers.0.image',
      before: `${IMAGE_REPOSITORY}@sha256:${'d'.repeat(64)}`,
      after: IMAGE,
    };
    const build = { path: 'properties.template.containers.0.env.1.value', before: OLD, after: NEW };
    // The setting is AGENTX_RELEASE by the resource's own body, not by its place.
    const env = [
      { name: 'AGENTX_ROLE', value: 'all' },
      { name: 'AGENTX_RELEASE', value: NEW },
    ];
    const body = { properties: { template: { containers: [{ name: 'api', image: IMAGE, env }] } } };
    const moved = { ...modify([image, build]), after: body };
    expect(whatIfShape(result(moved))).toEqual([]);
    const cpu = { path: 'properties.template.containers.0.resources.cpu', before: 0.5, after: 1 };
    expect(whatIfShape(result(modify([image, cpu])))).toEqual([{ resource: API, change: 'Modify', leaves: [cpu] }]);
    // Anything else counts: an image not ours, our image elsewhere, a commit in another setting or path.
    const others = [
      { ...image, after: `ghcr.io/someone/else@sha256:${'e'.repeat(64)}` },
      { ...image, path: 'properties.template.volumes.0.image' },
      { ...build, path: 'properties.template.containers.0.env.0.value' },
      { ...build, path: 'tags.release' },
    ];
    for (const other of others) {
      expect(whatIfShape(result({ ...modify([other]), after: body }))).toEqual([
        { resource: API, change: 'Modify', leaves: [other] },
      ]);
    }
    // A new workload's own image and build drop out the same way.
    const created = { resourceId: API, changeType: 'Create', after: body };
    expect(whatIfShape(result(created))[0]?.leaves.map((leaf) => leaf.path)).toEqual([
      'properties.template.containers.0.env.0.name',
      'properties.template.containers.0.env.0.value',
      'properties.template.containers.0.env.1.name',
      'properties.template.containers.0.name',
    ]);
    // A deploy with nothing but a property-less change (Deploy) keeps it.
    expect(whatIfShape(result({ resourceId: API, changeType: 'Deploy' }))).toEqual([
      { resource: API, change: 'Deploy', leaves: [] },
    ]);
  });

  // S191 review: apps carries the records, so a record lost or moved is a real change the partner must see.
  it("keeps a hand deploy's record on the migration job when it changes, lost or moved, like any other tag", () => {
    const JOB = API.replace('containerApps/ca-agentx-stg-api', 'jobs/job-agentx-stg-migrate');
    const record = (path: string, before: unknown, after: unknown) => ({ path, before, after });
    const tagged = (...leaves: unknown[]) =>
      modify([{ path: 'tags', propertyChangeType: 'Modify', children: leaves }], JOB);
    for (const [kept, path] of [
      [record('agentx-deployed-access', OLD, null), 'tags.agentx-deployed-access'],
      [record('agentx-deployed-secrets', OLD, NEW), 'tags.agentx-deployed-secrets'],
      [record('agentx-deployed-foundation', undefined, NEW), 'tags.agentx-deployed-foundation'],
      [record('environment', 'staging', NEW), 'tags.environment'],
    ] as const) {
      expect(whatIfShape(result(tagged(kept)))).toEqual([
        { resource: JOB, change: 'Modify', leaves: [{ path, before: kept.before, after: kept.after }] },
      ]);
    }
  });

  it('refuses a what-if that did not succeed', () => {
    expect(() => whatIfShape({ status: 'Failed', changes: [] })).toThrow(
      "Azure's what-if didn't succeed (Failed): this step was not sent.",
    );
    expect(() => whatIfShape(null)).toThrow("Azure's what-if didn't succeed (no status): this step was not sent.");
  });

  it('hashes the same changes the same, in any order or case of ID, and any other value otherwise', () => {
    const one = modify([{ path: 'a', before: 1, after: 2 }], '/X/One');
    const two = modify([{ path: 'b', before: true, after: false }], '/x/two');
    const hash = shapeHash(whatIfShape(result(one, two)));
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(shapeHash(whatIfShape(result(two, { ...one, resourceId: '/x/one' })))).toBe(hash);
    expect(shapeHash(whatIfShape(result(one, modify([{ path: 'b', before: true, after: true }], '/x/two'))))).not.toBe(
      hash,
    );
  });
});

describe('describeShape', () => {
  it('names each resource without the subscription, shows numbers and switches, and never a text', () => {
    const shape: Changed[] = [
      { resource: '/x/new', change: 'Create', leaves: [{ path: 'a', before: null, after: 'secret.example' }] },
      {
        resource: API,
        change: 'Modify',
        leaves: [
          { path: 'properties.cpu', before: 0.5, after: 1 },
          { path: 'properties.host', before: 'auth.example.invalid', after: 'other.example.invalid' },
          ...Array.from({ length: 12 }, (_, at) => ({ path: `p${String(at)}`, before: true, after: false })),
        ],
      },
    ];
    const lines = describeShape('apps', shape);
    expect(lines.slice(0, 5)).toEqual([
      "apps: Azure's what-if shows 2 resource(s) changing:",
      '  Create /x/new (1 values)',
      '  Modify Microsoft.App/containerApps/ca-agentx-stg-api',
      '    properties.cpu: 0.5 -> 1',
      '    properties.host',
    ]);
    expect(lines.at(-1)).toBe('    and 2 more');
    expect(lines.join('\n')).not.toMatch(/example|00000000/);
    expect(describeShape('secrets', [])).toEqual(["secrets: Azure's what-if shows no change."]);
  });
});

describe('describeShape on what a reviewer must see (review S190)', () => {
  it('shows the values of a grant, a rule and a way in, each GUID out but a built-in role by its name', () => {
    const grant = `${API}/providers/Microsoft.Authorization/roleAssignments/0f0f0f0f-0000-4000-8000-000000000001`;
    const role = (guid: string) =>
      `/subscriptions/${SUBSCRIPTION}/providers/Microsoft.Authorization/roleDefinitions/${guid}`;
    const lines = describeShape('apps', [
      {
        resource: grant,
        change: 'Modify',
        leaves: [
          {
            path: 'properties.roleDefinitionId',
            before: role('acdd72a7-3385-48ef-bd42-f606fba81ae7'),
            after: role('8e3af657-a8ff-443c-a75c-2fe8c4bcb635'),
          },
        ],
      },
      {
        resource: API,
        change: 'Modify',
        leaves: [
          { path: 'properties.configuration.ingress.external', before: false, after: true },
          {
            path: 'properties.configuration.ingress.ipSecurityRestrictions.0.ipAddressRange',
            before: null,
            after: '0.0.0.0/0',
          },
          { path: 'properties.template.containers.0.env.2.value', before: 'a', after: 'b' },
        ],
      },
      {
        resource: `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg/securityRules/new`,
        change: 'Create',
        leaves: [{ path: 'properties.sourceAddressPrefix', before: null, after: '*' }],
      },
    ]);
    expect(lines).toEqual([
      "apps: Azure's what-if shows 3 resource(s) changing:",
      '  Modify Microsoft.App/containerApps/ca-agentx-stg-api/providers/Microsoft.Authorization/roleAssignments/0f0f0f0f-0000-4000-8000-000000000001',
      '    properties.roleDefinitionId: /subscriptions/<id>/providers/Microsoft.Authorization/roleDefinitions/Reader -> /subscriptions/<id>/providers/Microsoft.Authorization/roleDefinitions/Owner',
      '  Modify Microsoft.App/containerApps/ca-agentx-stg-api',
      '    properties.configuration.ingress.external: false -> true',
      '    properties.configuration.ingress.ipSecurityRestrictions.0.ipAddressRange: null -> 0.0.0.0/0',
      '    properties.template.containers.0.env.2.value',
      '  Create Microsoft.Network/networkSecurityGroups/nsg/securityRules/new',
      '    properties.sourceAddressPrefix: null -> *',
    ]);
  });
});

describe('describeGrants: who each changed grant and trust is for (review S190)', () => {
  const GROUP = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers`;
  const identity = (name: string, principalId?: string, changeType = 'NoChange') => ({
    resourceId: `${GROUP}/Microsoft.ManagedIdentity/userAssignedIdentities/${name}`,
    changeType,
    after: { properties: principalId === undefined ? {} : { principalId } },
  });
  const grant = (name: string, principalId: string, changeType = 'Create') => ({
    resourceId: `${GROUP}/Microsoft.Authorization/roleAssignments/${name}`,
    changeType,
    after: { properties: { principalId } },
  });
  const trust = (identityName: string, changeType = 'Modify') => ({
    resourceId: `${GROUP}/Microsoft.ManagedIdentity/userAssignedIdentities/${identityName}/federatedIdentityCredentials/github`,
    changeType,
  });

  it('names an identity of the deployment, and flags a grant or trust to anything it doesn’t make', () => {
    const OURS = '11111111-1111-4111-8111-111111111111';
    const lines = describeGrants({
      status: 'Succeeded',
      changes: [
        identity('id-agentx-stg-api', OURS),
        identity('id-agentx-stg-new', undefined, 'Create'),
        grant('a', OURS),
        grant('b', '22222222-2222-4222-8222-222222222222'),
        grant('c', "[reference('id-agentx-stg-new').principalId]"),
        grant('unchanged', '22222222-2222-4222-8222-222222222222', 'NoChange'),
        trust('id-agentx-stg-api'),
        trust('id-someone-else', 'Create'),
      ],
    });
    expect(lines).toEqual([
      'Who the changed grants and trusts are for:',
      '  Create grant to id-agentx-stg-api, an identity of this deployment: Microsoft.Authorization/roleAssignments/a',
      "  Create grant to an existing principal this deployment doesn't make (<id>): Microsoft.Authorization/roleAssignments/b",
      "  Create grant to a principal the what-if can't resolve yet: Microsoft.Authorization/roleAssignments/c",
      "  Create trust on an existing identity this deployment doesn't make: id-someone-else",
    ]);
    expect(describeGrants({ status: 'Succeeded', changes: [grant('d', OURS, 'NoChange')] })).toEqual([]);
    expect(describeGrants(null)).toEqual([]);
  });

  it('takes an identity the template leaves out (Ignore) or deletes as not its own: a grant or trust to it is flagged', () => {
    const OTHER = '33333333-3333-4333-8333-333333333333';
    const GONE = '44444444-4444-4444-8444-444444444444';
    const lines = describeGrants({
      status: 'Succeeded',
      changes: [
        identity('id-agentx-stg-infra', OTHER, 'Ignore'),
        identity('id-agentx-stg-old', GONE, 'Delete'),
        trust('id-agentx-stg-infra', 'Create'),
        grant('e', OTHER),
        grant('f', GONE),
      ],
    });
    expect(lines).toEqual([
      'Who the changed grants and trusts are for:',
      "  Create trust on an existing identity this deployment doesn't make: id-agentx-stg-infra",
      "  Create grant to an existing principal this deployment doesn't make (<id>): Microsoft.Authorization/roleAssignments/e",
      "  Create grant to an existing principal this deployment doesn't make (<id>): Microsoft.Authorization/roleAssignments/f",
    ]);
  });
});

/** A CLI that answers the what-if and the deployment as told, and keeps every call with what went into its environment. */
function whatIfAz(answer: { whatIf?: AzResult; create?: AzResult } = {}) {
  const calls: { args: readonly string[]; values: Readonly<Record<string, string>> | undefined }[] = [];
  const az: Az = {
    interactive: () => {
      throw new Error('never interactive');
    },
    run: (args, values) => {
      calls.push({ args, values });
      if (args[2] === 'what-if') return answer.whatIf ?? ok({ status: 'Succeeded', changes: [] });
      if (args[2] === 'create') return answer.create ?? { status: 0, stdout: '', stderr: '' };
      return ok({});
    },
  };
  return { az, calls };
}

describe('unattendedAz', () => {
  const ASKED = [
    'deployment',
    'group',
    'create',
    '--subscription',
    SUBSCRIPTION,
    '--resource-group',
    'rg-agentx-staging',
    '--name',
    'n',
    '--parameters',
    'staging.apps.bicepparam',
    '--confirm-with-what-if',
  ];
  const VALUES = { AGENTX_AZURE_APP_HOST: 'app.example.invalid' };
  const EMPTY = shapeHash([]);

  it('in a plan, asks the what-if alone, with the values, and ends with its hash, sending nothing', () => {
    const { az, calls } = whatIfAz();
    const said: string[] = [];
    const planning = unattendedAz(az, 'plan', {}, (line) => said.push(line));
    expect(() => planning.interactive(ASKED, VALUES)).toThrow(Planned);
    try {
      planning.interactive(ASKED, VALUES);
    } catch (error) {
      expect(error).toMatchObject({ part: 'apps', hash: EMPTY, message: 'apps planned: nothing was sent.' });
    }
    expect(calls.map((call) => call.args.slice(0, 3).join(' '))).toEqual([
      'deployment group what-if',
      'deployment group what-if',
    ]);
    expect(calls[0]?.args).toEqual([
      ...ASKED.slice(0, 2),
      'what-if',
      ...ASKED.slice(3, -1),
      // AZ5f: read rights alone, as the plan's identity has.
      '--validation-level',
      'ProviderNoRbac',
      '--no-pretty-print',
      '--output',
      'json',
    ]);
    expect(calls[0]?.values).toBe(VALUES);
    expect(said).toContain("apps: Azure's what-if shows no change.");
  });

  it('in a deploy, sends only the what-if the plan approved, without a question, and passes reads through', () => {
    const { az, calls } = whatIfAz();
    const said: string[] = [];
    expect(unattendedAz(az, 'deploy', { apps: EMPTY }, (line) => said.push(line)).interactive(ASKED, VALUES)).toBe(0);
    expect(calls[1]?.args).toEqual([...ASKED.slice(0, -1), '--output', 'none']);
    expect(calls[1]?.values).toBe(VALUES);
    expect(unattendedAz(az, 'deploy', {}, () => undefined).run(['account', 'show'])).toEqual(ok({}));
  });

  it('sends nothing when the what-if is not the approved one, or fails, and says why', () => {
    for (const [approved, whatIf, words] of [
      [{ apps: 'f'.repeat(64) }, undefined, "apps's what-if isn't the one the partner approved"],
      [{}, undefined, "apps's what-if isn't the one the partner approved"],
      [
        { apps: EMPTY },
        { status: 1, stdout: '', stderr: 'ERROR: Forbidden({"error":{"code":"AuthorizationFailed"}})' },
        "Azure's what-if of apps failed (Forbidden, AuthorizationFailed): apps was not sent.",
      ],
      // AZ5d: the CLI's shape when the what-if's async answer can't be read, named by its code and the right alone.
      [
        { apps: EMPTY },
        {
          status: 1,
          stdout: '',
          stderr: `ERROR: (AuthorizationFailed) The client 'x' with object id 'y' does not have authorization to perform action 'Microsoft.Resources/subscriptions/operationresults/read' over scope '/subscriptions/${'0'.repeat(8)}' or the scope is invalid.\nCode: AuthorizationFailed\nMessage: The client 'x'`,
        },
        "Azure's what-if of apps failed (AuthorizationFailed, missing Microsoft.Resources/subscriptions/operationresults/read): apps was not sent.",
      ],
      [
        { apps: EMPTY },
        { status: 1, stdout: '', stderr: 'Code: InvalidTemplate\nMessage: about /subscriptions/abc' },
        "Azure's what-if of apps failed (InvalidTemplate): apps was not sent.",
      ],
    ] as const) {
      const { az, calls } = whatIfAz(whatIf === undefined ? {} : { whatIf });
      const said: string[] = [];
      expect(unattendedAz(az, 'deploy', approved, (line) => said.push(line)).interactive(ASKED, VALUES)).toBe(1);
      expect(calls.filter((call) => call.args[2] === 'create')).toEqual([]);
      expect(said.join('\n')).toContain(words);
    }
  });

  it('answers deploy.ts’s check alone (what-if in the command’s place) by the approved hash, sending nothing', () => {
    const CHECK = ASKED.with(2, 'what-if');
    const approved = whatIfAz();
    expect(unattendedAz(approved.az, 'deploy', { apps: EMPTY }, () => undefined).interactive(CHECK, VALUES)).toBe(0);
    const changed = whatIfAz();
    const said: string[] = [];
    expect(
      unattendedAz(changed.az, 'deploy', { apps: 'f'.repeat(64) }, (line) => said.push(line)).interactive(
        CHECK,
        VALUES,
      ),
    ).toBe(1);
    for (const { calls } of [approved, changed]) {
      expect(calls.map((call) => call.args[2])).toEqual(['what-if']);
    }
    expect(said.at(-1)).toContain('so apps was not sent');
  });

  it('says what Azure gave when the deployment itself fails, never the request', () => {
    const { az } = whatIfAz({
      create: {
        status: 1,
        stdout: '',
        stderr: 'ERROR: Conflict({"error":{"code":"InvalidTemplate","message":"app.example.invalid"}})',
      },
    });
    const said: string[] = [];
    expect(unattendedAz(az, 'deploy', { apps: EMPTY }, (line) => said.push(line)).interactive(ASKED, VALUES)).toBe(1);
    expect(said.at(-1)).toBe(
      "Azure didn't finish the apps deployment (Conflict, InvalidTemplate): what it did is in the resource group's deployments. Read why there, fix it, and run the release workflow again.",
    );
  });

  it('refuses anything but a deployment with its what-if, and the certificates', () => {
    const { az } = whatIfAz();
    const unattended = unattendedAz(az, 'deploy', {}, () => undefined);
    expect(() => unattended.interactive(['deployment', 'group', 'show'], {})).toThrow(
      "An unattended run can't answer az deployment group show: it was not sent.",
    );
    expect(() =>
      unattended.interactive(
        ASKED.map((arg) => (arg === 'staging.apps.bicepparam' ? 'staging.certificates.bicepparam' : arg)),
        {},
      ),
    ).toThrow(
      'An unattended run sends foundation, secrets or apps, not staging.certificates.bicepparam: it was not sent.',
    );
    // Nor the partner's access deployment (review S190, mutation M13): a role, a guardrail, the lock, the budget.
    expect(() =>
      unattended.interactive(
        ASKED.map((arg) => (arg === 'staging.apps.bicepparam' ? 'staging.access.bicepparam' : arg)),
        {},
      ),
    ).toThrow('An unattended run sends foundation, secrets or apps, not staging.access.bicepparam: it was not sent.');
  });
});

describe('unattendedTerminal', () => {
  it('prints, and fails any question, hidden or not, rather than answer one by chance', async () => {
    const said: string[] = [];
    const terminal = unattendedTerminal((line) => said.push(line));
    terminal.say('hello');
    expect(said).toEqual(['hello']);
    await expect(terminal.ask('Deploy? ')).rejects.toThrow('An unattended run can\'t answer "Deploy?"');
    await expect(terminal.askHidden('Paste it: ')).rejects.toThrow('this step stays a hand deploy');
  });
});

describe('needsOf', () => {
  const readers = new Map([
    ['deploy/azure/main.bicep', ['foundation'] as const],
    ['deploy/azure/names.bicep', ['foundation', 'secrets', 'apps', 'certificates'] as const],
    ['deploy/azure/apps.bicep', ['apps'] as const],
    ['deploy/azure/secrets.bicep', ['secrets'] as const],
  ]);
  const never = (): boolean => false;

  it('names each deployment that reads a changed file, in order, and the set-up job after apps for its own areas', () => {
    expect(
      needsOf(
        ['deploy/azure/apps.bicep', 'deploy/azure/Main.bicep', 'README.md', 'deploy/azure/infra.ts'],
        readers,
        never,
      ),
    ).toEqual({
      steps: ['foundation', 'apps'],
      byHand: [],
    });
    expect(needsOf(['db/bootstrap/roles.sql'], readers, never)).toEqual({ steps: ['apps', 'db-setup'], byHand: [] });
    // A role, a guardrail or the budget (the partner's access deployment) is never CI's.
    expect(
      needsOf(
        ['deploy/azure/modules/roles.bicep'],
        new Map([['deploy/azure/modules/roles.bicep', ['access'] as const]]),
        never,
      ),
    ).toEqual({
      steps: [],
      byHand: ['deploy/azure/modules/roles.bicep: access reads it, which only the partner runs (deploy.ts access)'],
    });
    expect(needsOf(['deploy/azure/secrets.bicep', 'deploy/azure/infra.test.ts'], readers, never)).toEqual({
      steps: ['secrets'],
      byHand: [],
    });
  });

  it('leaves out what a record has deployed, and keeps the certificates and unread Bicep a person’s', () => {
    expect(
      needsOf(
        ['deploy/azure/names.bicep'],
        readers,
        (deployment) => deployment === 'foundation' || deployment === 'certificates',
      ),
    ).toEqual({ steps: ['secrets', 'apps'], byHand: [] });
    const needs = needsOf(['deploy/azure/names.bicep', 'deploy/azure/deployers/deployers.bicep'], readers, never);
    expect(needs.steps).toEqual(['foundation', 'secrets', 'apps']);
    expect(needs.byHand).toEqual([
      'deploy/azure/names.bicep: certificates reads it, which only the partner runs (deploy.ts certificates)',
      expect.stringMatching(/^deploy\/azure\/deployers\/deployers\.bicep: no deployment CI makes reads it \(/),
    ]);
  });
});

/** A container as Azure gives a release workload's. */
const container = (name: string, release: string, role = 'all') => ({
  name,
  image: IMAGE,
  command: ['node'],
  args: [],
  env: [
    { name: 'AGENTX_RELEASE', value: release },
    { name: 'AGENTX_ROLE', value: role },
  ],
  resources: { cpu: 0.5, memory: '1Gi' },
  volumeMounts: [],
});

/** A history: `line` oldest first, and the files changed from each commit to NEW. */
const history = (line: readonly string[], changed: Readonly<Record<string, readonly string[]>>): History => ({
  isAncestor: (ancestor, target) => line.includes(ancestor) && line.indexOf(ancestor) <= line.indexOf(target),
  changedFiles: (from) => changed[from] ?? [],
  fileAt: () => undefined,
  filesIn: () => [],
  mainline: () => new Map(line.toReversed().map((commit, place) => [commit, place] as const)),
});

/** What Bicep says each deployment reads, in full paths. */
const SAID: ReadonlyMap<string, readonly string[]> = new Map(
  [...PARAMS_PATHS].map(([deployment, params]) => [
    params,
    [params, full(`deploy/azure/${deployment === 'foundation' ? 'main' : deployment}.bicep`)],
  ]),
);

/** An unattended run's pieces over a staging that runs OLD, with deploy.ts stood in for. */
function infraOver(options: {
  readonly changed?: readonly string[];
  readonly role?: string;
  readonly line?: readonly string[];
  readonly deploy?: (request: Request, steps: Steps) => Promise<number>;
  readonly tags?: Readonly<Record<string, string>>;
  /** The commit the workloads run (a hand apps puts them at the merge's). */
  readonly running?: string;
  /** What changed since other commits than OLD (a record's). */
  readonly since?: Readonly<Record<string, readonly string[]>>;
}) {
  const said: string[] = [];
  const requests: { request: Request; steps: Steps }[] = [];
  const az: Az = {
    interactive: () => 0,
    run: (args) => {
      if (args.join(' ') === 'account show --output json') return ok({ id: SUBSCRIPTION });
      const url = args[args.indexOf('--url') + 1] ?? '';
      const workload = url.includes('/jobs/') ? 'migrate' : 'api';
      return ok({
        properties: { template: { containers: [container(workload, options.running ?? OLD, options.role)] } },
        tags: options.tags ?? {},
      });
    },
  };
  const infra: InfraSteps = {
    az,
    history: history(options.line ?? [OLD, NEW], { [OLD]: options.changed ?? [], ...options.since }),
    references: () => Promise.resolve(SAID),
    say: (line) => said.push(line),
    answers: {
      alertEmail: 'a@example.invalid',
      authHost: 'auth.example.invalid',
      appHost: 'app.example.invalid',
      adminEmail: 'b@example.invalid',
      apiClientId: '1',
    },
    deploy: (request, steps) => {
      requests.push({ request, steps });
      return options.deploy === undefined ? Promise.resolve(0) : options.deploy(request, steps);
    },
    steps: (terminal: Terminal, cli: Az) => ({ terminal, az: cli }) as unknown as Steps,
  };
  return { infra, said, requests };
}

describe('needsAt and plan', () => {
  it('plans nothing when the merge needs no hand deploy, and the release goes on alone', async () => {
    const { infra, said, requests } = infraOver({ changed: ['apps/api/src/x.ts'] });
    expect(await plan(infra, NEW, DIGEST)).toEqual({ steps: [], whatIf: {} });
    expect(said.at(-1)).toBe('This merge needs no infrastructure deploy: the release goes on by itself.');
    expect(requests).toEqual([]);
  });

  it('plans each needed deployment by its what-if’s hash, unattended in plan mode, and says the set-up job follows', async () => {
    const planned = (request: Request, steps: Steps): Promise<number> => {
      expect(steps.unattended?.mode).toBe('plan');
      expect(steps.unattended?.answers.alertEmail).toBe('a@example.invalid');
      return Promise.reject(
        new Planned(
          request.command === 'foundation' ? 'foundation' : 'apps',
          request.command.padEnd(64, '0').replace(/[^0-9a-f]/g, 'e'),
        ),
      );
    };
    const { infra, said, requests } = infraOver({
      changed: ['deploy/azure/main.bicep', 'db/bootstrap/roles.sql'],
      deploy: planned,
    });
    const made = await plan(infra, NEW, DIGEST);
    expect(made.steps).toEqual(['foundation', 'apps', 'db-setup']);
    expect(Object.keys(made.whatIf)).toEqual(['foundation', 'apps']);
    expect(requests.map(({ request }) => request)).toEqual([requestFor('foundation', NEW), requestFor('apps', NEW)]);
    expect(said).toContain(
      'This merge needs: foundation, apps, db-setup. Each what-if follows; nothing is changed until Approve.',
    );
    expect(said).toContain('db-setup: then the set-up job runs (jobs.ts run db-setup), with its log.');
  });

  it('fails the plan when a step stops before Azure is asked, so nothing can be approved', async () => {
    const { infra } = infraOver({ changed: ['deploy/azure/main.bicep'], deploy: () => Promise.resolve(1) });
    await expect(plan(infra, NEW, DIGEST)).rejects.toThrow("foundation stopped before Azure's what-if");
    const { infra: broken } = infraOver({
      changed: ['deploy/azure/main.bicep'],
      deploy: () => Promise.reject(new Error('no vault')),
    });
    await expect(plan(broken, NEW, DIGEST)).rejects.toThrow('no vault');
  });

  it('plans nothing and says why when a person must deploy: an unread file, a load run, or staging outside the history', async () => {
    const unread = infraOver({ changed: ['deploy/azure/deployers/deployers.bicep'] });
    expect(await plan(unread.infra, NEW, DIGEST)).toEqual({ steps: [], whatIf: {} });
    expect(unread.said).toContain('This merge needs a hand deploy CI does not make, so nothing is planned:');
    expect((await needsAt(infraOver({ role: 'web' }).infra, NEW, DIGEST)).byHand).toEqual([
      'a load run is up: a person ends it (load.ts finish, then apps) first',
    ]);
    const OTHER = 'e'.repeat(40);
    const outside = infraOver({ changed: ['deploy/azure/main.bicep'], line: [OTHER, NEW] });
    expect((await needsAt(outside.infra, NEW, DIGEST)).steps).toEqual([]);
  });

  it('leaves out a deployment whose record already sent the file as it is now', async () => {
    const recorded = infraOver({
      changed: ['deploy/azure/main.bicep', 'deploy/azure/apps.bicep'],
      tags: { 'agentx-deployed-foundation': NEW },
    });
    expect((await needsAt(recorded.infra, NEW, DIGEST)).steps).toEqual(['apps']);
  });

  // AZ5c: S190's first dry run planned nothing after a hand apps at the merge, though no foundation had sent #646.
  it('plans a deployment whose own record is behind on its files, though a hand apps moved the workloads past them', async () => {
    const handApps = infraOver({
      running: NEW,
      tags: { 'agentx-deployed-foundation': OLD },
      since: { [OLD]: ['deploy/azure/main.bicep', 'deploy/azure/apps.bicep'] },
    });
    expect(await needsAt(handApps.infra, NEW, DIGEST)).toEqual({ steps: ['foundation'], byHand: [] });
    // A record behind on a file only a person deploys says so, and plans nothing for it.
    const access = infraOver({
      running: NEW,
      tags: { 'agentx-deployed-access': OLD },
      since: { [OLD]: ['deploy/azure/access.bicep'] },
    });
    expect(await needsAt(access.infra, NEW, DIGEST)).toEqual({
      steps: [],
      byHand: ['deploy/azure/access.bicep: access reads it, which only the partner runs (deploy.ts access)'],
    });
    // Every record current: nothing.
    const current = infraOver({ running: NEW, tags: { 'agentx-deployed-foundation': NEW } });
    expect(await needsAt(current.infra, NEW, DIGEST)).toEqual({ steps: [], byHand: [] });
  });
});

describe('the plan between the jobs, and a deploy step', () => {
  const HASH = 'f'.repeat(64);

  it('reads back only the shape the plan job writes', () => {
    expect(planFrom(JSON.stringify({ steps: ['foundation', 'db-setup'], whatIf: { foundation: HASH } }))).toEqual({
      steps: ['foundation', 'db-setup'],
      whatIf: { foundation: HASH },
    });
    for (const bad of [
      {},
      { steps: ['owner'], whatIf: {} },
      { steps: ['apps'], whatIf: { apps: 'x' } },
      { steps: [], whatIf: { apps: HASH } },
      { steps: ['apps'], whatIf: null },
    ]) {
      expect(() => planFrom(JSON.stringify(bad))).toThrow("The plan job's output isn't a plan: nothing was deployed.");
    }
  });

  it('deploys an approved step unattended in deploy mode, and refuses one the plan lacks', async () => {
    const { infra, requests, said } = infraOver({});
    expect(await deployStep(infra, 'apps', NEW, { steps: ['apps'], whatIf: { apps: HASH } })).toBe(0);
    expect(requests[0]?.request).toEqual(requestFor('apps', NEW));
    expect(requests[0]?.steps.unattended?.mode).toBe('deploy');
    expect(await deployStep(infra, 'foundation', NEW, { steps: ['apps'], whatIf: { apps: HASH } })).toBe(1);
    expect(said.at(-1)).toBe('The approved plan has no foundation: nothing was deployed.');
  });

  it('asks for the plain foundation, secrets’ machine part, and apps migrating first', () => {
    expect(requestFor('foundation', NEW)).toEqual({ command: 'foundation', loadSize: false, alwaysOn: false });
    expect(requestFor('secrets', NEW)).toEqual({ command: 'secrets', plan: { kind: 'keys' } });
    expect(requestFor('apps', NEW)).toEqual({
      command: 'apps',
      commit: NEW,
      keepRunning: false,
      loadRun: false,
      migrateFirst: true,
    });
  });
});

describe('answers, the summary and main', () => {
  const ENV = Object.fromEntries(
    Object.values(ANSWER_VARIABLES).map((variable, at) => [variable, `value${String(at)}.example`]),
  );

  it('takes each answer from its variable, and names those not set, never a value', () => {
    expect(answersFrom(ENV).authHost).toBe(ENV.AGENTX_AZURE_AUTH_HOST);
    // A secret set through a pipe carries a line break: trimmed, as a typed answer is (S192).
    expect(answersFrom({ ...ENV, AGENTX_AZURE_AUTH_HOST: ' auth.example.invalid\r\n' }).authHost).toBe(
      'auth.example.invalid',
    );
    expect(() => answersFrom({ ...ENV, AGENTX_AZURE_APP_HOST: ' \r\n' })).toThrow(/doesn't give AGENTX_AZURE_APP_HOST/);
    expect(() => answersFrom({ ...ENV, AGENTX_AZURE_APP_HOST: '' })).toThrow(
      "GitHub's environment doesn't give AGENTX_AZURE_APP_HOST: set each as a secret of staging-whatif and staging-infra (Settings, Environments). Nothing was deployed.",
    );
  });

  it('keeps the answers and every GUID off the summary page', () => {
    expect(scrubbed(`Signed in (${SUBSCRIPTION}) to ${String(ENV.AGENTX_AZURE_AUTH_HOST)}`, ENV)).toBe(
      'Signed in (<id>) to <AGENTX_AZURE_AUTH_HOST>',
    );
  });

  it('plans: writes the plan as the step output and the words as the summary; deploys a step with the plan given', async () => {
    const written: { file: string; text: string }[] = [];
    const outlets = (env: Record<string, string>) => ({
      env: { ...ENV, ...env },
      append: (file: string, text: string) => written.push({ file, text }),
    });
    const made = infraOver({ changed: [] });
    expect(
      await main(['plan', NEW, DIGEST], outlets({ GITHUB_OUTPUT: 'out', GITHUB_STEP_SUMMARY: 'sum' }), (say) => ({
        ...made.infra,
        say,
      })),
    ).toBe(0);
    expect(written[0]).toEqual({ file: 'out', text: 'plan={"steps":[],"whatIf":{}}\nneeded=false\n' });
    expect(written[1]).toEqual({
      file: 'sum',
      text: '```\nThis merge needs no infrastructure deploy: the release goes on by itself.\n```\n',
    });
    const HASH = 'f'.repeat(64);
    const deploying = infraOver({});
    const PLAN = JSON.stringify({ steps: ['secrets'], whatIf: { secrets: HASH } });
    expect(await main(['deploy', 'secrets', NEW], outlets({ PLAN }), () => deploying.infra)).toBe(0);
    expect(deploying.requests[0]?.request).toEqual(requestFor('secrets', NEW));
  });

  it('refuses what it is not asked properly, and says an error as the run’s last word', async () => {
    const outlets = { env: ENV, append: () => undefined };
    const made = infraOver({});
    expect(await main(['nothing'], outlets, () => made.infra)).toBe(2);
    expect(await main(['plan', 'abc', DIGEST], outlets, () => made.infra)).toBe(2);
    expect(await main(['deploy', 'certificates', NEW], outlets, () => made.infra)).toBe(2);
    expect(
      await main(['deploy', 'apps', NEW], { env: { ...ENV, PLAN: '{}' }, append: () => undefined }, () => made.infra),
    ).toBe(1);
  });
});

describe('deployDeployers, from the partner’s terminal', () => {
  /** A terminal answering `answer` to its one question, keeping what it says. */
  const terminal = (answer: string) => {
    const said: string[] = [];
    const asked: string[] = [];
    const scripted: Terminal = {
      say: (line) => said.push(line),
      ask: (question) => {
        asked.push(question);
        return Promise.resolve(answer);
      },
      askHidden: () => Promise.reject(new Error('no hidden question')),
    };
    return { scripted, said, asked };
  };
  /** A CLI whose what-if ends with `status`, and whose read back shows `state` with the two client IDs. */
  const cli = (status: number, state: string) => {
    const calls: (readonly string[])[] = [];
    const az: Az = {
      interactive: (args) => {
        calls.push(args);
        return status;
      },
      run: (args) => {
        calls.push(args);
        if (args[0] === 'account') return ok({ id: SUBSCRIPTION, name: 'Azure subscription 1' });
        return ok({
          provisioningState: state,
          outputs: { infraClientId: { value: 'infra-client' }, whatIfClientId: { value: 'whatif-client' } },
        });
      },
    };
    return { az, calls };
  };
  const NOW = () => new Date('2026-11-13T10:00:00Z');

  it('asks first, deploys with the what-if answered by the partner, then gives each environment its client ID', async () => {
    const { scripted, said, asked } = terminal('y');
    const { az, calls } = cli(0, 'Succeeded');
    expect(await deployDeployers(scripted, az, NOW)).toBe(0);
    expect(asked).toEqual(["Deploy staging's deployers into it? [y/N] "]);
    expect(calls[1]).toEqual([
      'deployment',
      'sub',
      'create',
      '--subscription',
      SUBSCRIPTION,
      '--name',
      'agentx-staging-deployers-20261113T100000Z',
      '--location',
      'uaenorth',
      '--parameters',
      'deployers/staging.bicepparam',
      '--confirm-with-what-if',
    ]);
    expect(said.slice(-2)).toEqual(['  staging-infra: infra-client', '  staging-whatif: whatif-client']);
  });

  it('does nothing on a no, and says so when the what-if is declined or the deployment failed', async () => {
    const declined = cli(0, 'Succeeded');
    expect(await deployDeployers(terminal('n').scripted, declined.az, NOW)).toBe(1);
    expect(declined.calls).toHaveLength(1);
    for (const [status, state] of [
      [1, 'Succeeded'],
      [0, 'Failed'],
    ] as const) {
      const { scripted, said } = terminal('y');
      expect(await deployDeployers(scripted, cli(status, state).az, NOW)).toBe(1);
      expect(said.at(-1)).toMatch(
        /^The deployers weren't deployed \((?:declined or not read|Failed)\): nothing more was done\.$/,
      );
    }
  });

  it('main: names a secret the environment lacks before anything starts', async () => {
    const said: string[] = [];
    const log = console.log;
    console.log = (line: string) => said.push(line);
    try {
      expect(await main(['plan', NEW, DIGEST], { env: {}, append: () => undefined })).toBe(1);
    } finally {
      console.log = log;
    }
    expect(said.at(-1)).toMatch(/^GitHub's environment doesn't give AGENTX_AZURE_ALERT_EMAIL, /);
  });
});

describe('the deployers (deployers/deployers.bicep)', () => {
  const DEPLOYERS = path.join(AZURE_DIR, 'deployers');
  const text = (file: string): string => readFileSync(path.join(DEPLOYERS, file), 'utf8');

  it('lints clean, every rule an error, and trusts exactly the two environments by names.bicep’s own repository', () => {
    inCopy((dir) => {
      for (const file of readdirSync(path.join(dir, 'deployers')).filter((each) => /\.bicep(?:param)?$/.test(each))) {
        expect({ file, ...lint(dir, `deployers/${file}`) }).toMatchObject({ file, status: 0 });
      }
      build(dir, 'deployers/deployers.bicep');
    });
    const names = readFileSync(path.join(AZURE_DIR, 'names.bicep'), 'utf8');
    const repository = /func githubRepository\(\) string => '([^']+)'/.exec(names)?.[1];
    expect(text('deployers.bicep')).toContain(`var repository = '${String(repository)}'`);
    expect(text('deployers.bicep')).toContain("infraSubject: '${repository}:environment:${environment}-infra'");
    expect(text('deployers.bicep')).toContain("whatIfSubject: '${repository}:environment:${environment}-whatif'");
  });

  it('lets the infra identity give exactly the roles the deployments give, never Owner or a wildcard, never to itself', () => {
    const access = text('staging-access.bicep');
    const words = [...(/var customRoleWords = \[([^\]]*)\]/.exec(access)?.[1] ?? '').matchAll(/'([^']+)'/g)].map(
      (match) => match[1],
    );
    const given = new Set<string>();
    for (const file of ['modules/roles.bicep', 'names.bicep']) {
      const source = readFileSync(path.join(AZURE_DIR, file), 'utf8');
      for (const match of source.matchAll(/guid\((?:resourceGroup\(\)\.id|groupId), '([a-z-]+)'\)/g))
        given.add(String(match[1]));
    }
    expect(words.toSorted()).toEqual([...given].toSorted());
    const vaultReader = /var vaultReaderRole = '([0-9a-f-]+)'/.exec(
      readFileSync(path.join(AZURE_DIR, 'modules/secret-access.bicep'), 'utf8'),
    )?.[1];
    expect(access).toContain(`var vaultReaderRole = '${String(vaultReader)}'`);
    expect(access).toContain('ForAnyOfAnyValues:GuidNotEquals {${infraPrincipalId}}');
    const everything = `${text('deployers.bicep')}${access}${text('identities.bicep')}`;
    // No role of its own in the group, and on the subscription the deployment record alone: no role, policy, setting
    // or budget write (review S190), all of which are the partner's access deployment.
    expect(access).not.toMatch(/roleDefinitions@/);
    expect(text('deployers.bicep')).not.toMatch(/'Microsoft\.(?:Authorization|Consumption|Insights)\/[^']*\/write'/);
    // AZ5d: each role can read a what-if's async answer, which Azure serves from the subscription's results.
    expect(
      text('deployers.bicep').match(/'Microsoft\.Resources\/subscriptions\/operationresults\/read'/g),
    ).toHaveLength(2);
    // Owner, User Access Administrator, and any wildcard action.
    expect(everything).not.toMatch(/8e3af657-a8ff-443c-a75c-2fe8c4bcb635|18d7d88d-d35e-4fb5-a5c3-7773c20a72d9|\/\*'/);
  });

  it('snapshots in a subscription: two regional identities, each trusting one environment, in their own group', () => {
    const snapshot = inCopy((dir) =>
      deploymentSnapshot(dir, 'deployers/staging.bicepparam', undefined, {}, SUBSCRIPTION),
    );
    const of = (type: string) => snapshot.predictedResources.filter((resource) => resource.type === type);
    expect(of('Microsoft.Resources/resourceGroups').map((group) => group.name)).toEqual([
      'rg-agentx-staging-deployers',
    ]);
    expect(
      of('Microsoft.ManagedIdentity/userAssignedIdentities').map((identity) => [
        identity.name,
        (identity.properties as { isolationScope?: string }).isolationScope,
      ]),
    ).toEqual([
      ['id-agentx-stg-infra', 'Regional'],
      ['id-agentx-stg-whatif', 'Regional'],
    ]);
    const subjects = of('Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials').map(
      (trust) => (trust.properties as { subject?: string }).subject,
    );
    expect(subjects.map((subject) => String(subject).replace(/^.*:environment:/, ''))).toEqual([
      'staging-infra',
      'staging-whatif',
    ]);
  });
});
