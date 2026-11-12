// The release tool: its check (G4-3a) and the release itself (G4-3b). Nothing
// here reaches Azure: the CLI is a stand-in that answers from a script, or a
// stand-in staging that changes as a release writes to it. git is asked only
// what this checkout holds; the history is a line of made-up commits
// (git.test.ts reads a real one).
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { fileReferences } from '../../tooling/bicep/references.ts';
import type { Outcome } from '../image/verify.ts';
import { type Az, type AzResult, type Deployment, DEPLOYMENTS, RECORDED, RECORDS_JOB, recordTag } from './deploy.ts';
import type { History } from './git.ts';
import { jobName, JOBS_API } from './jobs.ts';
import {
  changes,
  check,
  COMING_FIRST,
  OUTSIDE_HISTORY,
  decide,
  type Decision,
  type Folder,
  HAND_DEPLOYED,
  LOAD_RUN_UP,
  handDeployedList,
  main,
  migrateFirst,
  NOT_AS_DEPLOYED,
  ORDER,
  PARAMS_PATHS,
  parseArguments,
  type Readers,
  readersFrom,
  type Records,
  recordsIn,
  release,
  released,
  type ReleaseSteps,
  type Running,
  runningIn,
  TEST_FILE,
  USAGE,
  UsageError,
  type Workload,
  WORKLOADS,
  workloadUrl,
} from './release.ts';
import { environmentSnapshot, inCopy, paramsFiles } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const REPOSITORY = 'ghcr.io/shahbaz242630/agent-x';

/** Made-up commits and digests, in the shapes git and ghcr.io give. */
const commit = (fill: string): string => fill.repeat(40);
const digest = (fill: string): string => `sha256:${fill.repeat(64)}`;
const OLD = commit('a');
const NEW = commit('b');
const LATER = commit('e');
const OLD_IMAGE = `${REPOSITORY}@${digest('1')}`;
const NEW_IMAGE = `${REPOSITORY}@${digest('2')}`;

/** The host the settings name, which nothing printed may show (CI's logs are public). */
const HOST = 'app.example.invalid';

/** A setting's name assembled from its words, so no line pairs a secret's name with a value (PRs #27 and #28). */
const setting = (...words: readonly string[]): string => words.join('_');

/** A container as Azure gives it (read from staging, S24), with made-up values. */
const azureContainer = (name: string, overrides: Readonly<Record<string, unknown>> = {}): Record<string, unknown> => ({
  image: OLD_IMAGE,
  name,
  command: ['node', `apps/${name}/src/main.ts`],
  args: [],
  env: [
    { name: 'AGENTX_ENV', value: 'staging' },
    { name: 'AGENTX_RELEASE', value: OLD },
    { name: 'AGENTX_PUBLIC_ORIGIN', value: `https://${HOST}` },
    { name: setting('AGENTX', 'DB', 'PASSWORD', 'FILE'), value: '/mnt/secrets/login' },
    { name: 'AGENTX_FROM_VAULT', secretRef: 'a-secret' },
  ],
  // The app's also carries the disk Azure works out from the size.
  resources: { cpu: 0.5, memory: '1Gi', ephemeralStorage: '2Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
  ...overrides,
});

/** A container's settings with its build replaced. */
const builtAt = (release: string): readonly unknown[] =>
  (azureContainer('x').env as readonly { name: string }[]).map((entry) =>
    entry.name === 'AGENTX_RELEASE' ? { name: 'AGENTX_RELEASE', value: release } : entry,
  );

const running = (workload: Workload, overrides: Readonly<Record<string, unknown>> = {}): Running =>
  runningIn(workload, [azureContainer(WORKLOADS[workload].container, overrides)]);

/** The vault the workloads' secrets are read from, and each workload's identity, as Bicep writes their IDs. */
const VAULT = 'kv-agentx-stg-test';
const GROUP_ID = `/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers`;
const identityOf = (workload: Workload): string =>
  `${GROUP_ID}/Microsoft.ManagedIdentity/userAssignedIdentities/id-agentx-stg-${workload}`;

/** The migration job's trigger, time limit and runs, with Azure's nulls when as Azure gives them. */
const jobConfiguration = (azure: boolean): Record<string, unknown> => ({
  triggerType: 'Manual',
  replicaTimeout: 900,
  replicaRetryLimit: 0,
  manualTriggerConfig: { parallelism: 1, replicaCompletionCount: 1 },
  ...(azure ? { scheduleTriggerConfig: null, eventTriggerConfig: null } : {}),
});

/** The API's door, internal on 8080, with Azure's own spelling and fields when as Azure gives it. */
const appConfiguration = (azure: boolean): Record<string, unknown> => ({
  ...(azure ? { activeRevisionsMode: 'Single', service: null, runtime: null } : {}),
  ingress: {
    external: false,
    targetPort: 8080,
    transport: azure ? 'Auto' : 'auto',
    allowInsecure: false,
    traffic: [{ latestRevision: true, weight: 100 }],
    ...(azure ? { exposedPort: 0, customDomains: null, ipSecurityRestrictions: null } : {}),
  },
});

/**
 * A workload around its containers (AZ2c), as Azure gives it (read from staging, S188: its nulls, `Auto`, an
 * identity's ID with `resourcegroups` in lower case, the vault's address resolved) or as the snapshot predicts it
 * (the vault's address an ARM expression). The one secret is the one azureContainer's setting refers to.
 */
function around(workload: Workload, containers: unknown, as: 'azure' | 'snapshot'): Record<string, unknown> {
  const azure = as === 'azure';
  const identity = identityOf(workload);
  const keyVaultUrl = azure
    ? `https://${VAULT}.vault.azure.net/secrets/a-secret`
    : `[uri(reference('${GROUP_ID}/Microsoft.KeyVault/vaults/${VAULT}', '2025-05-01').vaultUri, 'secrets/a-secret')]`;
  const job = workload === 'migrate';
  return {
    identity: {
      type: 'UserAssigned',
      userAssignedIdentities: { [azure ? identity.replace('resourceGroups', 'resourcegroups') : identity]: {} },
    },
    properties: {
      environmentId: `${GROUP_ID}/Microsoft.App/managedEnvironments/cae-agentx-staging`,
      workloadProfileName: 'Consumption',
      configuration: {
        ...(azure ? { dapr: null, registries: null, identitySettings: [] } : {}),
        secrets: [{ name: 'a-secret', keyVaultUrl, identity }],
        ...(job ? jobConfiguration(azure) : appConfiguration(azure)),
      },
      template: {
        containers,
        ...(azure ? { initContainers: null } : {}),
        volumes: [{ name: 'secrets', storageType: 'Secret', secrets: [{ secretRef: 'a-secret', path: 'a-secret' }] }],
        ...(job
          ? {}
          : {
              scale: { minReplicas: 0, maxReplicas: 1, ...(azure ? { cooldownPeriod: 300, rules: null } : {}) },
              terminationGracePeriodSeconds: 30,
            }),
      },
    },
  };
}

/** What git says of this repository, a line each. */
function gitSays(...args: readonly string[]): string[] {
  const done = spawnSync('git', args, {
    cwd: fileURLToPath(new URL('../../', import.meta.url)),
    encoding: 'utf8',
    windowsHide: true,
  });
  if (done.status !== 0) throw new Error(`git ${args.join(' ')}: ${done.stderr}`);
  return done.stdout.split('\n').filter((line) => line !== '');
}

describe('parseArguments', () => {
  it('reads check or release with a full commit and a digest', () => {
    for (const command of ['check', 'release'] as const) {
      expect(parseArguments([command, NEW, digest('2')])).toEqual({ command, commit: NEW, digest: digest('2') });
    }
  });

  it('refuses anything else, saying why', () => {
    for (const [argv, message] of [
      [[], 'say check or release, not nothing'],
      [['deploy', NEW, digest('2')], 'say check or release, not deploy'],
      [['check'], "nothing isn't a full commit (40 lower-case hex)"],
      [['check', NEW.slice(1), digest('2')], `${NEW.slice(1)} isn't a full commit (40 lower-case hex)`],
      [['check', NEW.toUpperCase(), digest('2')], `${NEW.toUpperCase()} isn't a full commit (40 lower-case hex)`],
      [['check', 'main', digest('2')], "main isn't a full commit (40 lower-case hex)"],
      [['check', NEW], "nothing isn't an image digest (sha256: and 64 lower-case hex)"],
      [['check', NEW, '2'.repeat(64)], `${'2'.repeat(64)} isn't an image digest (sha256: and 64 lower-case hex)`],
      [['check', NEW, `${digest('2')}0`], `${digest('2')}0 isn't an image digest (sha256: and 64 lower-case hex)`],
      [['check', NEW, digest('2'), 'more'], 'check takes a commit and a digest, not more as well'],
      [['release', NEW, digest('2'), 'more'], 'release takes a commit and a digest, not more as well'],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(new UsageError(message));
    }
  });
});

describe('what only a person deploys', () => {
  it('is read from hand-deployed.json beside the Bicep, each area with why and what to run', () => {
    expect(HAND_DEPLOYED.map(({ prefix, except }) => [prefix, except])).toEqual([
      ['deploy/azure/', '.ts'],
      ['db/bootstrap/', undefined],
      ['apps/db-setup/', undefined],
      ['packages/platform/src/db/server-setup.ts', undefined],
      ['packages/platform/src/db/scram.ts', undefined],
      ['packages/platform/src/config/setup.ts', undefined],
    ]);
    for (const { why } of HAND_DEPLOYED) expect(why).toMatch(/foundation|apps/);
  });

  it('leaves test files out only because the image does: .dockerignore drops them after all it lets in', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    // Docker's own reading: a line starting # skipped, then each trimmed, a blank one skipped; the last match wins.
    const rules = readFileSync(`${root}.dockerignore`, 'utf8')
      .split('\n')
      .filter((line) => !line.startsWith('#'))
      .map((line) => line.trim())
      .filter((line) => line !== '');
    const dropped = rules.lastIndexOf(`**/*${TEST_FILE}`);
    expect(dropped).toBeGreaterThan(-1);
    expect(rules.slice(dropped + 1).filter((line) => line.startsWith('!'))).toEqual([]);
    // The build reads that file and no other: one beside the Dockerfile (Dockerfile.dockerignore) would take its
    // place. The load test's image has its own beside its own Dockerfile, read by that build alone (D2c).
    expect(gitSays('ls-files', '--cached', '--others', '--exclude-standard', '--', '*.dockerignore').sort()).toEqual([
      '.dockerignore',
      'tooling/load/Dockerfile.dockerignore',
    ]);
  });

  it('holds no links, so no file a person deploys can take its content from a test file', () => {
    // A link's content is its target's path: a change to the target changes nothing git lists for the link.
    expect(gitSays('ls-files', '--stage').filter((line) => line.startsWith('120000 '))).toEqual([]);
  });

  it('names files and folders that exist, so a rename leaves no area guarding nothing', () => {
    const root = fileURLToPath(new URL('../../', import.meta.url));
    for (const { prefix } of HAND_DEPLOYED)
      expect({ prefix, found: existsSync(`${root}${prefix}`) }).toEqual({ prefix, found: true });
  });

  it('refuses a list that is not one', () => {
    const list = (entries: unknown) => () => handDeployedList(entries);
    expect(list({})).toThrow('hand-deployed.json must be a list of areas');
    expect(list([])).toThrow('hand-deployed.json must be a list of areas');
    for (const entry of [
      { why: 'x' },
      { prefix: '', why: 'x' },
      { prefix: 'a/' },
      { prefix: 'a/', why: 'x', more: 'y' },
      null,
    ]) {
      expect(list([entry])).toThrow(
        'each area in hand-deployed.json is a prefix and a reason, and at most an ending it excepts',
      );
    }
    expect(list([{ prefix: 'a/', why: 'x', except: '' }])).toThrow("a/'s exception must be an ending");
    expect(list([{ prefix: 'a/', why: 'x', except: 1 }])).toThrow("a/'s exception must be an ending");
    expect(
      handDeployedList([
        { prefix: 'a/', why: 'x', except: '.ts' },
        { prefix: 'b/', why: 'y' },
      ]),
    ).toEqual([
      { prefix: 'a/', why: 'x', except: '.ts' },
      { prefix: 'b/', why: 'y' },
    ]);
  });
});

describe('what a workload runs', () => {
  it("is read from its one container, keeping Azure's own fields but the disk Azure works out", () => {
    for (const workload of ORDER) {
      const { container } = WORKLOADS[workload];
      const found = running(workload);
      expect(found.image).toBe(OLD_IMAGE);
      expect(found.release).toBe(OLD);
      expect(found.container).toEqual({ ...azureContainer(container), resources: { cpu: 0.5, memory: '1Gi' } });
    }
    // A size without the disk is read the same.
    expect(running('api', { resources: { cpu: 0.5, memory: '1Gi' } }).container.resources).toEqual({
      cpu: 0.5,
      memory: '1Gi',
    });
  });

  it('reads no argument list, as Azure gives back an empty one, as none, and sends none back (S188)', () => {
    const { args: _dropped, ...withoutArgs } = azureContainer('api');
    const read = runningIn('api', [withoutArgs]);
    expect(read.container.args).toEqual([]);
    expect(released(read, read.image, read.release).args).toEqual([]);
  });

  it("refuses anything that isn't the workload a release knows, saying why, so it is deployed by hand", () => {
    const container = azureContainer('api');
    const env = container.env as readonly Record<string, unknown>[];
    const refused = (containers: unknown, why: string): void => {
      expect(() => runningIn('api', containers)).toThrow(
        `containerApps/ca-agentx-stg-api isn't the api a release knows (${why}): deploy it by hand.`,
      );
    };
    const with_ = (overrides: Readonly<Record<string, unknown>>): unknown => [{ ...container, ...overrides }];
    const withSettings = (settings: readonly unknown[]): unknown => with_({ env: settings });
    refused(undefined, 'it must run exactly one container');
    refused([], 'it must run exactly one container');
    refused([container, container], 'it must run exactly one container');
    refused(container, 'it must run exactly one container');
    // A field this tool doesn't copy, such as a probe it would drop.
    refused(with_({ probes: [], stdin: true }), "its container has probes, stdin, which this tool doesn't copy");
    refused(with_({ name: 'migrate' }), "its container isn't named api");
    // Another image, one whose name is as long as ours, a tag in place of a
    // digest, or a repository whose name only starts like ours.
    for (const image of [
      `ghcr.io/zitadel/zitadel@${digest('3')}`,
      `${REPOSITORY.replace(/x$/, 'y')}@${digest('3')}`,
      `${REPOSITORY}:v1`,
      `${REPOSITORY}-other@${digest('3')}`,
      `${REPOSITORY}@${digest('3')}x`,
      undefined,
    ]) {
      refused(with_({ image }), `it doesn't run ${REPOSITORY} by digest`);
    }
    refused(with_({ command: 'node main.ts' }), 'its command or arguments are not lists of words');
    refused(with_({ args: [1] }), 'its command or arguments are not lists of words');
    refused(with_({ args: null }), 'its command or arguments are not lists of words');
    refused(with_({ command: undefined }), 'its command or arguments are not lists of words');
    refused(with_({ resources: { cpu: '0.5', memory: '1Gi' } }), 'its size is not given');
    refused(with_({ resources: { cpu: 0.5 } }), 'its size is not given');
    refused(with_({ resources: undefined }), 'its size is not given');
    refused(
      with_({ resources: { cpu: 0.5, memory: '1Gi', gpu: 1 } }),
      "its size has gpu, which this tool doesn't copy",
    );
    refused(withSettings(undefined as never), 'its settings are not a list');
    refused(with_({ env: {} }), 'its settings are not a list');
    refused(withSettings([...env, { value: 'x' }]), 'a setting has no name');
    refused(withSettings([...env, null]), 'a setting has no name');
    refused(
      withSettings([...env, { name: 'AGENTX_MORE', value: 'x', note: 'y' }]),
      'the setting AGENTX_MORE has more than a name and its value',
    );
    refused(
      withSettings([...env, { name: 'AGENTX_BOTH', value: 'x', secretRef: 'a-secret' }]),
      'the setting AGENTX_BOTH has neither a value nor a secret reference alone',
    );
    refused(
      withSettings([...env, { name: 'AGENTX_NEITHER' }]),
      'the setting AGENTX_NEITHER has neither a value nor a secret reference alone',
    );
    // Its build named nowhere, twice, from the vault, or as something that isn't a commit.
    const others = env.filter((entry) => entry.name !== 'AGENTX_RELEASE');
    for (const settings of [
      others,
      [...env, { name: 'AGENTX_RELEASE', value: NEW }],
      [...others, { name: 'AGENTX_RELEASE', secretRef: 'a-secret' }],
      [...others, { name: 'AGENTX_RELEASE', value: 'main' }],
    ]) {
      refused(withSettings(settings), "it doesn't name its build in one AGENTX_RELEASE");
    }
    refused(with_({ volumeMounts: undefined }), 'its mounts are not a list');
    refused(
      with_({ volumeMounts: [{ volumeName: 'secrets', mountPath: '/mnt/secrets', subPath: 'x' }] }),
      'a mount is more than a volume and a path',
    );
    refused(with_({ volumeMounts: [{ volumeName: 'secrets' }] }), 'a mount is more than a volume and a path');
    // The job is named by its own path.
    expect(() => runningIn('migrate', [])).toThrow(
      "jobs/job-agentx-stg-migrate isn't the migrate a release knows (it must run exactly one container): deploy it by hand.",
    );
  });

  it('is the shape apps.bicep deploys each of them in, at the API version this tool reads them with', () => {
    const created = inCopy((dir) => environmentSnapshot(dir, 'staging').together).predictedResources;
    for (const workload of ORDER) {
      const [kind, name] = WORKLOADS[workload].path.split('/');
      const deployed = created.find(
        (resource) => resource.type === `Microsoft.App/${String(kind)}` && resource.name === name,
      );
      expect(deployed?.apiVersion).toBe(JOBS_API);
      const containers = (deployed?.properties as { template?: { containers?: unknown } } | undefined)?.template
        ?.containers;
      expect(runningIn(workload, containers).container.name).toBe(WORKLOADS[workload].container);
    }
  });
});

describe('a released container', () => {
  it('has the new image and build, and every other field as it was', () => {
    const before = running('api');
    const after = released(before, NEW_IMAGE, NEW);
    expect(after).toEqual({
      ...before.container,
      image: NEW_IMAGE,
      env: before.container.env.map((entry) => (entry.name === 'AGENTX_RELEASE' ? { ...entry, value: NEW } : entry)),
    });
    // The secret stays a reference, and what was read isn't changed.
    expect(after.env).toContainEqual({ name: 'AGENTX_FROM_VAULT', secretRef: 'a-secret' });
    expect(before.container.image).toBe(OLD_IMAGE);
    expect(changes(before.container, after)).toEqual([
      `image ${OLD_IMAGE} → ${NEW_IMAGE}`,
      `AGENTX_RELEASE ${OLD} → ${NEW}`,
    ]);
    expect(changes(before.container, before.container)).toEqual([]);
    expect(changes(before.container, { ...before.container, image: NEW_IMAGE })).toEqual([
      `image ${OLD_IMAGE} → ${NEW_IMAGE}`,
    ]);
  });
});

/**
 * A history along one line of commits, oldest first: one is in another's
 * history when it comes no later; a commit off the line is in none. `changed`
 * lists what differs from each commit to NEW.
 */
function history(
  line: readonly string[],
  changed: Readonly<Record<string, readonly string[]>> = {},
  files: Readonly<Record<string, Readonly<Record<string, string>>>> = {},
): History {
  return {
    isAncestor: (ancestor, target) =>
      line.includes(ancestor) && line.includes(target) && line.indexOf(ancestor) <= line.indexOf(target),
    changedFiles: (from, to) => {
      expect(to).toBe(NEW);
      return changed[from] ?? [];
    },
    fileAt: (commit, file) => files[commit]?.[file],
    filesIn: (commit, folder) =>
      Object.keys(files[commit] ?? {})
        .filter((file) => file.startsWith(`${folder}/`))
        .map((file) => file.slice(folder.length + 1)),
  };
}

/** The repository, whose files Bicep names by their full paths. */
const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const full = (file: string): string => path.join(ROOT, file);

/**
 * What Bicep might say each deployment reads, in its shape (full paths, the
 * parameters file among them), made up: the real lists are tested below.
 */
const SAID: ReadonlyMap<string, readonly string[]> = new Map(
  [...PARAMS_PATHS].map(([deployment, params]) => {
    const own: Readonly<Record<Deployment, readonly string[]>> = {
      foundation: ['main.bicep', 'modules/postgres.bicep', 'shared.json'],
      secrets: ['secrets.bicep', 'shared.json'],
      apps: ['apps.bicep'],
      certificates: ['certificates.bicep'],
    };
    return [params, [params, ...[...own[deployment], 'names.bicep'].map((file) => full(`deploy/azure/${file}`))]];
  }),
);

/** What the stand-in apps.bicep gives each workload (AZ2c): the container azureContainer makes, at any image and build. */
const TEMPLATES: ReadonlyMap<Workload, unknown> = new Map(
  ORDER.map(
    (workload) => [workload, around(workload, [azureContainer(WORKLOADS[workload].container)], 'snapshot')] as const,
  ),
);

/** Stand-in templates, as a Folder's or migrateFirst's: each workload's container from apps.bicep, or Bicep's failure. */
const templatesOf =
  (given: ReadonlyMap<Workload, unknown> | Error = TEMPLATES): Folder['templates'] =>
  () => {
    if (given instanceof Error) throw given;
    return given;
  };

/** This folder as a check finds it: at a commit, clean or not, with Bicep's answer or failure; each question kept. */
function folderAt(
  head: string,
  answer: ReadonlyMap<string, readonly string[]> | Error = SAID,
  clean = true,
  templates: ReadonlyMap<Workload, unknown> | Error = TEMPLATES,
): { folder: Folder; asked: string[][] } {
  const asked: string[][] = [];
  const folder: Folder = {
    checkout: () => ({ head, clean }),
    references: (files) => {
      asked.push([...files]);
      return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
    },
    templates: templatesOf(templates),
  };
  return { folder, asked };
}

const both = (api: Running, migrate: Running): ReadonlyMap<Workload, Running> =>
  new Map([
    ['migrate', migrate],
    ['api', api],
  ]);

const at =
  (release: string, image = OLD_IMAGE) =>
  (workload: Workload) =>
    running(workload, { image, env: builtAt(release) });

describe('deciding a release', () => {
  it('does nothing when both already run the commit, as that image', () => {
    const current = at(NEW, NEW_IMAGE);
    expect(decide(both(current('api'), current('migrate')), NEW, NEW_IMAGE, history([NEW]))).toEqual({
      kind: 'current',
    });
    // The same build under another image is not the same release, nor one already past.
    expect(decide(both(current('api'), current('migrate')), NEW, OLD_IMAGE, history([NEW])).kind).toBe('release');
  });

  it('does nothing when both run a later commit that has it: a release run again after a newer one', () => {
    const later = at(LATER);
    expect(decide(both(later('api'), later('migrate')), NEW, NEW_IMAGE, history([OLD, NEW, LATER]))).toEqual({
      kind: 'past',
    });
    // Only one of them past it is no reason to skip the other.
    expect(decide(both(later('api'), at(OLD)('migrate')), NEW, NEW_IMAGE, history([OLD, NEW, LATER])).kind).toBe(
      'by-hand',
    );
  });

  it('updates the migration job, then the API, when nothing a person deploys changed', () => {
    const decided = decide(
      both(running('api'), running('migrate')),
      NEW,
      NEW_IMAGE,
      history([OLD, NEW], {
        [OLD]: [
          'apps/api/src/main.ts',
          'db/migrations/0002_next.sql',
          'deploy/azure/release.ts',
          'packages/platform/src/db/server-setup.test.ts',
        ],
      }),
    );
    expect(decided.kind).toBe('release');
    if (decided.kind !== 'release') return;
    expect([...decided.updates.keys()]).toEqual(['migrate', 'api']);
    expect(decided.updates.get('api')).toEqual(released(running('api'), NEW_IMAGE, NEW));
    expect(decided.updates.get('migrate')).toEqual(released(running('migrate'), NEW_IMAGE, NEW));
  });

  describe('a new migration adding a trigger to a table already built (decision 49)', () => {
    const BUILT = 'db/migrations/0001_built.sql';
    const ADDS = 'db/migrations/0082_marks.sql';
    const COMING = 'packages/platform/src/db/coming.json';
    const builtSql = 'CREATE TABLE app.things (id uuid);';
    const addsSql = 'CREATE TRIGGER marks AFTER UPDATE ON app.things FOR EACH ROW EXECUTE FUNCTION app.mark();';
    const coming = JSON.stringify({
      triggers: [
        {
          table: 'app.things',
          name: 'marks',
          definition: 'CREATE TRIGGER marks',
          function: 'app.mark',
          body: 'a'.repeat(64),
        },
      ],
      bodies: [],
    });
    const decideFrom = (old: Readonly<Record<string, string>>) =>
      decide(
        both(running('api'), running('migrate')),
        NEW,
        NEW_IMAGE,
        history([OLD, NEW], { [OLD]: [ADDS] }, { [OLD]: old, [NEW]: { [BUILT]: builtSql, [ADDS]: addsSql } }),
      );

    it('stops when the image staging runs did not carry it as coming: it would page as it migrates', () => {
      expect(decideFrom({ [BUILT]: builtSql })).toEqual({
        kind: 'coming-first',
        reasons: [
          `0082_marks.sql adds marks on app.things, which the code before it didn't carry in coming.json's triggers (staging runs ${OLD})`,
        ],
      });
    });

    it('never asks for a hand deploy, which would go round it: the coming entry first, before any other reason', async () => {
      const line = history(
        [OLD, NEW],
        { [OLD]: [ADDS, 'deploy/azure/apps.bicep'] },
        { [OLD]: { [BUILT]: builtSql }, [NEW]: { [BUILT]: builtSql, [ADDS]: addsSql } },
      );
      const { status, said } = await checked(staging(OLD), line);
      expect(status).toBe(1);
      expect(said).toContain(`A release of ${NEW} stops here, red: ${COMING_FIRST}`);
      expect(COMING_FIRST).toContain('never a hand deploy');
      expect(said.filter((one) => one.includes('needs a hand deploy'))).toEqual([]);
    });

    it('goes ahead when it did', () => {
      expect(decideFrom({ [BUILT]: builtSql, [COMING]: coming }).kind).toBe('release');
    });

    it('looks no further for a migration staging already ran', () => {
      expect(decideFrom({ [BUILT]: builtSql, [ADDS]: addsSql }).kind).toBe('release');
    });
  });

  it('stops for a hand deploy when what a person deploys changed, whatever its case, saying each file and why', () => {
    const why = (prefix: string): string => HAND_DEPLOYED.find((area) => area.prefix === prefix)?.why ?? '';
    for (const [file, prefix] of [
      ['deploy/azure/apps.bicep', 'deploy/azure/'],
      ['deploy/azure/staging.apps.bicepparam', 'deploy/azure/'],
      ['deploy/azure/github-ranges.json', 'deploy/azure/'],
      ['deploy/azure/hand-deployed.json', 'deploy/azure/'],
      ['deploy/azure/modules/release.bicep', 'deploy/azure/'],
      // Where a Windows checkout puts it all the same, and an ending the exception doesn't match.
      ['Deploy/Azure/apps.bicep', 'deploy/azure/'],
      ['deploy/azure/tool.TS', 'deploy/azure/'],
      ['db/bootstrap/roles.sql', 'db/bootstrap/'],
      ['apps/db-setup/src/main.ts', 'apps/db-setup/'],
      ['packages/platform/src/db/server-setup.ts', 'packages/platform/src/db/server-setup.ts'],
      ['packages/platform/src/db/scram.ts', 'packages/platform/src/db/scram.ts'],
      ['packages/platform/src/config/setup.ts', 'packages/platform/src/config/setup.ts'],
    ] as const) {
      expect(
        decide(
          both(running('api'), running('migrate')),
          NEW,
          NEW_IMAGE,
          history([OLD, NEW], { [OLD]: ['README.md', file] }),
        ),
      ).toEqual({ kind: 'by-hand', reasons: [`${file} changed since ${OLD}: ${why(prefix)}`] });
    }
  });

  it('goes ahead when only test files changed where a person deploys, since they never ship (partner, S41)', () => {
    const decided = (files: readonly string[]): Decision =>
      decide(both(running('api'), running('migrate')), NEW, NEW_IMAGE, history([OLD, NEW], { [OLD]: files }));
    // B1c-1's release, stopped by the set-up job's test; another area's test; where a Windows checkout puts
    // the area, which is still found without case while the ending is matched with it.
    for (const file of [
      'apps/db-setup/src/main.test.ts',
      'apps/db-setup/src/main.db.test.ts',
      'db/bootstrap/roles.test.ts',
      'Apps/DB-Setup/src/main.test.ts',
    ]) {
      expect(decided(['README.md', file]).kind).toBe('release');
    }
    const why = HAND_DEPLOYED.find(({ prefix }) => prefix === 'apps/db-setup/')?.why ?? '';
    for (const file of [
      // A name the image would hold, however close to a test's: its case, a longer ending, another language.
      'apps/db-setup/src/main.Test.ts',
      'apps/db-setup/src/main.test.ts.orig',
      'apps/db-setup/src/main.test.js',
      // A file in a folder named like a test: the image drops it too, but only a test file's own name counts.
      'apps/db-setup/src/fixtures.test.ts/roles.sql',
    ]) {
      expect(decided([file])).toEqual({ kind: 'by-hand', reasons: [`${file} changed since ${OLD}: ${why}`] });
    }
    // A test beside a file that ships: red for that file alone.
    expect(decided(['apps/db-setup/src/main.test.ts', 'apps/db-setup/src/main.ts'])).toEqual({
      kind: 'by-hand',
      reasons: [`apps/db-setup/src/main.ts changed since ${OLD}: ${why}`],
    });
  });

  it('stops for a hand deploy when what either runs is not in the commit, and reads the changes since each', () => {
    const older = commit('c');
    const migrate = at(older)('migrate');
    // What the API runs isn't in the commit's history: nothing it changed can be read, so a person deploys it.
    expect(decide(both(running('api'), migrate), NEW, NEW_IMAGE, history([older, NEW]))).toEqual({
      kind: 'by-hand',
      reasons: [`staging runs ${OLD}, which isn't in ${NEW}'s history; ${OUTSIDE_HISTORY}`],
    });
    // Both are in it: the job, which fell behind, is read from its own build, so what changed since then counts.
    expect(
      decide(
        both(running('api'), migrate),
        NEW,
        NEW_IMAGE,
        history([older, OLD, NEW], { [older]: ['deploy/azure/apps.bicep'], [OLD]: [] }),
      ),
    ).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/apps.bicep changed since ${older}: ${HAND_DEPLOYED[0]?.why ?? ''}`],
    });
  });

  it('names the hand deploys that read a changed file once Bicep has said, and the reason for any none reads', () => {
    const readers = readersFrom(SAID);
    const reasons = (file: string): unknown =>
      decide(
        both(running('api'), running('migrate')),
        NEW,
        NEW_IMAGE,
        history([OLD, NEW], { [OLD]: ['README.md', file] }),
        readers,
      );
    const red = (file: string, reason: string): void => {
      expect(reasons(file)).toEqual({ kind: 'by-hand', reasons: [`${file} changed since ${OLD}: ${reason}`] });
    };
    const foundation =
      'deploy.ts foundation reads it, so run it by hand, its what-if read, then run this release again';
    red('deploy/azure/modules/postgres.bicep', foundation);
    // Where a Windows checkout puts it all the same.
    red('Deploy/Azure/Modules/Postgres.bicep', foundation);
    // apps is what a release reads, so nothing follows it.
    red('deploy/azure/apps.bicep', 'deploy.ts apps reads it, so run it by hand, its what-if read');
    red(
      'deploy/azure/shared.json',
      'deploy.ts foundation and secrets read it, so run each by hand in that order, each what-if read, then run this release again',
    );
    red(
      'deploy/azure/names.bicep',
      'deploy.ts foundation, secrets, apps and certificates read it, so run each by hand in that order, each what-if read',
    );
    // Read by no deployment: the gate's own list, and the set-up job's files.
    red('deploy/azure/hand-deployed.json', HAND_DEPLOYED[0]?.why ?? '');
    red('db/bootstrap/roles.sql', HAND_DEPLOYED[1]?.why ?? '');
    // Whether it is red never rests on what Bicep said: a file no area holds stays out of it.
    const ts = readersFrom(new Map([...SAID].map(([params, read]) => [params, [...read, full('deploy/azure/x.ts')]])));
    expect(
      decide(
        both(running('api'), running('migrate')),
        NEW,
        NEW_IMAGE,
        history([OLD, NEW], { [OLD]: ['deploy/azure/x.ts'] }),
        ts,
      ).kind,
    ).toBe('release');
  });
});

describe('deciding a release on the hand deploys records (T1b)', () => {
  const readers = readersFrom(SAID);
  /** A commit between OLD and NEW. */
  const MIDDLE = commit('d');
  const postgres = 'deploy/azure/modules/postgres.bicep';
  /** A release of NEW from OLD where the files changed, with the records, and what changed since each record. */
  const decided = (
    files: readonly string[],
    records: Records,
    since: Readonly<Record<string, readonly string[]>> = {},
    // null: Bicep hasn't said (undefined would take the default).
    known: Readers | null = readers,
  ): Decision =>
    decide(
      both(running('api'), running('migrate')),
      NEW,
      NEW_IMAGE,
      history([OLD, MIDDLE, NEW], { [OLD]: files, ...since }),
      known ?? undefined,
      records,
    );
  const red = (file: string, reason: string) => ({
    kind: 'by-hand',
    reasons: [`${file} changed since ${OLD}: ${reason}`],
  });
  const runFoundation =
    'deploy.ts foundation reads it, so run it by hand, its what-if read, then run this release again';
  const every: Records = new Map([
    ['foundation', NEW],
    ['secrets', NEW],
    ['certificates', NEW],
  ]);

  it('takes a changed file only recorded deploys read as deployed once each record has it as it is now', () => {
    expect(decided([postgres], new Map([['foundation', NEW]]))).toEqual({
      kind: 'release',
      updates: new Map([
        ['migrate', released(running('migrate'), NEW_IMAGE, NEW)],
        ['api', released(running('api'), NEW_IMAGE, NEW)],
      ]),
      deployed: [`${postgres} changed since ${OLD}: deployed by hand, foundation from ${NEW}`],
    });
    // Recorded earlier, with the file unchanged since.
    expect(decided([postgres], new Map([['foundation', MIDDLE]]), { [MIDDLE]: ['apps/api/src/main.ts'] }).kind).toBe(
      'release',
    );
    // Read by two, each recorded.
    expect(
      decided(
        ['deploy/azure/shared.json'],
        new Map([
          ['foundation', NEW],
          ['secrets', MIDDLE],
        ]),
        { [MIDDLE]: [] },
      ),
    ).toMatchObject({
      kind: 'release',
      deployed: [
        `deploy/azure/shared.json changed since ${OLD}: deployed by hand, foundation from ${NEW}, secrets from ${MIDDLE}`,
      ],
    });
  });

  it('stays red, naming only the deploys whose record lacks the file, when any does', () => {
    // Recorded before the file last changed, in either case.
    expect(decided([postgres], new Map([['foundation', MIDDLE]]), { [MIDDLE]: [postgres] })).toEqual(
      red(postgres, runFoundation),
    );
    expect(
      decided([postgres], new Map([['foundation', MIDDLE]]), { [MIDDLE]: ['Deploy/Azure/Modules/Postgres.bicep'] }),
    ).toEqual(red(postgres, runFoundation));
    // A path git itself gives in capitals, in both diffs.
    const capitals = 'Deploy/Azure/Modules/Postgres.bicep';
    expect(decided([capitals], new Map([['foundation', MIDDLE]]), { [MIDDLE]: [capitals] })).toEqual(
      red(capitals, runFoundation),
    );
    // Recorded at a commit this one doesn't have: a branch's, or a later one.
    expect(decided([postgres], new Map([['foundation', commit('9')]]))).toEqual(red(postgres, runFoundation));
    expect(decided([postgres], new Map([['foundation', LATER]]))).toEqual(red(postgres, runFoundation));
    // Only another deploy recorded, or none.
    expect(
      decided(
        [postgres],
        new Map([
          ['secrets', NEW],
          ['certificates', NEW],
        ]),
      ),
    ).toEqual(red(postgres, runFoundation));
    expect(decided([postgres], new Map())).toEqual(red(postgres, runFoundation));
    // Read by two, one recorded: the other named alone.
    expect(decided(['deploy/azure/shared.json'], new Map([['foundation', NEW]]))).toEqual(
      red(
        'deploy/azure/shared.json',
        'deploy.ts secrets reads it, so run it by hand, its what-if read, then run this release again',
      ),
    );
    // One file covered and one not: red for the one not.
    expect(decided([postgres, 'deploy/azure/secrets.bicep'], new Map([['foundation', NEW]]))).toEqual(
      red(
        'deploy/azure/secrets.bicep',
        'deploy.ts secrets reads it, so run it by hand, its what-if read, then run this release again',
      ),
    );
  });

  it('judges each release staging runs on its own, against the same records', () => {
    const older = commit('c');
    // The job fell behind: it runs an older commit than the API.
    const split = (records: Records, since: Readonly<Record<string, readonly string[]>>): Decision =>
      decide(
        both(running('api'), at(older)('migrate')),
        NEW,
        NEW_IMAGE,
        history([older, OLD, MIDDLE, NEW], { [older]: [postgres], [OLD]: [postgres], ...since }),
        readers,
        records,
      );
    expect(split(new Map([['foundation', MIDDLE]]), { [MIDDLE]: [] })).toMatchObject({
      kind: 'release',
      deployed: [
        `${postgres} changed since ${older}: deployed by hand, foundation from ${MIDDLE}`,
        `${postgres} changed since ${OLD}: deployed by hand, foundation from ${MIDDLE}`,
      ],
    });
    expect(split(new Map([['foundation', MIDDLE]]), { [MIDDLE]: [postgres] })).toEqual({
      kind: 'by-hand',
      reasons: [
        `${postgres} changed since ${older}: ${runFoundation}`,
        `${postgres} changed since ${OLD}: ${runFoundation}`,
      ],
    });
  });

  it('never takes a record for apps, a file no deployment reads, or when Bicep has not said', () => {
    // apps's stamp is what staging runs: no record stands in for it.
    const runApps = 'deploy.ts apps reads it, so run it by hand, its what-if read';
    expect(decided(['deploy/azure/apps.bicep'], every)).toEqual(red('deploy/azure/apps.bicep', runApps));
    // Not even a record for apps itself, which recordsIn never reads but a caller could hand in.
    const forApps = new Map<string, string>([...every, ['apps', NEW]]) as unknown as Records;
    expect(decided(['deploy/azure/apps.bicep'], forApps)).toEqual(red('deploy/azure/apps.bicep', runApps));
    expect(decided(['deploy/azure/names.bicep'], every)).toEqual(red('deploy/azure/names.bicep', runApps));
    expect(decided(['deploy/azure/hand-deployed.json'], every)).toEqual(
      red('deploy/azure/hand-deployed.json', HAND_DEPLOYED[0]?.why ?? ''),
    );
    expect(decided(['db/bootstrap/roles.sql'], every)).toEqual(
      red('db/bootstrap/roles.sql', HAND_DEPLOYED[1]?.why ?? ''),
    );
    expect(decided([postgres], every, {}, null)).toEqual(red(postgres, HAND_DEPLOYED[0]?.why ?? ''));
  });
});

describe('the hand deploys records', () => {
  it("are read from each recorded deploy's tag on the migration job, and nothing else", () => {
    const said: string[] = [];
    const tags = {
      environment: 'staging',
      'agentx-deployed-foundation': NEW,
      'agentx-deployed-certificates': OLD,
      'agentx-deployed-apps': NEW,
      'Agentx-Deployed-Secrets': NEW,
    };
    expect(recordsIn(tags, (line) => said.push(line))).toEqual(
      new Map([
        ['foundation', NEW],
        ['certificates', OLD],
      ]),
    );
    expect(said).toEqual([]);
  });

  it("count a record that isn't a commit for nothing, saying so without its value", () => {
    for (const value of ['main', NEW.toUpperCase(), NEW.slice(1), `${NEW} `, 1, null]) {
      const said: string[] = [];
      expect(recordsIn({ 'agentx-deployed-secrets': value }, (line) => said.push(line))).toEqual(new Map());
      expect(said).toEqual(["The migration job's agentx-deployed-secrets isn't a commit, so it counts for nothing."]);
    }
  });

  it('are held on the job CI releases, one tag for each deploy but apps', () => {
    expect(RECORDS_JOB).toBe(jobName('migrate'));
    expect(`jobs/${RECORDS_JOB}`).toBe(WORKLOADS.migrate.path);
    expect(RECORDED.map(recordTag)).toEqual([
      'agentx-deployed-foundation',
      'agentx-deployed-secrets',
      'agentx-deployed-certificates',
    ]);
    expect([...RECORDED, 'apps'].sort()).toEqual(Object.keys(DEPLOYMENTS).sort());
  });
});

describe('which hand deploys read each file', () => {
  it("is read from Bicep's answers by each file's path in the repository, in lower case, in DEPLOYMENTS order", () => {
    const readers = readersFrom(SAID);
    expect(readers.get('deploy/azure/names.bicep')).toEqual(['foundation', 'secrets', 'apps', 'certificates']);
    expect(readers.get('deploy/azure/modules/postgres.bicep')).toEqual(['foundation']);
    expect(readers.get('deploy/azure/staging.apps.bicepparam')).toEqual(['apps']);
    // A file said twice is one reader, and a path in the repository in another case is the same file.
    const upper = (file: string): string => path.join(ROOT, path.relative(ROOT, file).toUpperCase());
    const twice = new Map([...SAID].map(([params, read]) => [params, [...read, ...read, ...read.map(upper)]]));
    expect(readersFrom(twice)).toEqual(readers);
  });

  it("refuses answers missing a deployment's, or naming a file outside the repository", () => {
    const without = new Map(SAID);
    without.delete(PARAMS_PATHS.get('secrets') ?? '');
    expect(() => readersFrom(without)).toThrow('Bicep said nothing of what secrets reads');
    // On Windows, a file on another drive has no path relative to the repository at all.
    const otherDrive = process.platform === 'win32' ? 'Z:\\elsewhere.bicep' : '/elsewhere.bicep';
    for (const outside of [path.join(ROOT, '..', 'elsewhere.bicep'), path.dirname(path.resolve(ROOT)), otherDrive]) {
      const answers = new Map([...SAID].map(([params, read]) => [params, [...read, outside]]));
      expect(() => readersFrom(answers)).toThrow(
        `Bicep says a deployment reads ${outside}, which isn't in the repository`,
      );
    }
    const root = new Map([...SAID].map(([params, read]) => [params, [...read, path.resolve(ROOT)]]));
    expect(() => readersFrom(root)).toThrow("which isn't in the repository");
  });

  it('asks about every parameters file here, each named once', () => {
    expect(Object.values(DEPLOYMENTS).sort()).toEqual(paramsFiles());
    expect([...PARAMS_PATHS.values()]).toEqual(Object.values(DEPLOYMENTS).map((file) => full(`deploy/azure/${file}`)));
  });

  it('is what the pinned Bicep says of our deployments: the foundation alone reads the infrastructure', async () => {
    const readers = readersFrom(await fileReferences([...PARAMS_PATHS.values()]));
    const all = ['foundation', 'secrets', 'apps', 'certificates'];
    expect(Object.fromEntries(readers)).toEqual({
      'deploy/azure/app-keys.json': all,
      'deploy/azure/apps.bicep': ['apps'],
      'deploy/azure/bicepconfig.json': all,
      'deploy/azure/certificates.bicep': ['certificates'],
      // The database server's generation (AZ25), through names.bicep: a change asks for every hand deploy.
      'deploy/azure/database-generation.json': all,
      'deploy/azure/dns-allowed.json': ['foundation'],
      'deploy/azure/github-ranges.json': ['foundation'],
      'deploy/azure/main.bicep': ['foundation'],
      'deploy/azure/modules/activity-downloads.bicep': ['foundation', 'apps'],
      'deploy/azure/modules/communication.bicep': ['foundation'],
      'deploy/azure/modules/dns-policy.bicep': ['foundation'],
      'deploy/azure/modules/environment.bicep': ['foundation'],
      'deploy/azure/modules/evidence.bicep': ['foundation', 'apps'],
      'deploy/azure/modules/job-watch.bicep': ['foundation'],
      'deploy/azure/modules/keyvault.bicep': ['foundation'],
      'deploy/azure/modules/metrics.bicep': ['foundation'],
      'deploy/azure/modules/monitoring.bicep': ['foundation'],
      'deploy/azure/modules/network.bicep': ['foundation'],
      'deploy/azure/modules/postgres.bicep': ['foundation'],
      'deploy/azure/modules/release.bicep': ['foundation'],
      'deploy/azure/modules/secret-access.bicep': ['secrets'],
      'deploy/azure/names.bicep': all,
      'deploy/azure/secrets.bicep': ['secrets'],
      'deploy/azure/staging.apps.bicepparam': ['apps'],
      'deploy/azure/staging.bicepparam': ['foundation'],
      'deploy/azure/staging.certificates.bicepparam': ['certificates'],
      'deploy/azure/staging.secrets.bicepparam': ['secrets'],
    });
    // None of it a test file, which a release lets through unasked.
    expect([...readers.keys()].filter((file) => file.endsWith(TEST_FILE))).toEqual([]);
  }, 60_000);
});

/** A stand-in CLI: the account and the two workloads, recording each call. */
function fakeAz(
  containers: Readonly<Record<Workload, unknown>>,
  calls: string[][],
  account: unknown = { name: 'Azure subscription 1', id: SUBSCRIPTION },
  jobTags: Readonly<Record<string, unknown>> = {},
): Az {
  const answer = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
  return {
    interactive: () => {
      throw new Error('check never runs the CLI interactively');
    },
    run: (args) => {
      calls.push([...args]);
      if (args[0] === 'account') return answer(account);
      // What deploys left on record (AZ2c): no revision or run of another build.
      if (args.some((arg) => arg.includes('/revisions?') || arg.includes('/executions?'))) return answer({ value: [] });
      const workload = ORDER.find((each) => args.includes(workloadUrl(SUBSCRIPTION, each)));
      if (args[0] === 'rest' && workload !== undefined) {
        return answer({
          id: 'x',
          ...(workload === 'migrate' ? { tags: jobTags } : {}),
          ...around(workload, containers[workload], 'azure'),
        });
      }
      return { status: 1, stdout: '', stderr: `unexpected: az ${args.join(' ')}` };
    },
  };
}

/** The stand-in image check: every image is CI's signed build of the commit asked about. */
const signedAsNamed = (): Outcome => ({ verified: true });

/** The one line a release says while no pin is set (AZ2c H3). */
const NOT_PINNED =
  "Not pinned (AGENTX_AUTH_HOST_SHA256, AGENTX_APP_HOST_SHA256, AGENTX_OIDC_CLIENT_ID_SHA256 unset): the auth host, app host, API's client ID held to shape alone. Nothing is wrong; set each as a staging secret to hold it exactly.";

/** Both workloads at a build, as the stand-in CLI answers them. */
const staging = (release: string, image = OLD_IMAGE): Readonly<Record<Workload, unknown>> => ({
  api: [azureContainer('api', { image, env: builtAt(release) })],
  migrate: [azureContainer('migrate', { image, env: builtAt(release) })],
});

/** A check of NEW against staging, with what it said and did. */
async function checked(
  containers: Readonly<Record<Workload, unknown>>,
  line: History,
  account?: unknown,
  folder: Folder = folderAt(NEW).folder,
  jobTags: Readonly<Record<string, unknown>> = {},
): Promise<{ status: number | undefined; said: string[]; calls: string[][]; error: unknown }> {
  const said: string[] = [];
  const calls: string[][] = [];
  try {
    const status = await check(
      { command: 'check', commit: NEW, digest: digest('2') },
      {
        az: fakeAz(containers, calls, account, jobTags),
        history: line,
        folder,
        say: (said_) => said.push(said_),
        verify: signedAsNamed,
        pins: {},
      },
    );
    return { status, said, calls, error: undefined };
  } catch (error) {
    return { status: undefined, said, calls, error };
  }
}

describe('check', () => {
  it('reads the two from Resource Manager, and says what a release would change in each, changing nothing', async () => {
    const { folder, asked } = folderAt(NEW);
    const { status, said, calls } = await checked(
      staging(OLD),
      history([OLD, NEW], { [OLD]: ['apps/api/src/main.ts'] }),
      undefined,
      folder,
    );
    expect(status).toBe(0);
    // Bicep is asked only once a release is red.
    expect(asked).toEqual([]);
    expect(said).toEqual([
      'Signed in to the subscription "Azure subscription 1".',
      `migrate runs ${OLD} (${OLD_IMAGE}).`,
      `api runs ${OLD} (${OLD_IMAGE}).`,
      NOT_PINNED,
      `A release of ${NEW} would update, in order:`,
      `  migrate: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
      `  api: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
    ]);
    // Reads only: the account, then each workload by GET, at the version apps.bicep deploys it with, then what
    // deploys left on record (AZ2c): the API's revisions and migrate's runs.
    const at = (resource: string): string[] => [
      'rest',
      '--method',
      'get',
      '--url',
      `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/${resource}?api-version=${JOBS_API}`,
      '--output',
      'json',
    ];
    expect(calls).toEqual([
      ['account', 'show', '--output', 'json'],
      ...ORDER.map((workload) => at(WORKLOADS[workload].path)),
      at(`${WORKLOADS.api.path}/revisions`),
      at(`${WORKLOADS.migrate.path}/executions`),
    ]);
  });

  it('says so when a release has nothing to do, or staging is already past the commit', async () => {
    const current = await checked(staging(NEW, NEW_IMAGE), history([NEW]));
    expect(current.status).toBe(0);
    expect(current.said.at(-1)).toBe(`Both already run ${NEW}: a release has nothing to do.`);
    const past = await checked(staging(LATER), history([NEW, LATER]));
    expect(past.status).toBe(0);
    expect(past.said.at(-1)).toBe(
      `Staging already runs a later commit than ${NEW}: a release of it has nothing to do.`,
    );
  });

  it('ends with failure when it needs a hand deploy, giving each reason and the deploys that read each file', async () => {
    const { folder, asked } = folderAt(NEW);
    const { status, said } = await checked(
      staging(OLD),
      history([OLD, NEW], { [OLD]: ['db/bootstrap/roles.sql', 'deploy/azure/modules/postgres.bicep'] }),
      undefined,
      folder,
    );
    expect(status).toBe(1);
    expect(said.slice(-3)).toEqual([
      `A release of ${NEW} stops here, red: this needs a hand deploy.`,
      `  db/bootstrap/roles.sql changed since ${OLD}: ${HAND_DEPLOYED[1]?.why ?? ''}`,
      `  deploy/azure/modules/postgres.bicep changed since ${OLD}: deploy.ts foundation reads it, so run it by hand, its what-if read, then run this release again`,
    ]);
    // Bicep was asked once, about every deployment.
    expect(asked).toEqual([[...PARAMS_PATHS.values()]]);
  });

  it('goes ahead on a change only recorded deploys read, saying which records it rests on', async () => {
    const { folder, asked } = folderAt(NEW);
    const { status, said } = await checked(
      staging(OLD),
      history([OLD, NEW], { [OLD]: ['deploy/azure/modules/postgres.bicep'] }),
      undefined,
      folder,
      { 'agentx-deployed-foundation': NEW },
    );
    expect(status).toBe(0);
    expect(said.slice(3)).toEqual([
      `The migration job records: foundation sent ${NEW}.`,
      NOT_PINNED,
      'Deployed by hand already, as the migration job records:',
      `  deploy/azure/modules/postgres.bicep changed since ${OLD}: deployed by hand, foundation from ${NEW}`,
      `A release of ${NEW} would update, in order:`,
      `  migrate: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
      `  api: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
    ]);
    expect(asked).toHaveLength(1);
  });

  it("stays red on a record that isn't a commit, saying so", async () => {
    const { status, said } = await checked(
      staging(OLD),
      history([OLD, NEW], { [OLD]: ['deploy/azure/modules/postgres.bicep'] }),
      undefined,
      folderAt(NEW).folder,
      { 'agentx-deployed-foundation': 'main' },
    );
    expect(status).toBe(1);
    expect(said).toContain("The migration job's agentx-deployed-foundation isn't a commit, so it counts for nothing.");
    expect(said).toContain('The migration job holds no hand deploy records.');
  });

  it("leaves the deploys unsaid, still red whatever the records, when this folder isn't the commit or Bicep can't say", async () => {
    const changed = history([OLD, NEW], { [OLD]: ['deploy/azure/modules/postgres.bicep'] });
    const reason = `  deploy/azure/modules/postgres.bicep changed since ${OLD}: ${HAND_DEPLOYED[0]?.why ?? ''}`;
    const broken: Folder = {
      checkout: () => {
        throw new Error("git couldn't say which commit this folder is at:\nfatal: not a git repository");
      },
      references: () => Promise.reject(new Error('never asked')),
      templates: templatesOf(),
    };
    const cases: [Folder, string][] = [
      [folderAt(OLD).folder, `this folder is at ${OLD}, not ${NEW}`],
      [folderAt(NEW, SAID, false).folder, `this folder is at ${NEW} with changes, not ${NEW}`],
      [folderAt(NEW, new Error("Bicep didn't answer within 60 s")).folder, "Bicep didn't answer within 60 s"],
      [folderAt(NEW, new Map()).folder, 'Bicep said nothing of what foundation reads'],
      [broken, "git couldn't say which commit this folder is at:\nfatal: not a git repository"],
    ];
    // A record that would cover the file, were it known that only foundation reads it.
    const recorded = { 'agentx-deployed-foundation': NEW };
    for (const [folder, why] of cases) {
      const { status, said } = await checked(staging(OLD), changed, undefined, folder, recorded);
      expect(status).toBe(1);
      expect(said.slice(-4)).toEqual([
        `Which hand deploy reads each file goes unsaid: ${why}.`,
        `The migration job records: foundation sent ${NEW}.`,
        `A release of ${NEW} stops here, red: this needs a hand deploy.`,
        reason,
      ]);
    }
    // Bicep isn't asked about a folder that isn't a clean checkout of the commit.
    for (const [head, clean] of [
      [OLD, true],
      [NEW, false],
    ] as const) {
      const { folder, asked } = folderAt(head, SAID, clean);
      await checked(staging(OLD), changed, undefined, folder);
      expect(asked).toEqual([]);
    }
  });

  it('never prints the subscription or the host the settings name, whatever it ends with', async () => {
    const outcomes = await Promise.all([
      checked(staging(OLD), history([OLD, NEW])),
      checked(staging(NEW, NEW_IMAGE), history([NEW])),
      checked(staging(LATER), history([NEW, LATER])),
      checked(staging(OLD), history([OLD, NEW], { [OLD]: ['deploy/azure/apps.bicep'] })),
      checked({ ...staging(OLD), api: [azureContainer('api', { probes: [] })] }, history([OLD, NEW])),
    ]);
    for (const { said, error } of outcomes) {
      const printed = [...said, error instanceof Error ? error.message : ''].join('\n');
      expect(printed).not.toContain(SUBSCRIPTION);
      expect(printed).not.toContain(HOST);
    }
  });

  it('refuses an account that names no subscription, reading nothing more', async () => {
    // No ID, one that isn't a subscription's, none at all, or a sign-in to a tenant alone (its "ID" the tenant's).
    const tenant = '00000000-0000-0000-0000-00000000000d';
    for (const account of [
      { name: 'x' },
      { name: 'x', id: 'not-a-subscription' },
      null,
      { name: 'x', id: tenant, tenantId: tenant },
    ]) {
      const { error, calls } = await checked(staging(OLD), history([OLD, NEW]), account);
      expect(error).toMatchObject({ message: "The Azure CLI named no subscription it's signed in to." });
      expect(calls).toHaveLength(1);
    }
  });
});

/** What a release writes: the method, the URL and the body, as sent. */
interface Write {
  readonly method: string;
  readonly url: string;
  readonly body: unknown;
}

const TENANT = '00000000-0000-0000-0000-00000000000c';

/** An az call that succeeded, answering with the value as JSON. */
const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/** An az call that succeeded and printed nothing. */
const AZ_DONE: AzResult = { status: 0, stdout: '', stderr: '' };

/** An error as `az rest` prints it: the HTTP reason, then Azure's answer, which names the subscription and quotes the host. */
const azRestError = (reason: string, code: string): string => {
  const message = `The client may not perform action(s) on /subscriptions/${SUBSCRIPTION}/x with https://${HOST}`;
  return `ERROR: ${reason}(${JSON.stringify({ error: { code, message } })})`;
};

type State = 'Succeeded' | 'Failed' | 'Canceled' | 'InProgress';

/** One of the two workloads as the stand-in holds it. */
interface Held {
  release: string;
  image: string;
  state: State;
  command: readonly string[];
}

/** A revision of the API: what it runs, and how Azure describes it. */
interface HeldRevision {
  image: string;
  release: string;
  provisioningState: string;
  active: boolean;
  trafficWeight: number;
  healthState: string;
}

/**
 * A stand-in for staging as a release sees it: the migration job and its runs,
 * the API and its revisions, each changed by what a release sends and settling
 * over later reads, with a knob for every way the review found Azure can
 * behave. Time moves only when the release sleeps.
 */
class Staging {
  readonly calls: string[][] = [];
  readonly writes: Write[] = [];
  clock = new Date('2026-09-18T12:00:00Z').getTime();
  account: unknown = { name: 'Azure subscription 1', id: SUBSCRIPTION, tenantId: TENANT };
  job: Held & { limit: unknown } = {
    release: OLD,
    image: OLD_IMAGE,
    state: 'Succeeded',
    command: ['node'],
    limit: 900,
  };
  /** The migration job's tags, which hold the hand deploys' records (T1b). */
  jobTags: Readonly<Record<string, unknown>> = { environment: 'staging', product: 'agent-x' };
  app: Held & { suffix: unknown; env: readonly unknown[] } = {
    release: OLD,
    image: OLD_IMAGE,
    state: 'Succeeded',
    command: ['node'],
    suffix: '',
    env: builtAt(OLD),
  };
  /** What the commit's apps.bicep gives each (AZ2c): the workloads staging holds, at any image and build. */
  templates: ReadonlyMap<Workload, unknown> | Error = new Map(
    ORDER.map(
      (workload) =>
        [
          workload,
          around(workload, [azureContainer(WORKLOADS[workload].container, { command: ['node'] })], 'snapshot'),
        ] as const,
    ),
  );
  /** A change made to a workload outside a deploy, as every read of it shows it (AZ2c). */
  meddleWith: (workload: Workload, resource: Record<string, unknown>) => unknown = (_workload, resource) => resource;
  /** The pins the release is given (AZ2c H3), and what the image check answers. */
  pins: Readonly<Record<string, string | undefined>> = {};
  signed: (image: string, commit: string) => Outcome = signedAsNamed;
  latest = 'ca-agentx-stg-api--0000007';
  ready = 'ca-agentx-stg-api--0000007';
  revisions = new Map<string, HeldRevision>([
    [
      'ca-agentx-stg-api--0000007',
      {
        image: OLD_IMAGE,
        release: OLD,
        provisioningState: 'Provisioned',
        active: true,
        trafficWeight: 100,
        healthState: 'Healthy',
      },
    ],
  ]);
  runs: { name: string; status: string; image: string; polls: number; release?: string }[] = [
    { name: 'job-agentx-stg-migrate-aocy0fb', status: 'Succeeded', image: OLD_IMAGE, polls: 0 },
  ];

  /** After a PATCH, for `lag` reads Azure still shows what was there, marked `lagState`; then `settleAfter` reads InProgress; then `settleAs`. */
  lag = 1;
  lagState: State = 'Succeeded';
  settleAfter = 1;
  settleAs: State = 'Succeeded';
  /** The API's settling alone, when it differs from the job's. */
  apiSettleAs: State | undefined;
  /** Once the API has settled, its new revision is named after `revisionLag` reads, then ready after `readyAfter`. */
  revisionLag = 0;
  readyAfter = 1;
  newRevision = 'ca-agentx-stg-api--0000008';
  /** The new revision takes traffic, and is active, after `trafficAfter` reads of it. */
  trafficAfter = 1;
  newRevisionHealth = 'Healthy';
  newRevisionImage: string | undefined;
  newRevisionRelease: string | undefined;
  newRevisionState = 'Provisioned';
  /** Where the new revision ends up once it takes traffic: each can fall short on its own. */
  newRevisionActive = true;
  newRevisionTraffic = 100;
  /** How every revision's container is recorded: its name, and whether it carries its build. */
  revisionContainer: { readonly name: string; readonly stamped: boolean; readonly sidecar?: boolean } = {
    name: 'api',
    stamped: true,
  };
  /** How a start goes: how many runs it makes, whether it names one, when it is listed, how the run ends, of which image. */
  newRuns = 1;
  startNames: 'nothing' | 'its run' | 'another' = 'nothing';
  listLag = 0;
  runPolls = 2;
  runEndsAs = 'Succeeded';
  runImage: string | undefined;
  newRunName: string | undefined;
  /** The door: what it answers each time it is asked. */
  probes: (number | undefined)[] = [undefined, 200];
  answered = false;
  /** A write Azure refuses, a read it fails from the nth of its kind, and another deploy between two reads of a workload. */
  refuse: { readonly method: string; readonly stderr: string } | undefined;
  failRead: { readonly what: RegExp; readonly from: number } | undefined;
  meddle: ((staging: Staging) => void) | undefined;

  private pending: { workload: Workload; lag: number; settling: number; apply: () => void } | undefined;
  private lists = 0;
  /** Whether the API was updated: only an update makes a new revision. */
  private updated = false;

  private held(workload: Workload): Held {
    return workload === 'migrate' ? this.job : this.app;
  }

  private resource(workload: Workload): unknown {
    const held = this.held(workload);
    let state: State = held.state;
    const pending = this.pending?.workload === workload ? this.pending : undefined;
    if (pending !== undefined && pending.lag > 0) {
      pending.lag -= 1;
      state = this.lagState;
    } else if (pending !== undefined) {
      pending.apply();
      if (pending.settling > 0) {
        pending.settling -= 1;
        state = 'InProgress';
      } else {
        this.pending = undefined;
        state = held.state;
      }
    }
    if (workload === 'api' && this.pending === undefined) this.renameAndReady();
    return this.meddleWith(workload, this.shape(workload, state));
  }

  /** A workload as Azure gives it now, marked with `state`. */
  shape(workload: Workload, state: State = this.held(workload).state): Record<string, unknown> {
    const held = this.held(workload);
    const container = azureContainer(WORKLOADS[workload].container, {
      image: held.image,
      command: held.command,
      env: workload === 'api' ? this.app.env : builtAt(held.release),
    });
    const { identity, properties } = around(workload, [container], 'azure') as {
      identity: unknown;
      properties: { configuration: Record<string, unknown>; template: Record<string, unknown> };
    };
    return {
      ...(workload === 'migrate' ? { tags: this.jobTags } : {}),
      identity,
      properties: {
        ...properties,
        provisioningState: state,
        ...(workload === 'migrate'
          ? { configuration: { ...properties.configuration, replicaTimeout: this.job.limit } }
          : {
              latestRevisionName: this.latest,
              latestReadyRevisionName: this.ready,
              template: { ...properties.template, revisionSuffix: this.app.suffix },
            }),
      },
    };
  }

  /** Once the API holds a new build, its new revision is named, then made ready, over later reads. */
  private renameAndReady(): void {
    if (!this.updated || this.app.state !== 'Succeeded' || this.revisions.has(this.newRevision)) {
      if (this.latest !== this.ready) {
        if (this.readyAfter > 0) this.readyAfter -= 1;
        else this.ready = this.latest;
      }
      return;
    }
    if (this.revisionLag > 0) {
      this.revisionLag -= 1;
      return;
    }
    this.revisions.set(this.newRevision, {
      image: this.newRevisionImage ?? this.app.image,
      release: this.newRevisionRelease ?? this.app.release,
      provisioningState: this.newRevisionState,
      active: false,
      trafficWeight: 0,
      healthState: 'None',
    });
    this.latest = this.newRevision;
  }

  private patched(workload: Workload, body: string | undefined): void {
    const sent = JSON.parse(body ?? '{}') as {
      properties: {
        template: {
          revisionSuffix?: string;
          containers: { image: string; command: string[]; env: { name: string; value?: string }[] }[];
        };
      };
    };
    if (workload === 'api') this.app.suffix = sent.properties.template.revisionSuffix;
    const [container] = sent.properties.template.containers;
    const build = container?.env.find((entry) => entry.name === 'AGENTX_RELEASE')?.value ?? '';
    const settleAs = workload === 'api' ? (this.apiSettleAs ?? this.settleAs) : this.settleAs;
    this.pending = {
      workload,
      lag: this.lag,
      settling: this.settleAfter,
      apply: () => {
        Object.assign(this.held(workload), {
          image: container?.image,
          release: build,
          command: container?.command,
          state: settleAs,
        });
        if (workload === 'api') {
          this.app.env = container?.env ?? [];
          this.updated = true;
        }
      },
    };
  }

  private revision(name: string): unknown {
    const found = this.revisions.get(name);
    if (found === undefined) return undefined;
    if (name === this.newRevision) {
      if (this.trafficAfter > 0) this.trafficAfter -= 1;
      else Object.assign(found, { active: this.newRevisionActive, trafficWeight: this.newRevisionTraffic });
      found.healthState = this.answered ? this.newRevisionHealth : 'None';
    }
    return {
      properties: {
        provisioningState: found.provisioningState,
        active: found.active,
        trafficWeight: found.trafficWeight,
        healthState: found.healthState,
        // A revision's container as Azure records it (the first real release, S24):
        // its own defaults filled in (`probes: []`), and no `args`.
        template: {
          containers: [
            Object.fromEntries(
              Object.entries({
                ...azureContainer(this.revisionContainer.name, {
                  image: found.image,
                  command: ['node'],
                  env: builtAt(found.release).filter(
                    (entry) => this.revisionContainer.stamped || (entry as { name: string }).name !== 'AGENTX_RELEASE',
                  ),
                }),
                probes: [],
              }).filter(([field]) => field !== 'args'),
            ),
            // A second container, such as a sidecar added by hand: never one CI sends.
            ...(this.revisionContainer.sidecar ? [{ name: 'sidecar', image: 'ghcr.io/example/sidecar:1' }] : []),
          ],
        },
      },
    };
  }

  /** A write recorded, then refused if the test says so; or a read failed, once it has been made as often as the test says. */
  private refusal(
    method: string,
    url: string,
    flag: string | undefined,
    body: string | undefined,
  ): AzResult | undefined {
    if (method !== 'get') {
      this.writes.push({
        method,
        url,
        body: flag === '--body' ? (JSON.parse(String(body)) as unknown) : undefined,
      });
      if (this.refuse?.method === method) return { status: 1, stdout: '', stderr: this.refuse.stderr };
    } else if (this.failRead?.what.test(url) === true) {
      const seen = this.calls.filter((call) => call.includes(url)).length;
      if (seen >= this.failRead.from)
        return { status: 1, stdout: '', stderr: azRestError('Too Many Requests', 'TooManyRequests') };
    }
    return undefined;
  }

  /** A call on the migration job's runs: the list, a start, or a run's reading; undefined for any other. */
  private migrateCall(method: string, url: string, jobBase: string, query: string): AzResult | undefined {
    if (method === 'get' && url === `${jobBase}/executions${query}`) {
      this.lists += 1;
      const listed = this.runs.filter(
        (run) => run.polls >= 0 && (this.lists > this.listLag || !run.name.includes('new')),
      );
      // Each run's template names its build (AZ2c: what deploys left on record); the first run's is OLD.
      return json({
        value: listed.map(({ name, status, image, release }) => ({
          name,
          properties: {
            status,
            template: {
              containers: [{ name: 'migrate', image, env: [{ name: 'AGENTX_RELEASE', value: release ?? OLD }] }],
            },
          },
        })),
      });
    }
    if (method === 'post' && url === `${jobBase}/start${query}`) return this.startMigrate();
    const run = this.runs.find((each) => url === `${jobBase}/executions/${each.name}${query}`);
    if (method === 'get' && run !== undefined) {
      if (run.polls > 0) run.polls -= 1;
      else if (run.status === 'Running') run.status = this.runEndsAs;
      return json({
        name: run.name,
        properties: { status: run.status, template: { containers: [{ name: 'migrate', image: run.image }] } },
      });
    }
    return undefined;
  }

  /** A start of the migration job: the new runs listed, and the name the start gives as the test says. */
  private startMigrate(): AzResult {
    this.lists = 0;
    const made: string[] = [];
    for (let index = 0; index < this.newRuns; index += 1) {
      const name = this.newRunName ?? `job-agentx-stg-migrate-new${String(index)}x`;
      made.push(name);
      this.runs.unshift({
        name,
        status: 'Running',
        image: this.runImage ?? this.job.image,
        release: this.job.release,
        polls: this.runPolls,
      });
    }
    if (this.startNames === 'its run') return json({ name: made[0] });
    if (this.startNames === 'another') return json({ name: 'job-agentx-stg-migrate-other1' });
    return AZ_DONE;
  }

  az(): Az {
    const query = `?api-version=${JOBS_API}`;
    const jobBase = workloadUrl(SUBSCRIPTION, 'migrate').replace(query, '');
    const appBase = workloadUrl(SUBSCRIPTION, 'api').replace(query, '');
    return {
      interactive: () => {
        throw new Error('a release never runs the CLI interactively');
      },
      run: (args) => {
        this.calls.push([...args]);
        if (args[0] === 'account') return json(this.account);
        const [, , method = '', , url = '', flag, body] = args;
        const refused = this.refusal(method, url, flag, body);
        if (refused !== undefined) return refused;
        const workload = ORDER.find((each) => url === workloadUrl(SUBSCRIPTION, each));
        if (method === 'get' && workload !== undefined) {
          if (this.calls.filter((call) => call.includes(url)).length === 2) this.meddle?.(this);
          return json(this.resource(workload));
        }
        if (method === 'patch' && workload !== undefined) {
          this.patched(workload, body);
          return AZ_DONE;
        }
        const migrate = this.migrateCall(method, url, jobBase, query);
        if (migrate !== undefined) return migrate;
        // The API's revisions, each with its build (AZ2c: what deploys left on record).
        if (method === 'get' && url === `${appBase}/revisions${query}`) {
          return json({
            value: [...this.revisions].map(([name, held]) => ({
              name,
              properties: {
                template: { containers: [{ name: 'api', env: [{ name: 'AGENTX_RELEASE', value: held.release }] }] },
              },
            })),
          });
        }
        const revision = /\/revisions\/([^?]+)\?/.exec(url)?.[1];
        if (method === 'get' && url.startsWith(`${appBase}/revisions/`) && revision !== undefined) {
          const found = this.revision(revision);
          if (found !== undefined) return json(found);
        }
        return { status: 1, stdout: '', stderr: `unexpected: az ${args.join(' ')}` };
      },
    };
  }

  steps(
    line: History,
    verified = true,
  ): ReleaseSteps & { readonly said: string[]; readonly templates: Folder['templates'] } {
    const said: string[] = [];
    return {
      az: this.az(),
      history: line,
      folder: folderAt(NEW, SAID, true, this.templates).folder,
      templates: templatesOf(this.templates),
      say: (text) => said.push(text),
      said,
      now: () => new Date(this.clock),
      sleep: (ms) => {
        this.clock += ms;
        return Promise.resolve();
      },
      // The new image as the test says; what staging runs as `signed` answers (AZ2c H2).
      verify: (image, commit) => {
        if (image !== NEW_IMAGE) return this.signed(image, commit);
        return verified
          ? { verified: true }
          : { verified: false, reason: 'SIGNATURE_REFUSED', detail: 'not signed by CI on main' };
      },
      pins: this.pins,
      probe: (url) => {
        expect(url).toBe(`https://${HOST}/health`);
        const status = this.probes.length > 1 ? this.probes.shift() : this.probes[0];
        if (status === 200) this.answered = true;
        return Promise.resolve(status);
      },
    };
  }
}

const RELEASE_NEW = { command: 'release', commit: NEW, digest: digest('2') } as const;

/** The commit's templates made to give each workload what staging now holds, for a test of something else (AZ2c). */
function deployedAsIs(azure: Staging): void {
  azure.templates = new Map(ORDER.map((workload) => [workload, azure.shape(workload)] as const));
}

/** A release of NEW from OLD on a history where nothing a person deploys changed. */
const ordinary = (): History => history([OLD, NEW], { [OLD]: ['apps/api/src/main.ts'] });

/** A release's outcome: its status or error, what it said, and both together for looking through. */
async function outcome(azure: Staging, line = ordinary()) {
  const steps = azure.steps(line);
  const ended_ = await release(RELEASE_NEW, steps).then(
    (status) => ({ status, error: undefined as unknown }),
    (error: unknown) => ({ status: undefined, error }),
  );
  const message = ended_.error instanceof Error ? ended_.error.message : '';
  return { ...ended_, said: steps.said, message, printed: [...steps.said, message].join('\n') };
}

const methods = (azure: Staging): string[] => azure.writes.map((write) => write.method);

describe('release', () => {
  it('checks the image, updates and runs the migration, then updates the API and waits for it to serve', async () => {
    const azure = new Staging();
    const { status, said, printed } = await outcome(azure);
    expect(status).toBe(0);
    // Exactly three writes, in order: the job's containers, its start (no body), the API's containers.
    expect(azure.writes).toEqual([
      {
        method: 'patch',
        url: workloadUrl(SUBSCRIPTION, 'migrate'),
        body: {
          properties: {
            template: { containers: [released(running('migrate', { command: ['node'] }), NEW_IMAGE, NEW)] },
          },
        },
      },
      { method: 'post', url: workloadUrl(SUBSCRIPTION, 'migrate').replace('?', '/start?'), body: undefined },
      {
        method: 'patch',
        url: workloadUrl(SUBSCRIPTION, 'api'),
        body: {
          properties: {
            template: {
              revisionSuffix: '',
              containers: [released(running('api', { command: ['node'] }), NEW_IMAGE, NEW)],
            },
          },
        },
      },
    ]);
    expect(said).toEqual([
      `Checking ${NEW_IMAGE} was signed by CI on main at ${NEW}, with its SBOM...`,
      'Signed in to the subscription "Azure subscription 1".',
      `migrate runs ${OLD} (${OLD_IMAGE}).`,
      `api runs ${OLD} (${OLD_IMAGE}).`,
      NOT_PINNED,
      `Updating migrate: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}.`,
      `migrate holds ${NEW}.`,
      'Started job-agentx-stg-migrate-new0x.',
      '  job-agentx-stg-migrate-new0x: Running',
      '  job-agentx-stg-migrate-new0x: Succeeded',
      `Updating api: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}.`,
      `api holds ${NEW}.`,
      "The API's new revision ca-agentx-stg-api--0000008 takes all traffic; asking the door for /health...",
      `Released ${NEW}: job-agentx-stg-migrate-new0x succeeded, and the API's revision ca-agentx-stg-api--0000008 holds it, takes all traffic and is healthy; its door answered /health.`,
    ]);
    expect(printed).not.toContain(HOST);
    expect(printed).not.toContain(SUBSCRIPTION);
  });

  it('reads and changes nothing when the image is refused', async () => {
    const azure = new Staging();
    const steps = azure.steps(ordinary(), false);
    expect(await release(RELEASE_NEW, steps)).toBe(1);
    expect(azure.calls).toEqual([]);
    expect(steps.said.at(-1)).toBe(
      'The image was refused (SIGNATURE_REFUSED), so nothing was read or changed:\nnot signed by CI on main',
    );
  });

  it('releases a change only recorded deploys read, saying so, with the writes an ordinary release makes', async () => {
    const azure = new Staging();
    azure.jobTags = { ...azure.jobTags, 'agentx-deployed-foundation': NEW };
    const ended_ = await outcome(azure, history([OLD, NEW], { [OLD]: ['deploy/azure/modules/postgres.bicep'] }));
    expect(ended_.status).toBe(0);
    expect(ended_.said).toContain(
      `  deploy/azure/modules/postgres.bicep changed since ${OLD}: deployed by hand, foundation from ${NEW}`,
    );
    const plain = new Staging();
    expect((await outcome(plain)).status).toBe(0);
    expect(azure.writes).toEqual(plain.writes);
    // Without the record, the same change stays red and writes nothing.
    const unrecorded = new Staging();
    const red = await outcome(unrecorded, history([OLD, NEW], { [OLD]: ['deploy/azure/modules/postgres.bicep'] }));
    expect(red.status).toBe(1);
    expect(unrecorded.writes).toEqual([]);
  });

  it('writes nothing when a person must deploy it, or staging is already past it', async () => {
    const cases: [History, number, string][] = [
      [
        history([OLD, NEW], { [OLD]: ['deploy/azure/apps.bicep'] }),
        1,
        `  deploy/azure/apps.bicep changed since ${OLD}: deploy.ts apps reads it, so run it by hand, its what-if read`,
      ],
      [history([NEW, OLD]), 0, `Staging already runs a later commit than ${NEW}: a release of it has nothing to do.`],
    ];
    for (const [line, status, last] of cases) {
      const azure = new Staging();
      const ended_ = await outcome(azure, line);
      expect(ended_.status).toBe(status);
      expect(ended_.said.at(-1)).toBe(last);
      expect(azure.writes).toEqual([]);
    }
  });

  it('has nothing to do when both hold the commit and the API serves it; red when it holds it but does not', async () => {
    const holding = (): Staging => {
      const azure = new Staging();
      Object.assign(azure.job, { release: NEW, image: NEW_IMAGE });
      Object.assign(azure.app, { release: NEW, image: NEW_IMAGE, env: builtAt(NEW) });
      return azure;
    };
    const serving = holding();
    serving.revisions.set('ca-agentx-stg-api--0000007', {
      image: NEW_IMAGE,
      release: NEW,
      provisioningState: 'Provisioned',
      active: true,
      trafficWeight: 100,
      healthState: 'Healthy',
    });
    const served_ = await outcome(serving);
    expect(served_.status).toBe(0);
    expect(served_.said.at(-1)).toBe(
      `Both already run ${NEW}, and the API serves it from ca-agentx-stg-api--0000007: a release has nothing to do.`,
    );
    // A release that stopped after the API's update: its template holds the commit, the old revision serves.
    const stopped = holding();
    const red = await outcome(stopped);
    expect(red.status).toBe(1);
    expect(red.said.at(-1)).toBe(
      `Both hold ${NEW}, but the API doesn't serve it: it runs ${OLD} (${OLD_IMAGE}), not this release. Look at its revisions, then deploy by hand (apps).`,
    );
    const unready = holding();
    unready.latest = 'ca-agentx-stg-api--0000009';
    const notReady = await outcome(unready);
    expect(notReady.said.at(-1)).toBe(
      `Both hold ${NEW}, but the API doesn't serve it: its latest revision ca-agentx-stg-api--0000009 isn't the ready one (ca-agentx-stg-api--0000007). Look at its revisions, then deploy by hand (apps).`,
    );
    // The same image under another build is not this release either.
    const otherBuild = holding();
    otherBuild.revisions.set('ca-agentx-stg-api--0000007', {
      image: NEW_IMAGE,
      release: LATER,
      provisioningState: 'Provisioned',
      active: true,
      trafficWeight: 100,
      healthState: 'Healthy',
    });
    expect((await outcome(otherBuild)).said.at(-1)).toBe(
      `Both hold ${NEW}, but the API doesn't serve it: it runs ${LATER} (${NEW_IMAGE}), not this release. Look at its revisions, then deploy by hand (apps).`,
    );
    // A revision whose container isn't the API's, carries no build, or has another beside it, is never taken as serving this release.
    const shapes: [{ readonly name: string; readonly stamped: boolean; readonly sidecar?: boolean }, string][] = [
      [{ name: 'other', stamped: true }, 'it runs none (no container named api), not this release'],
      [{ name: 'api', stamped: false }, `it runs none (${NEW_IMAGE}), not this release`],
      [{ name: 'api', stamped: true, sidecar: true }, 'it runs none (no container named api), not this release'],
    ];
    for (const [revisionContainer, why] of shapes) {
      const odd = holding();
      odd.revisionContainer = revisionContainer;
      odd.revisions.set('ca-agentx-stg-api--0000007', {
        image: NEW_IMAGE,
        release: NEW,
        provisioningState: 'Provisioned',
        active: true,
        trafficWeight: 100,
        healthState: 'Healthy',
      });
      expect((await outcome(odd)).said.at(-1)).toBe(
        `Both hold ${NEW}, but the API doesn't serve it: ${why}. Look at its revisions, then deploy by hand (apps).`,
      );
      expect(odd.writes).toEqual([]);
    }
    for (const azure of [serving, stopped, unready, otherBuild]) expect(azure.writes).toEqual([]);
  });

  it('writes nothing when what it needs later is missing or staging is mid-change, saying nothing was changed', async () => {
    const origin = (value: string) => (azure: Staging) => {
      azure.app.env = builtAt(OLD).map((entry) =>
        (entry as { name: string }).name === 'AGENTX_PUBLIC_ORIGIN' ? { name: 'AGENTX_PUBLIC_ORIGIN', value } : entry,
      );
    };
    const noOrigin = 'The API names no https origin (AGENTX_PUBLIC_ORIGIN) to check it through once released.';
    const noLimit = 'Azure gave no time limit for migrate, so how long to wait for its run is unknown.';
    const cases: [string, (azure: Staging) => void][] = [
      [
        noOrigin,
        (azure) => {
          azure.app.env = builtAt(OLD).filter((entry) => (entry as { name: string }).name !== 'AGENTX_PUBLIC_ORIGIN');
        },
      ],
      [noOrigin, origin(`http://${HOST}`)],
      [noOrigin, origin(`https://${HOST}/path`)],
      [noLimit, (azure) => (azure.job.limit = undefined)],
      [noLimit, (azure) => (azure.job.limit = 0)],
      [noLimit, (azure) => (azure.job.limit = 1.5)],
      [
        "migrate has runs that haven't ended (job-agentx-stg-migrate-busy1 Running).",
        (azure) =>
          azure.runs.unshift({ name: 'job-agentx-stg-migrate-busy1', status: 'Running', image: OLD_IMAGE, polls: 99 }),
      ],
      [
        'migrate is Failed from an earlier change, so nothing was sent: look at it first.',
        (azure) => (azure.job.state = 'Failed'),
      ],
      [
        'api is InProgress from an earlier change, so nothing was sent: look at it first.',
        (azure) => (azure.app.state = 'InProgress'),
      ],
    ];
    for (const [message, arrange] of cases) {
      const azure = new Staging();
      arrange(azure);
      deployedAsIs(azure);
      const ended_ = await outcome(azure);
      expect(ended_.message).toBe(`${message}\nLeft: nothing was changed.`);
      expect(azure.writes).toEqual([]);
    }
  });

  it('clears a revision suffix set by hand with an empty one, never sending it again to be refused as taken (AZ7)', async () => {
    const azure = new Staging();
    azure.app.suffix = 'hand';
    const { status } = await outcome(azure);
    expect(status).toBe(0);
    const [, , api] = azure.writes;
    expect(api?.body).toMatchObject({ properties: { template: { revisionSuffix: '' } } });
    expect(azure.app.suffix).toBe('');
  });

  it('runs the migration again without resending the job when it already holds the commit', async () => {
    const azure = new Staging();
    Object.assign(azure.job, { release: NEW, image: NEW_IMAGE });
    const { status, said } = await outcome(azure, history([OLD, NEW]));
    expect(status).toBe(0);
    expect(said).toContain(`migrate already holds ${NEW}: nothing to send.`);
    expect(methods(azure)).toEqual(['post', 'patch']);
  });

  it('leaves the API as it was when the migration fails, saying what it left and how to read the log', async () => {
    for (const ending of ['Failed', 'Stopped', 'Degraded']) {
      const azure = new Staging();
      azure.runEndsAs = ending;
      const ended_ = await outcome(azure);
      expect(ended_.status).toBe(1);
      expect(methods(azure)).toEqual(['patch', 'post']);
      expect(ended_.said.at(-1)).toBe(
        `job-agentx-stg-migrate-new0x ended ${ending}, so the API wasn't updated. Read its log: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-new0x\nLeft: migrate holds ${NEW}; the API is on ${OLD}.`,
      );
    }
  });

  it("names a refusal by Azure's HTTP reason and code alone, never its message or the subscription, and says what it left", async () => {
    const cases: [string, number, string, string][] = [
      ['patch', 0, 'Azure refused the update of migrate (Forbidden, LinkedAuthorizationFailed)', 'nothing'],
      ['post', 1, 'Azure refused to start migrate (Forbidden, AuthorizationFailed)', `migrate holds ${NEW}, not run`],
    ];
    for (const [method, writesBefore, message, left] of cases) {
      const azure = new Staging();
      azure.refuse = {
        method,
        stderr: azRestError('Forbidden', writesBefore === 0 ? 'LinkedAuthorizationFailed' : 'AuthorizationFailed'),
      };
      const ended_ = await outcome(azure);
      expect(ended_.message).toContain(message);
      const leftSaid = left === 'nothing' ? `migrate may hold ${NEW}, not run` : left;
      expect(ended_.message).toContain(`\nLeft: ${leftSaid}`);
      expect(ended_.printed).not.toContain(HOST);
      expect(ended_.printed).not.toContain(SUBSCRIPTION);
      expect(azure.writes).toHaveLength(writesBefore + 1);
    }
    // The API's update refused: the migration ran, and the API is left on the old build.
    const api = new Staging();
    let patches = 0;
    const refusing = api.az();
    const steps = { ...api.steps(ordinary()) };
    const az: Az = {
      interactive: (args, values) => refusing.interactive(args, values),
      run: (args) => {
        if (args[2] === 'patch' && (patches += 1) === 2)
          return { status: 1, stdout: '', stderr: azRestError('Conflict', 'ContainerAppOperationInProgress') };
        return refusing.run(args);
      },
    };
    await expect(release(RELEASE_NEW, { ...steps, az })).rejects.toThrow(
      `Azure refused the update of api (Conflict, ContainerAppOperationInProgress). Its message isn't shown, since it can quote the settings sent: the resource group's activity log has it.\nLeft: migrate ran ${NEW}; the API is on ${OLD}.`,
    );
    // An error in no known shape still names none of it.
    const unknown = new Staging();
    unknown.refuse = { method: 'patch', stderr: `ERROR: something about /subscriptions/${SUBSCRIPTION}` };
    const odd = await outcome(unknown);
    expect(odd.message).toContain('Azure refused the update of migrate (no reason given).');
    expect(odd.printed).not.toContain(SUBSCRIPTION);
  });

  it('names a failed read by what it was reading alone, never the URL or the subscription, and says what it left', async () => {
    const cases: [RegExp, number, string][] = [
      [
        /jobs\/job-agentx-stg-migrate\?/,
        3,
        `Azure didn't answer the read of migrate (Too Many Requests, TooManyRequests).\nLeft: migrate may hold ${NEW}, not run; the API is on ${OLD}.`,
      ],
      [
        /executions\/job-agentx-stg-migrate-new0x/,
        1,
        `Azure didn't answer the read of job-agentx-stg-migrate-new0x (Too Many Requests, TooManyRequests).\nLeft: migrate holds ${NEW}, its run job-agentx-stg-migrate-new0x not seen to end; the API is on ${OLD}.`,
      ],
      [
        /revisions\/ca-agentx-stg-api--0000008/,
        1,
        `Azure didn't answer the read of ca-agentx-stg-api--0000008 (Too Many Requests, TooManyRequests).\nLeft: migrate ran ${NEW}; the API's template holds ${NEW}, and until a new revision serves it the old one does.`,
      ],
    ];
    for (const [what, from, message] of cases) {
      const azure = new Staging();
      azure.failRead = { what, from };
      const ended_ = await outcome(azure);
      expect(ended_.message).toBe(message);
      expect(ended_.printed).not.toContain(SUBSCRIPTION);
      expect(ended_.printed).not.toContain(HOST);
    }
  });

  it('stops without writing over another deploy that came between its read and its write', async () => {
    for (const meddle of [
      (staging: Staging) => (staging.job.release = LATER),
      (staging: Staging) => (staging.job.image = NEW_IMAGE),
      // A settings change that stamps nothing is another deploy's too.
      (staging: Staging) => (staging.job.command = ['node', 'other.ts']),
    ]) {
      const azure = new Staging();
      azure.meddle = meddle;
      const ended_ = await outcome(azure, history([OLD, NEW, LATER]));
      expect(ended_.message).toMatch(
        /^migrate changed while this release ran \(it now runs [0-9a-f]{40}, ghcr\.io\/shahbaz242630\/agent-x@sha256:[0-9a-f]{64}\): another deploy is going on, so it wasn't updated\.\nLeft: migrate may hold/,
      );
      expect(azure.writes).toEqual([]);
    }
  });

  it('waits past Azure still showing the old container, or its old state, before an update is its own', async () => {
    for (const lagState of ['Succeeded', 'Failed', 'InProgress'] as const) {
      const azure = new Staging();
      azure.lag = 2;
      azure.lagState = lagState;
      expect((await outcome(azure)).status).toBe(0);
    }
  });

  it('stops when an update fails or never settles, the job or the API, saying what it left', async () => {
    const cases: [(azure: Staging) => void, string, string[]][] = [
      [
        (azure) => (azure.settleAs = 'Failed'),
        `Azure's update of migrate ended Failed.\nLeft: migrate may hold ${NEW}, not run; the API is on ${OLD}.`,
        ['patch'],
      ],
      [
        (azure) => (azure.settleAs = 'Canceled'),
        `Azure's update of migrate ended Canceled.\nLeft: migrate may hold ${NEW}, not run; the API is on ${OLD}.`,
        ['patch'],
      ],
      [
        (azure) => (azure.settleAfter = 1000),
        `Azure hadn't settled the update of migrate after 10 minutes (InProgress).\nLeft: migrate may hold ${NEW}, not run; the API is on ${OLD}.`,
        ['patch'],
      ],
      [
        (azure) => (azure.lag = 1000),
        `Azure hadn't settled the update of migrate after 10 minutes (Succeeded, not yet holding it).\nLeft: migrate may hold ${NEW}, not run; the API is on ${OLD}.`,
        ['patch'],
      ],
      [
        (azure) => (azure.apiSettleAs = 'Failed'),
        `Azure's update of api ended Failed.\nLeft: migrate ran ${NEW}; the API's template holds ${NEW}, and until a new revision serves it the old one does.`,
        ['patch', 'post', 'patch'],
      ],
    ];
    for (const [arrange, message, writes] of cases) {
      const azure = new Staging();
      arrange(azure);
      expect((await outcome(azure)).message).toBe(message);
      expect(methods(azure)).toEqual(writes);
    }
  });

  it('finds its run however Azure answers the start: named or not, listed at once or a little later', async () => {
    for (const [startNames, listLag] of [
      ['nothing', 2],
      ['its run', 0],
      ['its run', 2],
    ] as const) {
      const azure = new Staging();
      azure.startNames = startNames;
      azure.listLag = listLag;
      const ended_ = await outcome(azure);
      expect(ended_.status).toBe(0);
      expect(ended_.said).toContain('Started job-agentx-stg-migrate-new0x.');
    }
  });

  it("refuses a run it can't be sure is its own, or of its image, and a start that lists nothing in time", async () => {
    const left = `migrate holds ${NEW}, not run (a start that failed late may still have begun one: look at migrate's runs); the API is on ${OLD}.`;
    const cases: [(azure: Staging) => void, string][] = [
      [
        (azure) => (azure.newRuns = 2),
        "migrate was started, but 2 new runs are listed, so which is this release's is unknown.",
      ],
      [(azure) => (azure.newRuns = 0), 'migrate was started, but no new run was listed within 2 minutes.'],
      [
        (azure) => (azure.startNames = 'another'),
        'Azure listed migrate\'s new run as "job-agentx-stg-migrate-new0x" and started "job-agentx-stg-migrate-other1", which isn\'t this release\'s run.',
      ],
      [
        (azure) => (azure.newRunName = 'job-agentx-stg-db-setup-new0x'),
        "Azure listed migrate's new run as \"job-agentx-stg-db-setup-new0x\", which isn't this release's run.",
      ],
    ];
    for (const [arrange, message] of cases) {
      const azure = new Staging();
      arrange(azure);
      expect((await outcome(azure)).message).toBe(`${message}\nLeft: ${left}`);
      expect(methods(azure)).toEqual(['patch', 'post']);
    }
    const other = new Staging();
    other.runImage = `${REPOSITORY}@${digest('9')}`;
    expect((await outcome(other)).message).toBe(
      `job-agentx-stg-migrate-new0x runs ${REPOSITORY}@${digest('9')}, not this release's image: another release started it.\nLeft: migrate holds ${NEW}, its run job-agentx-stg-migrate-new0x not seen to end; the API is on ${OLD}.`,
    );
    expect(methods(other)).toEqual(['patch', 'post']);
  });

  it('gives up on a run that does not end in time, saying how to wait for it and what it left', async () => {
    const azure = new Staging();
    azure.runPolls = 1000;
    expect((await outcome(azure)).message).toBe(
      `job-agentx-stg-migrate-new0x hadn't ended 1200 s after it started. To wait for it: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-new0x\nLeft: migrate holds ${NEW}, its run job-agentx-stg-migrate-new0x not seen to end; the API is on ${OLD}.`,
    );
    expect(methods(azure)).toEqual(['patch', 'post']);
  });

  it("waits for the API's new revision: named after the old, taking traffic over time, healthy once it has answered", async () => {
    const azure = new Staging();
    azure.revisionLag = 2;
    azure.readyAfter = 2;
    azure.trafficAfter = 3;
    azure.probes = [undefined, 503, 200];
    const ended_ = await outcome(azure);
    expect(ended_.status).toBe(0);
    expect(ended_.said.at(-1)).toContain("the API's revision ca-agentx-stg-api--0000008 holds it");
  });

  it("stops when the API's new revision isn't this release, isn't ready, serving, answering or healthy in time", async () => {
    const left = `\nLeft: migrate ran ${NEW}; the API's template holds ${NEW}, and until a new revision serves it the old one does.`;
    const cases: [string, (azure: Staging) => void][] = [
      ["The API's new revision wasn't ready 5 minutes after its update.", (azure) => (azure.readyAfter = 1000)],
      [
        `The API's new revision ca-agentx-stg-api--0000008 doesn't serve this release: it runs ${NEW} (${REPOSITORY}@${digest('9')}), not this release.`,
        (azure) => (azure.newRevisionImage = `${REPOSITORY}@${digest('9')}`),
      ],
      [
        `The API's new revision ca-agentx-stg-api--0000008 doesn't serve this release: it runs ${LATER} (${NEW_IMAGE}), not this release.`,
        (azure) => (azure.newRevisionRelease = LATER),
      ],
      [
        "The API's new revision ca-agentx-stg-api--0000008 doesn't serve this release: Failed, active false, 0% of traffic, None.",
        (azure) => (azure.newRevisionState = 'Failed'),
      ],
      [
        "The API's new revision wasn't serving 5 minutes after its update. (Provisioned, active false, 0% of traffic, None)",
        (azure) => (azure.trafficAfter = 1000),
      ],
      // Each of the three falling short alone: still provisioning, inactive, or without all the traffic.
      [
        "The API's new revision wasn't serving 5 minutes after its update. (Provisioning, active true, 100% of traffic, None)",
        (azure) => (azure.newRevisionState = 'Provisioning'),
      ],
      [
        "The API's new revision wasn't serving 5 minutes after its update. (Provisioned, active false, 100% of traffic, None)",
        (azure) => (azure.newRevisionActive = false),
      ],
      [
        "The API's new revision wasn't serving 5 minutes after its update. (Provisioned, active true, 50% of traffic, None)",
        (azure) => (azure.newRevisionTraffic = 50),
      ],
      [
        "The API's new revision wasn't answering /health 5 minutes after its update.",
        (azure) => (azure.probes = [503]),
      ],
      [
        "The API's new revision wasn't healthy once it answered 5 minutes after its update. (Provisioned, active true, 100% of traffic, Unhealthy)",
        (azure) => (azure.newRevisionHealth = 'Unhealthy'),
      ],
      [
        'Azure named the API\'s revision "ca-agentx-stg-login--0000008", which isn\'t one of its revisions.',
        (azure) => (azure.newRevision = 'ca-agentx-stg-login--0000008'),
      ],
    ];
    for (const [message, arrange] of cases) {
      const azure = new Staging();
      arrange(azure);
      expect((await outcome(azure)).message).toBe(`${message}${left}`);
      expect(methods(azure)).toEqual(['patch', 'post', 'patch']);
    }
  });

  it('refuses while a load run is up (the API at AGENTX_ROLE web), before anything is written, migrate included (4D2e D13)', async () => {
    const azure = new Staging();
    azure.app = { ...azure.app, env: [...azure.app.env, { name: 'AGENTX_ROLE', value: 'web' }] };
    const ended_ = await outcome(azure);
    expect(ended_.status).toBe(1);
    expect(ended_.said).toContain(LOAD_RUN_UP);
    expect(methods(azure)).toEqual([]);
    expect(azure.writes).toEqual([]);
    // `check` says the same, and changes nothing.
    const checking = new Staging();
    checking.app = azure.app;
    const steps = checking.steps(ordinary());
    expect(await check(RELEASE_NEW, steps)).toBe(1);
    expect(steps.said).toContain(LOAD_RUN_UP);
    expect(methods(checking)).toEqual([]);
    // The API at `all`, said outright by its template, is staging's own shape: released as ever.
    const all = new Staging();
    all.app = { ...all.app, env: [...all.app.env, { name: 'AGENTX_ROLE', value: 'all' }] };
    deployedAsIs(all);
    expect((await outcome(all)).status).toBe(0);
  });
});

describe('main', () => {
  it('says how to use it, and ends with 2, when the arguments are wrong, reaching nothing', async () => {
    const said: string[] = [];
    const nothing = (): never => {
      throw new Error('reached');
    };
    expect(await main(['check', 'main'], (line) => said.push(line), nothing, nothing, nothing)).toBe(2);
    expect(said).toEqual([`main isn't a full commit (40 lower-case hex)\n${USAGE}`]);
  });

  it('says what went wrong, and ends with 1, when Azure or git fails', async () => {
    const said: string[] = [];
    const failing: Az = {
      interactive: () => 0,
      run: () => ({ status: 1, stdout: '', stderr: azRestError('Unauthorized', 'ExpiredAuthenticationToken') }),
    };
    expect(
      await main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => failing,
        () => history([NEW]),
      ),
    ).toBe(1);
    expect(said).toEqual(["The Azure CLI isn't signed in (Unauthorized, ExpiredAuthenticationToken)."]);
  });

  it('checks, or releases, and ends with its status', async () => {
    const said: string[] = [];
    const azure = new Staging();
    const { now, sleep, verify, probe, folder } = azure.steps(ordinary());
    expect(
      await main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => fakeAz(staging(OLD), []),
        () => history([OLD, NEW]),
        () => ({ now, sleep, verify, probe }),
        () => folderAt(NEW).folder,
        {},
      ),
    ).toBe(0);
    expect(said.at(-1)).toMatch(/^ {2}api: image /);
    const releasedLines: string[] = [];
    expect(
      await main(
        ['release', NEW, digest('2')],
        (line) => releasedLines.push(line),
        () => azure.az(),
        ordinary,
        () => ({ now, sleep, verify, probe }),
        () => folder,
        {},
      ),
    ).toBe(0);
    expect(releasedLines.at(-1)).toMatch(/^Released /);
  });
});

describe('migrateFirst: the migration run ahead of a hand deploy (deploy.ts apps --migrate-first, AZ6)', () => {
  const BUILT = 'db/migrations/0001_built.sql';
  const ADDS = 'db/migrations/0082_marks.sql';
  const builtSql = 'CREATE TABLE app.things (id uuid);';
  const addsSql = 'CREATE TRIGGER marks AFTER UPDATE ON app.things FOR EACH ROW EXECUTE FUNCTION app.mark();';

  /** migrateFirst's outcome: the run's name or the error's message, and what it said. */
  async function ranFirst(azure: Staging, line = ordinary()) {
    const steps = azure.steps(line);
    const done = await migrateFirst(steps, SUBSCRIPTION, NEW, digest('2')).then(
      (name) => ({ name, message: '' }),
      (error: unknown) => ({ name: undefined, message: error instanceof Error ? error.message : String(error) }),
    );
    return { ...done, said: steps.said };
  }

  it('updates the migration job to the image and runs it to success, leaving the API as it is', async () => {
    const azure = new Staging();
    const { name, said } = await ranFirst(azure);
    expect(name).toBe('job-agentx-stg-migrate-new0x');
    expect(azure.writes).toEqual([
      {
        method: 'patch',
        url: workloadUrl(SUBSCRIPTION, 'migrate'),
        body: {
          properties: {
            template: { containers: [released(running('migrate', { command: ['node'] }), NEW_IMAGE, NEW)] },
          },
        },
      },
      { method: 'post', url: workloadUrl(SUBSCRIPTION, 'migrate').replace('?', '/start?'), body: undefined },
    ]);
    expect(azure.app.release).toBe(OLD);
    expect(said.at(-1)).toBe(
      `job-agentx-stg-migrate-new0x succeeded: the database holds every migration ${NEW} brings.`,
    );
  });

  it('runs the job without resending it when it already holds the image, as after a hand apps (S174)', async () => {
    const azure = new Staging();
    Object.assign(azure.job, { release: NEW, image: NEW_IMAGE });
    const { name } = await ranFirst(azure);
    expect(name).toBe('job-agentx-stg-migrate-new0x');
    expect(methods(azure)).toEqual(['post']);
  });

  it('stops, saying what it left and how to read the log, when the run fails', async () => {
    const azure = new Staging();
    azure.runEndsAs = 'Failed';
    const { message } = await ranFirst(azure);
    expect(message).toBe(
      `job-agentx-stg-migrate-new0x ended Failed, so nothing was deployed. Read its log: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-new0x\nLeft: migrate holds ${NEW}; the API is unchanged, on ${OLD}.`,
    );
    expect(methods(azure)).toEqual(['patch', 'post']);
  });

  it('changes nothing while the job is unsettled from an earlier change', async () => {
    const unsettled = new Staging();
    unsettled.job.state = 'Failed';
    expect((await ranFirst(unsettled)).message).toBe(
      'migrate is Failed from an earlier change, so nothing was sent: look at it first.\nLeft: nothing was changed.',
    );
    expect(unsettled.writes).toEqual([]);
  });

  it('is held to decision 49 against the build the API runs, as a release is, and changes nothing when it fails', async () => {
    const notComing = new Staging();
    const comingLine = history(
      [OLD, NEW],
      { [OLD]: [ADDS] },
      { [OLD]: { [BUILT]: builtSql }, [NEW]: { [BUILT]: builtSql, [ADDS]: addsSql } },
    );
    const refused = await ranFirst(notComing, comingLine);
    expect(refused.message).toBe(
      `The migration wasn't run, and nothing was changed: ${COMING_FIRST}\n  0082_marks.sql adds marks on app.things, which the code before it didn't carry in coming.json's triggers (staging runs ${OLD})`,
    );
    expect(notComing.writes).toEqual([]);
    const outside = new Staging();
    const elsewhere = await ranFirst(outside, history([NEW]));
    expect(elsewhere.message).toBe(
      `The API runs ${OLD}, which isn't in ${NEW}'s history, so whether it knows what this image's migrations add can't be checked (decision 49): the migration wasn't run, and nothing was changed.`,
    );
    expect(outside.writes).toEqual([]);
  });
});

describe('AZ2c: each workload held to what the commit gives it, beyond its image and build', () => {
  /** Staging's API settings with one changed: its value, or the setting itself. */
  const apiEnvWith = (change: (entry: { name: string; value?: string }) => unknown): readonly unknown[] =>
    builtAt(OLD).map((entry) => change(entry as { name: string; value?: string }));

  it("stops a release red, writing nothing, when migrate's command was changed outside a deploy", async () => {
    const azure = new Staging();
    azure.job.command = ['node', '-e', 'fetch(process.env.X)'];
    const { status, said, printed } = await outcome(azure);
    expect(status).toBe(1);
    expect(azure.writes).toEqual([]);
    expect(said.slice(-2)).toEqual([
      `A release of ${NEW} stops here, red: ${NOT_AS_DEPLOYED}`,
      '  migrate: its command is not the template’s',
    ]);
    // What it ran is never printed: only names.
    expect(printed).not.toContain('fetch');
    expect(NOT_AS_DEPLOYED).toContain('deploy it by hand with apps after checking who changed it');
    expect(NOT_AS_DEPLOYED).toContain('Incident-Response-Playbook section B');
  });

  it("stops on any of the API's settings changed, added, dropped or turned into a secret, naming the setting alone", async () => {
    const cases: [readonly unknown[], string][] = [
      [
        apiEnvWith((entry) =>
          entry.name === 'AGENTX_PUBLIC_ORIGIN' ? { ...entry, value: 'https://evil.example' } : entry,
        ),
        'api: its setting AGENTX_PUBLIC_ORIGIN holds another value than the template gives',
      ],
      [
        [...builtAt(OLD), { name: 'NODE_OPTIONS', value: '--require /tmp/x.js' }],
        "api: it has a setting the template doesn't: NODE_OPTIONS",
      ],
      [
        builtAt(OLD).filter((entry) => (entry as { name: string }).name !== 'AGENTX_ENV'),
        "api: it lacks the template's setting AGENTX_ENV",
      ],
      [
        apiEnvWith((entry) => (entry.name === 'AGENTX_ENV' ? { name: 'AGENTX_ENV', secretRef: 'a-secret' } : entry)),
        'api: its setting AGENTX_ENV reads a secret where the template gives a value',
      ],
      [
        apiEnvWith((entry) =>
          entry.name === 'AGENTX_FROM_VAULT' ? { name: 'AGENTX_FROM_VAULT', secretRef: 'other' } : entry,
        ),
        "api: its setting AGENTX_FROM_VAULT doesn't read the secret the template names",
      ],
    ];
    for (const [env, reason] of cases) {
      const azure = new Staging();
      azure.app.env = env;
      const { status, said, printed } = await outcome(azure);
      expect(status).toBe(1);
      expect(azure.writes).toEqual([]);
      expect(said.at(-1)).toBe(`  ${reason}`);
      expect(printed).not.toContain('evil');
      expect(printed).not.toContain('/tmp/x.js');
    }
  });

  it('lets a release through when only the image and build differ, Azure dropping empty arguments', async () => {
    const azure = new Staging();
    // The template's AGENTX_RELEASE names another commit and image: both are the release's to write.
    azure.templates = new Map(
      ORDER.map((workload) => [
        workload,
        around(
          workload,
          [azureContainer(WORKLOADS[workload].container, { command: ['node'], env: builtAt(LATER), image: 'x' })],
          'snapshot',
        ),
      ]),
    );
    expect((await outcome(azure)).status).toBe(0);
    const { args: _none, ...withoutArgs } = azureContainer('api', { env: builtAt(OLD) });
    const { status } = await checked({ ...staging(OLD), api: [withoutArgs] }, history([OLD, NEW]));
    expect(status).toBe(0);
  });

  it('says the same in a check, red, changing nothing', async () => {
    const { status, said, calls } = await checked(
      { ...staging(OLD), migrate: [azureContainer('migrate', { env: builtAt(OLD), args: ['--other'] })] },
      history([OLD, NEW]),
    );
    expect(status).toBe(1);
    expect(said.slice(-2)).toEqual([
      `A release of ${NEW} stops here, red: ${NOT_AS_DEPLOYED}`,
      '  migrate: its arguments are not the template’s',
    ]);
    expect(calls.every((call) => call[0] === 'account' || call[2] === 'get')).toBe(true);
  });

  it("stops before any write when the commit's templates can't be read, keeping the subscription out", async () => {
    const elsewhere = new Staging();
    const stepsAt = (head: string, clean: boolean): ReturnType<Staging['steps']> => ({
      ...elsewhere.steps(ordinary()),
      folder: folderAt(head, SAID, clean).folder,
    });
    for (const [steps, start] of [
      [stepsAt(OLD, true), `This folder is at ${OLD}, not ${NEW}, so`],
      [stepsAt(NEW, false), `This folder is at ${NEW} with changes, not ${NEW}, so`],
    ] as const) {
      const failed = await release(RELEASE_NEW, steps).then(
        () => '',
        (error: unknown) => (error instanceof Error ? error.message : ''),
      );
      expect(failed.startsWith(start)).toBe(true);
      expect(failed).toContain('nothing was changed. Run this again from a clean checkout of the commit');
    }
    const broken = new Staging();
    broken.templates = new Error(`bicep snapshot failed: /subscriptions/${SUBSCRIPTION}/x`);
    const { status, message } = await outcome(broken);
    expect(status).toBeUndefined();
    expect(message).toBe(
      `What apps.bicep gives the API and the migration job couldn't be read (bicep snapshot failed: /subscriptions/the subscription/x), so whether the API or the migration job was changed outside a deploy (AZ2c) is unknown, and nothing was changed. Run this again from a clean checkout of the commit with the pinned Bicep (node tooling/bicep/install.ts).`,
    );
    for (const azure of [elsewhere, broken]) expect(azure.writes).toEqual([]);
  });

  it('holds a re-run with nothing to do too, read-only: a changed workload is red, not "nothing to do" (item 2)', async () => {
    const changed = (release: string, image: string): Readonly<Record<Workload, unknown>> => ({
      ...staging(release, image),
      migrate: [azureContainer('migrate', { image, env: builtAt(release), args: ['--other'] })],
    });
    for (const [containers, line, build] of [
      [staging(NEW, NEW_IMAGE), history([NEW]), NEW],
      [staging(LATER), history([NEW, LATER]), LATER],
    ] as const) {
      const asked: string[] = [];
      const folder: Folder = {
        ...folderAt(NEW).folder,
        templates: (_subscription, build) => {
          asked.push(build);
          return TEMPLATES;
        },
      };
      expect((await checked(containers, line, undefined, folder)).status).toBe(0);
      // The templates of the build each workload runs, read once for both.
      expect(asked).toEqual([build]);
    }
    for (const [containers, line] of [
      [changed(NEW, NEW_IMAGE), history([NEW])],
      [changed(LATER, OLD_IMAGE), history([NEW, LATER])],
    ] as const) {
      const { status, said, calls } = await checked(containers, line);
      expect(status).toBe(1);
      expect(said.slice(-2)).toEqual([
        `A release of ${NEW} stops here, red: ${NOT_AS_DEPLOYED}`,
        '  migrate: its arguments are not the template’s',
      ]);
      expect(calls.every((call) => call[0] === 'account' || call[2] === 'get')).toBe(true);
    }
    // A re-run's release red the same way, writing nothing.
    const azure = new Staging();
    Object.assign(azure.job, { release: NEW, image: NEW_IMAGE, command: ['sh'] });
    Object.assign(azure.app, { release: NEW, image: NEW_IMAGE, env: builtAt(NEW) });
    expect((await outcome(azure)).status).toBe(1);
    expect(azure.writes).toEqual([]);
  });

  it('stops on a roll-back, even to an older commit’s own signed image, and on migrate behind the API (review item 1)', async () => {
    const MID = commit('c');
    const line = (): History => history([OLD, MID, NEW], { [OLD]: [], [MID]: [] });
    const said = async (
      arrange: (azure: Staging) => void,
    ): Promise<{ status: number | undefined; said: string[]; writes: unknown[] }> => {
      const azure = new Staging();
      arrange(azure);
      const done = await outcome(azure, line());
      return { status: done.status, said: done.said, writes: azure.writes };
    };
    const revisionAt = (release: string) => ({
      image: OLD_IMAGE,
      release,
      provisioningState: 'Provisioned',
      active: false,
      trafficWeight: 0,
      healthState: 'None',
    });
    for (const [arrange, reason] of [
      [
        (azure: Staging) => azure.revisions.set('ca-agentx-stg-api--0000006', revisionAt(MID)),
        `  api: it runs ${OLD}, older than ${MID}, which one of its revisions ran: rolled back, a suspected breach`,
      ],
      [
        (azure: Staging) =>
          azure.runs.push({
            name: 'job-agentx-stg-migrate-mid1',
            status: 'Succeeded',
            image: OLD_IMAGE,
            polls: 0,
            release: MID,
          }),
        `  migrate: it runs ${OLD}, older than ${MID}, which a run of it or an API revision ran: rolled back, a suspected breach`,
      ],
      [
        (azure: Staging) => {
          Object.assign(azure.app, { release: MID, env: builtAt(MID) });
          azure.revisions.set('ca-agentx-stg-api--0000007', revisionAt(MID));
        },
        `  migrate: it runs ${OLD}, behind the API's ${MID}, which no deploy leaves (migrate is always moved first): a suspected breach`,
      ],
    ] as const) {
      const done = await said(arrange);
      expect(done.status, reason).toBe(1);
      expect(done.writes).toEqual([]);
      expect(done.said).toContain(reason);
      expect(done.said).toContain(`A release of ${NEW} stops here, red: ${NOT_AS_DEPLOYED}`);
    }
    // Migrate is held to the API's revisions as well as its own runs.
    const byRevision = await said((azure) => azure.revisions.set('ca-agentx-stg-api--0000006', revisionAt(MID)));
    expect(byRevision.said).toContain(
      `  migrate: it runs ${OLD}, older than ${MID}, which a run of it or an API revision ran: rolled back, a suspected breach`,
    );
    // Migrate ahead of the API, as --migrate-first or a stopped release leaves it: released as ever.
    const ahead = await said((azure) => {
      Object.assign(azure.job, { release: MID });
      azure.runs.push({
        name: 'job-agentx-stg-migrate-mid1',
        status: 'Succeeded',
        image: OLD_IMAGE,
        polls: 0,
        release: MID,
      });
    });
    expect(ahead.status).toBe(0);
  });

  it('reads no template when a hand deploy is needed anyway', async () => {
    const unread = new Error('never read');
    const byHand = await checked(
      staging(OLD),
      history([OLD, NEW], { [OLD]: ['deploy/azure/apps.bicep'] }),
      undefined,
      folderAt(NEW, SAID, true, unread).folder,
    );
    expect(byHand.status).toBe(1);
    expect(byHand.said).toContain(`A release of ${NEW} stops here, red: this needs a hand deploy.`);
  });

  it("sends migrate's container as the commit gives it ahead of a hand deploy, saying what differed (--migrate-first)", async () => {
    const azure = new Staging();
    azure.job.command = ['node', '-e', 'x'];
    const steps = azure.steps(ordinary());
    expect(await migrateFirst(steps, SUBSCRIPTION, NEW, digest('2'))).toBe('job-agentx-stg-migrate-new0x');
    expect(azure.writes[0]?.body).toEqual({
      properties: { template: { containers: [released(running('migrate', { command: ['node'] }), NEW_IMAGE, NEW)] } },
    });
    expect(steps.said).toContain(
      `migrate isn't as ${NEW}'s apps.bicep has it, beyond its image and build (its command is not the template’s): it runs as apps.bicep says. If apps.bicep didn't change it since ${OLD}, someone changed it outside a deploy: treat it as a suspected breach (Incident-Response-Playbook section B).`,
    );
  });

  it('refuses --migrate-first, plainly and changing nothing, when the commit gives migrate what only apps can send (M3)', async () => {
    const needsApps = (template: Record<string, unknown>): Promise<{ message: string; writes: unknown[] }> => {
      const azure = new Staging();
      azure.templates = new Map([['migrate', template]]);
      return migrateFirst(azure.steps(ordinary()), SUBSCRIPTION, NEW, digest('2')).then(
        () => ({ message: '', writes: azure.writes }),
        (error: unknown) => ({ message: error instanceof Error ? error.message : '', writes: azure.writes }),
      );
    };
    const withSecret = around('migrate', [azureContainer('migrate', { command: ['node'] })], 'snapshot') as {
      properties: { configuration: { secrets: unknown[] } };
    };
    withSecret.properties.configuration.secrets.push({ name: 'new-secret', keyVaultUrl: 'x', identity: 'y' });
    const deployTime = around(
      'migrate',
      [azureContainer('migrate', { command: ['node'], env: [{ name: 'X', value: "[reference('r', 'v').hostName]" }] })],
      'snapshot',
    );
    for (const [template, why] of [
      [withSecret, "it lacks the template's secret new-secret"],
      [deployTime, "the setting X is given only at deploy time, so it can't be sent from the template alone"],
    ] as const) {
      const { message, writes } = await needsApps(template);
      expect(message).toBe(
        `migrate isn't as ${NEW}'s apps.bicep has it beyond its containers (${why}), and --migrate-first sends its containers alone. If this commit adds a secret, mount or deploy-time setting to migrate: run apps --api-stopped first (Incident-Response-Playbook section L). If it doesn't, someone changed the job outside a deploy: treat it as a suspected breach (section B).\nLeft: nothing was changed.`,
      );
      expect(writes).toEqual([]);
    }
  });

  it('names a field or setting it refuses so no line break or workflow command can reach the log', () => {
    const odd = 'x\n::error::y';
    for (const [container, said] of [
      [{ ...azureContainer('api'), [odd]: 1 }, 'its container has x???error??y'],
      [azureContainer('api', { resources: { cpu: 0.5, memory: '1Gi', [odd]: 1 } }), 'its size has x???error??y'],
      [
        azureContainer('api', { env: [...builtAt(OLD), { name: odd, value: 'v', other: 1 }] }),
        'the setting x???error??y has more',
      ],
      [azureContainer('api', { env: [...builtAt(OLD), { name: odd }] }), 'the setting x???error??y has neither'],
    ] as const) {
      expect(() => runningIn('api', [container])).toThrow(said);
    }
  });

  /** A release against staging with one workload changed beyond its containers, outside a deploy. */
  async function meddled(
    target: Workload,
    change: (resource: Record<string, unknown>) => void,
  ): Promise<{ status: number | undefined; said: string[]; printed: string; writes: unknown[] }> {
    const azure = new Staging();
    azure.meddleWith = (workload, resource) => {
      if (workload !== target) return resource;
      const copy = structuredClone(resource);
      change(copy);
      return copy;
    };
    const { status, said, printed } = await outcome(azure);
    return { status, said, printed, writes: azure.writes };
  }

  /** A resource's object at a path, to change in place. */
  const inside = (resource: Record<string, unknown>, ...path: readonly string[]): Record<string, unknown> =>
    path.reduce<Record<string, unknown>>((found, key) => found[key] as Record<string, unknown>, resource);

  it('stops on anything else about a workload changed: its init containers, secrets, volumes, identity, registries, door, scale, trigger', async () => {
    const cases: [Workload, (resource: Record<string, unknown>) => void, string][] = [
      [
        'migrate',
        (resource) => (inside(resource, 'properties', 'template').initContainers = [{ name: 'x', image: 'evil' }]),
        'migrate: its template.initContainers is not the template’s',
      ],
      [
        'api',
        (resource) =>
          (inside(resource, 'properties', 'configuration').secrets = [{ name: 'a-secret', value: 'evil-literal' }]),
        'api: its secret a-secret holds value, not only a vault reference',
      ],
      [
        'migrate',
        (resource) =>
          (inside(resource, 'properties', 'configuration').secrets = [
            {
              name: 'a-secret',
              keyVaultUrl: 'https://evil.vault.azure.net/secrets/a-secret',
              identity: identityOf('migrate'),
            },
          ]),
        'migrate: its secret a-secret is read from another vault entry than the template’s',
      ],
      [
        'migrate',
        (resource) =>
          (inside(resource, 'properties', 'configuration').secrets = [
            {
              name: 'a-secret',
              keyVaultUrl: `https://${VAULT}.vault.azure.net/secrets/a-secret`,
              identity: identityOf('api'),
            },
          ]),
        'migrate: its secret a-secret is read as another identity than the template’s',
      ],
      [
        'migrate',
        (resource) =>
          (inside(resource, 'properties', 'template').volumes = [
            { name: 'secrets', storageType: 'Secret', secrets: [{ secretRef: 'a-secret', path: 'db-owner-password' }] },
          ]),
        'migrate: its volumes are not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'identity').userAssignedIdentities = { [identityOf('migrate')]: {} }),
        'api: it runs as other identities than the template’s',
      ],
      [
        'migrate',
        (resource) =>
          (inside(resource, 'properties', 'configuration').registries = [{ server: 'evil.azurecr.io', identity: 'x' }]),
        'migrate: its configuration.registries is not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'properties', 'configuration', 'ingress').external = true),
        'api: its configuration.ingress.external is not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'properties', 'configuration', 'ingress').allowInsecure = true),
        'api: its configuration.ingress.allowInsecure is not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'properties', 'configuration', 'ingress').transport = 'tcp'),
        'api: its configuration.ingress.transport is not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'properties', 'template', 'scale').maxReplicas = 30),
        'api: its template.scale.maxReplicas is not the template’s',
      ],
      [
        'api',
        (resource) => (inside(resource, 'properties', 'template', 'scale').minReplicas = 5),
        'api: its template.scale.minReplicas is neither 0 nor 1',
      ],
      [
        'migrate',
        (resource) => (inside(resource, 'properties', 'configuration').triggerType = 'Schedule'),
        'migrate: its configuration.triggerType is not the template’s',
      ],
      [
        'migrate',
        (resource) => (inside(resource, 'properties', 'configuration', 'manualTriggerConfig').parallelism = 5),
        'migrate: its configuration.manualTriggerConfig is not the template’s',
      ],
    ];
    for (const [workload, change, reason] of cases) {
      const { status, said, printed, writes } = await meddled(workload, change);
      expect(status, reason).toBe(1);
      expect(writes).toEqual([]);
      expect(said, reason).toContain(`  ${reason}`);
      expect(printed).not.toContain('evil');
    }
    // `apps --keep-running`'s one replica is staging's own shape.
    const kept = await meddled(
      'api',
      (resource) => (inside(resource, 'properties', 'template', 'scale').minReplicas = 1),
    );
    expect(kept.status).toBe(0);
  });

  it("stops when a workload's build isn't the commit its image was signed for, a suspected breach (H2)", async () => {
    const azure = new Staging();
    azure.signed = (image, commit) =>
      image === OLD_IMAGE && commit === OLD
        ? { verified: false, reason: 'SIGNATURE_REFUSED', detail: 'signed for another commit' }
        : { verified: true };
    const { status, said } = await outcome(azure);
    expect(status).toBe(1);
    expect(azure.writes).toEqual([]);
    expect(said.slice(-2)).toEqual([
      `  migrate: its image isn't CI's signed build of ${OLD}, the commit its AGENTX_RELEASE names (SIGNATURE_REFUSED): a suspected breach`,
      `  api: its image isn't CI's signed build of ${OLD}, the commit its AGENTX_RELEASE names (SIGNATURE_REFUSED): a suspected breach`,
    ]);
    // Each image and build is checked once, both workloads running the same.
    const asked: string[] = [];
    const once = new Staging();
    once.signed = (image, commit) => {
      asked.push(`${image} ${commit}`);
      return { verified: true };
    };
    expect((await outcome(once)).status).toBe(0);
    expect(asked).toEqual([`${OLD_IMAGE} ${OLD}`]);
  });

  it('holds the shell’s values to their pins when set, says so in one line when not, never printing either (H3)', async () => {
    const MARKED = 'app-host.shell-marker.invalid';
    /** Staging whose template gives the API's public origin from the shell's app host, as apps.bicep does. */
    const pinned = (pins: Readonly<Record<string, string>>): Staging => {
      const azure = new Staging();
      const container = azureContainer('api', {
        command: ['node'],
        env: (builtAt(OLD) as { name: string; value?: string }[]).map((entry) =>
          entry.name === 'AGENTX_PUBLIC_ORIGIN' ? { ...entry, value: `https://${MARKED}` } : entry,
        ),
      });
      azure.templates = new Map([
        ...(azure.templates as ReadonlyMap<Workload, unknown>),
        ['api', around('api', [container], 'snapshot')],
      ]);
      azure.pins = pins;
      return azure;
    };
    const sha = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
    const unset = await outcome(pinned({}));
    expect(unset.status).toBe(0);
    expect(unset.said).toContain(NOT_PINNED);
    // Pinned right: the app host whatever its case; the two others carried by no setting here are each a reason.
    const right = await outcome(pinned({ AGENTX_APP_HOST_SHA256: sha(HOST).toUpperCase() }));
    expect(right.status).toBe(0);
    expect(right.said).toContain(
      "Not pinned (AGENTX_AUTH_HOST_SHA256, AGENTX_OIDC_CLIENT_ID_SHA256 unset): the auth host, API's client ID held to shape alone. Nothing is wrong; set each as a staging secret to hold it exactly.",
    );
    for (const [pins, reason] of [
      [
        { AGENTX_APP_HOST_SHA256: sha('evil.example') },
        "api: the app host its settings carry isn't the one AGENTX_APP_HOST_SHA256 pins",
      ],
      [
        { AGENTX_APP_HOST_SHA256: 'not-a-hash' },
        "AGENTX_APP_HOST_SHA256 isn't a SHA-256 (64 hex), so the app host can't be checked: set it again",
      ],
      [{ AGENTX_AUTH_HOST_SHA256: sha(HOST) }, 'no setting carries the auth host, which AGENTX_AUTH_HOST_SHA256 pins'],
    ] as const) {
      const azure = pinned(pins);
      const { status, said, printed } = await outcome(azure);
      expect(status, reason).toBe(1);
      expect(azure.writes).toEqual([]);
      expect(said).toContain(`  ${reason}`);
      expect(printed).not.toContain(HOST);
      expect(printed).not.toContain(sha(HOST));
    }
  });
});
