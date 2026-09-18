// The release tool's check (G4-3a). Nothing here reaches Azure: the CLI is a
// stand-in that answers from a script and records each call, and the history
// is either a stand-in or a throwaway repository made here.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import { JOBS_API } from './jobs.ts';
import {
  changes,
  check,
  decide,
  HAND_DEPLOYED,
  type History,
  main,
  ORDER,
  parseArguments,
  realHistory,
  released,
  type Running,
  runningIn,
  USAGE,
  UsageError,
  type Workload,
  WORKLOADS,
  workloadUrl,
} from './release.ts';
import { environmentSnapshot, inCopy } from './snapshot.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000b';
const REPOSITORY = 'ghcr.io/shahbaz242630/agent-x';

/** Made-up commits and digests, in the shapes git and ghcr.io give. */
const commit = (fill: string): string => fill.repeat(40);
const digest = (fill: string): string => `sha256:${fill.repeat(64)}`;
const OLD = commit('a');
const NEW = commit('b');
const OLD_IMAGE = `${REPOSITORY}@${digest('1')}`;
const NEW_IMAGE = `${REPOSITORY}@${digest('2')}`;

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
    { name: 'AGENTX_DB_HOST', value: 'db.example.invalid' },
    { name: setting('AGENTX', 'DB', 'PASSWORD', 'FILE'), value: '/mnt/secrets/login' },
    { name: 'AGENTX_FROM_VAULT', secretRef: 'a-secret' },
  ],
  // The app's also carries the disk Azure works out from the size.
  resources: { cpu: 0.5, memory: '1Gi', ephemeralStorage: '2Gi' },
  volumeMounts: [{ mountPath: '/mnt/secrets', volumeName: 'secrets' }],
  ...overrides,
});

const running = (workload: Workload, overrides: Readonly<Record<string, unknown>> = {}): Running =>
  runningIn(workload, [azureContainer(WORKLOADS[workload].container, overrides)]);

describe('parseArguments', () => {
  it('reads check with a full commit and a digest', () => {
    expect(parseArguments(['check', NEW, digest('2')])).toEqual({ command: 'check', commit: NEW, digest: digest('2') });
  });

  it('refuses anything else, saying why', () => {
    for (const [argv, message] of [
      [[], 'say check, not nothing'],
      [['release', NEW, digest('2')], 'say check, not release'],
      [['check'], "nothing isn't a full commit (40 lower-case hex)"],
      [['check', NEW.slice(1), digest('2')], `${NEW.slice(1)} isn't a full commit (40 lower-case hex)`],
      [['check', NEW.toUpperCase(), digest('2')], `${NEW.toUpperCase()} isn't a full commit (40 lower-case hex)`],
      [['check', 'main', digest('2')], "main isn't a full commit (40 lower-case hex)"],
      [['check', NEW], "nothing isn't an image digest (sha256: and 64 lower-case hex)"],
      [['check', NEW, '2'.repeat(64)], `${'2'.repeat(64)} isn't an image digest (sha256: and 64 lower-case hex)`],
      [['check', NEW, `${digest('2')}0`], `${digest('2')}0 isn't an image digest (sha256: and 64 lower-case hex)`],
      [['check', NEW, digest('2'), 'more'], 'check takes a commit and a digest, not more as well'],
    ] as const) {
      expect(() => parseArguments(argv)).toThrow(new UsageError(message));
    }
  });
});

describe('what a workload runs', () => {
  it("is read from its one container, keeping Azure's own fields but the disk Azure works out", () => {
    for (const workload of ORDER) {
      const { container } = WORKLOADS[workload];
      const found = running(workload);
      expect(found.image).toBe(OLD_IMAGE);
      expect(found.release).toBe(OLD);
      const { ephemeralStorage: _disk, ...size } = azureContainer(container).resources as Record<string, unknown>;
      expect(found.container).toEqual({ ...azureContainer(container), resources: size });
    }
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
    // A field a release doesn't copy, such as a probe it would drop.
    refused(with_({ probes: [], stdin: true }), "its container has probes, stdin, which a release doesn't copy");
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
    refused(with_({ resources: { cpu: '0.5', memory: '1Gi' } }), 'its size is not given');
    refused(with_({ resources: { cpu: 0.5 } }), 'its size is not given');
    refused(with_({ resources: undefined }), 'its size is not given');
    refused(withSettings(undefined as never), 'its settings are not a list');
    refused(with_({ env: {} }), 'its settings are not a list');
    refused(withSettings([...env, { value: 'x' }]), 'a setting has no name');
    refused(withSettings([...env, null]), 'a setting has no name');
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

/** A history in which `ancestors` are in the new commit's and `changed` differ from each. */
function history(changed: Readonly<Record<string, readonly string[]>>, ancestors = Object.keys(changed)): History {
  return {
    isAncestor: (ancestor, target) => {
      expect(target).toBe(NEW);
      return ancestors.includes(ancestor);
    },
    changedFiles: (from, to) => {
      expect(to).toBe(NEW);
      return changed[from] ?? [];
    },
  };
}

const both = (api: Running, migrate: Running): ReadonlyMap<Workload, Running> =>
  new Map([
    ['migrate', migrate],
    ['api', api],
  ]);

describe('deciding a release', () => {
  it('does nothing when both already run the commit, as that image', () => {
    const current = (workload: Workload): Running =>
      running(workload, {
        image: NEW_IMAGE,
        env: [{ name: 'AGENTX_RELEASE', value: NEW }],
      });
    expect(decide(both(current('api'), current('migrate')), NEW, NEW_IMAGE, history({}))).toEqual({
      kind: 'current',
    });
    // The same build under another image is not the same release.
    expect(decide(both(current('api'), current('migrate')), NEW, OLD_IMAGE, history({ [NEW]: [] })).kind).toBe(
      'release',
    );
  });

  it('updates the migration job, then the API, when nothing a person deploys changed', () => {
    const decided = decide(
      both(running('api'), running('migrate')),
      NEW,
      NEW_IMAGE,
      history({ [OLD]: ['apps/api/src/main.ts', 'db/migrations/0002_next.sql', 'deploy/azure/release.ts'] }),
    );
    expect(decided.kind).toBe('release');
    if (decided.kind !== 'release') return;
    expect([...decided.updates.keys()]).toEqual(['migrate', 'api']);
    expect(decided.updates.get('api')).toEqual(released(running('api'), NEW_IMAGE, NEW));
    expect(decided.updates.get('migrate')).toEqual(released(running('migrate'), NEW_IMAGE, NEW));
  });

  it('stops for a hand deploy when what a person deploys changed, saying each file and why', () => {
    const why = (prefix: string): string => HAND_DEPLOYED.find((rule) => rule.prefix === prefix)?.why ?? '';
    for (const [file, prefix] of [
      ['deploy/azure/apps.bicep', 'deploy/azure/'],
      ['deploy/azure/staging.apps.bicepparam', 'deploy/azure/'],
      ['deploy/azure/github-ranges.json', 'deploy/azure/'],
      ['deploy/azure/modules/release.bicep', 'deploy/azure/'],
      ['db/bootstrap/roles.sql', 'db/bootstrap/'],
      ['apps/db-setup/src/main.ts', 'apps/db-setup/'],
    ] as const) {
      expect(
        decide(both(running('api'), running('migrate')), NEW, NEW_IMAGE, history({ [OLD]: ['README.md', file] })),
      ).toEqual({ kind: 'by-hand', reasons: [`${file} changed since ${OLD}: ${why(prefix)}`] });
    }
  });

  it('stops for a hand deploy when what either runs is not in the commit, and reads the changes since each', () => {
    const older = commit('c');
    const migrate = running('migrate', { env: [{ name: 'AGENTX_RELEASE', value: older }] });
    // What the API runs isn't in the commit's history: nothing it changed can be read, so a person deploys it.
    expect(decide(both(running('api'), migrate), NEW, NEW_IMAGE, history({ [older]: [] }, [older]))).toEqual({
      kind: 'by-hand',
      reasons: [`staging runs ${OLD}, which isn't in ${NEW}'s history`],
    });
    // Both are in it: the job, which fell behind, is read from its own build, so what changed since then counts.
    expect(
      decide(
        both(running('api'), migrate),
        NEW,
        NEW_IMAGE,
        history({ [older]: ['deploy/azure/apps.bicep'], [OLD]: [] }),
      ),
    ).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/apps.bicep changed since ${older}: ${HAND_DEPLOYED[0]?.why ?? ''}`],
    });
  });
});

/** A stand-in CLI: the account and the two workloads, recording each call. */
function fakeAz(containers: Readonly<Record<Workload, unknown>>, calls: string[][]): Az {
  const answer = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
  return {
    interactive: () => {
      throw new Error('check never runs the CLI interactively');
    },
    run: (args) => {
      calls.push([...args]);
      if (args[0] === 'account') return answer({ name: 'Azure subscription 1', id: SUBSCRIPTION });
      const workload = ORDER.find((each) => args.includes(workloadUrl(SUBSCRIPTION, each)));
      if (args[0] === 'rest' && workload !== undefined) {
        return answer({ id: 'x', properties: { template: { containers: containers[workload] } } });
      }
      return { status: 1, stdout: '', stderr: `unexpected: az ${args.join(' ')}` };
    },
  };
}

describe('check', () => {
  const both_ = { api: [azureContainer('api')], migrate: [azureContainer('migrate')] };

  it('reads the two from Resource Manager, and says what a release would change in each, changing nothing', () => {
    const calls: string[][] = [];
    const said: string[] = [];
    const status = check(
      { command: 'check', commit: NEW, digest: digest('2') },
      {
        az: fakeAz(both_, calls),
        history: history({ [OLD]: ['apps/api/src/main.ts'] }),
        say: (line) => said.push(line),
      },
    );
    expect(status).toBe(0);
    expect(said).toEqual([
      `Signed in to the subscription "Azure subscription 1" (${SUBSCRIPTION}).`,
      `migrate runs ${OLD} (${OLD_IMAGE}).`,
      `api runs ${OLD} (${OLD_IMAGE}).`,
      `A release of ${NEW} would update, in order:`,
      `  migrate: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
      `  api: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}, and nothing else`,
    ]);
    // Reads only: the account, then each workload by GET, at the version apps.bicep deploys it with.
    expect(calls).toEqual([
      ['account', 'show', '--output', 'json'],
      ...ORDER.map((workload) => [
        'rest',
        '--method',
        'get',
        '--url',
        `https://management.azure.com/subscriptions/${SUBSCRIPTION}/resourceGroups/rg-agentx-staging/providers/Microsoft.App/${WORKLOADS[workload].path}?api-version=${JOBS_API}`,
        '--output',
        'json',
      ]),
    ]);
  });

  it('says so when a release has nothing to do', () => {
    const said: string[] = [];
    const current = (name: string): unknown => [
      azureContainer(name, { image: NEW_IMAGE, env: [{ name: 'AGENTX_RELEASE', value: NEW }] }),
    ];
    expect(
      check(
        { command: 'check', commit: NEW, digest: digest('2') },
        {
          az: fakeAz({ api: current('api'), migrate: current('migrate') }, []),
          history: history({}),
          say: (line) => said.push(line),
        },
      ),
    ).toBe(0);
    expect(said.at(-1)).toBe(`Both already run ${NEW}: a release has nothing to do.`);
  });

  it('ends with failure when it needs a hand deploy, giving each reason', () => {
    const said: string[] = [];
    expect(
      check(
        { command: 'check', commit: NEW, digest: digest('2') },
        {
          az: fakeAz(both_, []),
          history: history({ [OLD]: ['db/bootstrap/roles.sql'] }),
          say: (line) => said.push(line),
        },
      ),
    ).toBe(1);
    expect(said.slice(-2)).toEqual([
      `A release of ${NEW} would stop, red: this needs a hand deploy.`,
      `  db/bootstrap/roles.sql changed since ${OLD}: ${HAND_DEPLOYED[1]?.why ?? ''}`,
    ]);
  });
});

describe('main', () => {
  it('says how to use it, and ends with 2, when the arguments are wrong, reaching nothing', () => {
    const said: string[] = [];
    const nothing = (): never => {
      throw new Error('reached');
    };
    expect(main(['check', 'main'], (line) => said.push(line), nothing, nothing)).toBe(2);
    expect(said).toEqual([`main isn't a full commit (40 lower-case hex)\n${USAGE}`]);
  });

  it('says what went wrong, and ends with 1, when Azure or git fails', () => {
    const said: string[] = [];
    const failing: Az = {
      interactive: () => 0,
      run: () => ({ status: 1, stdout: '', stderr: 'ERROR: not signed in' }),
    };
    expect(
      main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => failing,
        () => history({}),
      ),
    ).toBe(1);
    expect(said).toEqual(['az account show failed:\nERROR: not signed in']);
  });

  it('checks and ends with its status', () => {
    const said: string[] = [];
    expect(
      main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => fakeAz({ api: [azureContainer('api')], migrate: [azureContainer('migrate')] }, []),
        () => history({ [OLD]: [] }),
      ),
    ).toBe(0);
    expect(said.at(-1)).toMatch(/^ {2}api: image /);
  });
});

describe('the history, from git', () => {
  let dir: string;
  const made: Record<'first' | 'tool' | 'bicep', string> = { first: '', tool: '', bicep: '' };

  // A throwaway repository, with this machine's git settings (signing, hooks)
  // kept out of it: they are for our own repository, not a fixture.
  beforeAll(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'agentx-release-'));
    const empty = path.join(dir, 'no-config');
    writeFileSync(empty, '');
    const env = {
      ...process.env,
      GIT_CONFIG_GLOBAL: empty,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'Fixture',
      GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Fixture',
      GIT_COMMITTER_EMAIL: 'fixture@example.invalid',
    };
    const repository = path.join(dir, 'repository');
    mkdirSync(repository);
    const git = (...args: readonly string[]): string => {
      const done = spawnSync('git', args, { cwd: repository, env, encoding: 'utf8', windowsHide: true });
      if (done.status !== 0) throw new Error(`git ${args.join(' ')}: ${done.stderr}`);
      return done.stdout.trim();
    };
    const commitFile = (file: string): string => {
      mkdirSync(path.dirname(path.join(repository, file)), { recursive: true });
      writeFileSync(path.join(repository, file), `${file}\n`);
      git('add', '--all');
      git('commit', '--quiet', '--message', file);
      return git('rev-parse', 'HEAD');
    };
    git('init', '--quiet');
    made.first = commitFile('README.md');
    made.tool = commitFile('deploy/azure/release.ts');
    made.bicep = commitFile('deploy/azure/apps.bicep');
  });

  afterAll(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('knows which commits are in which history, and a commit it does not have is in none', () => {
    const git = realHistory(path.join(dir, 'repository'));
    expect(git.isAncestor(made.first, made.bicep)).toBe(true);
    expect(git.isAncestor(made.bicep, made.bicep)).toBe(true);
    expect(git.isAncestor(made.bicep, made.first)).toBe(false);
    expect(git.isAncestor(commit('d'), made.bicep)).toBe(false);
    // A commit to compare with that it doesn't have is an error, not an answer.
    expect(() => git.isAncestor(made.first, commit('d'))).toThrow(
      `git couldn't compare ${made.first} and ${commit('d')}`,
    );
  });

  it('lists the files that changed between two commits', () => {
    const git = realHistory(path.join(dir, 'repository'));
    expect(git.changedFiles(made.first, made.bicep)).toEqual(['deploy/azure/apps.bicep', 'deploy/azure/release.ts']);
    expect(git.changedFiles(made.tool, made.bicep)).toEqual(['deploy/azure/apps.bicep']);
    expect(git.changedFiles(made.bicep, made.bicep)).toEqual([]);
    expect(() => git.changedFiles(commit('d'), made.bicep)).toThrow(
      `git couldn't list the changes from ${commit('d')} to ${made.bicep}`,
    );
  });

  it('reads the fixture as a release would: the tool changed alone goes ahead, the Bicep needs a hand deploy', () => {
    const git = realHistory(path.join(dir, 'repository'));
    const at = (release: string): Running => running('api', { env: [{ name: 'AGENTX_RELEASE', value: release }] });
    const fromTool = (target: string) =>
      decide(
        both(at(made.first), running('migrate', { env: [{ name: 'AGENTX_RELEASE', value: made.first }] })),
        target,
        NEW_IMAGE,
        git,
      );
    expect(fromTool(made.tool).kind).toBe('release');
    expect(fromTool(made.bicep)).toEqual({
      kind: 'by-hand',
      reasons: [`deploy/azure/apps.bicep changed since ${made.first}: ${HAND_DEPLOYED[0]?.why ?? ''}`],
    });
  });
});
