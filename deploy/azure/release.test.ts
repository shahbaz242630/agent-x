// The release tool: its check (G4-3a) and the release itself (G4-3b). Nothing
// here reaches Azure or git: the CLI is a stand-in that answers from a script,
// or a stand-in staging that changes as a release writes to it, and the history
// is a line of made-up commits (git.test.ts reads a real one).
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import type { History } from './git.ts';
import { JOBS_API } from './jobs.ts';
import {
  changes,
  check,
  decide,
  HAND_DEPLOYED,
  handDeployedList,
  main,
  ORDER,
  parseArguments,
  release,
  released,
  type ReleaseSteps,
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
    refused(
      with_({ resources: { cpu: 0.5, memory: '1Gi', gpu: 1 } }),
      "its size has gpu, which a release doesn't copy",
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
function history(line: readonly string[], changed: Readonly<Record<string, readonly string[]>> = {}): History {
  return {
    isAncestor: (ancestor, target) =>
      line.includes(ancestor) && line.includes(target) && line.indexOf(ancestor) <= line.indexOf(target),
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

  it('stops for a hand deploy when what either runs is not in the commit, and reads the changes since each', () => {
    const older = commit('c');
    const migrate = at(older)('migrate');
    // What the API runs isn't in the commit's history: nothing it changed can be read, so a person deploys it.
    expect(decide(both(running('api'), migrate), NEW, NEW_IMAGE, history([older, NEW]))).toEqual({
      kind: 'by-hand',
      reasons: [`staging runs ${OLD}, which isn't in ${NEW}'s history`],
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
});

/** A stand-in CLI: the account and the two workloads, recording each call. */
function fakeAz(
  containers: Readonly<Record<Workload, unknown>>,
  calls: string[][],
  account: unknown = { name: 'Azure subscription 1', id: SUBSCRIPTION },
): Az {
  const answer = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
  return {
    interactive: () => {
      throw new Error('check never runs the CLI interactively');
    },
    run: (args) => {
      calls.push([...args]);
      if (args[0] === 'account') return answer(account);
      const workload = ORDER.find((each) => args.includes(workloadUrl(SUBSCRIPTION, each)));
      if (args[0] === 'rest' && workload !== undefined) {
        return answer({ id: 'x', properties: { template: { containers: containers[workload] } } });
      }
      return { status: 1, stdout: '', stderr: `unexpected: az ${args.join(' ')}` };
    },
  };
}

/** Both workloads at a build, as the stand-in CLI answers them. */
const staging = (release: string, image = OLD_IMAGE): Readonly<Record<Workload, unknown>> => ({
  api: [azureContainer('api', { image, env: builtAt(release) })],
  migrate: [azureContainer('migrate', { image, env: builtAt(release) })],
});

/** A check of NEW against staging, with what it said and did. */
function checked(
  containers: Readonly<Record<Workload, unknown>>,
  line: History,
  account?: unknown,
): { status: number | undefined; said: string[]; calls: string[][]; error: unknown } {
  const said: string[] = [];
  const calls: string[][] = [];
  try {
    const status = check(
      { command: 'check', commit: NEW, digest: digest('2') },
      { az: fakeAz(containers, calls, account), history: line, say: (said_) => said.push(said_) },
    );
    return { status, said, calls, error: undefined };
  } catch (error) {
    return { status: undefined, said, calls, error };
  }
}

describe('check', () => {
  it('reads the two from Resource Manager, and says what a release would change in each, changing nothing', () => {
    const { status, said, calls } = checked(staging(OLD), history([OLD, NEW], { [OLD]: ['apps/api/src/main.ts'] }));
    expect(status).toBe(0);
    expect(said).toEqual([
      'Signed in to the subscription "Azure subscription 1".',
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

  it('says so when a release has nothing to do, or staging is already past the commit', () => {
    const current = checked(staging(NEW, NEW_IMAGE), history([NEW]));
    expect(current.status).toBe(0);
    expect(current.said.at(-1)).toBe(`Both already run ${NEW}: a release has nothing to do.`);
    const past = checked(staging(LATER), history([NEW, LATER]));
    expect(past.status).toBe(0);
    expect(past.said.at(-1)).toBe(
      `Staging already runs a later commit than ${NEW}: a release of it has nothing to do.`,
    );
  });

  it('ends with failure when it needs a hand deploy, giving each reason', () => {
    const { status, said } = checked(staging(OLD), history([OLD, NEW], { [OLD]: ['db/bootstrap/roles.sql'] }));
    expect(status).toBe(1);
    expect(said.slice(-2)).toEqual([
      `A release of ${NEW} stops here, red: this needs a hand deploy.`,
      `  db/bootstrap/roles.sql changed since ${OLD}: ${HAND_DEPLOYED[1]?.why ?? ''}`,
    ]);
  });

  it('never prints the subscription or the host the settings name, whatever it ends with', () => {
    const outcomes = [
      checked(staging(OLD), history([OLD, NEW])),
      checked(staging(NEW, NEW_IMAGE), history([NEW])),
      checked(staging(LATER), history([NEW, LATER])),
      checked(staging(OLD), history([OLD, NEW], { [OLD]: ['deploy/azure/apps.bicep'] })),
      checked({ ...staging(OLD), api: [azureContainer('api', { probes: [] })] }, history([OLD, NEW])),
    ];
    for (const { said, error } of outcomes) {
      const printed = [...said, error instanceof Error ? error.message : ''].join('\n');
      expect(printed).not.toContain(SUBSCRIPTION);
      expect(printed).not.toContain(HOST);
    }
  });

  it('refuses an account that names no subscription, reading nothing more', () => {
    for (const account of [{ name: 'x' }, { name: 'x', id: 'not-a-subscription' }, null]) {
      const { error, calls } = checked(staging(OLD), history([OLD, NEW]), account);
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

/**
 * A stand-in for staging as a release sees it: the migration job and its runs,
 * the API and its revisions, each changed by the writes a release sends and
 * settling over later reads, with knobs for every way it can go wrong. Time
 * moves only when the release sleeps.
 */
class Staging {
  readonly calls: string[][] = [];
  readonly writes: Write[] = [];
  clock = new Date('2026-09-18T12:00:00Z').getTime();
  job = { release: OLD, image: OLD_IMAGE, state: 'Succeeded', limit: 900 as unknown, settling: 0 };
  app = {
    release: OLD,
    image: OLD_IMAGE,
    state: 'Succeeded',
    latest: 'ca-agentx-stg-api--0000007',
    ready: 'ca-agentx-stg-api--0000007',
    settling: 0,
    unready: 0,
    env: builtAt(OLD),
  };
  runs: { name: string; status: string; polls: number }[] = [
    { name: 'job-agentx-stg-migrate-aocy0fb', status: 'Succeeded', polls: 0 },
  ];
  revision: Record<string, unknown> = {
    provisioningState: 'Provisioned',
    active: true,
    trafficWeight: 100,
    healthState: 'Healthy',
  };
  /**
   * How an update is taken up: first, for `lag` reads, Azure still shows
   * what was there, marked Succeeded; then it settles as `settleAs` after
   * `settleAfter` more; the API's new revision is named after `revisionLag`
   * more, as `newRevision`. How the new run is named and ends, and how many a
   * start makes.
   */
  lag = 1;
  settleAs = 'Succeeded';
  settleAfter = 1;
  revisionLag = 0;
  newRevision = 'ca-agentx-stg-api--0000008';
  newRunName: string | undefined;
  private pending: { readonly workload: Workload; readonly apply: () => void } | undefined;
  runEndsAs = 'Succeeded';
  runPolls = 2;
  newRuns = 1;
  readyAfter = 1;
  refuse: { readonly method: string; readonly stderr: string } | undefined;
  probes: (number | undefined)[] = [undefined, 200];
  /** Something else deploys between the release's first read of a workload and its second. */
  meddle: ((staging: Staging) => void) | undefined;

  /** Takes an update up once Azure has shown what was there for `lag` reads. */
  private takeUp(workload: Workload): void {
    if (this.pending?.workload !== workload) return;
    if (this.lag > 0) {
      this.lag -= 1;
      return;
    }
    this.pending.apply();
    this.pending = undefined;
  }

  private jobResource(): unknown {
    this.takeUp('migrate');
    const settling = this.job.settling > 0;
    if (settling) this.job.settling -= 1;
    return {
      properties: {
        provisioningState: settling ? 'InProgress' : this.job.state,
        configuration: { replicaTimeout: this.job.limit },
        template: {
          containers: [azureContainer('migrate', { image: this.job.image, env: builtAt(this.job.release) })],
        },
      },
    };
  }

  private appResource(): unknown {
    this.takeUp('api');
    const settling = this.app.settling > 0;
    // Once the update is taken up and has succeeded, the new revision is named
    // after `revisionLag` more reads; until then the old one is still the latest.
    const renaming = this.app.release === NEW && this.app.state === 'Succeeded' && this.app.latest !== this.newRevision;
    if (settling) this.app.settling -= 1;
    else if (renaming && this.revisionLag > 0) this.revisionLag -= 1;
    else if (renaming) this.app.latest = this.newRevision;
    else if (this.app.unready > 0) this.app.unready -= 1;
    else this.app.ready = this.app.latest;
    return {
      properties: {
        provisioningState: settling ? 'InProgress' : this.app.state,
        latestRevisionName: this.app.latest,
        latestReadyRevisionName: this.app.ready,
        template: { containers: [azureContainer('api', { image: this.app.image, env: this.app.env })] },
      },
    };
  }

  private patched(workload: Workload, body: string | undefined): void {
    const sent = JSON.parse(body ?? '{}') as {
      properties: { template: { containers: { image: string; env: { name: string; value?: string }[] }[] } };
    };
    const [container] = sent.properties.template.containers;
    const build = container?.env.find((entry) => entry.name === 'AGENTX_RELEASE')?.value ?? '';
    const settle = { image: container?.image, release: build, state: this.settleAs, settling: this.settleAfter };
    this.pending = {
      workload,
      apply:
        workload === 'migrate'
          ? () => Object.assign(this.job, settle)
          : () => Object.assign(this.app, settle, { env: container?.env, unready: this.readyAfter }),
    };
  }

  az(): Az {
    const answer = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    const done: AzResult = { status: 0, stdout: '', stderr: '' };
    const query = `?api-version=${JOBS_API}`;
    const jobBase = workloadUrl(SUBSCRIPTION, 'migrate').replace(query, '');
    const appBase = workloadUrl(SUBSCRIPTION, 'api').replace(query, '');
    return {
      interactive: () => {
        throw new Error('a release never runs the CLI interactively');
      },
      run: (args) => {
        this.calls.push([...args]);
        if (args[0] === 'account') return answer({ name: 'Azure subscription 1', id: SUBSCRIPTION });
        const [, , method = '', , url = '', flag, body] = args;
        if (method !== 'get') {
          this.writes.push({
            method,
            url,
            body: flag === '--body' ? (JSON.parse(String(body)) as unknown) : undefined,
          });
          if (this.refuse?.method === method) return { status: 1, stdout: '', stderr: this.refuse.stderr };
        }
        const workload = ORDER.find((each) => url === workloadUrl(SUBSCRIPTION, each));
        if (method === 'get' && workload !== undefined) {
          if (this.calls.filter((call) => call.includes(url)).length === 2) this.meddle?.(this);
          return answer(workload === 'migrate' ? this.jobResource() : this.appResource());
        }
        if (method === 'patch' && workload !== undefined) {
          this.patched(workload, body);
          return done;
        }
        if (method === 'get' && url === `${jobBase}/executions${query}`) {
          return answer({ value: this.runs.map(({ name, status }) => ({ name, properties: { status } })) });
        }
        if (method === 'post' && url === `${jobBase}/start${query}`) {
          for (let made = 0; made < this.newRuns; made += 1) {
            this.runs.unshift({
              name: this.newRunName ?? `job-agentx-stg-migrate-new${String(made)}x`,
              status: 'Running',
              polls: this.runPolls,
            });
          }
          return done;
        }
        const run = this.runs.find((each) => url === `${jobBase}/executions/${each.name}${query}`);
        if (method === 'get' && run !== undefined) {
          if (run.polls > 0) run.polls -= 1;
          else if (run.status === 'Running') run.status = this.runEndsAs;
          return answer({ name: run.name, properties: { status: run.status } });
        }
        if (method === 'get' && url === `${appBase}/revisions/${this.app.latest}${query}`) {
          return answer({ properties: this.revision });
        }
        return { status: 1, stdout: '', stderr: `unexpected: az ${args.join(' ')}` };
      },
    };
  }

  steps(line: History, verified = true): ReleaseSteps & { readonly said: string[] } {
    const said: string[] = [];
    return {
      az: this.az(),
      history: line,
      say: (text) => said.push(text),
      said,
      now: () => new Date(this.clock),
      sleep: (ms) => {
        this.clock += ms;
        return Promise.resolve();
      },
      verify: () =>
        verified
          ? { verified: true }
          : { verified: false, reason: 'SIGNATURE_REFUSED', detail: 'not signed by CI on main' },
      probe: (url) => {
        expect(url).toBe(`https://${HOST}/health`);
        return Promise.resolve(this.probes.length > 1 ? this.probes.shift() : this.probes[0]);
      },
    };
  }
}

const RELEASE_NEW = { command: 'release', commit: NEW, digest: digest('2') } as const;

/** A release of NEW from OLD on a history where nothing a person deploys changed. */
const ordinary = (): History => history([OLD, NEW], { [OLD]: ['apps/api/src/main.ts'] });

/** What a release printed and threw, together, for looking through. */
const printed = (said: readonly string[], error?: unknown): string =>
  [...said, error instanceof Error ? error.message : ''].join('\n');

/** The error a release ended with, or nothing. */
const failure = (running_: Promise<number>): Promise<unknown> =>
  running_.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );

describe('release', () => {
  it('checks the image, updates and runs the migration, then updates the API and waits for it to serve', async () => {
    const azure = new Staging();
    const steps = azure.steps(ordinary());
    expect(await release(RELEASE_NEW, steps)).toBe(0);
    // Exactly three writes, in order: the job's containers, its start (no body), the API's containers.
    expect(azure.writes).toEqual([
      {
        method: 'patch',
        url: workloadUrl(SUBSCRIPTION, 'migrate'),
        body: { properties: { template: { containers: [released(running('migrate'), NEW_IMAGE, NEW)] } } },
      },
      { method: 'post', url: workloadUrl(SUBSCRIPTION, 'migrate').replace('?', '/start?'), body: undefined },
      {
        method: 'patch',
        url: workloadUrl(SUBSCRIPTION, 'api'),
        body: { properties: { template: { containers: [released(running('api'), NEW_IMAGE, NEW)] } } },
      },
    ]);
    expect(steps.said).toEqual([
      `Checking ${NEW_IMAGE} was signed by CI on main at ${NEW}, with its SBOM...`,
      'Signed in to the subscription "Azure subscription 1".',
      `migrate runs ${OLD} (${OLD_IMAGE}).`,
      `api runs ${OLD} (${OLD_IMAGE}).`,
      `Updating migrate: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}.`,
      `migrate runs ${NEW}.`,
      'Started job-agentx-stg-migrate-new0x.',
      '  job-agentx-stg-migrate-new0x: Running',
      '  job-agentx-stg-migrate-new0x: Succeeded',
      `Updating api: image ${OLD_IMAGE} → ${NEW_IMAGE}; AGENTX_RELEASE ${OLD} → ${NEW}.`,
      `api runs ${NEW}.`,
      "The API's new revision ca-agentx-stg-api--0000008 takes all traffic; asking it for /health...",
      `Released ${NEW}: job-agentx-stg-migrate-new0x succeeded, and the API serves it from ca-agentx-stg-api--0000008.`,
    ]);
    expect(printed(steps.said)).not.toContain(HOST);
    expect(printed(steps.said)).not.toContain(SUBSCRIPTION);
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

  it('writes nothing when there is nothing to do, or a person must deploy it', async () => {
    const cases: [History, number, string][] = [
      [
        history([OLD, NEW], { [OLD]: ['deploy/azure/apps.bicep'] }),
        1,
        `  deploy/azure/apps.bicep changed since ${OLD}: ${HAND_DEPLOYED[0]?.why ?? ''}`,
      ],
      [history([NEW, OLD]), 0, `Staging already runs a later commit than ${NEW}: a release of it has nothing to do.`],
    ];
    for (const [line, status, last] of cases) {
      const azure = new Staging();
      const steps = azure.steps(line);
      expect(await release(RELEASE_NEW, steps)).toBe(status);
      expect(steps.said.at(-1)).toBe(last);
      expect(azure.writes).toEqual([]);
    }
  });

  it('writes nothing when what it needs later is missing: a way to check the API, a time limit, an idle job', async () => {
    const origin = (value: string) => (azure: Staging) => {
      azure.app.env = builtAt(OLD).map((entry) =>
        (entry as { name: string }).name === 'AGENTX_PUBLIC_ORIGIN' ? { name: 'AGENTX_PUBLIC_ORIGIN', value } : entry,
      );
    };
    const noOrigin =
      'The API names no https origin (AGENTX_PUBLIC_ORIGIN) to check it through once released: nothing was changed.';
    const cases: [string, (azure: Staging) => void][] = [
      [
        noOrigin,
        (azure) => {
          azure.app.env = builtAt(OLD).filter((entry) => (entry as { name: string }).name !== 'AGENTX_PUBLIC_ORIGIN');
        },
      ],
      [noOrigin, origin(`http://${HOST}`)],
      [noOrigin, origin(`https://${HOST}/path`)],
      [noOrigin, origin(`https://${HOST}\n`)],
      [
        'Azure gave no time limit for migrate, so how long to wait for its run is unknown: nothing was changed.',
        (azure) => (azure.job.limit = undefined),
      ],
      [
        'Azure gave no time limit for migrate, so how long to wait for its run is unknown: nothing was changed.',
        (azure) => (azure.job.limit = 0),
      ],
      [
        'Azure gave no time limit for migrate, so how long to wait for its run is unknown: nothing was changed.',
        (azure) => (azure.job.limit = 1.5),
      ],
      [
        "migrate has runs that haven't ended (job-agentx-stg-migrate-busy1 Running), so nothing was changed.",
        (azure) => azure.runs.unshift({ name: 'job-agentx-stg-migrate-busy1', status: 'Running', polls: 99 }),
      ],
    ];
    for (const [message, arrange] of cases) {
      const azure = new Staging();
      arrange(azure);
      await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(message);
      expect(azure.writes).toEqual([]);
    }
  });

  it('leaves the API as it was when the migration fails, saying how to read its log', async () => {
    for (const ending of ['Failed', 'Stopped', 'Degraded']) {
      const azure = new Staging();
      azure.runEndsAs = ending;
      const steps = azure.steps(ordinary());
      expect(await release(RELEASE_NEW, steps)).toBe(1);
      expect(azure.writes.map((write) => write.method)).toEqual(['patch', 'post']);
      expect(steps.said.at(-1)).toBe(
        `job-agentx-stg-migrate-new0x ended ${ending}, so the API was left on ${OLD}. Read its log: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-new0x`,
      );
    }
  });

  it("shows Azure's refusal of a write by its code alone, never its message, which can quote the settings", async () => {
    const cases: [string, string, string, number][] = [
      [
        'patch',
        'LinkedAuthorizationFailed',
        "Azure refused the update of migrate (LinkedAuthorizationFailed). Its message isn't shown here",
        1,
      ],
      ['post', 'AuthorizationFailed', 'Azure refused to start migrate (AuthorizationFailed).', 2],
    ];
    for (const [method, code, message, writes] of cases) {
      const azure = new Staging();
      azure.refuse = {
        method,
        stderr: `ERROR: (${code}) Code: ${code} Message: sent https://${HOST} to /subscriptions/${SUBSCRIPTION}`,
      };
      const steps = azure.steps(ordinary());
      const error = await failure(release(RELEASE_NEW, steps));
      expect(error).toMatchObject({ message: expect.stringContaining(message) as unknown });
      expect(printed(steps.said, error)).not.toContain(HOST);
      expect(printed(steps.said, error)).not.toContain(SUBSCRIPTION);
      expect(azure.writes).toHaveLength(writes);
    }
    const azure = new Staging();
    azure.refuse = { method: 'patch', stderr: 'ERROR: something went wrong' };
    await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(
      "Azure refused the update of migrate (no code given). Its message isn't shown here, since it can quote the settings sent: run this release from your own terminal to read it.",
    );
  });

  it('stops without writing over another deploy that came between its read and its write', async () => {
    for (const meddle of [
      (staging: Staging) => (staging.job.release = LATER),
      (staging: Staging) => (staging.job.image = NEW_IMAGE),
    ]) {
      const azure = new Staging();
      azure.meddle = meddle;
      await expect(release(RELEASE_NEW, azure.steps(history([OLD, NEW, LATER])))).rejects.toThrow(
        /^migrate changed while this release ran \(it now runs [0-9a-f]{40}\): another deploy is going on, so nothing more was changed\.$/,
      );
      expect(azure.writes).toEqual([]);
    }
  });

  it('stops when an update fails or never settles', async () => {
    const cases: [(azure: Staging) => void, string][] = [
      [(azure) => (azure.settleAs = 'Failed'), "Azure's update of migrate ended Failed."],
      [(azure) => (azure.settleAs = 'Canceled'), "Azure's update of migrate ended Canceled."],
      [
        (azure) => (azure.settleAfter = 1000),
        "Azure hadn't settled the update of migrate after 10 minutes (InProgress).",
      ],
    ];
    for (const [arrange, message] of cases) {
      const azure = new Staging();
      arrange(azure);
      await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(message);
      expect(azure.writes).toHaveLength(1);
    }
  });

  it('gives up on a run that does not end in time, saying how to wait for it, and leaves the API', async () => {
    const azure = new Staging();
    azure.runPolls = 1000;
    await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(
      "job-agentx-stg-migrate-new0x hadn't ended 1200 s after it started, so the API was left as it was. To wait for it: node deploy/azure/jobs.ts wait migrate job-agentx-stg-migrate-new0x",
    );
    expect(azure.writes.map((write) => write.method)).toEqual(['patch', 'post']);
  });

  it("waits past the old revision still named latest after the API's update, and says which revision serves", async () => {
    const azure = new Staging();
    azure.revisionLag = 2;
    const steps = azure.steps(ordinary());
    expect(await release(RELEASE_NEW, steps)).toBe(0);
    expect(steps.said.at(-1)).toBe(
      `Released ${NEW}: job-agentx-stg-migrate-new0x succeeded, and the API serves it from ca-agentx-stg-api--0000008.`,
    );
  });

  it("refuses a run or a revision Azure names in a shape that isn't one of theirs, before it goes into a URL", async () => {
    const run = new Staging();
    run.newRunName = 'job-agentx-stg-db-setup-new0x';
    await expect(release(RELEASE_NEW, run.steps(ordinary()))).rejects.toThrow(
      `Azure named migrate's new run "job-agentx-stg-db-setup-new0x", which isn't one of its runs: the API was left as it was.`,
    );
    expect(run.writes.map((write) => write.method)).toEqual(['patch', 'post']);
    const revision = new Staging();
    revision.newRevision = 'ca-agentx-stg-login--0000008';
    await expect(release(RELEASE_NEW, revision.steps(ordinary()))).rejects.toThrow(
      `Azure named the API's new revision "ca-agentx-stg-login--0000008", which isn't one of its revisions.`,
    );
  });

  it('refuses to guess which run is its own when the start lists none, or two', async () => {
    for (const count of [0, 2]) {
      const azure = new Staging();
      azure.newRuns = count;
      await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(
        `migrate was started, but ${String(count)} new runs are listed, so which is this release's is unknown: the API was left as it was.`,
      );
      expect(azure.writes.map((write) => write.method)).toEqual(['patch', 'post']);
    }
  });

  it("stops when the API's new revision isn't ready, serving, answering or healthy in time", async () => {
    const cases: [string, (azure: Staging) => void][] = [
      ["The API's new revision wasn't ready 5 minutes after its update.", (azure) => (azure.readyAfter = 1000)],
      [
        "The API's new revision ca-agentx-stg-api--0000008 isn't serving (Provisioned, active false, 100% of traffic).",
        (azure) => (azure.revision.active = false),
      ],
      [
        "The API's new revision ca-agentx-stg-api--0000008 isn't serving (Failed, active true, 100% of traffic).",
        (azure) => (azure.revision.provisioningState = 'Failed'),
      ],
      [
        "The API's new revision ca-agentx-stg-api--0000008 isn't serving (Provisioned, active true, 0% of traffic).",
        (azure) => (azure.revision.trafficWeight = 0),
      ],
      [
        "The API's new revision wasn't answering /health 5 minutes after its update.",
        (azure) => (azure.probes = [503]),
      ],
      [
        "The API's new revision ca-agentx-stg-api--0000008 answered, but Azure calls it Unhealthy.",
        (azure) => (azure.revision.healthState = 'Unhealthy'),
      ],
    ];
    for (const [message, arrange] of cases) {
      const azure = new Staging();
      arrange(azure);
      await expect(release(RELEASE_NEW, azure.steps(ordinary()))).rejects.toThrow(message);
      expect(azure.writes.map((write) => write.method)).toEqual(['patch', 'post', 'patch']);
    }
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
      run: () => ({ status: 1, stdout: '', stderr: 'ERROR: not signed in' }),
    };
    expect(
      await main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => failing,
        () => history([NEW]),
      ),
    ).toBe(1);
    expect(said).toEqual(['az account show failed:\nERROR: not signed in']);
  });

  it('checks, or releases, and ends with its status', async () => {
    const said: string[] = [];
    expect(
      await main(
        ['check', NEW, digest('2')],
        (line) => said.push(line),
        () => fakeAz(staging(OLD), []),
        () => history([OLD, NEW]),
      ),
    ).toBe(0);
    expect(said.at(-1)).toMatch(/^ {2}api: image /);
    const azure = new Staging();
    const { now, sleep, verify, probe } = azure.steps(ordinary());
    const releasedLines: string[] = [];
    expect(
      await main(
        ['release', NEW, digest('2')],
        (line) => releasedLines.push(line),
        () => azure.az(),
        ordinary,
        () => ({ now, sleep, verify, probe }),
      ),
    ).toBe(0);
    expect(releasedLines.at(-1)).toMatch(/^Released /);
  });
});
