// The release tool: its check (G4-3a) and the release itself (G4-3b). Nothing
// here reaches Azure or git: the CLI is a stand-in that answers from a script,
// or a stand-in staging that changes as a release writes to it, and the history
// is a line of made-up commits (git.test.ts reads a real one).
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { fileReferences } from '../../tooling/bicep/references.ts';
import { type Az, type AzResult, type Deployment, DEPLOYMENTS, RECORDED, RECORDS_JOB, recordTag } from './deploy.ts';
import type { History } from './git.ts';
import { jobName, JOBS_API } from './jobs.ts';
import {
  changes,
  check,
  decide,
  type Decision,
  type Folder,
  HAND_DEPLOYED,
  handDeployedList,
  main,
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

/** This folder as a check finds it: at a commit, clean or not, with Bicep's answer or failure; each question kept. */
function folderAt(
  head: string,
  answer: ReadonlyMap<string, readonly string[]> | Error = SAID,
  clean = true,
): { folder: Folder; asked: string[][] } {
  const asked: string[][] = [];
  const folder: Folder = {
    checkout: () => ({ head, clean }),
    references: (files) => {
      asked.push([...files]);
      return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
    },
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

  it('never takes a record for apps, a file no deployment reads, or when Bicep has not said', () => {
    // apps's stamp is what staging runs: no record stands in for it.
    const runApps = 'deploy.ts apps reads it, so run it by hand, its what-if read';
    expect(decided(['deploy/azure/apps.bicep'], every)).toEqual(red('deploy/azure/apps.bicep', runApps));
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
      'deploy/azure/github-ranges.json': ['foundation'],
      'deploy/azure/main.bicep': ['foundation'],
      'deploy/azure/modules/environment.bicep': ['foundation'],
      'deploy/azure/modules/keyvault.bicep': ['foundation'],
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
      const workload = ORDER.find((each) => args.includes(workloadUrl(SUBSCRIPTION, each)));
      if (args[0] === 'rest' && workload !== undefined) {
        return answer({
          id: 'x',
          ...(workload === 'migrate' ? { tags: jobTags } : {}),
          properties: { template: { containers: containers[workload] } },
        });
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
      { az: fakeAz(containers, calls, account, jobTags), history: line, folder, say: (said_) => said.push(said_) },
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

/** An error as `az rest` prints it: the HTTP reason, then Azure's answer, which names the subscription and quotes the host. */
const azRestError = (reason: string, code: string): string =>
  `ERROR: ${reason}(${JSON.stringify({ error: { code, message: `The client may not perform action(s) on /subscriptions/${SUBSCRIPTION}/x with https://${HOST}` } })})`;

type State = 'Succeeded' | 'Failed' | 'Canceled' | 'InProgress';

/** One of the two workloads as the stand-in holds it. */
interface Held {
  release: string;
  image: string;
  state: State;
  command: readonly string[];
}

/** A revision of the API: what it runs, and how Azure describes it. */
interface Held_Revision {
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
  latest = 'ca-agentx-stg-api--0000007';
  ready = 'ca-agentx-stg-api--0000007';
  revisions = new Map<string, Held_Revision>([
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
  runs: { name: string; status: string; image: string; polls: number }[] = [
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
    const container = azureContainer(WORKLOADS[workload].container, {
      image: held.image,
      command: held.command,
      env: workload === 'api' ? this.app.env : builtAt(held.release),
    });
    return {
      ...(workload === 'migrate' ? { tags: this.jobTags } : {}),
      properties: {
        provisioningState: state,
        ...(workload === 'migrate'
          ? { configuration: { replicaTimeout: this.job.limit }, template: { containers: [container] } }
          : {
              latestRevisionName: this.latest,
              latestReadyRevisionName: this.ready,
              template: { revisionSuffix: this.app.suffix, containers: [container] },
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
        template: { containers: { image: string; command: string[]; env: { name: string; value?: string }[] }[] };
      };
    };
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
        if (args[0] === 'account') return answer(this.account);
        const [, , method = '', , url = '', flag, body] = args;
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
        const workload = ORDER.find((each) => url === workloadUrl(SUBSCRIPTION, each));
        if (method === 'get' && workload !== undefined) {
          if (this.calls.filter((call) => call.includes(url)).length === 2) this.meddle?.(this);
          return answer(this.resource(workload));
        }
        if (method === 'patch' && workload !== undefined) {
          this.patched(workload, body);
          return done;
        }
        if (method === 'get' && url === `${jobBase}/executions${query}`) {
          this.lists += 1;
          const listed = this.runs.filter(
            (run) => run.polls >= 0 && (this.lists > this.listLag || !run.name.includes('new')),
          );
          return answer({ value: listed.map(({ name, status }) => ({ name, properties: { status } })) });
        }
        if (method === 'post' && url === `${jobBase}/start${query}`) {
          this.lists = 0;
          const made: string[] = [];
          for (let index = 0; index < this.newRuns; index += 1) {
            const name = this.newRunName ?? `job-agentx-stg-migrate-new${String(index)}x`;
            made.push(name);
            this.runs.unshift({
              name,
              status: 'Running',
              image: this.runImage ?? this.job.image,
              polls: this.runPolls,
            });
          }
          if (this.startNames === 'its run') return answer({ name: made[0] });
          if (this.startNames === 'another') return answer({ name: 'job-agentx-stg-migrate-other1' });
          return done;
        }
        const run = this.runs.find((each) => url === `${jobBase}/executions/${each.name}${query}`);
        if (method === 'get' && run !== undefined) {
          if (run.polls > 0) run.polls -= 1;
          else if (run.status === 'Running') run.status = this.runEndsAs;
          return answer({
            name: run.name,
            properties: { status: run.status, template: { containers: [{ name: 'migrate', image: run.image }] } },
          });
        }
        const revision = /\/revisions\/([^?]+)\?/.exec(url)?.[1];
        if (method === 'get' && url.startsWith(`${appBase}/revisions/`) && revision !== undefined) {
          const found = this.revision(revision);
          if (found !== undefined) return answer(found);
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
      folder: folderAt(NEW).folder,
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
        const status = this.probes.length > 1 ? this.probes.shift() : this.probes[0];
        if (status === 200) this.answered = true;
        return Promise.resolve(status);
      },
    };
  }
}

const RELEASE_NEW = { command: 'release', commit: NEW, digest: digest('2') } as const;

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
          properties: { template: { containers: [released(running('api', { command: ['node'] }), NEW_IMAGE, NEW)] } },
        },
      },
    ]);
    expect(said).toEqual([
      `Checking ${NEW_IMAGE} was signed by CI on main at ${NEW}, with its SBOM...`,
      'Signed in to the subscription "Azure subscription 1".',
      `migrate runs ${OLD} (${OLD_IMAGE}).`,
      `api runs ${OLD} (${OLD_IMAGE}).`,
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
      [
        'The API has the revision suffix "hand" set, which a release would send again.',
        (azure) => (azure.app.suffix = 'hand'),
      ],
    ];
    for (const [message, arrange] of cases) {
      const azure = new Staging();
      arrange(azure);
      const ended_ = await outcome(azure);
      expect(ended_.message).toBe(`${message}\nLeft: nothing was changed.`);
      expect(azure.writes).toEqual([]);
    }
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
      expect(ended_.message).toContain(`\nLeft: ${left === 'nothing' ? `migrate may hold ${NEW}, not run` : left}`);
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
