// migration-state.ts (AZ6): what the database holds of an image's migrations, read from the migration job's runs
// as Azure records them, against a stand-in Azure CLI and history.
import { describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import type { History } from './git.ts';
import { migrationState } from './migration-state.ts';
import { workloadUrl } from './release.ts';

const SUBSCRIPTION = '00000000-0000-0000-0000-00000000000c';
const HOST = 'psql-agentx-stg-abcdef.postgres.database.azure.com';
const OLD_HOST = 'psql-agentx-stg-abcdef-r1.postgres.database.azure.com';
const OLD = 'a'.repeat(40);
const NEW = 'b'.repeat(40);
const EXECUTIONS = workloadUrl(SUBSCRIPTION, 'migrate').replace('?api-version=', '/executions?api-version=');
const runUrl = (name: string): string => EXECUTIONS.replace('/executions?', `/executions/${name}?`);

const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });

/** One of migrate's runs: as listed, and as its own record names the server and build. */
interface HeldRun {
  readonly name: string;
  readonly status?: string;
  readonly started?: unknown;
  readonly host?: string;
  readonly ran?: string;
  /** Its record's container, when it isn't the usual one. */
  readonly containers?: unknown;
}

/** An Azure CLI holding migrate's runs, or answering the list as given; it records the URLs read. */
function azWith(runs: readonly HeldRun[] | AzResult): Az & { readonly read: string[] } {
  const read: string[] = [];
  return {
    read,
    interactive: () => {
      throw new Error('never interactive');
    },
    run: (args) => {
      const url = args[args.indexOf('--url') + 1] ?? '';
      read.push(url);
      if (url === EXECUTIONS) {
        if (!Array.isArray(runs)) return runs as AzResult;
        return json({
          value: (runs as readonly HeldRun[]).map(({ name, status = 'Succeeded', started }) => ({
            name,
            properties: { status, startTime: started },
          })),
        });
      }
      const found = Array.isArray(runs)
        ? (runs as readonly HeldRun[]).find((run) => url === runUrl(run.name))
        : undefined;
      if (found === undefined) return { status: 1, stdout: '', stderr: 'ERROR: Bad Gateway' };
      const env = [
        { name: 'AGENTX_DB_HOST', value: found.host ?? HOST },
        { name: 'AGENTX_RELEASE', value: found.ran ?? OLD },
        { name: 'AGENTX_DB_MIGRATION_PASSWORD_FILE', secretRef: 'db-owner-password' },
      ];
      return json({
        name: found.name,
        properties: { template: { containers: found.containers ?? [{ name: 'migrate', image: 'x', env }] } },
      });
    },
  };
}

/** A history whose db/migrations holds, at each commit, the files given; a commit not given is one this clone lacks. */
function historyOf(files: Readonly<Record<string, readonly string[]>>): History {
  return {
    isAncestor: () => true,
    changedFiles: () => [],
    fileAt: () => undefined,
    filesIn: (commit, folder) => {
      expect(folder).toBe('db/migrations');
      const held = files[commit];
      if (held === undefined) throw new Error(`git couldn't list ${folder} at ${commit}`);
      return held;
    },
    mainline: () => new Map(),
  };
}

/** The image's own migrations: two beyond OLD's. */
const NEW_FILES = ['0001_first.sql', '0002_second.sql', '0003_third.sql', '0004_fourth.sql', 'README.md'];

const MIGRATIONS = {
  [OLD]: ['0001_first.sql', '0002_second.sql', 'README.md'],
  [NEW]: NEW_FILES,
};

const stateOf = (az: Az, files: Readonly<Record<string, readonly string[]>> = MIGRATIONS, release = NEW) =>
  migrationState(az, historyOf(files), SUBSCRIPTION, HOST, release);

describe('migrationState', () => {
  it("names what the image brings beyond the build migrate's newest successful run on the server ran", () => {
    const az = azWith([
      { name: 'job-agentx-stg-migrate-new2x', status: 'Failed', started: '2026-11-10T10:00:00Z', ran: NEW },
      { name: 'job-agentx-stg-migrate-old1x', started: '2026-11-01T10:00:00Z', ran: 'c'.repeat(40) },
      { name: 'job-agentx-stg-migrate-mid1x', started: '2026-11-05T10:00:00Z' },
    ]);
    expect(stateOf(az)).toEqual({
      kind: 'behind',
      run: 'job-agentx-stg-migrate-mid1x',
      ran: OLD,
      missing: ['0003_third.sql', '0004_fourth.sql'],
    });
    // Only the newest successful run is read once it is on the server; a failed one never counts.
    expect(az.read).toEqual([EXECUTIONS, runUrl('job-agentx-stg-migrate-mid1x')]);
  });

  it('holds them when that build carries every one, a later build included', () => {
    expect(stateOf(azWith([{ name: 'job-agentx-stg-migrate-new1x', ran: NEW }]))).toEqual({
      kind: 'holds',
      run: 'job-agentx-stg-migrate-new1x',
      ran: NEW,
    });
    expect(stateOf(azWith([{ name: 'job-agentx-stg-migrate-new1x', ran: NEW }]), MIGRATIONS, OLD).kind).toBe('holds');
  });

  it("passes over runs on another server, as a restore's earlier generation left them", () => {
    const az = azWith([
      { name: 'job-agentx-stg-migrate-gen1x', started: '2026-11-09T10:00:00Z', host: OLD_HOST, ran: NEW },
      { name: 'job-agentx-stg-migrate-gen0x', started: '2026-11-02T10:00:00Z' },
    ]);
    expect(stateOf(az)).toMatchObject({ kind: 'behind', run: 'job-agentx-stg-migrate-gen0x' });
  });

  it('is a first deploy when there is no migration job yet', () => {
    const missing = {
      status: 3,
      stdout: '',
      stderr: 'ERROR: Not Found({"error":{"code":"ResourceNotFound","message":"not found"}})',
    };
    expect(stateOf(azWith(missing))).toEqual({ kind: 'no-job' });
  });

  it("can't tell, and says why, whenever something isn't there to read", () => {
    const cases: [Az, string, Readonly<Record<string, readonly string[]>>?][] = [
      [
        azWith({ status: 1, stdout: '', stderr: 'ERROR: Bad Gateway({"error":{"code":"BadGateway"}})' }),
        "Azure didn't answer the read of migrate's runs (Bad Gateway, BadGateway)",
      ],
      [azWith({ status: 0, stdout: 'not json', stderr: '' }), "Azure's list of migrate's runs wasn't a list"],
      [azWith(json({ value: 'none' })), "Azure's list of migrate's runs wasn't a list"],
      [azWith([]), `Azure lists no successful run of migrate on ${HOST}`],
      [
        azWith([{ name: 'job-agentx-stg-migrate-new1x', host: OLD_HOST }]),
        `Azure lists no successful run of migrate on ${HOST}`,
      ],
      [azWith([{ name: 'not a run of migrate' }]), `Azure lists no successful run of migrate on ${HOST}`],
      [
        azWith([{ name: 'job-agentx-stg-migrate-new1x', containers: 'none' }]),
        `Azure lists no successful run of migrate on ${HOST}`,
      ],
      [
        azWith([{ name: 'job-agentx-stg-migrate-new1x', containers: [{ name: 'migrate' }] }]),
        `Azure lists no successful run of migrate on ${HOST}`,
      ],
      [
        azWith([{ name: 'job-agentx-stg-migrate-new1x', ran: 'latest' }]),
        "migrate's run job-agentx-stg-migrate-new1x names no build it ran",
      ],
      [
        azWith([{ name: 'job-agentx-stg-migrate-new1x' }]),
        `this folder's git can't list the migrations of ${OLD}, which migrate's run job-agentx-stg-migrate-new1x ran (git fetch origin, then run apps again)`,
        { [NEW]: NEW_FILES },
      ],
    ];
    for (const [az, why, files] of cases) expect(stateOf(az, files)).toEqual({ kind: 'unknown', why });
  });

  it("can't tell when a run's own record can't be read", () => {
    const az = azWith([{ name: 'job-agentx-stg-migrate-new1x' }]);
    const failing: Az = {
      ...az,
      run: (args) =>
        (args[args.indexOf('--url') + 1] ?? '') === EXECUTIONS
          ? az.run(args)
          : { status: 1, stdout: '', stderr: 'ERROR: Too Many Requests({"error":{"code":"TooManyRequests"}})' },
    };
    expect(stateOf(failing)).toEqual({
      kind: 'unknown',
      why: "Azure didn't answer the read of job-agentx-stg-migrate-new1x (Too Many Requests, TooManyRequests)",
    });
  });

  it('reads no more than twenty of the newest successful runs', () => {
    const runs = Array.from({ length: 25 }, (_, index) => ({
      name: `job-agentx-stg-migrate-r${String(index).padStart(2, '0')}x`,
      started: `2026-11-${String(index + 1).padStart(2, '0')}T10:00:00Z`,
      host: OLD_HOST,
    }));
    const az = azWith(runs);
    expect(stateOf(az).kind).toBe('unknown');
    expect(az.read).toHaveLength(21);
    expect(az.read[1]).toBe(runUrl('job-agentx-stg-migrate-r24x'));
  });
});
