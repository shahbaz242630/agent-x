// What stage-g.ts asks of Azure (stage-g-azure.ts), against a stand-in CLI
// that answers each command as Azure would and keeps what it was asked. And the
// runner's command line, start to end, on the same stand-in. Nothing here
// reaches Azure.
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { Az, AzResult } from './deploy.ts';
import {
  evidenceAccountOf,
  lastMaximum,
  LOAD_SKU,
  MEASURED_SETTINGS,
  p95OfCounts,
  realStageGAzure,
  stagingServerOf,
} from './stage-g-azure.ts';
import { main } from './stage-g.ts';

const SUBSCRIPTION = '6f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b';
const WORKSPACE_ID = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
const COPY = 'psql-agentx-stg-g-abcd1234';
const LOAD_IMAGE = `ghcr.io/shahbaz242630/agent-x-load@sha256:${'c'.repeat(64)}`;

const json = (value: unknown): AzResult => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
const refused: AzResult = { status: 1, stdout: '', stderr: 'ERROR: Bad Request' };

const STAGING_SERVER = {
  id: '/subscriptions/s/flexibleServers/psql-agentx-stg-q1w2e3',
  name: 'psql-agentx-stg-q1w2e3',
  network: { delegatedSubnetResourceId: '/subnets/database', privateDnsZoneArmResourceId: '/privateDnsZones/zone' },
};

const table = (columns: readonly string[], rows: readonly unknown[][]) => ({
  tables: [{ columns: columns.map((name) => ({ name })), rows }],
});

/** The CLI as Azure would answer it, `answer` first for what a test changes. */
class FakeCli implements Az {
  readonly calls: string[][] = [];
  answer: (args: readonly string[]) => AzResult | undefined = () => undefined;
  readonly queries: string[] = [];

  interactive(): number | null {
    throw new Error('never interactive');
  }

  run(args: readonly string[]): AzResult {
    this.calls.push([...args]);
    const given = this.answer(args);
    if (given !== undefined) return given;
    const said = args.join(' ');
    if (said.startsWith('account show')) return json({ name: 'Azure subscription 1', id: SUBSCRIPTION });
    if (said.startsWith('postgres flexible-server list')) return json([STAGING_SERVER, { name: COPY }]);
    if (said.startsWith('postgres flexible-server show'))
      return json({
        state: 'Ready',
        sku: { name: 'Standard_D16ads_v5' },
        highAvailability: { mode: 'ZoneRedundant', state: 'Healthy' },
      });
    if (said.startsWith('postgres flexible-server parameter show')) {
      return json({ value: '100', isConfigPendingRestart: false });
    }
    if (said.startsWith('postgres flexible-server')) return json({});
    if (said.startsWith('containerapp job execution list')) return json([]);
    if (said.startsWith('containerapp job start')) return json({ name: 'job-agentx-stg-load-mark-m1' });
    if (said.startsWith('containerapp job execution show')) {
      return json({
        properties: { status: 'Succeeded', startTime: '2026-11-06T10:00:00Z', endTime: '2026-11-06T10:01:00Z' },
      });
    }
    if (said.startsWith('containerapp job stop')) return json({});
    if (args[0] === 'rest') return this.#rest(args);
    throw new Error(`unexpected az ${said}`);
  }

  #rest(args: readonly string[]): AzResult {
    const url = args[args.indexOf('--url') + 1] ?? '';
    if (url.includes('/workspaces/log-agentx-stg?')) return json({ properties: { customerId: WORKSPACE_ID } });
    if (url.endsWith(`/workspaces/${WORKSPACE_ID}/query`)) {
      const { query } = JSON.parse(args[args.indexOf('--body') + 1] ?? '{}') as { query: string };
      this.queries.push(query);
      return json(this.#query(query));
    }
    if (url.includes('/Microsoft.App/jobs/')) {
      return json({
        properties: {
          configuration: { replicaTimeout: 900 },
          template: {
            containers: [
              {
                image: LOAD_IMAGE,
                env: [
                  { name: 'AGENTX_LOAD_DB_HOST', value: `${COPY}.postgres.database.azure.com` },
                  { name: 'OTHER', value: 'x' },
                ],
              },
            ],
          },
        },
      });
    }
    if (url.includes('/replicas?')) {
      return json({
        value: [{ name: 'rep1', properties: { runningState: 'Running', containers: [{ restartCount: 2 }] } }],
      });
    }
    if (url.includes('/containerApps/ca-agentx-stg-api?')) {
      return json({ properties: { latestRevisionName: 'api--r1', template: { scale: { minReplicas: 3 } } } });
    }
    if (url.includes('/Microsoft.Insights/metrics?')) {
      return json({
        value: [{ timeseries: [{ data: [{ maximum: 2 * 1024 * 1024 }, { maximum: 3 * 1024 * 1024 }, {}] }] }],
      });
    }
    if (url.includes('/containers?'))
      return json({ value: [{ name: 'audit-anchors' }, { name: 'audit-anchors-g-abcd1234' }] });
    if (url.includes('/containers/')) return json({});
    throw new Error(`unexpected az ${args.join(' ')}`);
  }

  #query(query: string) {
    if (query.includes("JobName == 'job-agentx-stg-load-mark'")) {
      return table(
        ['TimeGenerated', 'Source', 'Reason', 'Text'],
        [
          ['2026-11-06T10:00:30Z', 'stdout', '', JSON.stringify({ event: 'load.stageg_marked', server: COPY })],
          ['2026-11-06T10:01:00Z', 'platform', 'ContainerTerminated', 'ended'],
        ],
      );
    }
    if (query.includes('summarize n = count() by ms'))
      return table(
        ['ms', 'n'],
        [
          [20, 90],
          [80, 5],
          [120, 5],
        ],
      );
    if (query.includes('summarize n = count(), at = min(at) by event, level, org')) {
      return table(
        ['event', 'level', 'org', 'n', 'at'],
        [
          ['http.request_rate_limited', 'warn', 'org-busy', 2, '2026-11-06T10:05:00Z'],
          ['db.slow', 'error', '', 1, '2026-11-06T10:06:00Z'],
        ],
      );
    }
    if (query.includes('summarize at = max(at) by Replica')) {
      return table(['Replica', 'at'], [['api--r1/rep1', '2026-11-06T10:30:00Z']]);
    }
    return table(
      ['Replica', 'Log'],
      [['jobs--r1/j1', JSON.stringify({ time: '2026-11-06T10:05:00Z', event: 'jobs.pulse' })]],
    );
  }
}

function azureOn(cli: FakeCli) {
  const said: string[] = [];
  let clock = Date.parse('2026-11-06T11:00:00Z');
  const azure = realStageGAzure({
    az: cli,
    say: (line) => said.push(line),
    now: () => {
      clock += 1000;
      return new Date(clock);
    },
    sleep: (ms) => {
      clock += ms;
      return Promise.resolve();
    },
  });
  return { azure, said };
}

const WINDOW = { from: '2026-11-06T10:00:00.000Z', to: '2026-11-06T10:20:00.000Z' };

describe("Stage G's Azure", () => {
  it('holds the load size equal to main.bicep, and names the evidence store from the server', () => {
    const bicep = readFileSync(path.join(import.meta.dirname, 'main.bicep'), 'utf8');
    expect(bicep).toContain(`name: '${LOAD_SKU.name}'\n    tier: '${LOAD_SKU.tier}'`);
    expect(evidenceAccountOf('psql-agentx-stg-q1w2e3')).toBe('stagentxstgq1w2e3');
  });

  it('restores staging into its subnet and private zone, sizes the copy, and removes it', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    expect(azure.servers()).toEqual([STAGING_SERVER.name, COPY]);
    const staging = azure.stagingServer();
    azure.restore(COPY, staging, '2026-11-06T10:55:00.000Z');
    const restore = cli.calls.find((args) => args[2] === 'restore') ?? [];
    expect(restore.join(' ')).toBe(
      `postgres flexible-server restore --name ${COPY} --source-server ${STAGING_SERVER.id} --restore-time 2026-11-06T10:55:00.000Z --subscription ${SUBSCRIPTION} --resource-group rg-agentx-staging --subnet /subnets/database --private-dns-zone /privateDnsZones/zone --no-wait --yes`,
    );
    azure.resize(COPY);
    const said = cli.calls.map((args) => args.slice(0, 4).join(' '));
    expect(said).toContain('postgres flexible-server update --name');
    // Azure asks before the restart a resize brings; a job has no one to answer (S176's create stopped there).
    expect(cli.calls.find((args) => args[2] === 'update')).toContain('--yes');
    expect(cli.calls.find((args) => args[3] === 'set')).toContain('100');
    expect(said).toContain('postgres flexible-server restart --name');
    expect(azure.serverState(COPY)).toBe('Ready');
    expect(azure.serverSize(COPY)).toBe('Standard_D16ads_v5');
    expect(azure.connectionLimit(COPY)).toEqual({ limit: 100, waiting: false });
    azure.deleteServer(COPY);
    expect(cli.calls.at(-1)).toContain('--yes');
  });

  it("sets the load run's measurements on the copy, as foundation --load-size sets them on staging", () => {
    const bicep = readFileSync(path.join(import.meta.dirname, 'modules', 'postgres.bicep'), 'utf8');
    for (const [name, value] of Object.entries(MEASURED_SETTINGS)) {
      expect(bicep).toMatch(new RegExp(`name: '${name.replace('.', '[.]')}'\\n\\s+value: measured \\? '${value}'`));
    }
    const cli = new FakeCli();
    azureOn(cli).azure.resize(COPY);
    const set = cli.calls
      .filter((args) => args[3] === 'set')
      .map((args) => [args[7], args[args.indexOf('--value') + 1]]);
    expect(set).toEqual([['max_connections', '100'], ...Object.entries(MEASURED_SETTINGS)]);
    expect(cli.calls.at(-1)?.slice(0, 3)).toEqual(['postgres', 'flexible-server', 'restart']);
  });

  it("turns the copy's high availability, and reads its mode and state", () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    azure.setHa(COPY, 'ZoneRedundant');
    expect(cli.calls.at(-1)).toEqual(
      expect.arrayContaining(['update', '--name', COPY, '--zonal-resiliency', 'Enabled', '--yes']) as unknown,
    );
    expect(cli.calls.at(-1)).not.toContain('--no-wait');
    azure.setHa(COPY, 'Disabled');
    expect(cli.calls.at(-1)).toEqual(expect.arrayContaining(['--zonal-resiliency', 'Disabled']) as unknown);
    expect(azure.haOf(COPY)).toEqual({ mode: 'ZoneRedundant', state: 'Healthy' });
    cli.answer = (args) => (args[2] === 'show' ? json({}) : undefined);
    expect(azure.haOf(COPY)).toEqual({ mode: '', state: '' });
  });

  it('throws a Log Analytics answer given only in part, never taking it as all the lines', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    cli.answer = (args) =>
      args.some((arg) => arg.endsWith('/query'))
        ? json({ tables: [], error: { code: 'PartialError', message: 'query limits' } })
        : undefined;
    expect(() => azure.stepLog(WINDOW, [])).toThrow('Log Analytics answered only in part (PartialError: query limits)');
    cli.answer = (args) => (args.some((arg) => arg.endsWith('/query')) ? json({ error: {} }) : undefined);
    expect(() => azure.decisionP95(WINDOW)).toThrow('(no code: no message)');
  });

  it('says when Azure refuses, or has no server of that name', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    cli.answer = (args) => (args[0] === 'postgres' ? refused : undefined);
    expect(() => {
      azure.deleteServer(COPY);
    }).toThrow(`Azure refused deleting ${COPY}`);
    expect(azure.serverState(COPY)).toBeUndefined();
    expect(azure.serverSize(COPY)).toBeUndefined();
  });

  it("finds staging's own server, or refuses when there isn't exactly one with its network", () => {
    expect(stagingServerOf([STAGING_SERVER, { name: COPY }, { name: 'psql-agentx-stg-drill' }]).subnet).toBe(
      '/subnets/database',
    );
    expect(() => stagingServerOf([])).toThrow('holds 0 database servers of its own');
    expect(() => stagingServerOf('nothing')).toThrow('holds 0');
    expect(() => stagingServerOf([{ ...STAGING_SERVER, network: {} }])).toThrow('no ID, subnet or private zone');
  });

  it("reads a job's host, its runs, stops one, and runs load-mark with no request", async () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    expect(azure.jobHost('load-step')).toBe(`${COPY}.postgres.database.azure.com`);
    expect(azure.runsGoing('load-step')).toEqual([]);
    azure.stopRun('load-step', 'job-agentx-stg-load-step-x1');
    expect(cli.calls.at(-1)).toContain('job-agentx-stg-load-step-x1');
    const marked = await azure.runJob('load-mark', {
      request: undefined,
      lastEvent: 'load.stageg_marked',
      ifStuck: 'wait.',
    });
    expect(marked.printed).toEqual([{ event: 'load.stageg_marked', server: COPY }]);
    expect(cli.calls.some((args) => args.includes('patch'))).toBe(false);
    cli.answer = (args) => (args[0] === 'rest' ? refused : undefined);
    expect(azure.jobHost('load-step')).toBeUndefined();
  });

  it("reads the API's replicas with their restarts", () => {
    const { azure } = azureOn(new FakeCli());
    expect(azure.api().revision).toBe('api--r1');
    expect(azure.replicas('api--r1')).toEqual([{ name: 'rep1', restarts: 2 }]);
  });

  it("reads a step's background lines, counting the warnings, the offenders' apart", () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    const lines = azure.stepLog(WINDOW, ['d1e2f3a4-0000-8000-8000-00000000000b']);
    expect(lines.filter(({ replica }) => replica === 'counted').map(({ log }) => JSON.parse(log) as unknown)).toEqual([
      { time: '2026-11-06T10:05:00Z', level: 'warn', event: 'http.request_rate_limited', orgId: 'org-busy' },
      { time: '2026-11-06T10:05:00Z', level: 'warn', event: 'http.request_rate_limited', orgId: 'org-busy' },
      { time: '2026-11-06T10:06:00Z', level: 'error', event: 'db.slow' },
    ]);
    expect(lines.at(-1)).toEqual({
      replica: 'api--r1/rep1',
      log: JSON.stringify({ time: '2026-11-06T10:30:00Z', event: 'a later line' }),
    });
    expect(cli.queries[1]).toContain('set_has_element(dynamic(["d1e2f3a4-0000-8000-8000-00000000000b"]), org)');
    expect(cli.queries[0]).toContain("ContainerAppName in ('ca-agentx-stg-api', 'ca-agentx-stg-jobs')");
  });

  // S176's smoke on Azure: the workspace refused `j.time` (SYN0002, `time` is a
  // KQL keyword), so no step could be judged. The fixed queries were run on the
  // real workspace before this; here no query may name a keyword as a field.
  it('names no KQL keyword as a field in any query it asks', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    azure.stepLog(WINDOW, []);
    azure.decisionP95(WINDOW);
    expect(cli.queries).toHaveLength(4);
    for (const query of cli.queries) {
      expect(query).toContain("todatetime(j['time'])");
      expect(query).not.toMatch(/\bj\.(time|first|last|in|and|or|not|between)\b/);
    }
  });

  it('gives an org-less warning to the offender whose agent’s refused request it was, only beside offenders (S178)', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    azure.stepLog(WINDOW, ['d1e2f3a4-0000-8000-8000-00000000000b']);
    azure.stepLog(WINDOW, []);
    const [withOffenders, without] = [cli.queries[1], cli.queries[4]];
    for (const part of [
      'let offenderAgents = ',
      "event == 'spend_request.decided'",
      'let offenderCalls = ',
      "event == 'http.request_completed' and toint(j.status) >= 400",
      // A refused request is answered just after its warning: its line is looked for a minute past the step.
      `datetime(${new Date(Date.parse(WINDOW.to) + 60_000).toISOString()})`,
      '| join kind=inner offenderAgents on agent',
      '| join kind=leftouter offenderCalls on correlation',
      "| extend org = iff(org == '', callOrg, org)",
    ]) {
      expect(withOffenders).toContain(part);
    }
    expect(without).not.toContain('offenderCalls');
    expect(without).toContain('| extend org = tostring(j.orgId)');
  });

  it('leaves the offenders’ own decisions out of the p95, and only when there are offenders (S178)', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    azure.decisionP95(WINDOW, ['d1e2f3a4-0000-8000-8000-00000000000b', 'bad"]), x']);
    azure.decisionP95(WINDOW);
    expect(cli.queries[0]).toContain(
      '| where not(set_has_element(dynamic(["d1e2f3a4-0000-8000-8000-00000000000b", "bad"]), tostring(j.orgId)))',
    );
    expect(cli.queries[1]).not.toContain('set_has_element');
  });

  it('reads the decisions p95 from counts, and the metrics last reading', () => {
    const { azure } = azureOn(new FakeCli());
    expect(azure.decisionP95(WINDOW)).toBe(80);
    expect(azure.lastReading('memory', COPY, WINDOW)).toBe(3);
    expect(azure.lastReading('connections', COPY, WINDOW)).toBe(3 * 1024 * 1024);
    const cli = new FakeCli();
    cli.answer = (args) => (args.some((arg) => arg.includes('metrics')) ? refused : undefined);
    expect(azureOn(cli).azure.lastReading('memory', COPY, WINDOW)).toBeNull();
  });

  it('ranks the p95 nearest as logs.ts does, and takes a metrics answer apart', () => {
    expect(p95OfCounts([])).toBeNull();
    expect(p95OfCounts([{ ms: 5, n: 0 }])).toBeNull();
    expect(
      p95OfCounts([
        { ms: 9, n: 19 },
        { ms: 1, n: 1 },
      ]),
    ).toBe(9);
    expect(lastMaximum({}, 1)).toBeNull();
    expect(lastMaximum({ value: [{ timeseries: [{ data: 'x' }] }] }, 1)).toBeNull();
  });

  it('lists and removes anchors containers', () => {
    const cli = new FakeCli();
    const { azure } = azureOn(cli);
    expect(azure.anchorContainers('stagentxstgq1w2e3')).toEqual(['audit-anchors', 'audit-anchors-g-abcd1234']);
    expect(azure.deleteContainer('stagentxstgq1w2e3', 'audit-anchors-g-abcd1234')).toBe(true);
    cli.answer = (args) => (args.includes('delete') ? refused : undefined);
    expect(azure.deleteContainer('stagentxstgq1w2e3', 'audit-anchors-g-abcd1234')).toBe(false);
    cli.answer = (args) => (args.some((arg) => arg.includes('/containers?')) ? json({}) : undefined);
    expect(azure.anchorContainers('stagentxstgq1w2e3')).toEqual([]);
  });
});

describe("the runner's command line", () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'agentx-stage-g-main-'));
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('says the usage for a command it does not know', async () => {
    const said: string[] = [];
    expect(
      await main(
        ['make'],
        (line) => said.push(line),
        () => new FakeCli(),
        dir,
      ),
    ).toBe(2);
    expect(said.join('\n')).toContain('node deploy/azure/stage-g.ts create');
  });

  it("refuses to remove staging's own server, removing nothing", async () => {
    const said: string[] = [];
    const cli = new FakeCli();
    expect(
      await main(
        ['delete', STAGING_SERVER.name],
        (line) => said.push(line),
        () => cli,
        dir,
      ),
    ).toBe(1);
    expect(said.join('\n')).toContain("isn't a throwaway copy's name");
    expect(cli.calls.some((args) => args.includes('delete'))).toBe(false);
  });

  it('says no copy is kept', async () => {
    const said: string[] = [];
    expect(
      await main(
        ['status'],
        (line) => said.push(line),
        () => new FakeCli(),
        dir,
      ),
    ).toBe(0);
    expect(said.join('\n')).toContain('No Stage G copy is kept');
  });
});
