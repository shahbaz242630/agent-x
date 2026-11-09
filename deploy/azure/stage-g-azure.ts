// What stage-g.ts asks of Azure (4D2e Stage G), in one place, so the runner's
// own logic is tested against a stand-in of this and this against a stand-in
// CLI: staging's server and its network, the throwaway copy's restore, size,
// state and removal, the Stage G jobs, the API's replicas, a step's lines in
// the workspace, two metrics, and the copy's anchors containers.
//
// The CLI is started without a shell (deploy.ts realAz), so Git Bash's path
// conversion, which playbook L's restore needs MSYS_NO_PATHCONV against, never
// touches the subnet's and the private zone's IDs here.
import { ARM, azJson, isOwnServer, RESOURCE_GROUP, signedIn, text } from './deploy.ts';
import {
  type Api,
  API_APP,
  type JobRun,
  loadJobUrl,
  readApi,
  type Replica,
  replicasOf,
  type RunOptions,
  runWith,
} from './load-jobs.ts';
import { askWorkspace, jobName, type JobSteps, type StageGJob, unfinishedRuns, workspaceId } from './jobs.ts';
import { LOAD_SERVER_CONNECTIONS } from './policy.ts';
import { record } from './release.ts';
import type { LogLine, StepWindow } from '../../tooling/load/stageg-background.ts';

/** The load size (main.bicep `postgresSkus.load`; a test holds the two equal). */
export const LOAD_SKU = { name: 'Standard_D2ads_v5', tier: 'GeneralPurpose' } as const;

/** The jobs app, which keeps the background work (pulses, anchor checks) in a load run's split (4D2e D13). */
const JOBS_APP = 'ca-agentx-stg-jobs';

/** Staging's own server, and the network a copy must share to be reached: its subnet and private zone. */
export interface StagingServer {
  readonly id: string;
  readonly name: string;
  readonly subnet: string;
  readonly privateDnsZone: string;
}

/** A metric read at a step's end: the API's memory, or the copy's connections. */
export type Metric = 'memory' | 'connections';

/** The copy's high availability: zone-redundant for the ha test (PL-64), off for every other. */
type HaMode = 'ZoneRedundant' | 'Disabled';

/**
 * The load run's measurements, as `foundation --load-size` sets them on
 * staging's server (modules/postgres.bicep `measured`; a test holds the two
 * equal), so the copy's reports compare with PL-38's.
 */
export const MEASURED_SETTINGS: Readonly<Record<string, string>> = {
  'pg_qs.query_capture_mode': 'top',
  'pg_qs.store_query_plans': 'on',
  'pgms_wait_sampling.query_capture_mode': 'all',
  track_io_timing: 'on',
};

/** Everything the runner asks of Azure. */
export interface StageGAzure {
  readonly subscription: string;
  servers(): readonly string[];
  stagingServer(): StagingServer;
  /** Starts a point-in-time restore of staging's server to `copy`, returning at once. */
  restore(copy: string, source: StagingServer, at: string): void;
  /** The server's state (`Ready` once usable), or undefined when Azure has none of that name (yet). */
  serverState(name: string): string | undefined;
  /** The server's size as Azure has it now (`Standard_D16ads_v5`): a copy may be resized by hand mid-test (S177). */
  serverSize(name: string): string | undefined;
  /** The copy to the load size, its connection limit and measurements to the load run's, and a restart for them to take. */
  resize(name: string): void;
  /** Asks Azure to turn the copy's high availability to `mode`, returning at once. */
  setHa(name: string, mode: HaMode): void;
  /** The copy's high availability as Azure shows it: its mode and its state (`Healthy` once a standby runs). */
  haOf(name: string): { readonly mode: string; readonly state: string };
  connectionLimit(name: string): { readonly limit: number; readonly waiting: boolean };
  deleteServer(name: string): void;
  /** The database host a Stage G job reaches, or undefined when the job isn't there. */
  jobHost(job: StageGJob): string | undefined;
  runsGoing(job: StageGJob): readonly string[];
  stopRun(job: StageGJob, run: string): void;
  runJob(job: StageGJob, options: RunOptions): Promise<JobRun>;
  api(): Api;
  replicas(revision: string): readonly Replica[];
  /** The step's background lines (stageg-background.ts) as read so far, `offenders` kept apart. */
  stepLog(window: StepWindow, offenders: readonly string[]): readonly LogLine[];
  /** The decisions' p95 over the window, from the API's own lines, the offenders' left out; null when none was made in it. */
  decisionP95(window: StepWindow, offenders?: readonly string[]): number | null;
  /**
   * The metric's last 5-minute maximum in the window (MB of memory, or
   * connections): the soak's report reads each segment at its end, to compare
   * the first's with the last's. Null when none could be read.
   */
  lastReading(metric: Metric, server: string, window: StepWindow): number | null;
  anchorContainers(account: string): readonly string[];
  /** Removes an anchors container: false when Azure refused (its files' time not up, say). */
  deleteContainer(account: string, container: string): boolean;
}

/** The evidence store beside staging's server: both carry the same suffix (names.bicep). */
export const evidenceAccountOf = (stagingServer: string): string =>
  `stagentxstg${stagingServer.replace(/^psql-agentx-stg-/, '')}`;

const where = (subscription: string): string[] => ['--subscription', subscription, '--resource-group', RESOURCE_GROUP];

/** How far past a step's end its lines are looked for: they reach the workspace 4 to 9 minutes late. */
const LATE_MS = 40 * 60_000;

/** The background lines read whole: few, and each one's fields are read (stageg-background.ts). */
const KEPT_EVENTS = ['jobs.pulse', 'audit.anchor_check_done', 'job.stalled'];

const kql = (value: string): string => `'${value.replace(/[^A-Za-z0-9._:/ -]/g, '')}'`;

/** The apps' lines over the window and LATE_MS past it, each with the logger's own time and fields. */
function linesFrom(apps: readonly string[], { from, to }: StepWindow): string {
  const start = new Date(Date.parse(from) - 5 * 60_000).toISOString();
  const end = new Date(Date.parse(to) + LATE_MS).toISOString();
  return [
    'ContainerAppConsoleLogs',
    `| where TimeGenerated between (datetime(${start}) .. datetime(${end}))`,
    `| where ContainerAppName in (${apps.map(kql).join(', ')})`,
    '| extend j = parse_json(Log)',
    // j['time'], not j.time: `time` is a reserved word in KQL, and the workspace refuses the query (S176's smoke).
    "| extend at = todatetime(j['time']), event = tostring(j.event), level = tostring(j.level)",
    "| extend Replica = strcat(RevisionName, '/', ContainerGroupName)",
  ].join('\n');
}

/** The rows of the first table in Log Analytics' answer, each as named columns. */
function rowsOf(answer: unknown): Readonly<Record<string, unknown>>[] {
  const table = record((record(answer).tables as unknown[] | undefined)?.[0]);
  const columns = (Array.isArray(table.columns) ? table.columns : []).map((column) => text(record(column).name));
  const rows = Array.isArray(table.rows) ? table.rows : [];
  return rows.map((row) =>
    Object.fromEntries(columns.map((name, index) => [name, Array.isArray(row) ? (row[index] as unknown) : undefined])),
  );
}

/**
 * Most lines a step logs are decisions, 170 a second: read whole, an hour's
 * would pass the query API's 500,000 rows. So the background's few lines are
 * read whole, the warnings and errors counted by event (each count given back
 * as that many lines, the offenders' kept apart), and for each API replica its
 * last line past the step, which tells its lines are in.
 */
function stepLogQueries(window: StepWindow, offenders: readonly string[]): string[] {
  const base = linesFrom([API_APP, JOBS_APP], window);
  const inWindow = `at between (datetime(${window.from}) .. datetime(${window.to}))`;
  const kept = KEPT_EVENTS.map(kql).join(', ');
  const apart = offendersSet(offenders);
  const byCall = offenders.length === 0 ? { lets: [], join: [] } : offenderCalls(base, window, apart);
  return [
    `${base}\n| where at >= datetime(${window.from}) and event in (${kept})\n| project Replica, Log`,
    [
      ...byCall.lets,
      base,
      `| where ${inWindow} and level in ('warn', 'error', 'fatal') and event !in (${kept})`,
      '| extend org = tostring(j.orgId)',
      ...byCall.join,
      `| extend org = iff(set_has_element(${apart}, org), org, '')`,
      '| summarize n = count(), at = min(at) by event, level, org',
    ].join('\n'),
    `${base}\n| where ContainerAppName == ${kql(API_APP)} and at > datetime(${window.to})\n| summarize at = max(at) by Replica`,
  ];
}

/** How far past the step a refused request's line is looked for: logged as it is answered, just after its warning. */
const ANSWERED_AFTER_MS = 60_000;

/**
 * The offenders' refused requests, each by its correlation ID with its organisation, and the join that reads them: a
 * warning that names no organisation (a lock's wait run out, until server.ts's naming one is deployed) is the
 * offender's when its request was sent by one of the offender's agents (S178). An offender's agents are those its
 * decisions name; its refused requests are always logged, naming their agent (request-log.ts).
 */
function offenderCalls(base: string, window: StepWindow, apart: string): { lets: string[]; join: string[] } {
  const answeredBy = new Date(Date.parse(window.to) + ANSWERED_AFTER_MS).toISOString();
  return {
    lets: [
      'let offenderAgents = ' + base,
      `| where at between (datetime(${window.from}) .. datetime(${window.to})) and event == 'spend_request.decided'`,
      `| extend org = tostring(j.orgId) | where set_has_element(${apart}, org)`,
      '| project agent = tostring(j.agentId), org',
      '| distinct agent, org;',
      'let offenderCalls = ' + base,
      `| where at between (datetime(${window.from}) .. datetime(${answeredBy})) and event == 'http.request_completed' and toint(j.status) >= 400`,
      '| project correlation = tostring(j.correlationId), agent = tostring(j.agentId)',
      '| join kind=inner offenderAgents on agent',
      '| project correlation, callOrg = org',
      '| distinct correlation, callOrg;',
    ],
    join: [
      '| extend correlation = tostring(j.correlationId)',
      '| join kind=leftouter offenderCalls on correlation',
      "| extend org = iff(org == '', callOrg, org)",
    ],
  };
}

/** The offenders as a KQL set, each ID cut to the characters a UUID has. */
function offendersSet(offenders: readonly string[]): string {
  return `dynamic([${offenders.map((org) => '"' + org.replace(/[^0-9a-f-]/g, '') + '"').join(', ')}])`;
}

/**
 * The decisions' times in the step's window, counted by each time to a tenth of a millisecond. The offenders' are left
 * out: slow by design beside the neighbours (a stuck one's wait for its own rows), they are not the traffic judged (S178).
 */
const decisionQuery = (window: StepWindow, offenders: readonly string[]): string =>
  [
    linesFrom([API_APP], window),
    `| where event == 'spend_request.decided' and at between (datetime(${window.from}) .. datetime(${window.to}))`,
    ...(offenders.length === 0 ? [] : [`| where not(set_has_element(${offendersSet(offenders)}, tostring(j.orgId)))`]),
    '| summarize n = count() by ms = round(todouble(j.durationMs), 1)',
  ].join('\n');

/** The counted warnings and errors as the lines they stand for, the offenders' with their organisation. */
const countedLines = (rows: readonly Readonly<Record<string, unknown>>[]): LogLine[] =>
  rows.flatMap((row) => {
    const org = text(row.org);
    const log = JSON.stringify({
      time: text(row.at),
      level: text(row.level),
      event: text(row.event),
      ...(org === '' ? {} : { orgId: org }),
    });
    return Array.from({ length: Number(row.n) || 0 }, () => ({ replica: 'counted', log }));
  });

/** The decisions' p95 by nearest rank over counts of each time (to a tenth of a millisecond), as logs.ts ranks them. */
export function p95OfCounts(counts: readonly { readonly ms: number; readonly n: number }[]): number | null {
  const total = counts.reduce((sum, { n }) => sum + n, 0);
  if (total === 0) return null;
  const rank = Math.min(total, Math.ceil(0.95 * total));
  let seen = 0;
  return counts.toSorted((a, b) => a.ms - b.ms).find(({ n }) => (seen += n) >= rank)?.ms ?? null;
}

const METRICS: Readonly<Record<Metric, { readonly name: string; readonly scale: number }>> = {
  memory: { name: 'WorkingSetBytes', scale: 1024 * 1024 },
  connections: { name: 'active_connections', scale: 1 },
};

/** The runner's Azure, on the CLI the partner is signed in with. */
export function realStageGAzure(steps: JobSteps): StageGAzure {
  const { az } = steps;
  const subscription = signedIn(az, steps.say);
  const group = where(subscription);
  const server = (...args: string[]): string[] => ['postgres', 'flexible-server', ...args, ...group];
  const workspace = (): string => workspaceId(steps, subscription);
  const ask = (query: string, window: StepWindow) =>
    rowsOf(
      askWorkspace(
        steps,
        workspace(),
        query,
        `${new Date(Date.parse(window.from) - 5 * 60_000).toISOString()}/${new Date(Math.max(steps.now().getTime(), Date.parse(window.to) + LATE_MS)).toISOString()}`,
      ),
    );
  const ok = (args: string[], what: string): void => {
    const done = az.run(args);
    if (done.status !== 0) throw new Error(`Azure refused ${what}:\n${done.stderr.trim()}`);
  };
  const groupUrl = `${ARM}subscriptions/${subscription}/resourceGroups/${RESOURCE_GROUP}/providers`;
  return {
    subscription,
    servers: () =>
      (azJson(az, server('list')) as readonly unknown[]).map((each) => text(record(each).name)).filter(Boolean),
    stagingServer: () => stagingServerOf(azJson(az, server('list'))),
    restore: (copy, source, at) => {
      ok(
        [
          ...server('restore', '--name', copy, '--source-server', source.id, '--restore-time', at),
          ...['--subnet', source.subnet, '--private-dns-zone', source.privateDnsZone, '--no-wait', '--yes'],
        ],
        `the restore of ${source.name} to ${copy}`,
      );
    },
    serverState: (name) => {
      const done = az.run([...server('show', '--name', name), '--output', 'json']);
      return done.status === 0 ? text(record(JSON.parse(done.stdout)).state) : undefined;
    },
    serverSize: (name) => {
      const done = az.run([...server('show', '--name', name), '--output', 'json']);
      return done.status === 0 ? text(record(record(JSON.parse(done.stdout)).sku).name) : undefined;
    },
    resize: (name) => {
      // --yes on every update and restore: they ask before a restart, and no one can answer a job's prompt (S176).
      ok(
        server('update', '--name', name, '--sku-name', LOAD_SKU.name, '--tier', LOAD_SKU.tier, '--yes'),
        `resizing ${name}`,
      );
      ok(
        [
          ...server('parameter', 'set', '--server-name', name, '--name', 'max_connections'),
          ...['--value', String(LOAD_SERVER_CONNECTIONS)],
        ],
        `${name}'s connection limit`,
      );
      for (const [setting, value] of Object.entries(MEASURED_SETTINGS)) {
        ok(
          [...server('parameter', 'set', '--server-name', name, '--name', setting), ...['--value', value]],
          `${name}'s ${setting}`,
        );
      }
      ok(server('restart', '--name', name), `restarting ${name}`);
    },
    setHa: (name, mode) => {
      // Azure CLI 2.90 renamed --high-availability to --zonal-resiliency and dropped --no-wait here (S179): the
      // command now waits for the standby, which haOf then reads as Healthy.
      const resiliency = mode === 'ZoneRedundant' ? 'Enabled' : 'Disabled';
      ok(server('update', '--name', name, '--zonal-resiliency', resiliency, '--yes'), `${name}'s high availability`);
    },
    haOf: (name) => {
      const ha = record(record(azJson(az, server('show', '--name', name))).highAvailability);
      return { mode: text(ha.mode), state: text(ha.state) };
    },
    connectionLimit: (name) => {
      const shown = record(azJson(az, server('parameter', 'show', '--server-name', name, '--name', 'max_connections')));
      return { limit: Number(shown.value), waiting: shown.isConfigPendingRestart === true };
    },
    deleteServer: (name) => {
      ok(server('delete', '--name', name, '--yes'), `deleting ${name}`);
    },
    jobHost: (job) => {
      const done = az.run(['rest', '--method', 'get', '--url', loadJobUrl(subscription, job), '--output', 'json']);
      if (done.status !== 0) return undefined;
      const [container] = (record(record(record(JSON.parse(done.stdout)).properties).template).containers ??
        []) as unknown[];
      const env = record(container).env;
      const setting = (Array.isArray(env) ? env.map(record) : []).find(({ name }) => name === 'AGENTX_LOAD_DB_HOST');
      return text(setting?.value);
    },
    runsGoing: (job) => unfinishedRuns(steps, { subscription, job }),
    stopRun: (job, run) => {
      ok(
        ['containerapp', 'job', 'stop', ...group, '--name', jobName(job), '--job-execution-name', run],
        `stopping ${run}`,
      );
    },
    runJob: (job, options) => runWith(steps, subscription, job, options),
    api: () => readApi(az, subscription),
    replicas: (revision) => replicasOf(az, subscription, revision).each,
    stepLog: (window, offenders) => {
      const [kept = '', counted = '', after = ''] = stepLogQueries(window, offenders);
      return [
        ...ask(kept, window).map((row) => ({ replica: text(row.Replica), log: text(row.Log) })),
        ...countedLines(ask(counted, window)),
        ...ask(after, window).map((row) => ({
          replica: text(row.Replica),
          log: JSON.stringify({ time: text(row.at), event: 'a later line' }),
        })),
      ];
    },
    decisionP95: (window, offenders = []) => {
      const query = decisionQuery(window, offenders);
      return p95OfCounts(ask(query, window).map((row) => ({ ms: Number(row.ms), n: Number(row.n) })));
    },
    lastReading: (metric, copy, window) => {
      const { name, scale } = METRICS[metric];
      const resource =
        metric === 'memory'
          ? `${groupUrl}/Microsoft.App/containerApps/${API_APP}`
          : `${groupUrl}/Microsoft.DBforPostgreSQL/flexibleServers/${copy}`;
      const url = `${resource}/providers/Microsoft.Insights/metrics?api-version=2023-10-01&metricnames=${name}&aggregation=Maximum&interval=PT5M&timespan=${window.from}/${window.to}`;
      const done = az.run(['rest', '--method', 'get', '--url', url, '--output', 'json']);
      return done.status === 0 ? lastMaximum(JSON.parse(done.stdout), scale) : null;
    },
    anchorContainers: (account) => {
      const listed = record(
        azJson(az, [
          'rest',
          '--method',
          'get',
          '--url',
          `${groupUrl}/Microsoft.Storage/storageAccounts/${account}/blobServices/default/containers?api-version=2025-01-01`,
        ]),
      ).value;
      return (Array.isArray(listed) ? listed : []).map((each) => text(record(each).name));
    },
    deleteContainer: (account, container) =>
      az.run([
        'rest',
        '--method',
        'delete',
        '--url',
        `${groupUrl}/Microsoft.Storage/storageAccounts/${account}/blobServices/default/containers/${container}?api-version=2025-01-01`,
      ]).status === 0,
  };
}

/** Staging's own server among the group's, with its network, or an error saying why there isn't exactly one. */
export function stagingServerOf(listed: unknown): StagingServer {
  const own = (Array.isArray(listed) ? listed.map(record) : []).filter(({ name }) => isOwnServer(text(name)));
  const [found] = own;
  if (own.length !== 1 || found === undefined) {
    throw new Error(`${RESOURCE_GROUP} holds ${String(own.length)} database servers of its own, not one.`);
  }
  const network = record(found.network);
  const staging = {
    id: text(found.id),
    name: text(found.name),
    subnet: text(network.delegatedSubnetResourceId),
    privateDnsZone: text(network.privateDnsZoneArmResourceId),
  };
  if (staging.id === '' || staging.subnet === '' || staging.privateDnsZone === '') {
    throw new Error(
      `Azure gave no ID, subnet or private zone for ${staging.name}, so a copy couldn't be placed beside it.`,
    );
  }
  return staging;
}

/** The last reading's maximum in a metrics answer, scaled; null when it holds none. */
export function lastMaximum(answer: unknown, scale: number): number | null {
  const [series] = (record((record(answer).value as unknown[] | undefined)?.[0]).timeseries ?? []) as unknown[];
  const data = record(series).data;
  const readings = (Array.isArray(data) ? data : [])
    .map((point) => record(point).maximum)
    .filter((value): value is number => typeof value === 'number');
  const last = readings.at(-1);
  return last === undefined ? null : Math.round(last / scale);
}
