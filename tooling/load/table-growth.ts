// How much each table and index grew over a load run (4D2e F12, PL-65), to
// replace the byte figures Stage F's design only estimated, and how often each
// index was scanned meanwhile, the evidence for trimming one: sizes read after
// the seed and after the last phase, as the app's role, by the laptop's run and
// Azure's jobs alike, and the report's section on them.
import { type Database, type TableSize, type TableSizes, tableSizes } from '../../packages/platform/src/db/index.ts';

import type { PhaseResult } from './report.ts';

type GrowthStage = 'before' | 'after';

/** One end of the run as read: its sizes, or why they couldn't be read. */
export type GrowthEnd =
  | { readonly stage: GrowthStage; readonly sizes: TableSizes }
  | { readonly stage: GrowthStage; readonly problem: string };

/** The run's two ends, for the report; or why it can't say. */
export type TableGrowth = Ends | { readonly problem: string };

interface Ends {
  readonly before: TableSizes;
  readonly after: TableSizes;
}

/** How many tables the report names, the biggest growth first; the rest are one row, so the total stays whole. */
const TABLES_NAMED = 8;

const MB = 1024 ** 2;
const GB = 1024 ** 3;
const SECONDS_A_DAY = 86_400;
const NONE: TableSize = { rows: 0, indexes: 0, longValues: 0 };

/** A read that fails is said and never stops a run: this is only a report on it, and its checks must still run. */
export async function readGrowthEnd<Tables>(database: Database<Tables>, stage: GrowthStage): Promise<GrowthEnd> {
  try {
    return { stage, sizes: await tableSizes(database) };
  } catch (error) {
    return {
      stage,
      problem: `its tables' sizes couldn't be read: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null;

const hasNumbers = (value: unknown, keys: readonly string[]): boolean =>
  isRecord(value) && keys.every((key) => typeof value[key] === 'number');

/** Sizes as a job printed them: checked, since a line from the log is only JSON. */
function isSizes(value: unknown): value is TableSizes {
  return (
    isRecord(value) &&
    isRecord(value.tables) &&
    isRecord(value.indexes) &&
    Object.values(value.tables).every((size) => hasNumbers(size, ['rows', 'indexes', 'longValues'])) &&
    Object.values(value.indexes).every(
      (index) => hasNumbers(index, ['bytes', 'scans']) && isRecord(index) && typeof index.table === 'string',
    )
  );
}

/** What one end says, as a job's printed line or a read in hand: its sizes, or its problem. */
function endOf(end: Readonly<Record<string, unknown>> | undefined, which: GrowthStage) {
  if (typeof end?.problem === 'string') return { problem: `The ${which} reading: ${end.problem}` };
  return isSizes(end?.sizes) ? { sizes: end.sizes } : { problem: `The ${which} reading said nothing` };
}

/** The growth between two ends, each as read or as a job printed it. */
export function growthBetween(
  before: Readonly<Record<string, unknown>> | undefined,
  after: Readonly<Record<string, unknown>> | undefined,
): TableGrowth {
  const first = endOf(before, 'before');
  const last = endOf(after, 'after');
  if ('problem' in first) return { problem: first.problem };
  if ('problem' in last) return { problem: last.problem };
  return { before: first.sizes, after: last.sizes };
}

const megabytes = (bytes: number): string => (bytes / MB).toFixed(1);
const gigabytes = (bytes: number): string => (bytes / GB).toFixed(2);
const bytesOf = ({ rows, indexes, longValues }: TableSize): number => rows + indexes + longValues;
const minus = (after: TableSize, before: TableSize): TableSize => ({
  rows: after.rows - before.rows,
  indexes: after.indexes - before.indexes,
  longValues: after.longValues - before.longValues,
});
const plus = (a: TableSize, b: TableSize): TableSize => ({
  rows: a.rows + b.rows,
  indexes: a.indexes + b.indexes,
  longValues: a.longValues + b.longValues,
});
const byGrowth = <T extends { readonly name: string; readonly grew: number }>(a: T, b: T) =>
  b.grew - a.grew || (a.name < b.name ? -1 : 1);

interface TableRow {
  readonly name: string;
  readonly before: TableSize;
  readonly after: TableSize;
  readonly grew: number;
}

/** Each table, biggest growth first: a table that shrank (a sweep, a vacuum) counts in the total alone. */
const tableRows = ({ before, after }: Ends): TableRow[] =>
  Object.entries(after.tables)
    .map(([name, size]) => {
      const was = before.tables[name] ?? NONE;
      return { name, before: was, after: size, grew: bytesOf(size) - bytesOf(was) };
    })
    .toSorted(byGrowth);

/** The seconds of traffic the phases sent, or none when a phase didn't say. */
function trafficSeconds(phases: readonly PhaseResult[]): number | undefined {
  const each = phases.map(({ durationMs }) => durationMs);
  if (each.length === 0 || each.some((ms) => ms === undefined)) return undefined;
  return each.reduce<number>((sum, ms) => sum + (ms ?? 0), 0) / 1000;
}

/** A day at the run's own rate, and what one new request a second adds, in words: the figures Stage F's table estimated. */
function dayLines(total: number, created: number, seconds: number | undefined): string[] {
  const perRequest = `Each new request a second, kept up all day, would add ${gigabytes((total / created) * SECONDS_A_DAY)} GB a day.`;
  if (seconds === undefined)
    return [`A day at the run's rate: not measured, a phase didn't say how long it ran. ${perRequest}`];
  return [
    `A day at the run's rate, ${(created / seconds).toFixed(1)} new requests a second over ${seconds.toFixed(0)} s of traffic: ${gigabytes((total / seconds) * SECONDS_A_DAY)} GB. ${perRequest}`,
  ];
}

/** The indexes of the tables named, biggest growth first, with the scans the run made of each. */
function indexLines({ before, after }: Ends, tables: readonly string[], created: number): string[] {
  const rows = Object.entries(after.indexes)
    .filter(([, { table }]) => tables.includes(table))
    .map(([name, { bytes, scans }]) => {
      const was = before.indexes[name];
      return { name, grew: bytes - (was?.bytes ?? 0), scans: scans - (was?.scans ?? 0) };
    })
    .toSorted(byGrowth);
  return [
    '',
    "Each of those tables' indexes, and how many times the run scanned it: an index that grows and is never scanned is one to trim (Stage F names `audit.events_by_action` and `audit.events_by_actor`). Postgres's own counts, which a connection reports a few seconds late; on Azure, staging's other traffic counts too.",
    '',
    '| Index | Grew, MB | Bytes a new request | Scans in the run |',
    '| --- | --- | --- | --- |',
    ...rows.map(
      ({ name, grew, scans }) => `| ${name} | ${megabytes(grew)} | ${(grew / created).toFixed(0)} | ${String(scans)} |`,
    ),
  ];
}

/** The report's section: the tables that grew most and their parts, their indexes, and a day at the run's rate. */
export function growthSection(growth: TableGrowth | undefined, phases: readonly PhaseResult[]): string[] {
  const heading = ['', '## How much the tables grew', ''];
  if (growth === undefined) return [...heading, 'Not measured.'];
  if ('problem' in growth) return [...heading, `Not measured. ${growth.problem}.`];
  const created = phases.reduce((sum, phase) => sum + phase.created, 0);
  const rows = tableRows(growth);
  const total = rows.reduce((sum, { grew }) => sum + grew, 0);
  if (created === 0) return [...heading, `No new request, so no bytes a request: ${megabytes(total)} MB in all.`];

  const named = rows.slice(0, TABLES_NAMED);
  const sumOf = (some: readonly TableRow[], name: string): TableRow => ({
    name,
    before: some.reduce((sum, row) => plus(sum, row.before), NONE),
    after: some.reduce((sum, row) => plus(sum, row.after), NONE),
    grew: some.reduce((sum, row) => sum + row.grew, 0),
  });
  const cells = ({ name, before, after, grew }: TableRow) => {
    const parts = minus(after, before);
    return `| ${name} | ${megabytes(bytesOf(before))} | ${megabytes(bytesOf(after))} | ${megabytes(grew)} | ${megabytes(parts.rows)} / ${megabytes(parts.indexes)} / ${megabytes(parts.longValues)} | ${(grew / created).toFixed(0)} |`;
  };
  return [
    ...heading,
    "From after the seed to the end of the last phase, the database's own sizes: each table's rows, its indexes and its long values (TOAST), in whole disk pages, so dead rows count and a small table moves 8 KB at a time. Every table there is, so the timers' rows are in it, and on Azure whatever else staging did meanwhile. Every request the run sent is in these bytes, its replays and refusals too, set against the new ones. Hand-offs are paused, so what a paid payment adds isn't in them.",
    '',
    '| Table | Before, MB | After, MB | Grew, MB | Rows / indexes / long values grew, MB | Bytes a new request |',
    '| --- | --- | --- | --- | --- | --- |',
    ...named.map(cells),
    ...(rows.length > TABLES_NAMED
      ? [cells(sumOf(rows.slice(TABLES_NAMED), `The other ${String(rows.length - TABLES_NAMED)} tables`))]
      : []),
    cells(sumOf(rows, '**All tables**')),
    '',
    ...dayLines(total, created, trafficSeconds(phases)),
    ...indexLines(
      growth,
      named.map(({ name }) => name),
      created,
    ),
  ];
}
