// The security events' MACs and daily seals (S206 V6, Threat-Model R-15;
// ADR-012 §2). The failed sign-ins and rate-limit hits are an attack's
// evidence, and the database's owner, who holds none of the app's keys, could
// plant, edit or delete them unseen. Now:
//
// - Each row carries a MAC with `session-mac`, under a label of its own, over
//   every column, made in the app as the row is written. The write stays one
//   INSERT, with no lock beyond its own rows: a flood of refusals from many
//   addresses never queues on a shared head, as a chain written row by row
//   would make it (an attacker spraying sign-ins could then slow everyone's).
// - Each closed UTC day of rows is digested and the digest sealed on an audit
//   chain after the fact (the activity log's daily seal, reused: its digest,
//   its days by UUIDv7 ID, its grace and its steps): the global table's days on
//   the platform chain, an organisation's on its own chain. Only a day holding
//   rows is sealed: most organisations have none most days, and a day emptied
//   after its seal shows by its digest, one with rows slipped in between two
//   seals by the check between them.
// - When a day is sealed, a row whose MAC doesn't hold (planted, or edited
//   before the seal) raises the integrity alarm, then the day is sealed as it
//   stands, so that alarm is raised once. When a seal is checked, a row
//   deleted, edited or slipped in since shows as the day's digest no longer
//   holding, or as rows in a day between two seals that has none.
//
// What this doesn't catch: rows deleted before their day is sealed (at most a
// day and a quarter of hour after they were written), which R-15 keeps as the
// owner's residual power. Every one needs the owner login, which raises DB-3's
// alert.
//
// Rows are swept once past their retention, so a seal is checked only while
// every row of its day is well inside it (firstCheckableDay): an older seal's
// day may be part swept, which is no tampering.
import { KeyError, type KeyProvider, type Message } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type RawBuilder, sql, type Transaction } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type DayDigest, dayOfId, digestRows, idsOfDay, nextDay, sealHolds } from '../../activity/index.ts';
import type { SecurityEventsTables } from './tables.ts';

type SealTx = Transaction<SecurityEventsTables>;

/** The action a day's seal records: on the platform chain for the global table, on an organisation's own for its. */
export const SECURITY_EVENTS_SEALED = 'security_events.sealed';

/** The subject an organisation's seals are recorded about, its ID the organisation's. */
export const SECURITY_LOG_SUBJECT = 'security_log';

/** The form of the seal's lines, recorded with each seal so a later form can't be confused with this one. */
export const SECURITY_SEAL_FORM = 1;

/**
 * Rows written before 0106 have no MAC and none can be made for them. One without a MAC is believed only if its ID
 * was made before this; they are all swept within the retention period after it. Move it on if the release that
 * brings 0106 reaches a database later than this.
 */
export const MAC_REQUIRED_FROM = Date.parse('2026-12-10T00:00:00.000Z');

/** Which table: the global one (0012), or one organisation's rows of 0091. */
export type SecurityLog = { readonly orgId: string } | 'global';

/** What a row's MAC covers: every column it has. */
export interface EventFacts {
  readonly id: string;
  /** Null on the global table's rows. */
  readonly orgId: string | null;
  readonly kind: string;
  readonly reason: string;
  readonly ip: string | null;
  readonly userId: string | null;
  readonly agentId: string | null;
  readonly windowStart: Date;
  readonly count: number;
  readonly createdAt: Date;
}

/** Each table's label: a global row's MAC can never stand for an organisation's, nor either for another key's work. */
const GLOBAL_LABEL = 'agentx/security.event/v1';
const ORG_LABEL = 'agentx/security.org-event/v1';

/** An absent value apart from any present one. */
const maybe = (value: string | null): string[] => (value === null ? ['none'] : ['some', value]);

/**
 * An address in one form, however it was written: the API's text and Postgres's `inet` output of it read alike
 * (an IPv6 address compressed, its hex in lower case, by the URL parser).
 */
export const ipForm = (ip: string): string =>
  ip.includes(':') ? new URL(`http://[${ip}]/`).hostname : ip.split('.').map(Number).join('.');

const eventMessage = (facts: EventFacts): Message => [
  facts.orgId === null ? GLOBAL_LABEL : ORG_LABEL,
  facts.id.toLowerCase(),
  ...maybe(facts.orgId?.toLowerCase() ?? null),
  facts.kind,
  facts.reason,
  ...maybe(facts.ip === null ? null : ipForm(facts.ip)),
  ...maybe(facts.userId?.toLowerCase() ?? null),
  ...maybe(facts.agentId?.toLowerCase() ?? null),
  String(facts.windowStart.getTime()),
  String(facts.count),
  String(facts.createdAt.getTime()),
];

/** The row's MAC with the current `session-mac` key, as its columns keep it. */
export function eventMac(
  keys: KeyProvider,
  facts: EventFacts,
): { readonly mac: Buffer; readonly mac_key_version: number } {
  const { mac, keyVersion } = keys.mac('session-mac', eventMessage(facts));
  return { mac, mac_key_version: keyVersion };
}

/** The instant a UUIDv7 was made, in milliseconds. */
const msOfId = (id: string): number => Number.parseInt(id.replaceAll('-', '').slice(0, 12), 16);

/**
 * Whether the row's MAC holds with the version it names; a row with none only if written before MAC_REQUIRED_FROM.
 * A MAC or version made up (no such key version) holds for nothing, as a wrong one.
 */
export function eventMacHolds(
  keys: KeyProvider,
  facts: EventFacts,
  row: { readonly mac: unknown; readonly mac_key_version: unknown },
): boolean {
  const { mac, mac_key_version: version } = row;
  if (mac === null && version === null) return msOfId(facts.id) < MAC_REQUIRED_FROM;
  if (!Buffer.isBuffer(mac) || typeof version !== 'number' || !Number.isSafeInteger(version)) return false;
  try {
    return keys.verifyMac('session-mac', version, eventMessage(facts), mac);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** A time to the microsecond, in UTC, as text, so a tampered microsecond shows in the digest. */
const microText = (column: string) =>
  sql<string>`pg_catalog.to_char(${sql.ref(column)} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

/** The log's table, the condition that keeps a read to its rows, and its organisation and agent columns. */
const scopeOf = (log: SecurityLog) =>
  log === 'global'
    ? { table: sql.table('security.events'), own: sql<boolean>`true`, org: sql`null::uuid`, agent: sql`null::uuid` }
    : {
        table: sql.table('security.org_events'),
        own: sql<boolean>`org_id = ${log.orgId.toLowerCase()}::uuid`,
        org: sql`org_id`,
        agent: sql`agent_id`,
      };

/** A row as the seal reads it: its columns, and its times both as the MAC and as the digest read them. */
interface SealedRow {
  readonly id: string;
  readonly at: string;
  readonly duration_ms: number;
  readonly org_id: string | null;
  readonly kind: string;
  readonly reason: string;
  readonly ip: string | null;
  readonly user_id: string | null;
  readonly agent_id: string | null;
  readonly window_start: Date;
  readonly window_text: string;
  readonly count: number;
  readonly created_at: Date;
  readonly mac: Buffer | null;
  readonly mac_key_version: number | null;
}

/** A batch of the day's rows, by ID, after `after` when named. */
async function rowsOfDay(
  tx: SealTx,
  log: SecurityLog,
  day: string,
  after: string | undefined,
  limit: number,
): Promise<readonly SealedRow[]> {
  const { from, to } = idsOfDay(day);
  const { table, own, org, agent } = scopeOf(log);
  const past: RawBuilder<boolean> = after === undefined ? sql<boolean>`true` : sql<boolean>`id > ${after}::uuid`;
  // The row's own time is when it was written: an ID made then, within the activity log's bounds (`misdated`).
  const { rows } = await sql<SealedRow>`
    select id, ${microText('created_at')} as at, 0 as duration_ms, ${org} as org_id, kind, reason, ip, user_id,
      ${agent} as agent_id, window_start, ${microText('window_start')} as window_text, count, created_at, mac,
      mac_key_version
    from ${table}
    where ${own} and id >= ${from}::uuid and id < ${to}::uuid and ${past}
    order by id limit ${limit}
  `.execute(tx);
  return rows;
}

/** One row's line in the digest: every column, its MAC too, so a change to any shows. */
const lineOf = (row: SealedRow): readonly unknown[] => [
  row.id,
  row.at,
  row.org_id,
  row.kind,
  row.reason,
  row.ip,
  row.user_id,
  row.agent_id,
  row.window_text,
  row.count,
  row.mac === null ? null : row.mac.toString('hex'),
  row.mac_key_version,
];

const factsOf = (row: SealedRow): EventFacts => ({
  id: row.id,
  orgId: row.org_id,
  kind: row.kind,
  reason: row.reason,
  ip: row.ip,
  userId: row.user_id,
  agentId: row.agent_id,
  windowStart: row.window_start,
  count: row.count,
  createdAt: row.created_at,
});

/** A day's digest, and its first row whose MAC doesn't hold (null for none). */
export interface SecurityDayDigest extends DayDigest {
  readonly forged: string | null;
}

/** The log's digest of `day`, read `batch` rows at a time, each batch in a transaction `read` opens; each row's MAC checked. */
export async function securityDigestOfDay(
  read: <T>(work: (tx: SealTx) => Promise<T>) => Promise<T>,
  keys: KeyProvider,
  log: SecurityLog,
  day: string,
  batch: number,
): Promise<SecurityDayDigest> {
  let forged: string | null = null;
  const digest = await digestRows(
    day,
    batch,
    async (after, limit) => {
      const rows = await read((tx) => rowsOfDay(tx, log, day, after, limit));
      forged ??= rows.find((row) => !eventMacHolds(keys, factsOf(row), row))?.id ?? null;
      return rows;
    },
    lineOf,
  );
  return { ...digest, forged };
}

/** The log's day's count and last ID, read in one statement, to check a digest still stands before it is sealed. */
export async function securityCountOfDay(
  tx: SealTx,
  log: SecurityLog,
  day: string,
): Promise<{ readonly requests: number; readonly idTo: string | null }> {
  const { from, to } = idsOfDay(day);
  const { table, own } = scopeOf(log);
  // A UUID's text in lower case sorts as the UUID does; Postgres has no max() of uuid itself.
  const { rows } = await sql<{ requests: number; id_to: string | null }>`
    select pg_catalog.count(*)::int as requests, pg_catalog.max(id::text) as id_to from ${table}
    where ${own} and id >= ${from}::uuid and id < ${to}::uuid
  `.execute(tx);
  return { requests: rows[0]?.requests ?? 0, idTo: rows[0]?.id_to ?? null };
}

/** The first day from `day` on that holds a row of the log, or undefined for none: the next day to seal. */
export async function nextDayWithRows(tx: SealTx, log: SecurityLog, day: string): Promise<string | undefined> {
  const { table, own } = scopeOf(log);
  const { rows } = await sql<{ id: string }>`
    select id from ${table} where ${own} and id >= ${idsOfDay(day).from}::uuid order by id limit 1
  `.execute(tx);
  const first = rows[0];
  return first === undefined ? undefined : dayOfId(first.id);
}

/** Whether the log holds a row written in a day after `older` and before `newer`: one no seal holds. */
export async function rowsBetween(tx: SealTx, log: SecurityLog, older: string, newer: string): Promise<boolean> {
  const { table, own } = scopeOf(log);
  const { rows } = await sql`
    select id from ${table}
    where ${own} and id >= ${idsOfDay(nextDay(older)).from}::uuid and id < ${idsOfDay(newer).from}::uuid limit 1
  `.execute(tx);
  return rows.length > 0;
}

/**
 * The first day whose every row is well inside the retention at `now`: the sweep takes a row once its time written is
 * `retentionDays` old, and a day's rows were written within it, so the day after the one the sweep is in, and one
 * more for clocks. Older days are never sealed, nor their seals checked.
 */
export const firstCheckableDay = (now: Date, retentionDays: number): string =>
  nextDay(nextDay(new Date(now.getTime() - retentionDays * DAY_MS).toISOString().slice(0, 10)));

/** Why a seal doesn't hold: its day's digest, or rows in a day between it and the next newer seal, which none holds. */
export type SecuritySealBroken = 'digest' | 'unsealed_day';

/**
 * Checks a page of the log's seals, newest first (each its details), until the first whose day is older than
 * `checkableFrom`: each day digested again and held to its seal, and no row in a day between two seals. Why the first
 * that doesn't hold doesn't, or undefined.
 */
export async function brokenSecuritySeal(
  seals: readonly Readonly<Record<string, unknown>>[],
  {
    digest,
    between,
    checkableFrom,
  }: {
    readonly digest: (day: string) => Promise<DayDigest>;
    readonly between: (older: string, newer: string) => Promise<boolean>;
    readonly checkableFrom: string;
  },
): Promise<{ readonly day: string; readonly why: SecuritySealBroken } | undefined> {
  let newerDay: string | undefined;
  for (const details of seals) {
    const { day } = details;
    if (typeof day !== 'string') return { day: 'unnamed', why: 'digest' };
    // This seal's day, and every older one's, may be part swept by now.
    if (day < checkableFrom) return undefined;
    if (!sealHolds(await digest(day), details, SECURITY_SEAL_FORM)) return { day, why: 'digest' };
    if (newerDay !== undefined && nextDay(day) !== newerDay && (await between(day, newerDay)))
      return { day: nextDay(day), why: 'unsealed_day' };
    newerDay = day;
  }
  return undefined;
}

/** Why the log's seal can't be believed: a seal or record, a row's MAC, a row misdated, or a seal broken. */
type SecurityLogBroken = 'unsealed' | 'mac' | 'misdated' | SecuritySealBroken;

/**
 * Raises the integrity alarm for the log (`check: 'security_event'`), naming the day and the row where one is known.
 * No hold: these rows grant nothing, and holding an organisation over them would hand the owner a way to stop it.
 */
export function securityLogAlarm(
  logger: Logger,
  log: SecurityLog,
  reason: SecurityLogBroken,
  day: string | null,
  rowId?: string,
): void {
  // An organisation is named as every line names one: the logger's own field.
  (log === 'global' ? logger : logger.child({ orgId: log.orgId.toLowerCase() })).error('audit.integrity_failed', {
    chain: log === 'global' ? 'platform' : 'organisation',
    check: 'security_event',
    subjectType: SECURITY_LOG_SUBJECT,
    reason,
    day,
    ...(rowId === undefined ? {} : { rowId }),
  });
}
