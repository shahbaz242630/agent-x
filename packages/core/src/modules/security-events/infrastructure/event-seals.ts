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
//   A row with no MAC is never believed: those from before 0105 were given
//   theirs at the first start on it (legacy-seal.ts). The admins' page shows
//   only rows whose MAC holds and whose ID agrees with when they were written.
// - Each closed UTC day of rows is digested and the digest sealed on an audit
//   chain after the fact (the activity log's daily seal, reused: its days by
//   UUIDv7 ID, its grace and its steps): the global table's days on the
//   platform chain, an organisation's on its own chain. Only a day holding
//   rows is sealed: most organisations have none most days, and a day emptied
//   after its seal shows by its digest, one with rows slipped in between two
//   seals by the check between them.
// - A row whose ID was made far from when it says it was written (`misdated`:
//   the activity log's bounds) is left out of its day's digest and count, its
//   alarm raised as the day is sealed, so one such row never stops the seal.
//   Which rows are left out follows from each row alone, so none can be left
//   out to hide another: a sealed row edited into one changes the digest.
// - A row the seal can never reach (its ID before the days still checked, or
//   after tomorrow, while it says it was written recently) raises the alarm
//   on the next run (outOfRange).
// - When a day is sealed, a row whose MAC doesn't hold (planted, or edited
//   before the seal) raises the integrity alarm, then the day is sealed as it
//   stands, so that alarm is raised once. When a seal is checked, a row
//   deleted, edited or slipped in since shows as the day's digest no longer
//   holding, or as rows in a day between two seals that has none.
//
// The rows from before 0105 (`before_macs`) are given their MACs by a pass of
// their own (legacy-seal.ts), at the first start, in the background, so it may
// end before or after a day of them is sealed, or part way through it (staging,
// 20 Nov 2026: days sealed first, their rows given MACs after, each seal then
// failing its digest). So a marked row's line in the digest never holds its
// MAC (form 2): the seal is the same whenever the pass ran, and the MAC is
// still checked on its own each time the day is digested. A marked row with no
// MAC raises no alarm only if written before the time LegacyRows names
// (legacyExcused): while the pass hasn't ended, before the moment it began
// (`sealing_started`'s `until`), or now if it hasn't begun; once it has ended,
// before its scope began, the rows it left to the sweep. Any other is the
// alarm: a row the owner marks and strips today is caught, never waited for,
// and a pass held up (its lock taken) is its job's own alarm.
//
// So the mark is no longer quite nothing, as 0105's header says it is (a
// migration can't change): a marked row with no MAC, written early enough, is
// excused the alarm, though never believed, shown or counted. The bounds above
// keep the excuse to rows from before 0105.
//
// Rows deleted before their day is sealed are not in any digest; each run
// logs the count of every day not yet sealed (tallyFrom), and an alert holds
// the count sealed to the highest logged, off the database (R-15's residual).
//
// Rows are swept once past their retention, so a seal is checked only while
// every row of its day is well inside it (firstCheckableDay): an older seal's
// day may be part swept, which is no tampering.
import { createHash } from 'node:crypto';

import { KeyError, type KeyProvider, type Message } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type RawBuilder, sql, type Transaction } from 'kysely';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { type DayDigest, dayOfId, idsOfDay, nextDay, sealHolds, v7Floor } from '../../activity/index.ts';
import type { SecurityEventsTables } from './tables.ts';

type SealTx = Transaction<SecurityEventsTables>;

const HOUR_MS = 60 * 60_000;

/** The action a day's seal records: on the platform chain for the global table, on an organisation's own for its. */
export const SECURITY_EVENTS_SEALED = 'security_events.sealed';

/** The subject an organisation's seals are recorded about, its ID the organisation's. */
export const SECURITY_LOG_SUBJECT = 'security_log';

/**
 * The form of the seal's lines, recorded with each seal so a later form can't be confused with this one. 2: a row from
 * before 0105 is digested without its MAC. Form 1, the first (staging's alone), is still checked: securitySealHolds.
 */
export const SECURITY_SEAL_FORM = 2;

/**
 * What the pass giving the rows from before 0105 their MACs (legacy-seal.ts) says of a marked row with no MAC, read
 * from its records on the platform chain, each MAC-checked (legacyRowsAt): one written before `excusedBefore` raises no
 * alarm; any other does. Null excuses none: a record that can't be believed, or a pass past its cutoff with no end.
 */
export interface LegacyRows {
  readonly excusedBefore: Date | null;
}

/** Whether a row from before 0105 with no MAC is excused the alarm (LegacyRows): any other row whose MAC fails isn't. */
export const legacyExcused = (
  row: { readonly before_macs: boolean; readonly mac: unknown; readonly created_at: Date },
  legacy: LegacyRows,
): boolean =>
  row.before_macs && row.mac === null && legacy.excusedBefore !== null && row.created_at < legacy.excusedBefore;

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

/** What a row's MAC is made over: its table's label, then every column. */
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

/** A row's MAC with the current `session-mac` key, as its columns keep it. */
export function rowMac(
  keys: KeyProvider,
  message: Message,
): { readonly mac: Buffer; readonly mac_key_version: number } {
  const { mac, keyVersion } = keys.mac('session-mac', message);
  return { mac, mac_key_version: keyVersion };
}

/** The row's MAC, made over every column. */
export const eventMac = (keys: KeyProvider, facts: EventFacts) => rowMac(keys, eventMessage(facts));

/** What a kept refused message's MAC covers (0063's columns): its body is the AEAD's, bound to its ID already. */
export interface EvidenceFacts {
  readonly id: string;
  readonly reason: string;
  readonly ip: string | null;
  readonly body_key_version: number;
  readonly body_bytes: number;
  readonly received_at: Date;
}

/** A kept refused message's MAC's message, under its own label: no other row's MAC can stand for it. */
export const evidenceMessage = (facts: EvidenceFacts): Message => [
  'agentx/security.partner-event-evidence/v1',
  facts.id.toLowerCase(),
  facts.reason,
  ...maybe(facts.ip === null ? null : ipForm(facts.ip)),
  String(facts.body_key_version),
  String(facts.body_bytes),
  String(facts.received_at.getTime()),
];

/**
 * Whether a security row's MAC holds for the message, with the version it names. A row with none never does: the rows
 * from before 0105 were each given theirs at the first start on it (legacy-seal.ts). A MAC or version made up (no such
 * key version) holds for nothing.
 */
export function rowMacHolds(
  keys: KeyProvider,
  message: Message,
  row: { readonly mac: unknown; readonly mac_key_version: unknown },
): boolean {
  const { mac, mac_key_version: version } = row;
  if (!Buffer.isBuffer(mac) || typeof version !== 'number' || !Number.isSafeInteger(version)) return false;
  try {
    return keys.verifyMac('session-mac', version, message, mac);
  } catch (error) {
    if (error instanceof KeyError) return false;
    throw error;
  }
}

/** Whether the event row's MAC holds (rowMacHolds). */
export const eventMacHolds = (
  keys: KeyProvider,
  facts: EventFacts,
  row: { readonly mac: unknown; readonly mac_key_version: unknown },
): boolean => rowMacHolds(keys, eventMessage(facts), row);

/** A time to the microsecond, in UTC, as text, so a tampered microsecond shows in the digest. */
const microText = (column: string) =>
  sql<string>`pg_catalog.to_char(${sql.ref(column)} at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;

/** A row's ID's time, in ms, as Postgres reads its UUIDv7 bits. */
const ID_MS = sql<string>`('x' || pg_catalog.substr(pg_catalog.replace(id::text, '-', ''), 1, 12))::bit(48)::bigint`;

/** When it says it was written, in ms. */
const WRITTEN_MS = sql<string>`(pg_catalog.date_part('epoch', created_at) * 1000)::bigint`;

/**
 * Whether the row's ID was made when it says it was written: from 5 seconds before to 6 hours after, the activity
 * log's bounds (a server clock stepped back makes IDs late until it catches up). Any other is `misdated`.
 */
export const DATED = sql<boolean>`(${ID_MS} between ${WRITTEN_MS} - 5000 and ${WRITTEN_MS} + 21600000)`;

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

/** A row as the seal reads it: its columns, its times as the MAC and as the digest read them, and whether it is dated. */
interface SealedRow {
  readonly id: string;
  readonly at: string;
  readonly dated: boolean;
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
  readonly before_macs: boolean;
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
  const { rows } = await sql<SealedRow>`
    select id, ${microText('created_at')} as at, ${DATED} as dated, ${org} as org_id, kind, reason, ip, user_id,
      ${agent} as agent_id, window_start, ${microText('window_start')} as window_text, count, created_at, mac,
      mac_key_version, before_macs
    from ${table}
    where ${own} and id >= ${from}::uuid and id < ${to}::uuid and ${past}
    order by id limit ${limit}
  `.execute(tx);
  return rows;
}

/**
 * One row's line in the digest: every column, its MAC too, so a change to any shows; but as `form` 2 has it, a row from
 * before 0105 as if it had none (its MAC given whenever the pass ran: the header). Form 1 took each MAC as it stood.
 */
const lineOf = (row: SealedRow, form: 1 | 2): readonly unknown[] => {
  const macShown = form === 1 || !row.before_macs;
  return [
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
    macShown && row.mac !== null ? row.mac.toString('hex') : null,
    macShown ? row.mac_key_version : null,
  ];
};

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

/** A day's digest as form 1 had it, beside the current form's: what a seal of either is held to. */
export interface BothForms extends DayDigest {
  readonly formOne: string;
}

/**
 * A day's digest of its dated rows (its `misdated` always null: they are left out), in both forms; its first row whose
 * MAC doesn't hold and isn't excused, and its first left out.
 */
export interface SecurityDayDigest extends BothForms {
  readonly forged: string | null;
  readonly leftOut: string | null;
}

/**
 * The log's digest of `day`: SHA-256 over one line a dated row, by ID, each the JSON of lineOf and a newline (in each
 * form), read `batch` rows at a time, each batch in a transaction `read` opens; each row's MAC checked as it passes, a
 * row from before 0105 with none excused by `legacy`.
 */
export async function securityDigestOfDay(
  read: <T>(work: (tx: SealTx) => Promise<T>) => Promise<T>,
  keys: KeyProvider,
  log: SecurityLog,
  day: string,
  { batch, legacy }: { readonly batch: number; readonly legacy: LegacyRows },
): Promise<SecurityDayDigest> {
  const hash = createHash('sha256');
  const formOne = createHash('sha256');
  let requests = 0;
  let idFrom: string | null = null;
  let idTo: string | null = null;
  let forged: string | null = null;
  let leftOut: string | null = null;
  let after: string | undefined;
  for (;;) {
    const rows = await read((tx) => rowsOfDay(tx, log, day, after, batch));
    for (const row of rows) {
      if (!row.dated) {
        leftOut ??= row.id;
        continue;
      }
      hash.update(`${JSON.stringify(lineOf(row, 2))}\n`);
      formOne.update(`${JSON.stringify(lineOf(row, 1))}\n`);
      requests += 1;
      idFrom ??= row.id;
      idTo = row.id;
      if (forged === null && !eventMacHolds(keys, factsOf(row), row) && !legacyExcused(row, legacy)) forged = row.id;
    }
    after = rows.at(-1)?.id ?? after;
    if (rows.length < batch) break;
  }
  const digest = hash.digest('hex');
  return { day, requests, digest, formOne: formOne.digest('hex'), idFrom, idTo, misdated: null, forged, leftOut };
}

/** The log's day's count of dated rows and their last ID, in one statement, to check a digest still stands before it is sealed. */
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
    where ${own} and id >= ${from}::uuid and id < ${to}::uuid and ${DATED}
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
 * Whether the organisation has a row, or a seal on its chain (one deleted past the app fails the chain's own check):
 * one with neither has nothing to seal, check or tally. One statement in its transaction.
 */
export async function anythingToSeal(tx: SealTx, orgId: string): Promise<boolean> {
  const org = orgId.toLowerCase();
  const { rows } = await sql<{ found: boolean }>`
    select exists (select 1 from security.org_events where org_id = ${org}::uuid)
      or exists (select 1 from audit.events where org_id = ${org}::uuid and action = ${SECURITY_EVENTS_SEALED}) as found
  `.execute(tx);
  return rows[0]?.found === true;
}

/** A day not yet sealed, as the tally logs it: its dated rows' count and last ID. */
export interface DayTally {
  readonly day: string;
  readonly rows: number;
  readonly idTo: string;
}

/** The dated rows of each day from `day` on, by day (one statement, on the ID's index): what the tally line logs. */
export async function tallyFrom(tx: SealTx, log: SecurityLog, day: string): Promise<readonly DayTally[]> {
  const { table, own } = scopeOf(log);
  const { rows } = await sql<{ day: string; rows: number; id_to: string }>`
    select pg_catalog.to_char(pg_catalog.to_timestamp(${ID_MS} / 1000.0) at time zone 'UTC', 'YYYY-MM-DD') as day,
      pg_catalog.count(*)::int as rows, pg_catalog.max(id::text) as id_to
    from ${table}
    where ${own} and id >= ${idsOfDay(day).from}::uuid and ${DATED}
    group by 1 order by 1
  `.execute(tx);
  return rows.map((row) => ({ day: row.day, rows: row.rows, idTo: row.id_to }));
}

/**
 * The first row the seal can never reach though it says it was written recently, or undefined: its ID after
 * tomorrow, or before `checkableFrom` (the first day sealed or checked) while it says it was written or counted
 * well after that day began. An honest row's ID is made within moments of its time written, never so far off.
 * One statement, on the ID's index.
 */
export async function outOfRange(
  tx: SealTx,
  log: SecurityLog,
  now: Date,
  checkableFrom: string,
): Promise<string | undefined> {
  const { table, own } = scopeOf(log);
  const floor = idsOfDay(checkableFrom).from;
  const recent = new Date(Date.parse(`${checkableFrom}T00:00:00.000Z`) + HOUR_MS);
  const { rows } = await sql<{ id: string }>`
    select id from ${table}
    where ${own} and (
      id >= ${v7Floor(now.getTime() + DAY_MS)}::uuid
      or (id < ${floor}::uuid and (created_at >= ${recent} or window_start >= ${recent}))
    )
    order by id limit 1
  `.execute(tx);
  return rows[0]?.id;
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
 * Whether the seal holds the day as digested now: as form 2, or as form 1 either way, the rows from before 0105 with
 * their MACs or without, as its seals (staging's first, 20 Nov 2026) were made before or after the pass gave them; the
 * MACs are checked on their own. TODO(S206 AT10-style): form 1 goes with legacy-seal.ts, its seals all past the
 * retention.
 */
const securitySealHolds = (now: BothForms, details: Readonly<Record<string, unknown>>): boolean =>
  sealHolds(now, details, SECURITY_SEAL_FORM) ||
  [now.digest, now.formOne].some((digest) => sealHolds({ ...now, digest }, details, 1));

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
    readonly digest: (day: string) => Promise<BothForms>;
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
    if (!securitySealHolds(await digest(day), details)) return { day, why: 'digest' };
    if (newerDay !== undefined && nextDay(day) !== newerDay && (await between(day, newerDay)))
      return { day: nextDay(day), why: 'unsealed_day' };
    newerDay = day;
  }
  return undefined;
}

/** Why the log can't be believed: a seal or record, a row's MAC, a row misdated or out of the seal's reach, or a seal broken. */
type SecurityLogBroken = 'unsealed' | 'mac' | 'misdated' | 'out_of_range' | SecuritySealBroken;

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
