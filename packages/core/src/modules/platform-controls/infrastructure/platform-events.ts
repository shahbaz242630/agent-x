// Reading the platform chain's own events by their facts (B6-2b): what a job
// that copies something onto the chain needs to know where it got to, and
// whether it has copied a thing already. Reads only, as the app role; nothing
// here is a decision about authority. The chain itself is checked by the
// anchor check (A2b): an event planted to make a copy look done, or one
// deleted, breaks it.
//
// Each fact is compared as `(details::jsonb ->> '<name>')`, its name written
// into the SQL, so a read by the facts 0082 indexes (event, person, subject,
// and `at` for the latest time) is a few index entries, however many events of
// the action the chain holds (SA2). The containment test stays beside it, so
// what matches is exactly what matched before: a string fact, equal.
import { type Kysely, type RawBuilder, sql, type Transaction } from 'kysely';

import type { PlatformControlsTables } from './tables.ts';

/** A fact's name, as the SQL may hold it written out. */
const FACT_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;

/** A fact of the details, as 0082's indexes key it; a name that couldn't be written out safely throws. */
function fact(name: string): RawBuilder<string | null> {
  if (!FACT_NAME.test(name)) throw new TypeError(`Not a fact's name: ${JSON.stringify(name)}`);
  return sql<string | null>`(details::jsonb ->> ${sql.lit(name)})`;
}

type Reader = Kysely<PlatformControlsTables> | Transaction<PlatformControlsTables>;

/** The read latestPlatformTime runs: the greatest `name` by byte order, from 0082's index for `at`. */
export const latestPlatformTimeRead = (db: Reader, action: string, name: string) =>
  db
    .selectFrom('platform_controls.audit_events')
    .select(sql<string>`${fact(name)} collate "C"`.as('latest'))
    .where('action', '=', action)
    .where(sql<boolean>`${fact(name)} is not null`)
    .orderBy(sql`${fact(name)} collate "C"`, 'desc')
    .limit(1);

/**
 * The latest time in the details' `name` among the chain's events of
 * `action`, or undefined when there are none. Every value must be a time as
 * `Date.toISOString` writes it (UTC, 24 characters), as the copier's are, so
 * that byte order is time order; the one picked that isn't a time throws.
 */
export async function latestPlatformTime(
  db: Kysely<PlatformControlsTables>,
  action: string,
  name: string,
): Promise<Date | undefined> {
  const row = await latestPlatformTimeRead(db, action, name).executeTakeFirst();
  if (row === undefined) return undefined;
  const latest = new Date(row.latest);
  if (Number.isNaN(latest.getTime()) || latest.toISOString() !== row.latest) {
    throw new TypeError(`The platform chain's latest ${name} of ${action} is not a time as toISOString writes it`);
  }
  return latest;
}

/** Events of one action whose details hold facts as asked. */
export interface PlatformEventsMatching {
  readonly action: string;
  /** Facts the details must hold, each exactly. */
  readonly facts: Readonly<Record<string, string>>;
  /** Facts each of which must be one of the values listed. */
  readonly oneOf?: Readonly<Record<string, readonly string[]>>;
  /** Facts none of which may be one of the values listed; a fact the details don't hold is none of them. */
  readonly noneOf?: Readonly<Record<string, readonly string[]>>;
}

/** The condition on an event's details that `matching` asks for. */
const matches = ({ action, facts, oneOf = {}, noneOf = {} }: PlatformEventsMatching) =>
  sql.join(
    [
      sql`action = ${action}`,
      ...Object.entries(facts).map(([name, value]) => sql`${fact(name)} = ${value}`),
      sql`details::jsonb @> ${JSON.stringify(facts)}::jsonb`,
      ...Object.entries(oneOf).map(([name, values]) => sql`${fact(name)} = any(${values}::text[])`),
      ...Object.entries(noneOf).map(
        ([name, values]) => sql`not coalesce(${fact(name)} = any(${values}::text[]), false)`,
      ),
    ],
    sql` and `,
  );

/** The read latestPlatformTimeOf runs. */
export const latestPlatformTimeOfRead = (db: Reader, name: string, kinds: readonly PlatformEventsMatching[]) =>
  db
    .selectFrom('platform_controls.audit_events')
    .select(sql<Date | null>`max(${fact(name)}::timestamptz)`.as('latest'))
    .where(
      sql<boolean>`(${sql.join(
        kinds.map((kind) => sql`(${matches(kind)})`),
        sql` or `,
      )})`,
    );

/**
 * The latest time in the details' `name` among the chain's events that match
 * any of `kinds`, or undefined when there are none (B6-3d: when a person's
 * second factor was last removed). The value must be an ISO time; one that
 * isn't throws, so a reader deciding on it fails rather than passes.
 */
export async function latestPlatformTimeOf(
  db: Kysely<PlatformControlsTables>,
  name: string,
  kinds: readonly PlatformEventsMatching[],
): Promise<Date | undefined> {
  if (kinds.length === 0) return undefined;
  const row = await latestPlatformTimeOfRead(db, name, kinds).executeTakeFirst();
  return row?.latest ?? undefined;
}

/** The read platformEventWith runs. */
export const platformEventWithRead = (db: Reader, action: string, facts: Readonly<Record<string, string>>) =>
  db
    .selectFrom('platform_controls.audit_events')
    .select('seq')
    .where(sql<boolean>`${matches({ action, facts })}`)
    .limit(1);

/** Whether the chain holds an event of `action` whose details hold every one of `facts`, read outside a transaction or in one. */
export async function platformEventWith(
  db: Reader,
  action: string,
  facts: Readonly<Record<string, string>>,
): Promise<boolean> {
  return (await platformEventWithRead(db, action, facts).executeTakeFirst()) !== undefined;
}
