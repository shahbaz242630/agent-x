// Reading the platform chain's own events by their facts (B6-2b): what a job
// that copies something onto the chain needs to know where it got to, and
// whether it has copied a thing already. Reads only, as the app role; nothing
// here is a decision about authority. The chain itself is checked by the
// anchor check (A2b): an event planted to make a copy look done, or one
// deleted, breaks it.
import { type Kysely, sql } from 'kysely';

import type { PlatformControlsTables } from './tables.ts';

/**
 * The latest time in the details' `name` among the chain's events of
 * `action`, or undefined when there are none. The value must be an ISO time.
 */
export async function latestPlatformTime(
  db: Kysely<PlatformControlsTables>,
  action: string,
  name: string,
): Promise<Date | undefined> {
  const row = await db
    .selectFrom('platform_controls.audit_events')
    .select(sql<Date | null>`max((details::jsonb ->> ${name})::timestamptz)`.as('latest'))
    .where('action', '=', action)
    .executeTakeFirst();
  return row?.latest ?? undefined;
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
      sql`details::jsonb @> ${JSON.stringify(facts)}::jsonb`,
      ...Object.entries(oneOf).map(([name, values]) => sql`(details::jsonb ->> ${name}) = any(${values}::text[])`),
      ...Object.entries(noneOf).map(
        ([name, values]) => sql`not coalesce((details::jsonb ->> ${name}) = any(${values}::text[]), false)`,
      ),
    ],
    sql` and `,
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
  const row = await db
    .selectFrom('platform_controls.audit_events')
    .select(sql<Date | null>`max((details::jsonb ->> ${name})::timestamptz)`.as('latest'))
    .where(
      sql<boolean>`(${sql.join(
        kinds.map((kind) => sql`(${matches(kind)})`),
        sql` or `,
      )})`,
    )
    .executeTakeFirst();
  return row?.latest ?? undefined;
}

/** Whether the chain holds an event of `action` whose details hold every one of `facts`. */
export async function platformEventWith(
  db: Kysely<PlatformControlsTables>,
  action: string,
  facts: Readonly<Record<string, string>>,
): Promise<boolean> {
  const row = await db
    .selectFrom('platform_controls.audit_events')
    .select('seq')
    .where('action', '=', action)
    .where(sql<boolean>`details::jsonb @> ${JSON.stringify(facts)}::jsonb`)
    .limit(1)
    .executeTakeFirst();
  return row !== undefined;
}
