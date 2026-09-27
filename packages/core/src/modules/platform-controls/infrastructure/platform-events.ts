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
