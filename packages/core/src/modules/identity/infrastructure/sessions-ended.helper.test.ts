// When a person's sessions were last all ended, as both places keep it (R-15, S206): the column on their row, and
// the signed records on the platform chain. Every caller that ends them writes both in one transaction, with the same
// moment, so a test of a caller checks the two agree.
import type { Kysely } from 'kysely';

import type { PlatformControlsTables } from '../../platform-controls/index.ts';
import { SESSIONS_ENDED } from './sessions.ts';
import type { IdentityTables } from './tables.ts';

/** The column, and the moment of every signed end of the person's, oldest first, each as toISOString writes it. */
export async function endsKept(
  db: Kysely<IdentityTables & PlatformControlsTables>,
  userId: string,
): Promise<{ column: string | null; signed: string[] }> {
  const user = await db
    .selectFrom('identity.users')
    .select('sessions_ended_at')
    .where('id', '=', userId)
    .executeTakeFirstOrThrow();
  const events = await db
    .selectFrom('platform_controls.audit_events')
    .select('details')
    .where('action', '=', SESSIONS_ENDED)
    .orderBy('seq')
    .execute();
  const signed = events
    .map((event) => JSON.parse(event.details) as { person: string; at: string })
    .filter((details) => details.person === userId)
    .map((details) => details.at);
  return { column: user.sessions_ended_at?.toISOString() ?? null, signed };
}
