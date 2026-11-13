// SA3e (0090): the next of Zitadel's 16-bit machine IDs, in turn from the database's
// sequence, so every Zitadel copy that starts takes one no live copy holds (until
// 65,536 starts later). nextval is never rolled back, so a number is never handed out
// twice, even when the answer carrying it is lost.
import { limitedTransaction } from '@agentx/platform/db';
import { type Kysely, sql } from 'kysely';

import type { PlatformControlsTables } from './tables.ts';

/** The next machine ID, 0 to 65535, the sequence cycling past the top; the caller checks it is one. */
export async function nextMachineId(database: Kysely<PlatformControlsTables>): Promise<number | undefined> {
  const { rows } = await limitedTransaction(database, (tx) =>
    sql<{ id: number }>`SELECT pg_catalog.nextval('platform_controls.zitadel_machine_ids')::integer AS id`.execute(tx),
  );
  return rows.map((row) => row.id)[0];
}
