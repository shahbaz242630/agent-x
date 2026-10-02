import { limitStatements } from '@agentx/platform/db';
import type { Kysely, Transaction } from 'kysely';

import type { DirectoryTables } from './tables.ts';

/**
 * A read across organisations in a transaction of its own, read committed,
 * each statement limited to 10 seconds, so a hung read gives its connection
 * back.
 */
export function readAlone<T>(
  db: Kysely<DirectoryTables>,
  read: (tx: Transaction<DirectoryTables>) => Promise<T>,
): Promise<T> {
  return db
    .transaction()
    .setIsolationLevel('read committed')
    .execute(async (tx) => {
      await limitStatements(tx);
      return read(tx);
    });
}
