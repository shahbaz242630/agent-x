// The throwaway copy's sentinel, read and written on the connected database:
// apart from throwaway.ts because it needs the database package, which CI's
// release job (loading throwaway.ts through deploy.ts) doesn't install.
import { commentOnDatabase, type Database, databaseComment } from '../../packages/platform/src/db/index.ts';

import { sentinelOf } from './throwaway.ts';

/**
 * Why the connected database isn't the throwaway copy `server`, or undefined
 * when its sentinel names it. A database with no sentinel, staging's among
 * them, or one naming another copy, is refused.
 */
export async function sentinelProblem<T>(db: Database<T>, server: string): Promise<string | undefined> {
  const comment = await databaseComment(db);
  if (comment === sentinelOf(server)) return undefined;
  return !comment?.startsWith(sentinelOf(''))
    ? `The database at ${server} carries no Stage G sentinel, so it may be staging's own: nothing was changed. Run the load-mark job on the copy first.`
    : `The database at ${server} is marked as another copy (${comment}), so it isn't the one named: nothing was changed.`;
}

/**
 * Marks the connected database as the throwaway copy `server`, as its owner,
 * then reads the mark back. Only ever on a host the name rule allows: the caller
 * (stageg-job.ts `mark`) refuses any other before connecting.
 */
export async function markThrowaway<T>(db: Database<T>, server: string): Promise<string | undefined> {
  await commentOnDatabase(db, sentinelOf(server));
  return sentinelProblem(db, server);
}
