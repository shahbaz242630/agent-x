// Stage G's throwaway database (4D2e design item 5, PL-62, PL-63): a restore of
// staging's server under its own name, which a load run points the API, its jobs
// app and the load jobs at, so staging's own database is never a run's target.
// Three guards share the name rule below: deploy.ts refuses any other name for
// `apps --load-run --load-database`, policy.ts refuses a deployment pointing
// elsewhere, and every Stage G job (stageg-job.ts) refuses to start unless its
// host is such a copy and the copy carries its sentinel naming itself.
//
// The sentinel is the database's comment, written by the `mark` job as the
// database's owner, only into a copy. Not a table: the API's schema guard reads
// every table of every schema (schema-guard.ts) and would take a new one for
// tampering, holding the copy's organisations; a database comment is in no
// catalogue it reads. Staging's database has none, so a job pointed at staging
// finds no sentinel and refuses, whatever its settings say.
import { commentOnDatabase, type Database, databaseComment } from '../../packages/platform/src/db/index.ts';

/** The copy's name: staging's prefix, `g-`, and an ID of exactly THROWAWAY_ID_LENGTH lower-case letters or digits. */
const THROWAWAY_PREFIX = 'psql-agentx-stg-g-';
const THROWAWAY_ID_LENGTH = 8;
const THROWAWAY_SERVER = /^psql-agentx-stg-g-([a-z0-9]{8})$/;

/** Where Azure names a server in a private network (names.bicep `databaseHost`), the copy's as staging's. */
export const POSTGRES_HOST_SUFFIX = '.postgres.database.azure.com';

/** What the deploy tool is told, in words a person can act on. */
export const THROWAWAY_NAME_RULE = `${THROWAWAY_PREFIX}<${String(THROWAWAY_ID_LENGTH)} lower-case letters or digits>`;

/** The copy's ID, or undefined for any name that isn't a throwaway copy's. */
export const throwawayIdOf = (server: string): string | undefined => THROWAWAY_SERVER.exec(server)?.[1];

/**
 * Why `server` can't be a Stage G run's database, or undefined when it can.
 * Staging's own server can never fit: names.bicep names it
 * `psql-agentx-stg-<suffix>`, its suffix six letters or digits with no `g-`.
 */
export function throwawayServerProblem(server: string): string | undefined {
  return throwawayIdOf(server) === undefined
    ? `${server} isn't a throwaway copy's name: Stage G's database is named ${THROWAWAY_NAME_RULE}.`
    : undefined;
}

export const throwawayHost = (server: string): string => `${server}${POSTGRES_HOST_SUFFIX}`;

/** The copy's server named by a host, or undefined for a host that isn't a throwaway copy's. */
export function throwawayServerOfHost(host: string): string | undefined {
  if (!host.endsWith(POSTGRES_HOST_SUFFIX)) return undefined;
  const server = host.slice(0, -POSTGRES_HOST_SUFFIX.length);
  return throwawayIdOf(server) === undefined ? undefined : server;
}

/**
 * The container the copy's audit anchors go to (apps.bicep): its own, in the
 * write-once store, never staging's `audit-anchors`. The copy holds staging's
 * organisations, so its chains written beside staging's would read to staging
 * as wound back: a false tamper alarm there.
 */
export const throwawayAnchorsContainer = (id: string): string => `audit-anchors-g-${id}`;

/** The database comment that marks a copy: it names the server, so a copy can't vouch for another. */
export const sentinelOf = (server: string): string => `agentx-stage-g-throwaway ${server}`;

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
