// AT13f (Threat-Model R-15): the chain's end cut off by the database's owner,
// shared by the tests of each limit table made above the last anchor (a
// month's total, a payee's window). The owner, holding none of the app's
// keys, deletes every event since a saved head and every row those events
// made, then puts that earlier, genuinely sealed head back: every seal left
// is true and no event is missing between the anchor and the head, so only a
// head seen earlier (the digest the anchor process keeps) can tell.
import { checkStatesWith } from '@agentx/core/modules/audit';
import { MONTH_TOTALS, PAYEE_WINDOWS } from '@agentx/core/modules/limit-reservations';
import { SPEND_REQUESTS } from '@agentx/core/modules/spend-requests';
import { createDigestLog, type DigestLog } from '@agentx/platform/audit-chain';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import { type SavedHead, tamperAsOwner, type TestDatabase } from '@agentx/testing';

/** The user triggers that refuse the cut's deletes: off for it, back on before it commits. One statement each way. */
const GUARDS_OFF = `do $$ begin
  alter table audit.events disable trigger user;
  alter table limit_reservations.reservations disable trigger user;
  alter table limit_reservations.agent_periods disable trigger user;
  alter table limit_reservations.agent_zones disable trigger user;
  alter table limit_reservations.month_totals disable trigger user;
  alter table limit_reservations.payee_windows disable trigger user;
  alter table spend_requests.requests disable trigger user;
end $$`;
const GUARDS_ON = `do $$ begin
  alter table audit.events enable trigger user;
  alter table limit_reservations.reservations enable trigger user;
  alter table limit_reservations.agent_periods enable trigger user;
  alter table limit_reservations.agent_zones enable trigger user;
  alter table limit_reservations.month_totals enable trigger user;
  alter table limit_reservations.payee_windows enable trigger user;
  alter table spend_requests.requests enable trigger user;
end $$`;

/** The organisation's chain head as it stands now, saved by the owner to wind back to later. */
export async function savedHeadOf(database: TestDatabase, orgId: string): Promise<SavedHead> {
  const owner = await tamperAsOwner(database, PAYEE_WINDOWS, orgId);
  try {
    return await owner.saveHead();
  } finally {
    await owner.end();
  }
}

/**
 * The owner cuts the chain's end since `saved` off, in one transaction: its
 * events, an earlier sealed head put back, and every row they named as if
 * never made (the month's totals, the payee's windows, the requests with their
 * reservations and order claims, the agent's time zone and its months).
 */
export async function cutChainEndBack(database: TestDatabase, orgId: string, saved: SavedHead): Promise<void> {
  const owner = await tamperAsOwner(database, PAYEE_WINDOWS, orgId);
  try {
    await owner.query('begin');
    const named = await owner.query<{ type: string; id: string }>(
      'select distinct subject_type as type, subject_id::text as id from audit.events where org_id = $1 and seq > $2::bigint',
      [orgId, saved.seq],
    );
    const of = (type: string) => named.filter((one) => one.type === type).map((one) => one.id);
    await owner.query(GUARDS_OFF);
    await owner.query('delete from limit_reservations.month_totals where org_id = $1 and id = any($2::uuid[])', [
      orgId,
      of(MONTH_TOTALS.subject),
    ]);
    await owner.query('delete from limit_reservations.payee_windows where org_id = $1 and id = any($2::uuid[])', [
      orgId,
      of(PAYEE_WINDOWS.subject),
    ]);
    const requests = of(SPEND_REQUESTS.subject);
    await owner.query(
      'delete from limit_reservations.reservations where org_id = $1 and request_id = any($2::uuid[])',
      [orgId, requests],
    );
    await owner.query('delete from spend_requests.order_claims where org_id = $1 and request_id = any($2::uuid[])', [
      orgId,
      requests,
    ]);
    await owner.query('delete from spend_requests.requests where org_id = $1 and id = any($2::uuid[])', [
      orgId,
      requests,
    ]);
    // The agent's time zone, made with its first reservation, and the months locked under it.
    const zones = of('agent_zone');
    await owner.query('delete from limit_reservations.agent_periods where org_id = $1 and agent_id = any($2::uuid[])', [
      orgId,
      zones,
    ]);
    await owner.query('delete from limit_reservations.agent_zones where org_id = $1 and id = any($2::uuid[])', [
      orgId,
      zones,
    ]);
    await owner.windBack(saved);
    await owner.query(GUARDS_ON);
    await owner.query('commit');
  } finally {
    await owner.end();
  }
}

/**
 * Runs `work` with every signed state read held to a digest kept as the
 * process that keeps the anchors keeps one: the heads it has seen.
 */
export async function withDigest<T>(
  { keys, logger, now }: { readonly keys: KeyProvider; readonly logger: Logger; readonly now: () => Date },
  work: (digest: DigestLog) => Promise<T>,
): Promise<T> {
  const digest = createDigestLog({ keys, logger, now, epoch: 1, alertAfterMs: 60_000, mostBytes: 64 * 1024 * 1024 });
  checkStatesWith(digest);
  try {
    return await work(digest);
  } finally {
    checkStatesWith(undefined);
  }
}
