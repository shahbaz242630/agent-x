// The agent's month time zone as a signed record (0054; ADR-012 §2; PL-40):
// the zone an agent's months are counted in, kept for good from its first
// decision. Every read a decision rests on goes through the audit module's
// verifiedState with the description below, on the product's authority-table
// list (packages/core/src/authority-tables.ts); the row is made once and
// sealed in the transaction that adds it (`agent_zone.kept`).
//
// A row kept before 0054 has no signed event: `sealKeptZone` seals it once,
// from the zone of the mandate its agent's first request was decided under,
// which is the zone that decision kept (lockAgentMonth's `zoneIfNew`). The
// caller (the API, at start) reads that mandate through its signed state, so
// only a zone the signed records already name is sealed, never one an owner
// planted; one that differs is a tamper sign.
import type { SignedStateTable } from '@agentx/platform/db';
import type { Transaction } from 'kysely';

import type { AuditActor, AuditTables, SignedStates, StateCheck, TamperSign } from '../../audit/index.ts';
import type { LimitReservationsTables } from './tables.ts';

/** A transaction on the agent's zone and the audit tables, opened by withSignedStates for its organisation. */
export type ZonesTransaction = Transaction<LimitReservationsTables & AuditTables>;

/** An agent's zone row, as the signed state reads, records and checks it. */
export const AGENT_ZONES = {
  table: 'limit_reservations.agent_zones',
  subject: 'agent_zone',
  fields: [
    { column: 'time_zone', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  madeOnce: true,
} as const satisfies SignedStateTable & { readonly madeOnce: true };

/** The agent's kept zone, verified; none for an agent never weighed; or tampered with (its alarm raised). */
export type ZoneCheck =
  | { readonly outcome: 'kept'; readonly zone: string }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

/**
 * The zone the agent's months are kept in, read through its signed state
 * (`share`), in the caller's transaction, which must be withSignedStates' for
 * the organisation.
 */
export async function keptZoneOf(
  tx: ZonesTransaction,
  states: SignedStates,
  { orgId, agentId }: { readonly orgId: string; readonly agentId: string },
): Promise<ZoneCheck> {
  return zoneOf(await states.verifiedState(tx, AGENT_ZONES, { orgId, id: agentId }, 'share'));
}

/** The zone a signed read of the agent's row holds. */
function zoneOf(state: StateCheck): ZoneCheck {
  if (state.outcome === 'tampered') return state;
  if (state.outcome === 'missing') return { outcome: 'none' };
  // 0040's check holds the column to a zone's name (never null), and the seal to what was written.
  return { outcome: 'kept', zone: String(state.fields.get('time_zone')) };
}

/**
 * Many agents' kept zones (keptZoneOf), by agent ID in lower case, in two
 * statements (verifiedStates): the holdings check's, which holds each sealed
 * decision's month to its agent's zone.
 */
export async function keptZonesOf(
  tx: ZonesTransaction,
  states: SignedStates,
  orgId: string,
  agentIds: readonly string[],
): Promise<ReadonlyMap<string, ZoneCheck>> {
  if (agentIds.length === 0) return new Map();
  const checks = await states.verifiedStates(tx, AGENT_ZONES, orgId, agentIds);
  return new Map([...checks].map(([id, state]) => [id, zoneOf(state)]));
}

/**
 * Adds `zone` as the agent's for good, unless it has one already: true if this
 * call added it. Unsealed until sealNewZone, which the caller runs with its
 * own signed events at the end of the same transaction, as the audit head's
 * lock comes last (ADR-006 §6); until then nothing reads it but this call's
 * caller, which knows its zone.
 */
export async function addZone(
  tx: ZonesTransaction,
  {
    orgId,
    agentId,
    zone,
    at,
  }: { readonly orgId: string; readonly agentId: string; readonly zone: string; readonly at: Date },
): Promise<boolean> {
  const added = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by sealNewZone at the end of the same transaction
    .insertInto(AGENT_ZONES.table)
    .values({ org_id: orgId, id: agentId, agent_id: agentId, time_zone: zone, created_at: at })
    .onConflict((conflict) => conflict.doNothing())
    .returning('agent_id')
    .executeTakeFirst();
  return added !== undefined;
}

/** Seals the zone addZone just added in this transaction (withSignedStates'), by whoever's decision is the agent's first. */
export async function sealNewZone(
  tx: ZonesTransaction,
  states: SignedStates,
  {
    orgId,
    agentId,
    zone,
    at,
    actor,
  }: {
    readonly orgId: string;
    readonly agentId: string;
    readonly zone: string;
    readonly at: Date;
    readonly actor: AuditActor;
  },
): Promise<void> {
  await states.record(
    tx,
    AGENT_ZONES,
    { orgId, id: agentId },
    'new',
    { time_zone: zone, created_at: at },
    { actor, action: 'agent_zone.kept', details: { agentId: agentId.toLowerCase() } },
  );
}

/** A zone kept before 0054, still unsealed: its agent, zone and when it was kept. */
export interface UnsealedZone {
  readonly agentId: string;
  readonly zone: string;
  readonly createdAt: Date;
}

/** The most unsealed zones one call lists. */
export const MOST_UNSEALED_A_CALL = 200;

/** The organisation's zones kept before 0054 and not yet sealed, by agent, at most MOST_UNSEALED_A_CALL. */
export async function unsealedZones(tx: ZonesTransaction, orgId: string): Promise<UnsealedZone[]> {
  const rows = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the rows with no signed state yet, to seal: none is decided on before sealKeptZone checks it against the signed mandate
    .selectFrom(AGENT_ZONES.table)
    .select(['agent_id', 'time_zone', 'created_at'])
    .where('org_id', '=', orgId)
    .where('state_event_id', 'is', null)
    .where('state_version', '=', 1)
    .orderBy('agent_id')
    .limit(MOST_UNSEALED_A_CALL)
    .execute();
  return rows.map((row) => ({ agentId: row.agent_id, zone: row.time_zone, createdAt: row.created_at }));
}

/**
 * Seals a zone kept before 0054 when it is `expected` (the zone of the signed
 * mandate its agent's first request was decided under): `sealed`; otherwise a
 * tamper sign, its alarm raised (`mismatched`); `gone` if another process
 * sealed it first. In the caller's transaction (withSignedStates').
 */
export async function sealKeptZone(
  tx: ZonesTransaction,
  states: SignedStates,
  orgId: string,
  unsealed: UnsealedZone,
  expected: string,
): Promise<'sealed' | 'mismatched' | 'gone'> {
  if (unsealed.zone !== expected) {
    states.mismatch(AGENT_ZONES.subject, { orgId, id: unsealed.agentId });
    return 'mismatched';
  }
  // Locked and still unsealed, or another process sealed it first.
  const still = await tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- the row still unsealed as listed, locked to seal it: record('new') below writes and seals exactly these fields
    .selectFrom(AGENT_ZONES.table)
    .select('agent_id')
    .where('org_id', '=', orgId)
    .where('agent_id', '=', unsealed.agentId)
    .where('state_event_id', 'is', null)
    .where('state_version', '=', 1)
    .where('time_zone', '=', unsealed.zone)
    .forNoKeyUpdate()
    .executeTakeFirst();
  if (still === undefined) return 'gone';
  await states.record(
    tx,
    AGENT_ZONES,
    { orgId, id: unsealed.agentId },
    'new',
    { time_zone: unsealed.zone, created_at: unsealed.createdAt },
    {
      actor: { type: 'system', id: 'api' },
      action: 'agent_zone.kept',
      details: { agentId: unsealed.agentId.toLowerCase(), sealedLater: true },
    },
  );
  return 'sealed';
}
