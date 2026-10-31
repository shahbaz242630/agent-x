// The limit-reservations module (ADR-004, ADR-006 §6–§10; Phase 2 D2, D4): the
// agent's time zone and monthly periods every monthly check locks, and the
// reservations that are the monthly and split totals; a decision locks the
// agent's month, reads its total and reserves through them (D4).
export { RESERVATION, type ReservationState } from './domain/reservation.ts';
export {
  addZone,
  AGENT_ZONES,
  keptZoneOf,
  keptZonesOf,
  MOST_UNSEALED_A_CALL,
  sealKeptZone,
  sealNewZone,
  type UnsealedZone,
  unsealedZones,
  type ZoneCheck,
} from './infrastructure/agent-zones.ts';
export {
  agentMonth,
  type LockedMonth,
  lockAgentMonth,
  lockAgentPeriod,
  lockReservationsOf,
  monthSpentRead,
  type MonthToSum,
  monthsSpent,
  type NewReservation,
  releaseReservationsOf,
  reservationsFor,
  type ReservationSeen,
  type ReservationSettlement,
  reserve,
  reserveStatement,
  settleReservationsOf,
  splitHeld,
  splitHeldRead,
  type SplitToSum,
} from './infrastructure/reservations.ts';
export type { LimitReservationsTables } from './infrastructure/tables.ts';
