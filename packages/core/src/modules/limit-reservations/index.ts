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
  sealNewZone,
  type ZoneCheck,
  zoneInForce,
} from './infrastructure/agent-zones.ts';
export {
  checkMonthTotals,
  CUTOVER_ACTION,
  CUTOVER_SUBJECT,
  type CutOver,
  givenBack,
  MONTH_TOTALS,
  type MonthTotalCheck,
  monthTotalFrom,
  monthTotalGathered,
  monthTotalId,
  monthTotalKeyFrom,
  monthTotalKeyText,
  type MonthTotalKey,
  monthTotalOf,
  monthTotalOrder,
  monthTotalsCutOver,
  monthTotalToSend,
  MOST_TOTALS_CHECKED_A_PAGE,
  recordMonthTotal,
  reservationsHeldIn,
  type TotalsChecked,
  totalsMissing,
} from './infrastructure/month-totals.ts';
export { PAYEE_WINDOWS } from './infrastructure/payee-windows.ts';
export {
  agentMonth,
  agentMonthLocking,
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
  reserveStatement,
  settleReservationsOf,
  splitHeld,
  splitHeldRead,
  type SplitToSum,
} from './infrastructure/reservations.ts';
export type { LimitReservationsTables } from './infrastructure/tables.ts';
