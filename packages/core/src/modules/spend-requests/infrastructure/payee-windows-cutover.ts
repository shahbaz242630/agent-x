// An organisation made before GM-1b moved to signed payee windows (0112;
// R-15), once, in one transaction: every window its spend requests then held
// capacity in, in an hour a split window can still count, opened as a signed
// window (`payee_window.opened`), counted from the requests' signed states and
// their decisions' sealed instants, never from the reservations (the rows the
// owner could have cut); then its cutover event (`payee_windows.cutover`),
// after which a payee with no window holds nothing. Until it runs, every
// decision in it is refused busy (weighed-totals.ts). It runs only once the
// organisation's month totals are cut over (GM-1a), so a decision reading its
// windows cut over knows its totals are too.
//
// What a request holds is the month totals' cutover's rule (eachSignedHolding):
// waiting, approved or ready, its whole amount; handed off, as its payment
// says. A request whose decisions can't be read, or with no decision, stops
// the cutover (tampered, alarmed): nothing is opened, and the organisation
// stays busy rather than counting it as nothing. One whose decision sealed no
// month was decided before E1: no window counts it. Every request decided
// before this cutover sealed no windows (decisions are refused busy until it
// commits), so each is counted where its signed facts alone place it: its
// supplier's window, at its sealed hour. The payee-key windows count only
// requests decided since, which seal their windows (a key moved between two
// suppliers within the last 31 days is the one case a key's window misses an
// older request; its supplier's window still counts it). Where the
// reservations hold other than the requests do, the window is opened from the
// requests all the same, and the mismatch alarmed (`holding`).
import type { Transaction } from 'kysely';

import type { AuditEvent, AuditTables, SignedStates } from '../../audit/index.ts';
import {
  addToWindows,
  hourOf,
  keptFromHour,
  type LimitReservationsTables,
  monthTotalsCutOver,
  PAYEE_WINDOWS,
  payeeWindowOf,
  payeeWindowOrder,
  payeeWindowsCutOver,
  recordPayeeWindow,
  reservationsInWindows,
  sameFrom,
  WINDOWS_CUTOVER_ACTION,
  WINDOWS_CUTOVER_SUBJECT,
  type WindowsHeld,
} from '../../limit-reservations/index.ts';
import { eachSignedHolding } from './month-totals-cutover.ts';
import type { PaymentsOf } from './holdings-check.ts';
import { SPEND_REQUESTS } from './requests.ts';
import type { SpendRequestsTables } from './tables.ts';

type CutoverTransaction = Transaction<SpendRequestsTables & LimitReservationsTables & AuditTables>;

const OPENER = { type: 'system', id: 'api' } as const;

/**
 * What a windows' cutover did: cut over, with how many windows it opened; already cut over; not yet, its month totals
 * not cut over first; or not, something tampered with (alarmed).
 */
export type WindowsCutoverDone =
  | { readonly outcome: 'cut_over'; readonly opened: number; readonly mismatched: number }
  | { readonly outcome: 'already' | 'not_yet' | 'tampered' };

const ALREADY = Object.freeze({ outcome: 'already' as const });
const NOT_YET = Object.freeze({ outcome: 'not_yet' as const });
const TAMPERED = Object.freeze({ outcome: 'tampered' as const });
/** The windows already counted, or their log not believed: nothing to cut over. */
const STOPPED_BY = { cut_over: ALREADY, tampered: TAMPERED } as const;
/** The month totals not cut over yet, or their log not believed: the windows wait for them. */
const WAITING_ON = { not_yet: NOT_YET, tampered: TAMPERED } as const;

/**
 * The organisation cut over to signed payee windows, in the caller's transaction (withSignedStates' for it), at `at`;
 * `record` adds the cutover's own event to the organisation's chain (an audit trail's record, last).
 */
export async function cutOverPayeeWindows<Tx extends CutoverTransaction>(
  tx: Tx,
  states: SignedStates,
  orgId: string,
  {
    payments,
    record,
    at,
  }: { readonly payments: PaymentsOf<Tx>; readonly record: (event: AuditEvent) => Promise<unknown>; readonly at: Date },
): Promise<WindowsCutoverDone> {
  const now = await payeeWindowsCutOver(tx, states, orgId);
  if (now !== 'not_yet') return STOPPED_BY[now];
  const months = await monthTotalsCutOver(tx, states, orgId);
  if (months !== 'cut_over') return WAITING_ON[months];
  const keptFrom = keptFromHour(at);
  const signed: WindowsHeld = new Map();
  const sealedAhead: string[] = [];
  const read = await eachSignedHolding(tx, states, orgId, payments, (request, decision) => {
    // One sealing windows was decided by GM-1b's code, which refuses an organisation not cut over: past the app.
    if (decision.windows !== null) {
      states.mismatch(SPEND_REQUESTS.subject, { orgId, id: request.id });
      sealedAhead.push(request.id);
    }
    const hour = hourOf(decision.reservedAt);
    if (hour < keptFrom) return;
    const keys = [{ supplierId: request.supplierId, payeeKey: null, currency: request.amount.currency }];
    addToWindows(signed, orgId, keys, hour, request.amount.minor);
  });
  if (read === 'tampered' || sealedAhead.length > 0) return TAMPERED;
  const reserved = await reservationsInWindows(tx, orgId, keptFrom);
  const apart = [...new Set([...signed.keys(), ...reserved.keys()])].filter(
    (id) => !sameFrom(signed.get(id)?.held ?? new Map(), reserved.get(id)?.held ?? new Map(), keptFrom),
  );
  for (const id of apart) states.mismatch(PAYEE_WINDOWS.subject, { orgId, id });
  // Each read for change first, in order of ID, every one before any is opened: a window found before the cutover
  // (planted past the app, its read raising the alarm) opens none of them.
  const opening = [...signed.entries()].toSorted(([a], [b]) => payeeWindowOrder(a, b));
  for (const [id] of opening) {
    if ((await payeeWindowOf(tx, states, orgId, id, 'change')).outcome !== 'none') return TAMPERED;
  }
  for (const [, { key, held }] of opening) {
    await recordPayeeWindow(tx, states, orgId, key, { outcome: 'none' }, held, {
      at,
      change: { actor: OPENER, action: 'payee_window.opened', details: {} },
    });
  }
  await record({
    actor: OPENER,
    action: WINDOWS_CUTOVER_ACTION,
    subject: { type: WINDOWS_CUTOVER_SUBJECT, id: orgId, version: 1 },
    details: { opened: opening.length, mismatched: apart.length },
  });
  return { outcome: 'cut_over', opened: opening.length, mismatched: apart.length };
}
