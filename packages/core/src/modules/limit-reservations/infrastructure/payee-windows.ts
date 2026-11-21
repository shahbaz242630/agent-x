// A payee's split window as signed hourly totals (0112; GM-1b, R-15;
// ADR-006 §8 and §9; ADR-014 §5; ADR-012 §2): what its reservations hold, hour
// by hour, as far back as any split window reaches, read and changed through
// its signed state in the same transactions that reserve and release, so the
// database's owner can't take a payment past its approval by deleting, zeroing
// or releasing the payee's reservations. On the product's authority-table list
// (packages/core/src/authority-tables.ts), at level 11b: after a request (8),
// its reservation (11) and its agent's month total (11a), before the audit
// head (12). A holder of several takes them in order of ID.
//
// The split check counts a payee as its supplier, or its payee key where it
// has one (ADR-014 §3): so each reservation is counted in its supplier's row
// (`payee_key` null), and, with a key, in its key's row (`supplier_id` null)
// and the pair's (both). A payee's window is its supplier's and its key's, less
// the pair's, which both count (`payeeSplit`). A decision reads its payee's rows
// for change with its month's lock, on the same trip, and its reservation adds
// to them on the reservation's trip; its decision seals the rows' IDs
// (`payeeWindows`), so an ending gives back to the rows it added to, whatever
// the unsealed reservation now says.
//
// A row's ID is named by its organisation, supplier, key and currency
// (`payeeWindowId`), so one deleted reads as deleted (its signed events are
// still in the log), never as a payee with nothing held. A payee with no row
// and nothing signed holds nothing once the organisation is counted this way
// (`payeeWindowsCutOver`): born so, or cut over by the API's job, which opens
// every window then held from the signed spend requests. Before that, every
// decision is refused busy, never weighed from the reservations.
import {
  type GatheredRow,
  MOST_ROWS_GATHERED,
  MOST_SIGNED_ROWS_READ,
  type SentTogether,
  type SignedStateTable,
} from '@agentx/platform/db';
import { sql, type Transaction } from 'kysely';

import type {
  AuditTables,
  ChangeToSend,
  SignedChange,
  SignedStates,
  StateCheck,
  TamperSign,
  VerifiedState,
} from '../../audit/index.ts';
import { HOUR_MS, MOST_WINDOW_HOURS } from '../../../shared-kernel/index.ts';
import {
  type HeldByHour,
  heldByHourFrom,
  heldByHourText,
  heldSince,
  heldTaken,
  hourOf,
  keptFromHour,
  payeeSplit,
} from '../domain/held-by-hour.ts';
import { countedSince, type CutOver, monthTotalOrder } from './month-totals.ts';
import { namedId } from './named-id.ts';
import type { LimitReservationsTables } from './tables.ts';

type WindowsTransaction = Transaction<LimitReservationsTables & AuditTables>;

/** A payee's window row, as the signed state reads, records and checks it. */
export const PAYEE_WINDOWS = {
  table: 'limit_reservations.payee_windows',
  subject: 'payee_window',
  fields: [
    { column: 'supplier_id', type: 'uuid' },
    { column: 'payee_key', type: 'text' },
    { column: 'currency', type: 'text' },
    { column: 'held_by_hour', type: 'text' },
    { column: 'created_at', type: 'timestamptz' },
  ],
  // Fixed when the window is made: 0112's `fixed_at_creation` refuses any change after.
  fixedAtCreation: ['supplier_id', 'payee_key', 'currency', 'created_at'],
} as const satisfies SignedStateTable & { readonly fixedAtCreation: readonly string[] };

/** Whose window a row is: a supplier's (any key), a key's (any supplier), or the pair's; in one currency (G4). */
export interface PayeeWindowKey {
  readonly supplierId: string | null;
  readonly payeeKey: string | null;
  readonly currency: string;
}

/** A payee as a reservation names it: its supplier, and the supplier's payee key where it has one. */
export interface Payee {
  readonly supplierId: string;
  readonly payeeKey: string | null;
  readonly currency: string;
}

/**
 * The row's ID: named by whose window it is, the same every time. The key goes in as hex, as namedId lower-cases
 * each part and two payee keys may differ only in case; `-` for none, which no UUID or hex is.
 */
export const payeeWindowId = (orgId: string, { supplierId, payeeKey, currency }: PayeeWindowKey): string =>
  namedId([
    'payee_window',
    orgId,
    supplierId ?? '-',
    payeeKey === null ? '-' : Buffer.from(payeeKey, 'utf8').toString('hex'),
    currency,
  ]);

/** The rows a payee's reservation is counted in, and its window read from: its supplier's; with a key, its key's and the pair's. */
export const payeeWindowKeys = ({ supplierId, payeeKey, currency }: Payee): readonly PayeeWindowKey[] =>
  payeeKey === null
    ? [{ supplierId, payeeKey: null, currency }]
    : [
        { supplierId, payeeKey: null, currency },
        { supplierId: null, payeeKey, currency },
        { supplierId, payeeKey, currency },
      ];

/** Several rows' IDs in the order every holder of several locks them (11b): the month totals' order alike. */
export const payeeWindowOrder = monthTotalOrder;

/**
 * A payee window, verified: what it holds, whose it is, with the state to change it from; none (no row, nothing
 * signed); or tampered with (the alarm raised).
 */
export type PayeeWindowCheck =
  | {
      readonly outcome: 'held';
      readonly held: HeldByHour;
      readonly key: PayeeWindowKey;
      readonly state: VerifiedState;
    }
  | { readonly outcome: 'none' }
  | { readonly outcome: 'tampered'; readonly sign: TamperSign };

const NONE = Object.freeze({ outcome: 'none' as const });

/** The window a signed read of its row holds. */
export function payeeWindowFrom(check: StateCheck): PayeeWindowCheck {
  if (check.outcome === 'tampered') return check;
  if (check.outcome === 'missing') return NONE;
  // The seal holds them to what the app wrote, which is always in this form (0112's checks: none of them null).
  const held = heldByHourFrom(String(check.fields.get('held_by_hour')));
  if (held === undefined) throw new Error('A verified payee window holds no hours');
  const key = {
    supplierId: check.fields.get('supplier_id') ?? null,
    payeeKey: check.fields.get('payee_key') ?? null,
    currency: String(check.fields.get('currency')),
  };
  return Object.freeze({ outcome: 'held', held, key, state: check });
}

/** A window as a row to gather, so its read rides a trip made anyway (a decision's month lock). */
export const payeeWindowGathered = (orgId: string, key: PayeeWindowKey, lock: 'share' | 'change'): GatheredRow => ({
  table: PAYEE_WINDOWS,
  id: { id: payeeWindowId(orgId, key) },
  lock,
});

/** One window by its ID, read through its signed state, locked as asked, in withSignedStates' transaction. */
export async function payeeWindowOf(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  id: string,
  lock: 'share' | 'change',
): Promise<PayeeWindowCheck> {
  return payeeWindowFrom(await states.verifiedState(tx, PAYEE_WINDOWS, { orgId, id }, lock));
}

/**
 * The windows named, each once, locked as asked in order of ID (11b), a gather a statement for at most
 * MOST_ROWS_GATHERED of them, then each verified from it (no trip): by ID in lower case.
 */
export async function payeeWindowsOf(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  ids: readonly string[],
  lock: 'share' | 'change',
): Promise<ReadonlyMap<string, PayeeWindowCheck>> {
  const ordered = [...new Set(ids.map((id) => id.toLowerCase()))].toSorted(payeeWindowOrder);
  for (let start = 0; start < ordered.length; start += MOST_ROWS_GATHERED) {
    await states.gather(
      tx,
      orgId,
      ordered.slice(start, start + MOST_ROWS_GATHERED).map((id) => ({ table: PAYEE_WINDOWS, id: { id }, lock })),
    );
  }
  const read = new Map<string, PayeeWindowCheck>();
  for (const id of ordered) read.set(id, await payeeWindowOf(tx, states, orgId, id, lock));
  return read;
}

/**
 * What a payee's window holds from `fromHour` on, from its rows as read (payeeWindowKeys' order): its supplier's and
 * its key's, less the pair's. A row with none holds nothing; a row tampered with must be refused before.
 */
export function splitHeldIn(rows: readonly PayeeWindowCheck[], fromHour: number): bigint {
  const [supplier, key, pair] = rows.map((row) => (row.outcome === 'held' ? heldSince(row.held, fromHour) : 0n));
  return payeeSplit(supplier ?? 0n, key ?? 0n, pair ?? 0n);
}

/**
 * splitHeldIn less what `takes` hold in the window (a carry's own requests, each in the windows its decision sealed,
 * at its sealed hour): each row less its own share first, then the payee's split from them. `short` where a row
 * holds less than its own share: something past the app took it.
 */
export function splitHeldLess(
  rows: readonly { readonly id: string; readonly read: PayeeWindowCheck }[],
  fromHour: number,
  takes: readonly WindowTake[],
): bigint | 'short' {
  const sums = rows.map(({ id, read }) => {
    const held = read.outcome === 'held' ? heldSince(read.held, fromHour) : 0n;
    const own = takes
      .filter((take) => take.id.toLowerCase() === id.toLowerCase() && take.hour >= fromHour)
      .reduce((sum, { amount }) => sum + amount, 0n);
    return held - own;
  });
  if (sums.some((sum) => sum < 0n)) return 'short';
  const [supplier, key, pair] = sums;
  return payeeSplit(supplier ?? 0n, key ?? 0n, pair ?? 0n);
}

/**
 * The windows' cutover naming the windows a request decided before GM-1b was opened in (its supplier's, its key's and
 * the pair's), where its reservation's payee key holds to its decision's payee seal: about the request, by its ID,
 * under a subject of its own (its own signed state's events are its state changes alone). A request with none is
 * counted in its supplier's window alone.
 */
export const WINDOWS_NAMED_SUBJECT = 'spend_request_windows';
export const WINDOWS_NAMED_ACTION = 'spend_request.windows_named';

/** The payee windows' cutover event: about the organisation, by its ID, under a subject of its own. */
export const WINDOWS_CUTOVER_SUBJECT = 'payee_windows';
export const WINDOWS_CUTOVER_ACTION = 'payee_windows.cutover';

/**
 * Whether the organisation's payees are counted in signed windows: since its birth (its `organization.created` says
 * `payeeWindows: signed`) or its cutover; not yet; or its log can't be believed. Asked only where a window is missing.
 * The job cuts an organisation's windows over only once its month totals are (GM-1a), so this cut over says that too.
 */
export const payeeWindowsCutOver = (tx: WindowsTransaction, states: SignedStates, orgId: string): Promise<CutOver> =>
  countedSince(tx, states, orgId, {
    subject: WINDOWS_CUTOVER_SUBJECT,
    action: WINDOWS_CUTOVER_ACTION,
    born: 'payeeWindows',
  });

/** The fields of a new window, as it is added and sealed. */
const newFields = (key: PayeeWindowKey, held: HeldByHour, at: Date) => ({
  supplier_id: key.supplierId,
  payee_key: key.payeeKey,
  currency: key.currency,
  held_by_hour: heldByHourText(held),
  created_at: at,
});

/** A new window's insert, not run. */
const windowInsert = (tx: WindowsTransaction, orgId: string, key: PayeeWindowKey, held: HeldByHour, at: Date) =>
  tx
    // eslint-disable-next-line agentx/authority-tables-through-signed-state -- a new row, a plain insert, signed by the record of its first state in the same transaction
    .insertInto(PAYEE_WINDOWS.table)
    .values({ org_id: orgId, id: payeeWindowId(orgId, key), ...newFields(key, held, at) });

/** A window as read for change, or none: one tampered with is refused before anything is written to it. */
export type WindowToWrite = Exclude<PayeeWindowCheck, { readonly outcome: 'tampered' }>;

/**
 * A decision's write to one of its payee's windows, on the trip that holds its reservation (no trip of its own):
 * `held`, from the window read for change with its month, or a new row for a payee with none (its insert first).
 * The signed state's recordNewAndMove records it with the request's events (`alongside`).
 */
export function payeeWindowToSend(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  key: PayeeWindowKey,
  read: WindowToWrite,
  held: HeldByHour,
  at: Date,
): { readonly statements: readonly SentTogether[]; readonly sent: ChangeToSend } {
  const id = payeeWindowId(orgId, key);
  if (read.outcome === 'held') {
    const sent = states.changeToSend(tx, PAYEE_WINDOWS, { orgId, id }, read.state, {
      held_by_hour: heldByHourText(held),
    });
    return { statements: [sent.statement], sent };
  }
  const sent = states.changeToSend(tx, PAYEE_WINDOWS, { orgId, id }, 'new', newFields(key, held, at));
  return { statements: [windowInsert(tx, orgId, key, held, at), sent.statement], sent };
}

/** A window's new hours recorded on its own (an ending's, a payment's, the cutover's), from its read for change or new. */
export async function recordPayeeWindow(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  key: PayeeWindowKey,
  read: WindowToWrite,
  held: HeldByHour,
  { at, change }: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  const id = payeeWindowId(orgId, key);
  if (read.outcome === 'held') {
    await states.record(tx, PAYEE_WINDOWS, { orgId, id }, read.state, { held_by_hour: heldByHourText(held) }, change);
    return;
  }
  await windowInsert(tx, orgId, key, held, at).execute();
  await states.record(tx, PAYEE_WINDOWS, { orgId, id }, 'new', newFields(key, held, at), change);
}

/** Capacity a request held in a window, to give back: the window, the hour its decision sealed, its amount. */
export interface WindowTake {
  readonly id: string;
  readonly requestId: string;
  readonly hour: number;
  readonly amount: bigint;
}

/**
 * Each take given back to its window, read for change in this transaction (`read`, by ID in lower case: an ending,
 * a brake's batch, a payment's verified failure), one record a window for all its takes, the requests and amount in
 * its event. An hour older than any window counts has nothing to give back. A window tampered with is left (its alarm
 * raised by its read): the request still ends, as a brake must. One missing is nothing to give back before the
 * organisation's cutover, and after it a mismatch (`holding`): its request held capacity there. An hour holding less
 * than it gives back is a mismatch too, and goes to nothing, never below.
 */
export async function windowsGivenBack(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  read: ReadonlyMap<string, PayeeWindowCheck>,
  takes: readonly WindowTake[],
  recorded: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  const keptFrom = keptFromHour(recorded.at);
  const byWindow = new Map<string, WindowTake[]>();
  for (const take of takes.filter(({ hour }) => hour >= keptFrom)) {
    const id = take.id.toLowerCase();
    byWindow.set(id, [...(byWindow.get(id) ?? []), take]);
  }
  for (const [id, taken] of [...byWindow].toSorted(([a], [b]) => payeeWindowOrder(a, b))) {
    const window = read.get(id);
    if (window === undefined) throw new Error(`A payee window given back to was not read for change: ${id}`);
    if (window.outcome === 'tampered') continue;
    if (window.outcome === 'none') {
      if ((await payeeWindowsCutOver(tx, states, orgId)) !== 'not_yet')
        states.mismatch(PAYEE_WINDOWS.subject, { orgId, id });
      continue;
    }
    const { held, short } = heldTaken(window.held, taken, keptFrom);
    if (short) states.mismatch(PAYEE_WINDOWS.subject, { orgId, id });
    const { at, change } = recorded;
    await recordPayeeWindow(tx, states, orgId, window.key, window, held, {
      at,
      change: {
        ...change,
        details: {
          ...change.details,
          requestIds: [...new Set(taken.map(({ requestId }) => requestId.toLowerCase()))].join(','),
          amountMinor: taken.reduce((sum, { amount }) => sum + amount, 0n).toString(),
        },
      },
    });
  }
}

/**
 * windowsGivenBack for one request's capacity as its caller locked it (a payment's verified failure): none, for a
 * request that can't be believed or whose decision sealed no month (decided before E1), gives nothing back.
 */
export async function heldWindowsGivenBack(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  held:
    | { readonly windowsRead: ReadonlyMap<string, PayeeWindowCheck>; readonly windows: readonly WindowTake[] }
    | null
    | undefined,
  recorded: { readonly at: Date; readonly change: SignedChange },
): Promise<void> {
  if (held === null || held === undefined) return;
  await windowsGivenBack(tx, states, orgId, held.windowsRead, held.windows, recorded);
}

/** What the reservations hold in one hour, for one supplier, key and currency, and whether their decisions sealed windows. */
interface ReservedInHour {
  readonly supplierId: string;
  readonly payeeKey: string | null;
  readonly currency: string;
  readonly hour: number;
  readonly amount: bigint;
  /** Decided since GM-1b (its decision seals `payeeWindows`): counted in every row of its payee; else its supplier's alone. */
  readonly windowed: boolean;
}

/**
 * What the reservations hold (every state but RELEASED, 0040's rule), by supplier, key, currency and the hour they
 * were reserved in, from `fromHour` on, in one statement: those of the suppliers or keys named, or every one. Unsealed:
 * only ever compared with the signed windows (the holdings check, the cutover), never weighed. A reservation whose
 * decision sealed no month (decided before E1) is left out, as no window counts it; one whose decision sealed no
 * windows (decided before GM-1b) is counted in its supplier's row alone, as the cutover opened it.
 */
async function reservedByHour(
  tx: WindowsTransaction,
  fromHour: number,
  payees: { readonly supplierIds: readonly string[]; readonly payeeKeys: readonly string[] } | 'all',
): Promise<ReservedInHour[]> {
  if (payees !== 'all' && payees.supplierIds.length === 0 && payees.payeeKeys.length === 0) return [];
  const { rows } = await sql<{
    supplier_id: string;
    payee_key: string | null;
    currency: string;
    hour: string;
    held: string;
    windowed: boolean;
  }>`
    select r.supplier_id, r.payee_key, r.currency,
      pg_catalog.floor(pg_catalog.date_part('epoch', r.reserved_at) / 3600)::bigint::text as hour,
      pg_catalog.sum(r.amount_minor)::text as held, d.windowed
    from limit_reservations.reservations r
    cross join lateral (
      -- Its request's newest decided event, the one the holdings check reads.
      -- Windowed: its decision sealed its windows, or (decided before GM-1b) the windows' cutover named them.
      select pg_catalog.strpos(e.details, '"heldMonth"') > 0 as month_sealed,
             (pg_catalog.strpos(e.details, '"payeeWindows"') > 0 or exists (
               select from audit.events n
               where n.org_id = r.org_id and n.subject_type = ${WINDOWS_NAMED_SUBJECT}
                 and n.subject_id = r.request_id and n.action = ${WINDOWS_NAMED_ACTION})) as windowed
      from audit.events e
      where e.org_id = r.org_id and e.subject_type = 'spend_request' and e.subject_id = r.request_id
        and e.action = 'spend_request.decided'
      order by e.seq desc limit 1) d
    where r.state <> 'RELEASED' and d.month_sealed
      and r.reserved_at >= pg_catalog.to_timestamp(${fromHour * (HOUR_MS / 1000)}::double precision)
      and ${
        payees === 'all'
          ? sql<boolean>`true`
          : sql<boolean>`(r.supplier_id = any(${[...payees.supplierIds]}::uuid[])
              or r.payee_key = any(${[...payees.payeeKeys]}::text[]))`
      }
    group by r.supplier_id, r.payee_key, r.currency, 4, d.windowed`.execute(tx);
  return rows.map((row) => ({
    supplierId: row.supplier_id.toLowerCase(),
    payeeKey: row.payee_key,
    currency: row.currency,
    hour: Number(row.hour),
    amount: BigInt(row.held),
    windowed: row.windowed,
  }));
}

/** What each window holds by the reservations, by its ID: whose it is, and its hours. */
export type WindowsHeld = Map<string, { readonly key: PayeeWindowKey; readonly held: Map<number, bigint> }>;

/** `amount` added at `hour` to each window named, made if not there. */
export function addToWindows(
  windows: WindowsHeld,
  orgId: string,
  keys: readonly PayeeWindowKey[],
  hour: number,
  amount: bigint,
): void {
  for (const key of keys) {
    const id = payeeWindowId(orgId, key);
    const window = windows.get(id) ?? { key, held: new Map<number, bigint>() };
    window.held.set(hour, (window.held.get(hour) ?? 0n) + amount);
    windows.set(id, window);
  }
}

/** The windows the reservations would fill: a windowed one in every row of its payee, one before in its supplier's. */
function windowsOfReserved(orgId: string, reserved: readonly ReservedInHour[]): WindowsHeld {
  const windows: WindowsHeld = new Map();
  for (const { supplierId, payeeKey, currency, hour, amount, windowed } of reserved) {
    const keys = windowed
      ? payeeWindowKeys({ supplierId, payeeKey, currency })
      : [{ supplierId, payeeKey: null, currency }];
    addToWindows(windows, orgId, keys, hour, amount);
  }
  return windows;
}

/** What the reservations hold in each of the organisation's windows, from `fromHour` on (the cutover's comparison). */
export async function reservationsInWindows(
  tx: WindowsTransaction,
  orgId: string,
  fromHour: number,
): Promise<WindowsHeld> {
  return windowsOfReserved(orgId, await reservedByHour(tx, fromHour, 'all'));
}

/** Whether two windows' hours from `fromHour` on hold the same. */
export function sameFrom(a: HeldByHour, b: HeldByHour, fromHour: number): boolean {
  const from = (held: HeldByHour) => [...held].filter(([hour, amount]) => hour >= fromHour && amount > 0n);
  const left = from(a);
  return left.length === from(b).length && left.every(([hour, amount]) => b.get(hour) === amount);
}

/** The most windows one page of the holdings check reads: each a verified read, locked until its page ends. */
export const MOST_WINDOWS_CHECKED_A_PAGE = 200;

/** A page of the organisation's windows checked: windows compared, mismatched and tampered with, and where to go on. */
export interface WindowsChecked {
  readonly windows: number;
  readonly mismatched: number;
  readonly tampered: number;
  readonly next: string | null;
}

/**
 * The first hour the holdings check compares at `at`: every hour a window can count, none it may have let go (a
 * window keeps an hour more, keptFromHour, for clocks a little apart).
 */
const comparedFromHour = (at: Date): number => hourOf(at) - MOST_WINDOW_HOURS;

/**
 * One page of the organisation's payee windows (GM-1b), each verified and locked FOR SHARE, so every move of its
 * reservations (each made under the window's lock for change) waits for the page or comes before it, then held to
 * what its reservations hold in every hour a window counts, in one statement: a window and its reservations apart is
 * a mismatch (`holding`, alarmed). With the requests' own check (each reservation held to its signed request, its
 * instant and payee key to its sealed decision), a window is so held to the signed requests too. Listed from the rows
 * and the log, so one deleted is read as `deleted`, alarmed. In withSignedStates' transaction.
 */
export async function checkPayeeWindows(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  { after, limit, at }: { readonly after: string | null; readonly limit: number; readonly at: Date },
): Promise<WindowsChecked> {
  if (!Number.isInteger(limit) || limit < 1 || limit > MOST_WINDOWS_CHECKED_A_PAGE) {
    throw new RangeError(`A page is 1 to ${String(MOST_WINDOWS_CHECKED_A_PAGE)} payee windows`);
  }
  const { ids, next } = await states.objectIds(tx, orgId, PAYEE_WINDOWS, after, limit);
  const checks =
    ids.length === 0 ? new Map<string, StateCheck>() : await states.verifiedStates(tx, PAYEE_WINDOWS, orgId, ids);
  const verified: { readonly id: string; readonly key: PayeeWindowKey; readonly held: HeldByHour }[] = [];
  let tampered = 0;
  for (const [id, check] of checks) {
    const window = payeeWindowFrom(check);
    // Listed by its row or its signed events, a window not found is one tampered with (its read raised the alarm).
    if (window.outcome === 'held') verified.push({ id, key: window.key, held: window.held });
    else tampered += 1;
  }
  const fromHour = comparedFromHour(at);
  const named = (pick: (key: PayeeWindowKey) => string | null) => [
    ...new Set(verified.flatMap(({ key }) => pick(key) ?? [])),
  ];
  const reserved = windowsOfReserved(
    orgId,
    await reservedByHour(tx, fromHour, {
      supplierIds: named(({ supplierId }) => supplierId),
      payeeKeys: named(({ payeeKey }) => payeeKey),
    }),
  );
  let mismatched = 0;
  for (const { id, held } of verified) {
    if (!sameFrom(held, reserved.get(id)?.held ?? new Map(), fromHour)) {
      states.mismatch(PAYEE_WINDOWS.subject, { orgId, id });
      mismatched += 1;
    }
  }
  return { windows: ids.length, mismatched, tampered, next };
}

/**
 * Every window the reservations hold capacity in, in an hour a window counts, yet that has no row and nothing signed
 * (one deleted with its events, and no decision since), once the organisation is cut over: each alarmed (`holding`),
 * with how many. One gone with its events still in the log reads `deleted`, alarmed by its read. The reservations in
 * one statement, the windows a few hundred at a time (verifiedStates, FOR SHARE). Before the cutover there is none
 * to look for.
 */
export async function windowsMissing(
  tx: WindowsTransaction,
  states: SignedStates,
  orgId: string,
  at: Date,
): Promise<number> {
  if ((await payeeWindowsCutOver(tx, states, orgId)) !== 'cut_over') return 0;
  const ids = [...(await reservationsInWindows(tx, orgId, comparedFromHour(at))).keys()];
  let missing = 0;
  for (let start = 0; start < ids.length; start += MOST_SIGNED_ROWS_READ) {
    const checks = await states.verifiedStates(
      tx,
      PAYEE_WINDOWS,
      orgId,
      ids.slice(start, start + MOST_SIGNED_ROWS_READ),
    );
    for (const [id, check] of checks) {
      if (check.outcome !== 'missing') continue;
      states.mismatch(PAYEE_WINDOWS.subject, { orgId, id });
      missing += 1;
    }
  }
  return missing;
}
