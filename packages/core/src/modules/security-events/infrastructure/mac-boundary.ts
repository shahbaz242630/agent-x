// When the security rows' MACs began (S206 V6, 0106): rows written before
// this release carry none, and none can be made for them. The boundary is
// recorded once, as a sealed event on the platform chain, by the first API to
// start on 0106 (its start plus an hour, for the copies of the release before
// that still write without one); every later start finds it and leaves it.
// A row with no MAC is believed only if its ID was made before it. The
// database's owner can't move it: the event is sealed, and a chain with an
// event deleted or added past the app fails its check.
import { holdTransactionLock, limitedTransaction } from '@agentx/platform/db';
import type { KeyProvider } from '@agentx/platform/keys';
import type { Logger } from '@agentx/platform/observability';
import type { Kysely, Transaction } from 'kysely';

import type { Clock, IdGenerator } from '../../../shared-kernel/index.ts';
import {
  createPlatformChain,
  type PlatformControlsTables,
  platformEventSealed,
  platformEventsSigned,
} from '../../platform-controls/index.ts';

/** The platform event that records the boundary, and the lock it is recorded under (first writer wins). */
export const MACS_FROM = 'security_events.macs_from';

/** How long after the first start on 0106 a row may still come without a MAC: the release before's copies winding down. */
export const OLD_COPIES_MS = 60 * 60_000;

type PlatformDb = Kysely<PlatformControlsTables>;

/** The boundary the chain holds, in ms; undefined for none recorded yet, `unsealed` for one that can't be believed. */
async function boundaryIn(
  tx: Transaction<PlatformControlsTables>,
  keys: KeyProvider,
): Promise<number | undefined | 'unsealed'> {
  const [row] = await platformEventsSigned(tx).where('e.action', '=', MACS_FROM).orderBy('e.seq').limit(1).execute();
  if (row === undefined) return undefined;
  if (!platformEventSealed(keys, row)) return 'unsealed';
  // Sealed by the app as an ISO time; were it ever not one, NaN believes no row without a MAC, the safe way to fail.
  return Date.parse(String((JSON.parse(row.details) as Record<string, unknown>).from));
}

/**
 * Records the boundary unless one is: the first start's time plus OLD_COPIES_MS, under its lock so two starting at once
 * record one. Says the boundary, or `unsealed` for one recorded that can't be believed (the caller raises the alarm).
 */
export async function recordMacBoundary(
  db: PlatformDb,
  { keys, ids, clock }: { readonly keys: KeyProvider; readonly ids: IdGenerator; readonly clock: Clock },
): Promise<number | 'unsealed'> {
  return limitedTransaction(db, async (tx) => {
    await holdTransactionLock(tx, MACS_FROM);
    const found = await boundaryIn(tx, keys);
    if (found !== undefined) return found;
    const from = clock.now().getTime() + OLD_COPIES_MS;
    await createPlatformChain({ keys, ids }).record(tx, {
      actor: { type: 'system', id: 'api' },
      action: MACS_FROM,
      details: { from: new Date(from).toISOString() },
    });
    return from;
  });
}

/** The boundary, read once believed and then kept in memory. */
export type MacBoundary = (db: PlatformDb) => Promise<number>;

/**
 * The boundary as readers ask it: read from the chain until found and believed, then kept. None recorded, or one that
 * can't be believed (its alarm raised), is -Infinity: no row without a MAC is believed.
 */
export function macBoundary(keys: KeyProvider, logger: Logger): MacBoundary {
  let known: number | undefined;
  return async (db) => {
    if (known !== undefined) return known;
    const found = await limitedTransaction(db, (tx) => boundaryIn(tx, keys));
    if (found === 'unsealed') {
      logger.error('audit.integrity_failed', { chain: 'platform', check: 'security_event', reason: 'boundary' });
      return Number.NEGATIVE_INFINITY;
    }
    if (found === undefined) return Number.NEGATIVE_INFINITY;
    known = found;
    return found;
  };
}
