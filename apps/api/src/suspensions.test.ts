// Where a pause's choice is read (PAUSE_EVENTS: the request-voids job's query
// and its verified judging) against the statuses voidCauses lets a pause hold
// (PAUSED_IN): one table changed without the other would have the job's
// filter and its judging disagree (C3b's review). The versions a supplier's
// current one carries requests from (pausedFromOf, E3): the walk back through
// its version moves stops at the first that isn't a linked details change
// chosen to pause.
import type { AuditDetails, AuditTransaction, HistoryCheck, SignedStates } from '@agentx/core/modules/audit';
import { PAUSED_IN } from '@agentx/core/modules/spend-requests';
import { describe, expect, it } from 'vitest';

import { cancelsAtOnce, choiceIn, PAUSE_EVENTS, pausedFromOf } from './suspensions.ts';

describe('choiceIn', () => {
  it('reads a pause recorded as a pause, and anything else as a cancel: none, older events, a value past the app', () => {
    expect(choiceIn({ pendingRequests: 'pause', pendingStatementVersion: 1 })).toBe('pause');
    expect(choiceIn({ pendingRequests: 'cancel' })).toBe('cancel');
    expect(choiceIn({})).toBe('cancel');
    expect(choiceIn(undefined)).toBe('cancel');
    expect(choiceIn({ pendingRequests: 'PAUSE' })).toBe('cancel');
  });
});

describe('cancelsAtOnce', () => {
  it('reads only a cancel confirmed under words that said it acts whatever the status (C3c, version 2 on)', () => {
    expect(cancelsAtOnce({ pendingRequests: 'cancel', pendingStatementVersion: 2 })).toBe(true);
    expect(cancelsAtOnce({ pendingRequests: 'cancel', pendingStatementVersion: 3 })).toBe(true);
    expect(cancelsAtOnce({ pendingRequests: 'cancel', pendingStatementVersion: 1 })).toBe(false);
    expect(cancelsAtOnce({ pendingRequests: 'cancel' })).toBe(false);
    expect(cancelsAtOnce({ pendingRequests: 'pause', pendingStatementVersion: 2 })).toBe(false);
    expect(cancelsAtOnce(undefined)).toBe(false);
  });
});

describe('PAUSE_EVENTS', () => {
  it.each(Object.entries(PAUSED_IN))(
    'reads a pause for %s in exactly the statuses voidCauses holds one in',
    (which, statuses) => {
      expect(Object.keys(PAUSE_EVENTS[which as keyof typeof PAUSED_IN]).toSorted()).toEqual([...statuses].toSorted());
    },
  );
});

describe('pausedFromOf', () => {
  /** A move as the log keeps it, oldest first. */
  const move = (action: string, details: AuditDetails) => ({ event: { action, details } });
  const paused = (versionId: string, followsVersionId: string | null) =>
    move('supplier.details_changed', { pendingRequests: 'pause', versionId, followsVersionId });
  const carried = (moves: readonly ReturnType<typeof move>[], read: Partial<HistoryCheck> = { outcome: 'read' }) =>
    pausedFromOf(
      {} as AuditTransaction,
      { historyOf: () => Promise.resolve({ ...read, events: moves }) } as unknown as SignedStates,
      'org',
      { id: 'supplier', currentVersionId: 'v3' },
    );

  it('walks back from the current version through each linked change chosen to pause', async () => {
    expect(await carried([paused('v2', 'v1'), paused('v3', 'v2')])).toEqual(['v2', 'v1']);
  });

  it.each([
    [
      'a new payee made current, though its details read as a pause',
      move('supplier.payee_change_confirmed', { pendingRequests: 'pause', versionId: 'v2', followsVersionId: 'v1' }),
    ],
    ['a change chosen to cancel', move('supplier.details_changed', { pendingRequests: 'cancel', versionId: 'v2' })],
    ['a change naming no choice (from before it)', move('supplier.details_changed', { versionId: 'v2' })],
    ['a change to another version', paused('v9', 'v1')],
    ['a change naming no version it follows', paused('v2', null)],
  ])('stops at %s', async (_what, stop) => {
    expect(await carried([paused('v2', 'v1'), stop, paused('v3', 'v2')])).toEqual(['v2']);
  });

  it('carries from none for a supplier with no version moves', async () => {
    expect(await carried([])).toEqual([]);
  });

  it('throws for a history that can’t be believed', async () => {
    await expect(carried([], { outcome: 'tampered', sign: 'chain' })).rejects.toThrow('version history can');
  });
});
