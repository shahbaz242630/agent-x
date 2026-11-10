// Phase 3 E7 (decision 21): a source's consent-expiry choice, its newest
// choice event's, read from the log: none (linked before E7), cancel or
// pause; a log that can't be believed is never read as a choice.
import type { AuditTransaction, SignedStates } from '@agentx/core/modules/audit';
import { describe, expect, it } from 'vitest';

import { IntegrityFailure } from './errors.ts';
import { consentExpiriesOf, consentExpiryDetails, consentExpiryOf, holdsOverExpiry } from './consent-expiry-choice.ts';

const TX = {} as AuditTransaction;

/** Signed states whose history answers `answer` (only historyOf is read). */
const statesWith = (answer: Awaited<ReturnType<SignedStates['historyOf']>>) =>
  ({ historyOf: () => Promise.resolve(answer) }) as unknown as SignedStates;

/** A history whose newest choice event keeps `details`, or none. */
const read = (details?: Readonly<Record<string, unknown>>) =>
  statesWith({
    outcome: 'read',
    events: details === undefined ? [] : [{ event: { details } }],
  } as unknown as Awaited<ReturnType<SignedStates['historyOf']>>);

describe('a source’s consent-expiry choice (E7)', () => {
  it('reads each choice its newest event keeps, none for a source linked before the choice', async () => {
    expect(await consentExpiryOf(TX, read(consentExpiryDetails('pause')), 'org', 'source')).toBe('pause');
    expect(await consentExpiryOf(TX, read(consentExpiryDetails('cancel')), 'org', 'source')).toBe('cancel');
    expect(await consentExpiryOf(TX, read(), 'org', 'source')).toBeNull();
    expect(await consentExpiryOf(TX, read({ pendingRequests: 'keep' }), 'org', 'source')).toBeNull();
  });

  it('holds only for a pause', async () => {
    expect(await holdsOverExpiry(TX, read(consentExpiryDetails('pause')), 'org', 'source')).toBe(true);
    expect(await holdsOverExpiry(TX, read(consentExpiryDetails('cancel')), 'org', 'source')).toBe(false);
    expect(await holdsOverExpiry(TX, read(), 'org', 'source')).toBe(false);
  });

  it('throws for a history that can’t be believed: never read as a choice', async () => {
    const tampered = statesWith({ outcome: 'tampered', sign: 'log' } as unknown as Awaited<
      ReturnType<SignedStates['historyOf']>
    >);
    await expect(consentExpiryOf(TX, tampered, 'org', 'source')).rejects.toThrow(/can't be believed/);
  });

  it('reads a page of sources’ choices in order, their histories gathered in one read first (PM5)', async () => {
    const gathered: unknown[] = [];
    const chosen = { a: consentExpiryDetails('pause'), b: undefined, c: consentExpiryDetails('cancel') };
    const states = {
      gatherHistories: (_tx: unknown, orgId: string, finds: readonly { subjectId?: string }[]) => {
        gathered.push([orgId, finds.map((find) => find.subjectId)]);
        return Promise.resolve();
      },
      historyOf: (_tx: unknown, _orgId: string, find: { subjectId?: string }) => {
        const details = chosen[find.subjectId as keyof typeof chosen];
        return Promise.resolve({ outcome: 'read', events: details === undefined ? [] : [{ event: { details } }] });
      },
    } as unknown as SignedStates;

    expect(await consentExpiriesOf(TX, states, 'org', ['a', 'b', 'c'])).toEqual(['pause', null, 'cancel']);
    expect(gathered).toEqual([['org', ['a', 'b', 'c']]]);
  });

  it('reads nothing for no sources', async () => {
    expect(await consentExpiriesOf(TX, {} as SignedStates, 'org', [])).toEqual([]);
  });

  it('throws as an integrity failure (503) for any one history that can’t be believed', async () => {
    const states = {
      gatherHistories: () => Promise.resolve(),
      historyOf: () => Promise.resolve({ outcome: 'tampered', sign: 'log' }),
    } as unknown as SignedStates;

    await expect(consentExpiriesOf(TX, states, 'org', ['a'])).rejects.toBeInstanceOf(IntegrityFailure);
  });
});
