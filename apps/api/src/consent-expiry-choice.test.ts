// Phase 3 E7 (decision 21): a source's consent-expiry choice, its newest
// choice event's, read from the log: none (linked before E7), cancel or
// pause; a log that can't be believed is never read as a choice.
import { type AuditTransaction, MOST_HISTORIES_READ, type SignedStates } from '@agentx/core/modules/audit';
import { describe, expect, it } from 'vitest';

import { IntegrityFailure } from './errors.ts';
import {
  consentExpiryDetails,
  consentExpiryOf,
  holdsOverExpiry,
  withConsentExpiries,
} from './consent-expiry-choice.ts';

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

  it('reads a page of sources’ choices in order, gathered at most 8 histories a statement (PM5)', async () => {
    const gathered: (string | undefined)[][] = [];
    // 19 sources: three gathers (8, 8, 3), the most the store reads at once being 8; every third holds a pause.
    const sources = Array.from({ length: 19 }, (_, at) => ({ id: `s${String(at)}` }));
    const states = {
      gatherHistories: (_tx: unknown, _orgId: string, finds: readonly { subjectId?: string }[]) => {
        gathered.push(finds.map((find) => find.subjectId));
        return Promise.resolve();
      },
      historyOf: (_tx: unknown, _orgId: string, find: { subjectId?: string }) => {
        const at = Number(find.subjectId?.slice(1));
        const details = at % 3 === 0 ? consentExpiryDetails('pause') : undefined;
        return Promise.resolve({ outcome: 'read', events: details === undefined ? [] : [{ event: { details } }] });
      },
    } as unknown as SignedStates;

    const chosen = await withConsentExpiries(TX, states, 'org', sources);

    expect(gathered.map((part) => part.length)).toEqual([MOST_HISTORIES_READ, MOST_HISTORIES_READ, 3]);
    expect(gathered.flat()).toEqual(sources.map(({ id }) => id));
    expect(chosen).toEqual(sources.map((source, at) => ({ source, consentExpiry: at % 3 === 0 ? 'pause' : null })));
  });

  it('reads nothing for no sources', async () => {
    expect(await withConsentExpiries(TX, {} as SignedStates, 'org', [])).toEqual([]);
  });

  it('throws as an integrity failure (503) for any one history that can’t be believed', async () => {
    const states = {
      gatherHistories: () => Promise.resolve(),
      historyOf: () => Promise.resolve({ outcome: 'tampered', sign: 'log' }),
    } as unknown as SignedStates;

    await expect(withConsentExpiries(TX, states, 'org', [{ id: 'a' }])).rejects.toBeInstanceOf(IntegrityFailure);
  });
});
