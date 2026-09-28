// BR-03 (C1-1): an agent's and a key's machines, and how scopes are kept.
import { describe, expect, it } from 'vitest';

import { AGENT, AGENT_KEY, isScope, SCOPES, scopesOf, ScopesRefused, scopesText, scopesWithin } from './agent.ts';

const moves = (machine: { readonly moves: readonly { readonly from: string; readonly to: string }[] }) =>
  machine.moves.map(({ from, to }) => `${from}>${to}`).sort();

describe('an agent and its keys', () => {
  it('an agent starts ACTIVE, and is suspended and reactivated, as 0027’s guard lists', () => {
    expect(AGENT.initial).toBe('ACTIVE');
    expect(moves(AGENT)).toEqual(['ACTIVE>SUSPENDED', 'SUSPENDED>ACTIVE']);
  });

  it('a key starts ACTIVE and is revoked once, never brought back', () => {
    expect(AGENT_KEY.initial).toBe('ACTIVE');
    expect(moves(AGENT_KEY)).toEqual(['ACTIVE>REVOKED']);
  });
});

describe('scopes', () => {
  it('are kept sorted, one space apart, whatever order they came in', () => {
    expect(scopesText(['suppliers:read', 'requests:write'])).toBe('requests:write suppliers:read');
    expect(scopesText([...SCOPES].reverse())).toBe('requests:read requests:write sources:read suppliers:read');
  });

  it('fit the table’s check: words like `requests:write`, one space apart', () => {
    for (const scope of SCOPES) expect(scope).toMatch(/^[a-z]+:[a-z]+$/);
    expect(scopesText([...SCOPES]).length).toBeLessThanOrEqual(200);
  });

  it.each([
    [[], 'at least one scope is given'],
    [['requests:delete'], 'a scope is not one there is'],
    [['REQUESTS:READ'], 'a scope is not one there is'],
    [['requests:read', 'requests:read'], 'a scope is given twice'],
  ])('refuses %j: %s', (scopes, problem) => {
    expect(() => scopesText(scopes)).toThrow(ScopesRefused);
    expect(() => scopesText(scopes)).toThrow(problem);
  });

  it('names every problem at once', () => {
    const refused = (() => {
      try {
        scopesText(['nope', 'nope']);
      } catch (error) {
        return error;
      }
      return undefined;
    })();
    expect(refused).toBeInstanceOf(ScopesRefused);
    expect((refused as ScopesRefused).problems).toEqual(['a scope is not one there is', 'a scope is given twice']);
  });

  it('are read back from the kept text as they were given', () => {
    expect(scopesOf('requests:read suppliers:read')).toEqual(['requests:read', 'suppliers:read']);
  });

  it.each(['', 'suppliers:read requests:read', 'requests:read  suppliers:read', 'requests:read requests:read', 'x:y'])(
    'refuses a kept text scopesText never gives: %j',
    (text) => {
      expect(() => scopesOf(text)).toThrow();
    },
  );

  it('knows its own scopes', () => {
    expect(isScope('sources:read')).toBe(true);
    expect(isScope('sources:write')).toBe(false);
    expect(isScope(1)).toBe(false);
  });

  it('a key’s are within its agent’s only if every one is', () => {
    expect(scopesWithin(['requests:read'], ['requests:read', 'suppliers:read'])).toBe(true);
    expect(scopesWithin([], ['requests:read'])).toBe(true);
    expect(scopesWithin(['requests:read', 'requests:write'], ['requests:read'])).toBe(false);
  });
});
