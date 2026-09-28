// BR-03 (C1-1, C1-2): an agent's and a key's machines, how scopes are kept,
// an agent's name, and how a key is written and MACed.
import { describe, expect, it } from 'vitest';

import {
  AGENT,
  AGENT_KEY,
  agentKeyText,
  agentName,
  AgentNameRefused,
  isAgentName,
  isScope,
  KEY_DAYS,
  KEY_PREFIX,
  keyExpiresAt,
  keySecretMessage,
  SCOPES,
  scopesOf,
  ScopesRefused,
  scopesText,
  scopesWithin,
} from './agent.ts';

describe('an agent’s name (C1-2)', () => {
  it('is kept composed, as an organisation’s is', () => {
    expect(agentName('Café bot')).toBe('Café bot');
    expect(isAgentName('Purchasing bot')).toBe(true);
  });

  it.each(['', ' Bot', 'Bot\u0007', String.fromCharCode(0x200b), '...', 'b'.repeat(101)])('refuses %j', (name) => {
    expect(isAgentName(name)).toBe(false);
    expect(() => agentName(name)).toThrow(AgentNameRefused);
  });

  it('takes 100 characters, counted as code points, not UTF-16 units', () => {
    expect(isAgentName('b'.repeat(100))).toBe(true);
    expect(isAgentName('\u{1D400}'.repeat(100))).toBe(true);
    expect(isAgentName('\u{1D400}'.repeat(101))).toBe(false);
  });

  it('names its problems, never the name', () => {
    const refused = (() => {
      try {
        agentName(' Secret project bot');
      } catch (error) {
        return error;
      }
      return undefined;
    })();
    expect(refused).toBeInstanceOf(AgentNameRefused);
    expect((refused as AgentNameRefused).problems).toEqual(['the name starts or ends with a space']);
    expect((refused as Error).message).not.toContain('Secret');
  });
});

describe('a key (C1-2)', () => {
  const KEY_ID = '0199A0F0-0000-7000-8000-0000000000B1';
  const SECRET = Buffer.alloc(32, 0xfb);

  it(`expires ${String(KEY_DAYS)} days after it is issued`, () => {
    expect(keyExpiresAt(new Date('2026-09-28T09:00:00.000Z'))).toEqual(new Date('2026-12-27T09:00:00.000Z'));
  });

  it('is written axk_, its ID as 32 lower-case hex digits with no underscore, then its secret in base64url', () => {
    const text = agentKeyText(KEY_ID, SECRET);

    expect(text).toBe(`${KEY_PREFIX}0199a0f00000700080000000000000b1_${SECRET.toString('base64url')}`);
    expect(text.split('_')[1]).toMatch(/^[0-9a-f]{32}$/);
    expect(text).not.toContain('=');
  });

  it.each([
    ['an ID that isn’t a uuid', 'not-a-uuid', SECRET],
    ['a secret of 31 bytes', KEY_ID, Buffer.alloc(31)],
    ['a secret of 33 bytes', KEY_ID, Buffer.alloc(33)],
  ])('refuses %s', (_, keyId, secret) => {
    expect(() => agentKeyText(keyId, secret)).toThrow(RangeError);
  });

  it('is MACed over a label, its ID in lower case and its secret, so a MAC can’t be moved to another key', () => {
    expect(keySecretMessage(KEY_ID, SECRET)).toEqual(['agent-key', KEY_ID.toLowerCase(), SECRET]);
  });
});

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
