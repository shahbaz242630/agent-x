// An organisation's security events as its admins are shown them (6E1b,
// CO7b): a row that names no one is shown without an actor and asks no namer.
import { describe, expect, it } from 'vitest';

import type { OrgSecurityEvent } from '../../security-events/index.ts';

import { securityEventActorsOf, securityEventShown } from './security-events-shown.ts';

const AGENT = '01900000-0000-7000-8000-0000000000a1';

const row = (actor: OrgSecurityEvent['actor']): OrgSecurityEvent => ({
  id: '01900000-0000-7000-8000-000000000001',
  kind: 'rate_limited',
  reason: 'per_agent',
  ip: null,
  actor,
  windowStart: new Date('2026-11-17T10:00:00.000Z'),
  count: 3,
});

describe('security events as shown', () => {
  it('asks a namer only about the rows that name someone', () => {
    const agent = { type: 'agent', id: AGENT } as const;
    expect(securityEventActorsOf([row(null), row(agent)])).toEqual([agent]);
  });

  it('shows a row that names no one without an actor', () => {
    expect(securityEventShown(row(null), new Map())).toEqual({
      id: '01900000-0000-7000-8000-000000000001',
      kind: 'rate_limited',
      reason: 'per_agent',
      ip: null,
      actor: null,
      windowStart: '2026-11-17T10:00:00.000Z',
      count: 3,
    });
  });
});
