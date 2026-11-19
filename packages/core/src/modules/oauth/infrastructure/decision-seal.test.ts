// SEC-OAUTH-13 (tamper pass S205): a flow's decision is believed only with its own seal. The database's side, a
// planted or rewritten row refused at the token endpoint with the alarm, is oauth-connections.db.test.ts.
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import { decisionJudged, decisionSealed } from './decision-seal.ts';
import { codeEndsFrom, type DeviceFlowRead, type FlowRead } from './flows.ts';

const keysAt = (version: number, fill = 1) =>
  createKeyProvider(
    Object.fromEntries(
      PURPOSES.map((purpose, index) => [
        purpose,
        { current: version, versions: new Map([[version, Buffer.alloc(32, index + fill)]]) },
      ]),
    ),
  );

const keys = keysAt(1);
const ORG = '0199A0F0-0000-7000-8000-0000000E3A01';
const KEY = '0199a0f0-0000-7000-8000-0000000e3a02';
const DECIDED = new Date('2026-11-19T09:00:00Z');
const CODE_HASH = 'c'.repeat(64);

const undecided: FlowRead = {
  kind: 'code',
  id: '0199a0f0-0000-7000-8000-0000000e3a03',
  clientId: 'axcl_0123456789abcdef0123456789abcdef',
  redirectUri: 'https://chatgpt.com/connector/oauth/cb',
  state: 'xyz',
  codeChallenge: 'A'.repeat(43),
  scopesAsked: ['requests:read', 'suppliers:read'],
  resource: 'https://app.agentx.example/mcp',
  browserHash: 'b'.repeat(64),
  createdAt: new Date(DECIDED.getTime() - 60_000),
  endsAt: new Date(DECIDED.getTime() + 14 * 60_000),
  decided: null,
  decidedAt: null,
  orgId: null,
  keyId: null,
  seal: null,
  usedAt: null,
  codeHash: null,
  codeEndsAt: null,
};

/** The code flow as the token endpoint reads it once allowed and sealed. */
function allowedCode(): FlowRead {
  const fields = {
    orgId: ORG,
    keyId: KEY,
    codeHash: CODE_HASH,
    decidedAt: DECIDED,
    codeEndsAt: codeEndsFrom(DECIDED, CODE_HASH),
  };
  return { ...undecided, ...fields, decided: 'allowed', seal: decisionSealed(keys, undecided, fields) };
}

const undecidedDevice: DeviceFlowRead = {
  kind: 'device',
  id: '0199a0f0-0000-7000-8000-0000000e3a04',
  clientId: undecided.clientId,
  scopesAsked: ['requests:read'],
  resource: undecided.resource,
  deviceHash: 'd'.repeat(64),
  browserHash: 'b'.repeat(64),
  personHash: 'e'.repeat(64),
  intervalSeconds: 5,
  polledAt: null,
  createdAt: undecided.createdAt,
  endsAt: undecided.endsAt,
  decided: null,
  decidedAt: null,
  orgId: null,
  keyId: null,
  seal: null,
  usedAt: null,
};

function allowedDevice(): DeviceFlowRead {
  const fields = { orgId: ORG, keyId: KEY, codeHash: null, decidedAt: DECIDED, codeEndsAt: null };
  return { ...undecidedDevice, ...fields, decided: 'allowed', seal: decisionSealed(keys, undecidedDevice, fields) };
}

describe('SEC-OAUTH-13 a flow decision’s seal', () => {
  it('is sound for the flow it was made for, either kind, and whatever the IDs’ case', () => {
    expect(decisionJudged(keys, allowedCode())).toBe('sound');
    expect(decisionJudged(keys, allowedDevice())).toBe('sound');
    expect(decisionJudged(keys, { ...allowedCode(), orgId: ORG.toLowerCase() })).toBe('sound');
    expect(allowedCode().seal?.mac).toMatch(/^[0-9a-f]{64}$/);
    expect(allowedCode().seal?.keyVersion).toBe(1);
    expect(codeEndsFrom(DECIDED, null)).toBeNull();
  });

  it.each<[string, Partial<FlowRead>]>([
    ['another flow', { id: undecidedDevice.id }],
    ['another organisation', { orgId: '0199a0f0-0000-7000-8000-0000000e3aff' }],
    ['another connection', { keyId: '0199a0f0-0000-7000-8000-0000000e3aff' }],
    ['another client', { clientId: 'axcl_ffffffffffffffffffffffffffffffff' }],
    ['another redirect address', { redirectUri: 'https://attacker.example/cb' }],
    ['another PKCE challenge', { codeChallenge: 'B'.repeat(43) }],
    ['another code', { codeHash: 'f'.repeat(64) }],
    ['no code', { codeHash: null }],
    ['other scopes', { scopesAsked: ['requests:read'] }],
    ['another resource', { resource: 'https://elsewhere.example/mcp' }],
    ['a later end', { endsAt: new Date(undecided.endsAt.getTime() + 60_000) }],
    ['another decided time', { decidedAt: new Date(DECIDED.getTime() + 1) }],
    ['a later code end', { codeEndsAt: new Date(DECIDED.getTime() + 3_600_000) }],
    ['a MAC not its own', { seal: { mac: 'a'.repeat(64), keyVersion: 1 } }],
    ['a MAC cut short', { seal: { mac: 'abcd', keyVersion: 1 } }],
  ])('is tampered for %s', (_, changed) => {
    expect(decisionJudged(keys, { ...allowedCode(), ...changed })).toBe('tampered');
  });

  it('binds a device’s own code, and tells it from a code flow', () => {
    expect(decisionJudged(keys, { ...allowedDevice(), deviceHash: 'f'.repeat(64) })).toBe('tampered');
    expect(decisionJudged(keys, { ...allowedDevice(), id: undecided.id })).toBe('tampered');
  });

  it('refuses a flow not allowed, or allowed without its organisation, key or time', () => {
    for (const changed of [
      { decided: 'denied' as const },
      { decided: null },
      { orgId: null },
      { keyId: null },
      { decidedAt: null },
    ]) {
      expect(decisionJudged(keys, { ...allowedCode(), ...changed })).toBe('tampered');
    }
  });

  it('tells a flow with no seal (decided before 0100), and one sealed with a pepper version no longer held', () => {
    expect(decisionJudged(keys, { ...allowedCode(), seal: null })).toBe('unsealed');
    expect(decisionJudged(keys, { ...allowedCode(), seal: { mac: 'a'.repeat(64), keyVersion: 2 } })).toBe(
      'key_not_held',
    );
    // A pepper another server holds never makes a seal this one believes.
    expect(decisionJudged(keysAt(1, 7), allowedCode())).toBe('tampered');
  });
});
