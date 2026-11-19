// SEC-OAUTH-13 (tamper pass S205): a flow is believed, as opened and as decided, only with its own seals. The
// database's side, a planted or rewritten row never shown, decided or exchanged, with the alarm, is
// oauth-connections.db.test.ts.
import { createKeyProvider, type Message, PURPOSES } from '@agentx/platform/keys';
import { LogCapture, testLogger } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { scopesText } from '../../agents/index.ts';
import {
  decisionJudged,
  decisionSealed,
  openedFieldsOf,
  openJudged,
  openSealed,
  pendingFlowSound,
} from './flow-seals.ts';
import { codeEndsFrom, type DeviceFlowRead, type FlowRead } from './flows.ts';
import { PKCE_METHOD } from './pkce.ts';

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

const opening: FlowRead = {
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
  openSeal: null,
  usedAt: null,
  codeHash: null,
  codeEndsAt: null,
};

/** The code flow as a person's consent reads it, sealed as it opened. */
const undecided: FlowRead = { ...opening, openSeal: openSealed(keys, openedFieldsOf(opening)) };

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

const openingDevice: DeviceFlowRead = {
  kind: 'device',
  id: '0199a0f0-0000-7000-8000-0000000e3a04',
  clientId: undecided.clientId,
  scopesAsked: ['requests:read'],
  resource: undecided.resource,
  deviceHash: 'd'.repeat(64),
  userCodeHash: 'c'.repeat(64),
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
  openSeal: null,
  usedAt: null,
};

const undecidedDevice: DeviceFlowRead = {
  ...openingDevice,
  openSeal: openSealed(keys, openedFieldsOf(openingDevice)),
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

  it('tells a flow with no seal (decided before 0101), and one sealed with a pepper version no longer held', () => {
    expect(decisionJudged(keys, { ...allowedCode(), seal: null })).toBe('unsealed');
    expect(decisionJudged(keys, { ...allowedCode(), seal: { mac: 'a'.repeat(64), keyVersion: 2 } })).toBe(
      'key_not_held',
    );
    // A pepper another server holds never makes a seal this one believes.
    expect(decisionJudged(keysAt(1, 7), allowedCode())).toBe('tampered');
  });
});

describe('SEC-OAUTH-13 a flow’s seal as it opened', () => {
  it('is sound for the flow its client opened, either kind', () => {
    expect(openJudged(keys, undecided)).toBe('sound');
    expect(openJudged(keys, undecidedDevice)).toBe('sound');
    // Its decision doesn't touch it.
    expect(openJudged(keys, allowedCode())).toBe('sound');
  });

  it.each<[string, Partial<FlowRead>]>([
    ['another flow', { id: undecidedDevice.id }],
    ['another client', { clientId: 'axcl_ffffffffffffffffffffffffffffffff' }],
    ['another redirect address', { redirectUri: 'https://attacker.example/cb' }],
    ['another PKCE challenge', { codeChallenge: 'B'.repeat(43) }],
    ['other scopes', { scopesAsked: ['requests:read'] }],
    ['another resource', { resource: 'https://elsewhere.example/mcp' }],
    ['a later end', { endsAt: new Date(undecided.endsAt.getTime() + 60_000) }],
    ['the decision’s seal in its place', { openSeal: allowedCode().seal }],
  ])('is tampered for %s', (_, changed) => {
    expect(openJudged(keys, { ...undecided, ...changed })).toBe('tampered');
  });

  it('binds a device’s own code', () => {
    expect(openJudged(keys, { ...undecidedDevice, deviceHash: 'f'.repeat(64) })).toBe('tampered');
    expect(openJudged(keys, { ...undecidedDevice, userCodeHash: 'f'.repeat(64) })).toBe('tampered');
  });

  it('shows, claims or decides only a pending flow sealed as opened: anything else is the alarm, an error or a warning', () => {
    const capture = new LogCapture();
    const logger = testLogger(capture);
    expect(pendingFlowSound(keys, logger, undecided)).toBe(true);
    expect(capture.lines()).toEqual([]);
    expect(pendingFlowSound(keys, logger, { ...undecidedDevice, deviceHash: 'f'.repeat(64) })).toBe(false);
    expect(pendingFlowSound(keys, logger, opening)).toBe(false);
    expect(pendingFlowSound(keys, logger, { ...undecided, openSeal: { mac: 'a'.repeat(64), keyVersion: 2 } })).toBe(
      false,
    );
    expect(capture.lines().map(({ level, event }) => [level, event])).toEqual([
      ['error', 'audit.integrity_failed'],
      ['warn', 'oauth.flow_unsealed'],
      ['error', 'oauth.seal_key_not_held'],
    ]);
    expect(capture.lines()[0]).toMatchObject({ check: 'oauth_flow', objectId: undecidedDevice.id });
  });
});

describe('SEC-OAUTH-15 a flow’s state, bound by both seals (v2, S206)', () => {
  it('is tampered for a code flow’s state rewritten, added or taken out, as opened and as decided', () => {
    for (const state of ['abc', null]) {
      expect(openJudged(keys, { ...undecided, state })).toBe('tampered');
      expect(decisionJudged(keys, { ...allowedCode(), state })).toBe('tampered');
    }
    const stateless: FlowRead = { ...opening, state: null };
    const sealed = { ...stateless, openSeal: openSealed(keys, openedFieldsOf(stateless)) };
    expect(openJudged(keys, sealed)).toBe('sound');
    expect(openJudged(keys, { ...sealed, state: 'abc' })).toBe('tampered');
  });

  /** A v1 message, as the release before sealed it: all but the state. */
  const v1Parts = (flow: FlowRead): string[] => [
    flow.id,
    flow.kind,
    flow.clientId,
    flow.redirectUri,
    `${PKCE_METHOD}:${flow.codeChallenge}`,
    '',
    '',
    scopesText(flow.scopesAsked),
    flow.resource,
    flow.endsAt.toISOString(),
  ];
  const sealedAs = (message: Message) => {
    const { mac, keyVersion } = keys.mac('agent-key-pepper', message);
    return { mac: mac.toString('hex'), keyVersion };
  };
  const openedV1 = (flow: FlowRead) => sealedAs(['oauth-flow-open-v1', ...v1Parts(flow)]);
  const decidedV1 = (flow: FlowRead) => {
    const done = allowedCode();
    return sealedAs([
      'oauth-flow-decision-v1',
      ...v1Parts(flow),
      ORG.toLowerCase(),
      KEY,
      CODE_HASH,
      DECIDED.toISOString(),
      done.codeEndsAt?.toISOString() ?? '',
    ]);
  };

  it('never believes a v1 seal, which doesn’t bind the state: one that checks is superseded, even with its state rewritten', () => {
    expect(openJudged(keys, { ...undecided, openSeal: openedV1(undecided) })).toBe('superseded');
    expect(openJudged(keys, { ...undecided, state: 'abc', openSeal: openedV1(undecided) })).toBe('superseded');
    expect(decisionJudged(keys, { ...allowedCode(), seal: decidedV1(undecided) })).toBe('superseded');
    expect(decisionJudged(keys, { ...allowedCode(), state: null, seal: decidedV1(undecided) })).toBe('superseded');
    // A v1 seal binds what it always did: anything else changed is still the alarm.
    const otherClient = { clientId: 'axcl_ffffffffffffffffffffffffffffffff' };
    expect(openJudged(keys, { ...undecided, ...otherClient, openSeal: openedV1(undecided) })).toBe('tampered');
    expect(decisionJudged(keys, { ...allowedCode(), ...otherClient, seal: decidedV1(undecided) })).toBe('tampered');
    // Each label its own: an open v1 seal never stands for a decision's, nor a v1 one for a v2 one.
    expect(decisionJudged(keys, { ...allowedCode(), seal: openedV1(undecided) })).toBe('tampered');
  });

  it('refuses a pending flow sealed v1 with a warning, never the alarm', () => {
    const capture = new LogCapture();
    const logger = testLogger(capture);
    expect(pendingFlowSound(keys, logger, { ...undecided, openSeal: openedV1(undecided) })).toBe(false);
    expect(capture.lines()).toEqual([
      expect.objectContaining({ level: 'warn', event: 'oauth.flow_seal_superseded', flowId: undecided.id }),
    ]);
  });
});
