// SEC-OAUTH-17 (S207 H3, R-15): a client, registered or named by a kept document, is believed only with its own seal.
// The database's side, an owner's edits never believed, with the alarm, is oauth.db.test.ts and
// oauth-connections.db.test.ts.
import { createKeyProvider, PURPOSES } from '@agentx/platform/keys';
import { describe, expect, it } from 'vitest';

import {
  documentJudged,
  documentSealed,
  type DocumentFields,
  registeredJudged,
  registeredSealed,
  type RegisteredFields,
  sealIn,
} from './client-seals.ts';

/** Every purpose at version 1, its bytes from `fill`: another fill is another key. */
const keysOf = (fill: number) =>
  createKeyProvider(
    Object.fromEntries(
      PURPOSES.map((purpose, index) => [
        purpose,
        { current: 1, versions: new Map([[1, Buffer.alloc(32, index + fill)]]) },
      ]),
    ),
  );

const keys = keysOf(1);
const EVIL = 'https://attacker.example/cb';

const REGISTERED: RegisteredFields = {
  clientId: 'axcl_0123456789abcdef0123456789abcdef',
  name: 'ChatGPT',
  applicationType: 'web',
  redirectUris: ['https://chatgpt.com/connector/oauth/cb', 'https://chatgpt.com/connector/oauth/cb2'],
  grantTypes: ['authorization_code', 'refresh_token'],
  softwareId: 'chatgpt',
  softwareVersion: '1.0',
  createdAt: new Date('2026-11-20T09:00:00Z'),
};

const DOCUMENT: DocumentFields = {
  clientId: 'https://claude.ai/oauth/mcp-oauth-client-metadata',
  name: 'Claude',
  redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
  grantTypes: ['authorization_code', 'refresh_token'],
  fetchedAt: new Date('2026-11-20T09:00:00Z'),
  expiresAt: new Date('2026-11-21T09:00:00Z'),
};

describe('SEC-OAUTH-17 a registered client sealed as it registered', () => {
  const seal = registeredSealed(keys, REGISTERED);

  it('is sound as sealed, with the pepper version beside it', () => {
    expect(seal).toEqual({ mac: expect.stringMatching(/^[0-9a-f]{64}$/) as unknown, keyVersion: 1 });
    expect(registeredJudged(keys, REGISTERED, seal)).toBe('sound');
  });

  it.each<[string, Partial<RegisteredFields>]>([
    ['an address added', { redirectUris: [...REGISTERED.redirectUris, EVIL] }],
    ['an address replaced', { redirectUris: [EVIL, REGISTERED.redirectUris[1] ?? ''] }],
    ['its addresses reordered', { redirectUris: [...REGISTERED.redirectUris].reverse() }],
    ['a grant type added', { grantTypes: [...REGISTERED.grantTypes, 'urn:ietf:params:oauth:grant-type:device_code'] }],
    ['another ID', { clientId: 'axcl_ffffffffffffffffffffffffffffffff' }],
    ['another name', { name: 'Claude' }],
    ['another application type', { applicationType: 'native' }],
    ['no software ID', { softwareId: null }],
    ['another software version', { softwareVersion: '2.0' }],
    ['no software version', { softwareVersion: null }],
    ['another registration time', { createdAt: new Date(REGISTERED.createdAt.getTime() + 1) }],
  ])('with %s: tampered', (_, change) => {
    expect(registeredJudged(keys, { ...REGISTERED, ...change }, seal)).toBe('tampered');
  });

  it('an address moved across into the grant types never reads the same: each list is counted', () => {
    const [first = '', second = ''] = REGISTERED.redirectUris;
    const moved = { ...REGISTERED, redirectUris: [first], grantTypes: [second, ...REGISTERED.grantTypes] };
    expect(registeredJudged(keys, moved, registeredSealed(keys, REGISTERED))).toBe('tampered');
  });

  it('with no seal, unsealed; of a version not held, key_not_held; of another key, tampered', () => {
    expect(registeredJudged(keys, REGISTERED, null)).toBe('unsealed');
    expect(registeredJudged(keys, REGISTERED, { ...seal, keyVersion: 2 })).toBe('key_not_held');
    expect(registeredJudged(keys, REGISTERED, registeredSealed(keysOf(7), REGISTERED))).toBe('tampered');
  });

  it('a document’s seal never stands for a registered client’s, nor the other way: labels of their own', () => {
    const asDocument: DocumentFields = { ...DOCUMENT, clientId: REGISTERED.clientId, name: REGISTERED.name };
    expect(registeredJudged(keys, REGISTERED, documentSealed(keys, asDocument))).toBe('tampered');
    expect(documentJudged(keys, DOCUMENT, registeredSealed(keys, REGISTERED))).toBe('tampered');
  });

  it('a registered client and a document whose parts read the same, part for part, are told apart by label alone', () => {
    // Both messages, after their labels: the ID, the name, '3', '1', the address, '0', '0', the fetch, the end.
    const fetchedAt = DOCUMENT.fetchedAt;
    const expiresAt = DOCUMENT.expiresAt;
    const document: DocumentFields = {
      clientId: REGISTERED.clientId,
      name: REGISTERED.name,
      redirectUris: ['1', 'https://a.example/cb', '0'],
      grantTypes: [],
      fetchedAt,
      expiresAt,
    };
    const registered: RegisteredFields = {
      clientId: REGISTERED.clientId,
      name: REGISTERED.name,
      applicationType: '3',
      redirectUris: ['https://a.example/cb'],
      grantTypes: [],
      softwareId: '0',
      softwareVersion: fetchedAt.toISOString(),
      createdAt: expiresAt,
    };
    expect(registeredJudged(keys, registered, documentSealed(keys, document))).toBe('tampered');
    expect(documentJudged(keys, document, registeredSealed(keys, registered))).toBe('tampered');
  });
});

describe('SEC-OAUTH-17 a kept document sealed as it was kept', () => {
  const seal = documentSealed(keys, DOCUMENT);

  it('is sound as sealed', () => {
    expect(documentJudged(keys, DOCUMENT, seal)).toBe('sound');
  });

  it.each<[string, Partial<DocumentFields>]>([
    ['an address added', { redirectUris: [...DOCUMENT.redirectUris, EVIL] }],
    ['a grant type added', { grantTypes: [...DOCUMENT.grantTypes, 'urn:ietf:params:oauth:grant-type:device_code'] }],
    ['another client ID', { clientId: 'https://claude.ai/oauth/other' }],
    ['another name', { name: 'Claude (official)' }],
    ['another fetch time', { fetchedAt: new Date(DOCUMENT.fetchedAt.getTime() + 1) }],
    ['its day extended', { expiresAt: new Date(DOCUMENT.expiresAt.getTime() + 30 * 86_400_000) }],
  ])('with %s: tampered', (_, change) => {
    expect(documentJudged(keys, { ...DOCUMENT, ...change }, seal)).toBe('tampered');
  });

  it('with no seal, unsealed; of a version not held, key_not_held', () => {
    expect(documentJudged(keys, DOCUMENT, null)).toBe('unsealed');
    expect(documentJudged(keys, DOCUMENT, { ...seal, keyVersion: 3 })).toBe('key_not_held');
  });
});

describe('sealIn', () => {
  it('reads a seal only where both its MAC and its version are kept', () => {
    expect(sealIn('a'.repeat(64), 1)).toEqual({ mac: 'a'.repeat(64), keyVersion: 1 });
    expect(sealIn(null, 1)).toBeNull();
    expect(sealIn('a'.repeat(64), null)).toBeNull();
    expect(sealIn(null, null)).toBeNull();
  });
});
