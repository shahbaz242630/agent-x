// 6E3a: an MCP connection's tokens as text, one spelling each, and what their
// MAC is taken over (SEC-OAUTH-14: never a key's label).
import { describe, expect, it } from 'vitest';

import { DAY_MS } from '../../../shared-kernel/index.ts';
import { keySecretMessage } from './agent.ts';
import {
  connectionTokenMessage,
  connectionTokenSecretMessage,
  connectionTokenText,
  parseConnectionToken,
  REFRESH_IDLE_DAYS,
  tokenExpiresAt,
} from './connection.ts';

const KEY_ID = '0199a0f0-0000-7000-8000-0000000000a1';
const TOKEN_ID = '0199a0f0-0000-7000-8000-0000000000b2';
const RANDOM_PART = Buffer.alloc(32, 7);

describe('a connection token as text', () => {
  it('writes and reads back an access token and a refresh token, each by its own prefix alone', () => {
    const access = connectionTokenText('access', KEY_ID, TOKEN_ID, RANDOM_PART);
    const refresh = connectionTokenText('refresh', KEY_ID.toUpperCase(), TOKEN_ID, RANDOM_PART);
    expect(access).toMatch(/^axa_[0-9a-f]{32}_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$/);
    expect(refresh.startsWith('axr_')).toBe(true);
    expect(parseConnectionToken(access, 'access')).toEqual({
      kind: 'access',
      keyId: KEY_ID,
      tokenId: TOKEN_ID,
      secret: RANDOM_PART,
    });
    expect(parseConnectionToken(refresh, 'refresh')).toMatchObject({ kind: 'refresh', keyId: KEY_ID });
    // An access token is never a refresh token, nor the other way round.
    expect(parseConnectionToken(access, 'refresh')).toBeUndefined();
    expect(parseConnectionToken(refresh, 'access')).toBeUndefined();
  });

  it('takes no other spelling: capitals, padding, stray bits, a key, nothing', () => {
    const access = connectionTokenText('access', KEY_ID, TOKEN_ID, RANDOM_PART);
    expect(parseConnectionToken(access.toUpperCase(), 'access')).toBeUndefined();
    expect(parseConnectionToken(`${access}=`, 'access')).toBeUndefined();
    // The last character carries 2 bits past the secret's 256: set one, and it is another spelling of the same secret.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(access.slice(-1));
    const stray = `${access.slice(0, -1)}${alphabet.charAt(last | 1)}`;
    expect(parseConnectionToken(stray, 'access')).toBeUndefined();
    expect(
      parseConnectionToken(`axk_${'0'.repeat(32)}_${RANDOM_PART.toString('base64url')}`, 'access'),
    ).toBeUndefined();
    expect(parseConnectionToken('', 'access')).toBeUndefined();
  });

  it('refuses IDs that are no uuids, and a secret of any other length', () => {
    expect(() => connectionTokenText('access', 'not-a-uuid', TOKEN_ID, RANDOM_PART)).toThrow(RangeError);
    expect(() => connectionTokenText('access', KEY_ID, TOKEN_ID, Buffer.alloc(31))).toThrow(RangeError);
  });
});

describe('a token’s life', () => {
  const now = new Date('2026-11-18T09:00:00Z');
  const far = new Date(now.getTime() + 90 * DAY_MS);

  it('gives an access token an hour and a refresh token 30 days, never past its key', () => {
    expect(tokenExpiresAt('access', now, far)).toEqual(new Date('2026-11-18T10:00:00Z'));
    expect(tokenExpiresAt('refresh', now, far)).toEqual(new Date(now.getTime() + REFRESH_IDLE_DAYS * DAY_MS));
    const soon = new Date('2026-11-18T09:30:00Z');
    expect(tokenExpiresAt('access', now, soon)).toEqual(soon);
    expect(tokenExpiresAt('refresh', now, soon)).toEqual(soon);
  });
});

describe('SEC-OAUTH-14 what a token’s MAC is taken over', () => {
  it('binds its kind, key, ID, expiry and scopes under a label of its own', () => {
    const expiresAt = new Date('2026-11-18T10:00:00Z');
    const message = connectionTokenMessage(
      { kind: 'access', keyId: KEY_ID.toUpperCase(), tokenId: TOKEN_ID, expiresAt, scopes: 'requests:read' },
      RANDOM_PART,
    );
    expect(message).toEqual([
      'connection-token',
      'access',
      KEY_ID,
      TOKEN_ID,
      '2026-11-18T10:00:00.000Z',
      'requests:read',
      RANDOM_PART,
    ]);
    expect(message[0]).not.toBe(keySecretMessage(KEY_ID, RANDOM_PART)[0]);
  });

  it('SEC-OAUTH-16 R-15: makes a token’s secret from its kind, key and ID under a label of its own', () => {
    expect(connectionTokenSecretMessage({ kind: 'refresh', keyId: KEY_ID.toUpperCase(), tokenId: TOKEN_ID })).toEqual([
      'connection-token-secret',
      'refresh',
      KEY_ID,
      TOKEN_ID,
    ]);
  });
});
