// SEC-OAUTH-02, -03, -08, -11, -13 (6E3a): the OAuth server's own rules, apart
// from any database: PKCE S256 alone, redirect addresses matched exactly (a
// loopback's port aside), scopes asked and narrowed, and a client's
// registration checked before anything is kept. 6E3c (SEC-OAUTH-09): a
// device's codes, and a client named by its metadata document.
import { describe, expect, it } from 'vitest';

import { SCOPES } from '../../agents/index.ts';
import { checkRegistration, DEVICE_CODE_GRANT } from './client-metadata.ts';
import { checkClientMetadataDocument, isMetadataClientId } from './client-metadata-document.ts';
import {
  hashOf,
  isCodeText,
  isDeviceCodeText,
  isFlowCookie,
  isRegisteredClientId,
  newClientId,
  newCode,
  newDeviceCode,
  newFlowCookie,
  newUserCode,
  userCodeOf,
} from './codes.ts';
import { challengeOf, isCodeChallenge, isCodeVerifier, pkceMatches } from './pkce.ts';
import { isLoopback, isRegisteredRedirect, redirectMatches, redirectProblems } from '../domain/redirects.ts';
import { OFFLINE_ACCESS, scopeParameter, scopesAsked, scopesNarrowed } from './scopes.ts';

const VERIFIER = 'a'.repeat(43);

describe('SEC-OAUTH-02 PKCE: S256 alone, compared in constant time', () => {
  it('matches a verifier with the challenge made from it, and nothing else', () => {
    const challenge = challengeOf(VERIFIER);
    expect(isCodeChallenge(challenge)).toBe(true);
    expect(pkceMatches(VERIFIER, challenge)).toBe(true);
    expect(pkceMatches('b'.repeat(43), challenge)).toBe(false);
    // `plain`: the verifier as its own challenge is never taken.
    expect(pkceMatches(VERIFIER, VERIFIER)).toBe(false);
  });

  it('takes only RFC 7636 verifiers: 43 to 128 unreserved characters', () => {
    expect(isCodeVerifier('a'.repeat(42))).toBe(false);
    expect(isCodeVerifier('a'.repeat(128))).toBe(true);
    expect(isCodeVerifier('a'.repeat(129))).toBe(false);
    expect(isCodeVerifier(`${'a'.repeat(42)}~`)).toBe(true);
    expect(isCodeVerifier(`${'a'.repeat(42)}+`)).toBe(false);
    expect(pkceMatches('short', challengeOf('short'))).toBe(false);
    expect(pkceMatches(VERIFIER, 'not a challenge')).toBe(false);
  });
});

describe('SEC-OAUTH-03, -11 redirect addresses: registered exactly, matched exactly', () => {
  it('registers https, and http only to the loopback', () => {
    expect(redirectProblems('https://chatgpt.com/connector/oauth/callback')).toEqual([]);
    expect(redirectProblems('http://127.0.0.1:18789/oauth/mcp/callback')).toEqual([]);
    expect(redirectProblems('http://localhost/callback')).toEqual([]);
    expect(redirectProblems('http://[::1]:4000/cb')).toEqual([]);
    expect(redirectProblems('http://example.com/cb')).toEqual([
      "a redirect address is https, or http to the machine's own loopback",
    ]);
    expect(redirectProblems('cursor://anysphere/callback')).toEqual([
      "a redirect address is https, or http to the machine's own loopback",
    ]);
  });

  it('refuses a fragment, a wildcard, a user, no URL at all, and one too long', () => {
    expect(redirectProblems('https://a.example/cb#x')).toEqual(['a redirect address has no fragment']);
    expect(redirectProblems('https://*.example/cb')).toContain('a redirect address has no wildcard');
    expect(redirectProblems('https://user:pass@a.example/cb')).toEqual([
      'a redirect address names no user or password',
    ]);
    expect(redirectProblems('/relative')).toEqual(['a redirect address is an absolute URL']);
    expect(redirectProblems('')).toEqual(['a redirect address is 1 to 512 characters']);
    expect(redirectProblems(`https://a.example/${'x'.repeat(512)}`)).toEqual([
      'a redirect address is 1 to 512 characters',
    ]);
  });

  it('matches the very text registered, never a prefix, a path or a host like it', () => {
    const registered = 'https://claude.ai/api/mcp/auth_callback';
    expect(redirectMatches(registered, registered)).toBe(true);
    expect(redirectMatches(registered, `${registered}/more`)).toBe(false);
    expect(redirectMatches(registered, 'https://claude.ai/api/mcp/auth_callback?x=1')).toBe(false);
    expect(redirectMatches(registered, 'https://claude.ai.evil.example/api/mcp/auth_callback')).toBe(false);
    expect(redirectMatches(registered, 'https://CLAUDE.ai/api/mcp/auth_callback')).toBe(false);
  });

  it('matches a loopback address on any port, its host, path and query exactly', () => {
    const registered = 'http://127.0.0.1:27890/callback';
    expect(redirectMatches(registered, 'http://127.0.0.1:51234/callback')).toBe(true);
    expect(redirectMatches(registered, 'http://127.0.0.1/callback')).toBe(true);
    expect(redirectMatches(registered, 'http://localhost:51234/callback')).toBe(false);
    expect(redirectMatches(registered, 'http://127.0.0.1:51234/callback/')).toBe(false);
    expect(redirectMatches(registered, 'http://127.0.0.1:51234/callback?x=1')).toBe(false);
    expect(redirectMatches(registered, 'http://127.0.0.1:51234/callback#x')).toBe(false);
    expect(redirectMatches(registered, 'http://user@127.0.0.1:51234/callback')).toBe(false);
    expect(redirectMatches(registered, 'https://127.0.0.1:51234/callback')).toBe(false);
    expect(redirectMatches(registered, 'http://LOCALHOST:5/callback')).toBe(false);
    expect(redirectMatches('http://[::1]:1/cb', 'http://[::1]:2/cb')).toBe(true);
    expect(redirectMatches('https://a.example/cb', 'http://127.0.0.1:2/cb')).toBe(false);
    expect(isLoopback('http://127.0.0.1:1/x')).toBe(true);
    expect(isLoopback('https://127.0.0.1:1/x')).toBe(false);
    expect(isLoopback('not a url')).toBe(false);
    expect(isRegisteredRedirect(['https://a.example/cb', registered], 'http://127.0.0.1:9/callback')).toBe(true);
    expect(isRegisteredRedirect(['https://a.example/cb'], 'https://b.example/cb')).toBe(false);
  });
});

describe('SEC-OAUTH-08 scopes: asked among those there are, narrowed and never widened', () => {
  it('asks for every scope when none is named, offline_access alone included', () => {
    expect(scopesAsked(undefined)).toEqual(SCOPES);
    expect(scopesAsked('  ')).toEqual(SCOPES);
    expect(scopesAsked(OFFLINE_ACCESS)).toEqual(SCOPES);
    expect(scopesAsked(`requests:write requests:read ${OFFLINE_ACCESS}`)).toEqual(['requests:read', 'requests:write']);
  });

  it('refuses a word that is no scope, a word twice, and a parameter too long', () => {
    expect(scopesAsked('openid')).toBeUndefined();
    expect(scopesAsked('requests:read requests:read')).toBeUndefined();
    expect(scopesAsked('requests:read '.repeat(30))).toBeUndefined();
  });

  it('narrows a refresh to the scopes named, all of them held; keeps them all when none is named', () => {
    const held = ['requests:read', 'suppliers:read'] as const;
    expect(scopesNarrowed(undefined, held)).toEqual(held);
    expect(scopesNarrowed(OFFLINE_ACCESS, held)).toEqual(held);
    expect(scopesNarrowed('suppliers:read', held)).toEqual(['suppliers:read']);
    expect(scopesNarrowed('requests:write', held)).toBeUndefined();
    expect(scopesNarrowed('nope', held)).toBeUndefined();
    expect(scopeParameter(['requests:read', 'suppliers:read'])).toBe('requests:read suppliers:read');
  });
});

describe('the random texts handed out', () => {
  it('makes codes, cookies and client IDs of their own shapes, and keeps secrets as their SHA-256', () => {
    const code = newCode();
    expect(isCodeText(code)).toBe(true);
    expect(isCodeText(`${code}x`)).toBe(false);
    expect(isFlowCookie(newFlowCookie())).toBe(true);
    expect(isFlowCookie('short')).toBe(false);
    expect(isRegisteredClientId(newClientId())).toBe(true);
    expect(isRegisteredClientId('axcl_nothex')).toBe(false);
    expect(hashOf('abc')).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(newCode()).not.toBe(code);
  });
});

describe('SEC-OAUTH-13 a client registering itself', () => {
  const asked = { redirect_uris: ['https://chatgpt.com/connector/oauth/abc'], client_name: 'ChatGPT' };

  it('keeps a public code-flow client, refresh tokens always', () => {
    expect(checkRegistration(asked)).toEqual({
      outcome: 'valid',
      client: {
        name: 'ChatGPT',
        redirectUris: ['https://chatgpt.com/connector/oauth/abc'],
        applicationType: 'web',
        grantTypes: ['authorization_code', 'refresh_token'],
        softwareId: null,
        softwareVersion: null,
      },
    });
    const native = checkRegistration({
      redirect_uris: ['http://127.0.0.1:18789/oauth/mcp/callback'],
      grant_types: ['authorization_code'],
      software_id: 'openclaw',
      software_version: '2026.11.5',
    });
    expect(native).toMatchObject({
      outcome: 'valid',
      client: {
        // No name given: the redirect address's host is shown instead.
        name: '127.0.0.1:18789',
        applicationType: 'native',
        grantTypes: ['authorization_code', 'refresh_token'],
        softwareId: 'openclaw',
        softwareVersion: '2026.11.5',
      },
    });
  });

  it('shows a name that is no visible name as the host instead', () => {
    expect(checkRegistration({ ...asked, client_name: `${String.fromCharCode(0x20_2e)}gnp.exe` })).toMatchObject({
      client: { name: 'chatgpt.com' },
    });
  });

  it.each([
    [{ redirect_uris: [] }, 'invalid_redirect_uri'],
    [
      { redirect_uris: Array.from({ length: 6 }, (_, index) => `https://a.example/${String(index)}`) },
      'invalid_redirect_uri',
    ],
    [{ redirect_uris: ['https://a.example/cb', 'https://a.example/cb'] }, 'invalid_redirect_uri'],
    [{ redirect_uris: ['http://a.example/cb'] }, 'invalid_redirect_uri'],
    [{ ...asked, token_endpoint_auth_method: 'client_secret_basic' }, 'invalid_client_metadata'],
    [{ ...asked, response_types: ['token'] }, 'invalid_client_metadata'],
    [{ ...asked, grant_types: ['refresh_token'] }, 'invalid_client_metadata'],
    [{ ...asked, grant_types: ['authorization_code', 'implicit'] }, 'invalid_client_metadata'],
    [{ ...asked, scope: 'openid' }, 'invalid_client_metadata'],
    [{ ...asked, software_id: 'x'.repeat(256) }, 'invalid_client_metadata'],
    [{ ...asked, software_version: 'x'.repeat(256) }, 'invalid_client_metadata'],
  ])('refuses %j as %s', (registration, error) => {
    expect(checkRegistration(registration)).toMatchObject({ outcome: 'invalid', error });
  });
});

describe('a device’s codes (6E3c, RFC 8628 §3.2, §6.1)', () => {
  it('draws a device code as a secret, and a user code of eight consonants in two fours', () => {
    const device = newDeviceCode();
    expect(isDeviceCodeText(device)).toBe(true);
    expect(isDeviceCodeText(device.replace('axd_', 'axc_'))).toBe(false);
    expect(newDeviceCode()).not.toBe(device);
    const drawn = Array.from({ length: 200 }, newUserCode);
    for (const code of drawn) expect(code).toMatch(/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    expect(new Set(drawn).size).toBeGreaterThan(195);
  });

  it('reads a user code as typed: any case, its dash or spaces, and nothing that can be no code', () => {
    expect(userCodeOf('BCDF-GHJK')).toBe('BCDFGHJK');
    expect(userCodeOf(' bcdf ghjk ')).toBe('BCDFGHJK');
    expect(userCodeOf('bcdfghjk')).toBe('BCDFGHJK');
    expect(userCodeOf('BCDF-GHJ')).toBeUndefined();
    expect(userCodeOf('BCDF-GHJKL')).toBeUndefined();
    // A vowel, a digit or a Y is never in a code.
    expect(userCodeOf('ABCD-GHJK')).toBeUndefined();
    expect(userCodeOf('BCD1-GHJK')).toBeUndefined();
    expect(userCodeOf('BCDY-GHJK')).toBeUndefined();
  });

  it('registers a client for the device flow, with refresh tokens, and never one for refresh alone', () => {
    const device = checkRegistration({
      redirect_uris: ['http://127.0.0.1/callback'],
      grant_types: [DEVICE_CODE_GRANT],
    });
    expect(device).toMatchObject({ outcome: 'valid', client: { grantTypes: [DEVICE_CODE_GRANT, 'refresh_token'] } });
    expect(
      checkRegistration({ redirect_uris: ['http://127.0.0.1/callback'], grant_types: ['refresh_token'] }),
    ).toMatchObject({ outcome: 'invalid', error: 'invalid_client_metadata' });
  });
});

describe('SEC-OAUTH-09 a client named by its metadata document (6E3c, CIMD)', () => {
  const CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
  const DOCUMENT = {
    client_id: CLIENT_ID,
    client_name: 'Claude',
    redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
    grant_types: ['authorization_code', 'refresh_token', 'client_credentials'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
  };

  it.each([
    [CLIENT_ID, true],
    ['https://nousresearch.github.io/hermes/client.json?v=1', true],
    ['http://claude.ai/oauth/x', false],
    ['https://claude.ai', false],
    ['https://claude.ai/', false],
    ['https://claude.ai/a/../b', false],
    ['https://claude.ai/a/./b', false],
    ['https://claude.ai/x#frag', false],
    ['https://user@claude.ai/x', false],
    ['https://CLAUDE.ai/x', false],
    ['https://claude.ai:443/x', false],
    ['axcl_0123456789abcdef0123456789abcdef', false],
    [`https://claude.ai/${'x'.repeat(2048)}`, false],
  ])('takes %s as a document’s address: %s', (clientId, taken) => {
    expect(isMetadataClientId(clientId)).toBe(taken);
  });

  it('keeps the document’s name, addresses and the grants it knows', () => {
    expect(checkClientMetadataDocument(CLIENT_ID, DOCUMENT)).toEqual({
      outcome: 'valid',
      document: {
        clientId: CLIENT_ID,
        name: 'Claude',
        redirectUris: ['https://claude.ai/api/mcp/auth_callback'],
        grantTypes: ['authorization_code', 'refresh_token'],
      },
    });
    const bare = { client_id: CLIENT_ID, redirect_uris: ['http://localhost:27890/callback'] };
    expect(checkClientMetadataDocument(CLIENT_ID, bare)).toMatchObject({
      outcome: 'valid',
      document: { name: 'claude.ai', grantTypes: ['authorization_code'] },
    });
  });

  it.each([
    ['not an object', [], 'not_an_object'],
    ['another client’s ID', { ...DOCUMENT, client_id: 'https://claude.ai/other' }, 'client_id_mismatch'],
    ['no addresses', { ...DOCUMENT, redirect_uris: [] }, 'redirect_uris'],
    [
      'eleven addresses',
      { ...DOCUMENT, redirect_uris: Array.from({ length: 11 }, (_, n) => `https://a.example/${String(n)}`) },
      'redirect_uris',
    ],
    [
      'an address twice',
      { ...DOCUMENT, redirect_uris: ['https://a.example/cb', 'https://a.example/cb'] },
      'redirect_uris',
    ],
    ['plain http elsewhere', { ...DOCUMENT, redirect_uris: ['http://a.example/cb'] }, 'redirect_uris'],
    ['an address that is no text', { ...DOCUMENT, redirect_uris: [7] }, 'redirect_uris'],
    ['a secret client', { ...DOCUMENT, token_endpoint_auth_method: 'private_key_jwt' }, 'not_public'],
    ['a secret', { ...DOCUMENT, client_secret: 'shh' }, 'not_public'],
    ['no code response', { ...DOCUMENT, response_types: ['token'] }, 'response_types'],
    ['grant types that are no list', { ...DOCUMENT, grant_types: 'authorization_code' }, 'grant_types'],
    ['grant types none of which are ours', { ...DOCUMENT, grant_types: ['client_credentials'] }, 'grant_types'],
  ])('refuses %s', (_, document, reason) => {
    expect(checkClientMetadataDocument(CLIENT_ID, document)).toEqual({ outcome: 'invalid', reason });
  });
});
