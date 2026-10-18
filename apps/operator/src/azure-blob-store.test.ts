// Phase 3 E10c-3: the write-once container's store against a stand-in for
// Azure: the token asked as the job's identity, the blob written once and
// whole, one there already answered, and every failure named by its call,
// status and Azure's code alone, never the token, the header or a path.
import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { azureBlobOrigins, azureBlobStore, type AzureBlobSettings } from './azure-blob-store.ts';

/** Plain words, so secret scanners ignore them. */
const HEADER = 'identity header for these tests';
const ISSUED = 'issued value for these tests';

const SETTINGS: AzureBlobSettings = {
  url: 'https://stagentxstg01.blob.core.windows.net/audit-exports',
  clientId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
  identityEndpoint: 'http://localhost:42356/msi/token',
  identityHeader: HEADER,
};

const NAME = '0199a0f0-0000-7000-8000-00000000e10c/0199a0f0-0000-7000-8000-00000000e10d.ndjson';
const CONTENT = Buffer.from('{"seq":"1"}\n');

interface Call {
  readonly url: URL;
  readonly init: RequestInit;
}

/** A stand-in for Azure: the identity endpoint's answer, then the blob service's; every call kept. */
function azure(
  identity: Response = Response.json({ access_token: ISSUED, token_type: 'Bearer' }),
  blob: Response = new Response(null, { status: 201 }),
) {
  const calls: Call[] = [];
  const fetch = (url: string | URL, init: RequestInit = {}) => {
    calls.push({ url: new URL(url), init });
    return Promise.resolve(calls.length === 1 ? identity : blob);
  };
  return { calls, store: azureBlobStore({ settings: SETTINGS, fetch }) };
}

const refusedWith = (status: number, code?: string) =>
  new Response(null, { status, headers: code === undefined ? {} : { 'x-ms-error-code': code } });

describe('E10c-3 the write-once container', () => {
  it('asks a token as the job’s identity, then writes the blob once and whole', async () => {
    const { calls, store } = azure();

    expect(await store.put(NAME, CONTENT)).toBe('written');

    const [identity, blob] = calls;
    expect(identity?.url.origin).toBe('http://localhost:42356');
    expect(identity?.url.pathname).toBe('/msi/token');
    expect(Object.fromEntries(identity?.url.searchParams ?? [])).toEqual({
      'api-version': '2019-08-01',
      resource: 'https://storage.azure.com/',
      client_id: SETTINGS.clientId,
    });
    expect(identity?.init.headers).toEqual({ 'x-identity-header': HEADER });
    expect(blob?.url.href).toBe(`${SETTINGS.url}/${NAME}`);
    expect(blob?.init).toMatchObject({
      method: 'PUT',
      body: CONTENT,
      headers: {
        authorization: `Bearer ${ISSUED}`,
        'x-ms-version': '2024-11-04',
        'x-ms-blob-type': 'BlockBlob',
        'if-none-match': '*',
        'content-type': 'application/x-ndjson',
        'content-md5': createHash('md5').update(CONTENT).digest('base64'),
        'x-ms-meta-sha256': createHash('sha256').update(CONTENT).digest('hex'),
      },
    });
    // The time of the request, as the service's page asks of every write.
    expect(new Headers(blob?.init.headers).get('x-ms-date')).toMatch(/ GMT$/);
  });

  it.each([
    ['409', 409, 'BlobAlreadyExists'],
    ['412', 412, 'ConditionNotMet'],
  ])('answers a blob there already as such (%s), and never writes over it', async (_what, status, code) => {
    const { store } = azure(undefined, refusedWith(status, code));

    expect(await store.put(NAME, CONTENT)).toBe('there_already');
  });

  it.each([
    [
      'another conflict',
      refusedWith(409, 'ContainerBeingDeleted'),
      'the blob service answered 409 (ContainerBeingDeleted)',
    ],
    [
      'a refusal of the identity',
      refusedWith(403, 'AuthorizationPermissionMismatch'),
      'the blob service answered 403 (AuthorizationPermissionMismatch)',
    ],
    [
      'a code that is no constant',
      refusedWith(500, 'Server Busy; try later'),
      'the blob service answered 500 (no code)',
    ],
    ['no code at all', refusedWith(503), 'the blob service answered 503 (no code)'],
  ])('fails on %s, naming the status and code alone', async (_what, answer, said) => {
    const { store } = azure(undefined, answer);

    const failure = await store.put(NAME, CONTENT).catch((error: unknown) => error);

    expect(failure).toMatchObject({ name: 'EvidenceStoreFailed', message: `The evidence store failed: ${said}` });
    expect(String(failure)).not.toContain(ISSUED);
    expect(String(failure)).not.toContain(NAME);
  });

  it.each([
    ['refuses', refusedWith(400), 'the identity endpoint answered 400'],
    ['gives no token', Response.json({ token_type: 'Bearer' }), "the identity endpoint's answer holds no token"],
    [
      'gives a token that is no text',
      Response.json({ access_token: 7 }),
      "the identity endpoint's answer holds no token",
    ],
    ['answers with no JSON', new Response('<html>busy</html>'), "the identity endpoint's answer holds no token"],
  ])('writes nothing when the identity endpoint %s', async (_what, answer, said) => {
    const { calls, store } = azure(answer);

    await expect(store.put(NAME, CONTENT)).rejects.toThrow(`The evidence store failed: ${said}`);
    expect(calls).toHaveLength(1);
    expect(String(calls.map(({ url }) => url.href))).not.toContain(HEADER);
  });

  it('names the two origins it calls, for the outbound allowlist', () => {
    expect(azureBlobOrigins(SETTINGS)).toEqual([
      'http://localhost:42356',
      'https://stagentxstg01.blob.core.windows.net',
    ]);
  });
});
