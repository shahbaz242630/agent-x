// Phase 3 L5c: the download store, on a stand-in for Azure's blob service and
// on a local folder: a file written in blocks, committed in order over any
// earlier one, read back a part at a time, a token asked only every few
// minutes, and every failure named by its call, status and Azure's code alone.
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { AzureBlobSettings } from './azure.ts';
import { azureBlockStore, folderBlockStore } from './block-store.ts';

/** Plain words, so secret scanners ignore them. */
const HEADER = 'identity header for these tests';
const ISSUED = 'issued value for these tests';

const SETTINGS: AzureBlobSettings = {
  url: 'https://stagentxdl01.blob.core.windows.net/activity-downloads',
  clientId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
  identityEndpoint: 'http://localhost:42356/msi/token',
  identityHeader: HEADER,
};

const NAME = '0199a0f0-0000-7000-8000-00000000ae01/0199a0f0-0000-7000-8000-00000000ae02/2026-08.ndjson.gz';
const sha256 = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

interface Call {
  readonly url: URL;
  readonly init: RequestInit;
}

/** A stand-in for Azure: the identity endpoint's token, then the blob service's answers in turn; every call kept. */
function azure(blob: readonly Response[] = [], now = () => 0) {
  const calls: Call[] = [];
  const answers = [...blob];
  const fetch = (url: string | URL, init: RequestInit = {}) => {
    const asked = new URL(url);
    calls.push({ url: asked, init });
    if (asked.origin === 'http://localhost:42356') {
      return Promise.resolve(Response.json({ access_token: ISSUED, token_type: 'Bearer' }));
    }
    return Promise.resolve(answers.shift() ?? new Response(null, { status: 201 }));
  };
  return { calls, store: azureBlockStore({ settings: SETTINGS, fetch, now }) };
}

const headersOf = (call: Call | undefined) => new Headers(call?.init.headers);

describe('L5c the download store on Azure', () => {
  it('writes each block with its MD5, then the file of them in order, its type and SHA-256 kept with it', async () => {
    const { calls, store } = azure();
    const blocks = [Buffer.from('first '), Buffer.from('second')];

    await store.putBlock(NAME, 0, blocks[0] ?? Buffer.alloc(0));
    await store.putBlock(NAME, 1, blocks[1] ?? Buffer.alloc(0));
    await store.commit(NAME, 2, { contentType: 'application/gzip', sha256: sha256(Buffer.concat(blocks)) });

    const [, first, second, list] = calls;
    expect(first?.url.pathname).toBe(`/activity-downloads/${NAME}`);
    expect(Object.fromEntries(first?.url.searchParams ?? [])).toEqual({
      comp: 'block',
      blockid: Buffer.from('block-000000').toString('base64'),
    });
    expect(second?.url.searchParams.get('blockid')).toBe(Buffer.from('block-000001').toString('base64'));
    expect(headersOf(first).get('content-md5')).toBe(createHash('md5').update('first ').digest('base64'));
    expect(headersOf(first).get('authorization')).toBe(`Bearer ${ISSUED}`);
    expect(headersOf(first).get('x-ms-version')).toBe('2024-11-04');
    expect(list?.url.searchParams.get('comp')).toBe('blocklist');
    expect(list?.init.body).toBe(
      `<?xml version="1.0" encoding="utf-8"?><BlockList><Latest>${Buffer.from('block-000000').toString('base64')}</Latest><Latest>${Buffer.from('block-000001').toString('base64')}</Latest></BlockList>`,
    );
    expect(headersOf(list).get('x-ms-blob-content-type')).toBe('application/gzip');
    expect(headersOf(list).get('x-ms-meta-sha256')).toBe(sha256(Buffer.concat(blocks)));
  });

  it('asks a token once, and again only once it has been kept ten minutes', async () => {
    let at = 0;
    const { calls, store } = azure([], () => at);
    const tokens = () => calls.filter((call) => call.url.origin === 'http://localhost:42356').length;

    await store.putBlock(NAME, 0, Buffer.from('a'));
    at = 9 * 60_000;
    await store.putBlock(NAME, 1, Buffer.from('b'));
    expect(tokens()).toBe(1);
    at = 10 * 60_000;
    await store.putBlock(NAME, 2, Buffer.from('c'));
    expect(tokens()).toBe(2);
  });

  it('reads a part by its range, and refuses an answer longer than asked', async () => {
    const { calls, store } = azure([
      new Response(Buffer.from('cond'), { status: 206 }),
      new Response(Buffer.from('too long'), { status: 206 }),
    ]);

    expect((await store.read(NAME, 4, 4)).toString()).toBe('cond');
    expect(headersOf(calls[1]).get('x-ms-range')).toBe('bytes=4-7');
    expect(calls[1]?.init.method).toBe('GET');
    await expect(store.read(NAME, 0, 4)).rejects.toThrow(
      'The download store failed: the blob service answered more than was asked',
    );
  });

  it('names a refusal by its status and Azure’s code alone', async () => {
    const { store } = azure([
      new Response('<Error>the body, never shown</Error>', {
        status: 403,
        headers: { 'x-ms-error-code': 'AuthorizationPermissionMismatch' },
      }),
      new Response(null, { status: 416, headers: { 'x-ms-error-code': 'not a $constant' } }),
    ]);

    await expect(store.putBlock(NAME, 0, Buffer.from('a'))).rejects.toThrow(
      'The download store failed: the blob service answered 403 (AuthorizationPermissionMismatch)',
    );
    await expect(store.read(NAME, 99, 1)).rejects.toThrow(
      'The download store failed: the blob service answered 416 (no code)',
    );
  });

  it('refuses a name past plain path segments, a block out of range, and a part of no bytes, calling nothing', async () => {
    const { calls, store } = azure();

    await expect(store.putBlock('../other/file', 0, Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.putBlock('a/./b', 0, Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.putBlock('a?comp=list', 0, Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.putBlock(NAME, -1, Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.putBlock(NAME, 50_000, Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.commit(NAME, 0, { contentType: 'application/gzip', sha256: 'a'.repeat(64) })).rejects.toThrow(
      RangeError,
    );
    await expect(store.read(NAME, 0, 0)).rejects.toThrow(RangeError);
    await expect(store.read(NAME, -1, 4)).rejects.toThrow(RangeError);
    expect(calls).toEqual([]);
  });
});

describe('L5c the download store on a local folder', () => {
  let folder: string;

  beforeEach(async () => {
    folder = await mkdtemp(join(tmpdir(), 'agentx-blocks-'));
  });

  afterEach(async () => {
    await rm(folder, { recursive: true, force: true });
  });

  it('makes the file of its blocks in order once committed, over an earlier one, its blocks gone with it', async () => {
    const store = folderBlockStore(folder);
    await store.putBlock(NAME, 0, Buffer.from('old'));
    await store.commit(NAME, 1, { contentType: 'application/gzip', sha256: sha256(Buffer.from('old')) });

    await store.putBlock(NAME, 1, Buffer.from(' world'));
    await store.putBlock(NAME, 0, Buffer.from('hello'));
    await store.commit(NAME, 2, { contentType: 'application/gzip', sha256: sha256(Buffer.from('hello world')) });

    expect((await store.read(NAME, 0, 100)).toString()).toBe('hello world');
    expect((await store.read(NAME, 6, 3)).toString()).toBe('wor');
    expect(await readdir(join(folder, NAME, '..'))).toEqual(['2026-08.ndjson.gz']);
  });

  it('refuses to commit blocks that are not the file named, leaving no file', async () => {
    const store = folderBlockStore(folder);
    await store.putBlock(NAME, 0, Buffer.from('hello'));

    await expect(
      store.commit(NAME, 1, { contentType: 'application/gzip', sha256: sha256(Buffer.from('other')) }),
    ).rejects.toThrow("The download store failed: the file's blocks are not the file named");
    await expect(store.read(NAME, 0, 1)).rejects.toThrow();
  });
});
