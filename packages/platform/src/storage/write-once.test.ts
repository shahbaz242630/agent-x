// 4D2e E3: the write-once store, on an in-process stand-in for Azure's blob
// service and on a local folder: a second write of a name refused on both, a list
// by a name's start in order and in pages, the whole of a file read back, and
// every failure named by its call, status and Azure's code alone.
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { type AzureBlobSettings, BlobStoreFailed } from './azure.ts';
import { azureWriteOnceStore, folderWriteOnceStore, OverwriteRefused, type WriteOnceStore } from './write-once.ts';

/** Plain words, so secret scanners ignore them. */
const HEADER = 'identity header for these tests';
const ISSUED = 'issued value for these tests';

const SETTINGS: AzureBlobSettings = {
  url: 'https://stagentxev01.blob.core.windows.net/audit-anchors',
  clientId: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
  identityEndpoint: 'http://localhost:42356/msi/token',
  identityHeader: HEADER,
};

const NAME = 'e1/deltas/9000000000000-0199a0f0-0000-7000-8000-00000000ae01';

interface Call {
  readonly url: URL;
  readonly init: RequestInit;
}

/**
 * A stand-in for Azure holding its blobs as the real one does: a write with
 * `If-None-Match: *` over a blob there is refused as `refusal` says (the writer
 * role's answer by default), a list is in name order and in pages by marker.
 */
function azure(refusal: { status: number; code: string } = { status: 403, code: 'UnauthorizedBlobOverwrite' }) {
  const calls: Call[] = [];
  const blobs = new Map<string, Buffer>();
  const answer = (asked: URL, init: RequestInit): Response => {
    const path = asked.pathname.replace('/audit-anchors', '').replace(/^\//, '');
    if (init.method === 'PUT') {
      if (blobs.has(path)) {
        return new Response('<Error>never shown</Error>', {
          status: refusal.status,
          headers: { 'x-ms-error-code': refusal.code },
        });
      }
      blobs.set(path, init.body as Buffer);
      return new Response(null, { status: 201 });
    }
    if (asked.searchParams.get('comp') === 'list') {
      const start = asked.searchParams.get('prefix') ?? '';
      const most = Number(asked.searchParams.get('maxresults'));
      const after = asked.searchParams.get('marker') ?? '';
      const names = [...blobs.keys()].filter((name) => name.startsWith(start) && name > after).toSorted();
      const page = names.slice(0, most);
      const next = names.length > most ? (page.at(-1) ?? '') : '';
      const body = page.map((name) => `<Blob><Name>${name}</Name><Properties /></Blob>`).join('');
      return new Response(
        `<EnumerationResults><Blobs>${body}</Blobs><NextMarker>${next}</NextMarker></EnumerationResults>`,
      );
    }
    const found = blobs.get(path);
    return found === undefined
      ? new Response(null, { status: 404, headers: { 'x-ms-error-code': 'BlobNotFound' } })
      : new Response(found);
  };
  const fetch = (url: string | URL, init: RequestInit = {}) => {
    const asked = new URL(url);
    calls.push({ url: asked, init });
    return Promise.resolve(
      asked.origin === 'http://localhost:42356' ? Response.json({ access_token: ISSUED }) : answer(asked, init),
    );
  };
  return { calls, blobs, fetch, store: azureWriteOnceStore({ settings: SETTINGS, fetch }) };
}

/** What both stand-ins must do alike. */
function behavesAsWriteOnce(make: () => WriteOnceStore): void {
  it('gives back the bytes it was given', async () => {
    const store = make();
    await store.put(NAME, Buffer.from('the first line\n'));

    expect((await store.get(NAME)).toString()).toBe('the first line\n');
  });

  it('refuses a second write of a name, the same bytes or not, and the first stays', async () => {
    const store = make();
    await store.put(NAME, Buffer.from('first'));

    await expect(store.put(NAME, Buffer.from('second'))).rejects.toThrow(OverwriteRefused);
    await expect(store.put(NAME, Buffer.from('first'))).rejects.toThrow(
      'The write-once store refused the write: a file of that name is there already',
    );
    expect((await store.get(NAME)).toString()).toBe('first');
  });

  it('lists by a name’s start, in name order, in pages until the end', async () => {
    const store = make();
    for (const name of ['e1/deltas/3', 'e1/deltas/1', 'e1/deltas/2', 'e1/snapshots/1', 'e2/deltas/1']) {
      await store.put(name, Buffer.from(name));
    }

    const first = await store.list('e1/deltas/', 2);
    expect(first).toMatchObject({ names: ['e1/deltas/1', 'e1/deltas/2'], foreign: 0 });
    expect(typeof first.next).toBe('string');
    expect(await store.list('e1/deltas/', 2, first.next)).toEqual({
      names: ['e1/deltas/3'],
      foreign: 0,
      next: undefined,
    });
    expect(await store.list('e1/deltas/', 3)).toMatchObject({ next: undefined });
    expect((await store.list('e', 100)).names).toHaveLength(5);
  });

  it('lists nothing where nothing is', async () => {
    expect(await make().list('e9/', 10)).toEqual({ names: [], foreign: 0, next: undefined });
  });

  it('names a read of nothing as the store’s failure', async () => {
    await expect(make().get(NAME)).rejects.toThrow(BlobStoreFailed);
  });

  it('refuses a name past plain path segments, and a list it could not ask', async () => {
    const store = make();

    await expect(store.put('../other/file', Buffer.from('a'))).rejects.toThrow(RangeError);
    await expect(store.get('a?comp=list')).rejects.toThrow(RangeError);
    await expect(store.list('../', 10)).rejects.toThrow(RangeError);
    await expect(store.list('a b', 10)).rejects.toThrow(RangeError);
    await expect(store.list('e1/', 0)).rejects.toThrow(RangeError);
    await expect(store.list('e1/', 5001)).rejects.toThrow(RangeError);
    await expect(store.list('e1/', 1.5)).rejects.toThrow(RangeError);
  });
}

describe('4D2e E3 the write-once store on Azure', () => {
  behavesAsWriteOnce(() => azure().store);

  it('writes once, whole, with its MD5 and SHA-256, as the workload’s identity', async () => {
    const { calls, store } = azure();
    const bytes = Buffer.from('a line');

    await store.put(NAME, bytes);

    const [token, put] = calls;
    expect(new Headers(token?.init.headers).get('x-identity-header')).toBe(HEADER);
    expect(put?.url.pathname).toBe(`/audit-anchors/${NAME}`);
    expect(put?.init.method).toBe('PUT');
    expect(put?.init.body).toBe(bytes);
    const headers = new Headers(put?.init.headers);
    expect(headers.get('authorization')).toBe(`Bearer ${ISSUED}`);
    expect(headers.get('x-ms-blob-type')).toBe('BlockBlob');
    expect(headers.get('if-none-match')).toBe('*');
    expect(headers.get('content-md5')).toBe(createHash('md5').update(bytes).digest('base64'));
    expect(headers.get('x-ms-meta-sha256')).toBe(createHash('sha256').update(bytes).digest('hex'));
    expect(headers.get('x-ms-version')).toBe('2024-11-04');
  });

  it('asks the container for a list, with the start, the size and the marker it was given', async () => {
    const { calls, store } = azure();

    await store.list('e1/deltas/', 2, 'mark');

    const asked = calls[1]?.url;
    expect(asked?.pathname).toBe('/audit-anchors');
    expect(Object.fromEntries(asked?.searchParams ?? [])).toEqual({
      restype: 'container',
      comp: 'list',
      prefix: 'e1/deltas/',
      maxresults: '2',
      marker: 'mark',
    });
    expect(calls[1]?.init.method).toBe('GET');
  });

  it.each([
    ['the writer role’s answer, as staging gave it', 403, 'UnauthorizedBlobOverwrite'],
    ['an identity that may write', 409, 'BlobAlreadyExists'],
    ['the page on conditions', 412, 'ConditionNotMet'],
  ])('reads %s as an overwrite refused', async (_from, status, code) => {
    const { store } = azure({ status, code });
    await store.put(NAME, Buffer.from('first'));

    await expect(store.put(NAME, Buffer.from('second'))).rejects.toThrow(OverwriteRefused);
  });

  it.each([
    ['another refusal of the identity', 403, 'AuthorizationPermissionMismatch'],
    ['that code with another status', 409, 'UnauthorizedBlobOverwrite'],
    ['a code that is no constant', 403, 'not a $constant'],
  ])('names %s as a failure, by status and code alone, never its body', async (_what, status, code) => {
    const { store } = azure({ status, code });
    await store.put(NAME, Buffer.from('first'));

    const failure: unknown = await store.put(NAME, Buffer.from('second')).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(BlobStoreFailed);
    expect(failure).not.toBeInstanceOf(OverwriteRefused);
    expect(String(failure)).toContain(`answered ${String(status)} (`);
    expect(String(failure)).not.toContain('never shown');
  });

  it('names a refused list and a refused read by status and code', async () => {
    const refusing = azureWriteOnceStore({
      settings: SETTINGS,
      fetch: (url) =>
        Promise.resolve(
          new URL(url).origin === 'http://localhost:42356'
            ? Response.json({ access_token: ISSUED })
            : new Response('<Error />', { status: 403, headers: { 'x-ms-error-code': 'AuthorizationFailure' } }),
        ),
    });

    await expect(refusing.list('e1/', 10)).rejects.toThrow(
      'The write-once store failed: the blob service answered 403 (AuthorizationFailure)',
    );
    await expect(refusing.get(NAME)).rejects.toThrow(
      'The write-once store failed: the blob service answered 403 (AuthorizationFailure)',
    );
  });

  const answering = (xml: string): WriteOnceStore =>
    azureWriteOnceStore({
      settings: SETTINGS,
      fetch: (url) =>
        Promise.resolve(
          new URL(url).origin === 'http://localhost:42356'
            ? Response.json({ access_token: ISSUED })
            : new Response(xml),
        ),
    });

  it('leaves out, and counts, a name it would never write', async () => {
    const page = await answering(
      '<Blobs><Blob><Name>e1/deltas/1</Name></Blob><Blob>\n<Name>../odd name</Name></Blob></Blobs><NextMarker />',
    ).list('e1/', 10);

    expect(page).toEqual({ names: ['e1/deltas/1'], foreign: 1, next: undefined });
  });

  it('refuses a continuation of another form rather than send it on', async () => {
    await expect(answering('<NextMarker>a&amp;b</NextMarker>').list('e1/', 10)).rejects.toThrow(
      'The write-once store failed: the blob service answered a list with a continuation of another form',
    );
  });

  it('asks a token once, and again only once it has been kept ten minutes', async () => {
    let at = 0;
    const { calls, fetch } = azure();
    const store = azureWriteOnceStore({ settings: SETTINGS, fetch, now: () => at });
    const tokens = () => calls.filter((call) => call.url.origin === 'http://localhost:42356').length;

    await store.put('a', Buffer.from('a'));
    at = 9 * 60_000;
    await store.put('b', Buffer.from('b'));
    expect(tokens()).toBe(1);
    at = 10 * 60_000;
    await store.put('c', Buffer.from('c'));
    expect(tokens()).toBe(2);
  });
});

describe('4D2e E3 the write-once store on a local folder', () => {
  let folder: string;

  beforeEach(() => {
    folder = mkdtempSync(join(tmpdir(), 'agentx-write-once-'));
  });

  afterEach(async () => {
    await rm(folder, { recursive: true, force: true });
  });

  behavesAsWriteOnce(() => folderWriteOnceStore(folder));

  it('leaves no part-written file behind, a refused write or not', async () => {
    const store = folderWriteOnceStore(folder);
    await store.put('e1/a', Buffer.from('first'));
    await expect(store.put('e1/a', Buffer.from('second'))).rejects.toThrow(OverwriteRefused);

    expect(await readdir(join(folder, 'e1'))).toEqual(['a']);
  });

  it('never lists a file still being written', async () => {
    const store = folderWriteOnceStore(folder);
    await store.put('e1/a', Buffer.from('first'));
    // A write under way: a stopped process would leave one of these.
    await store.put('e1/b.0199a0f0-0000-7000-8000-00000000ae01.part', Buffer.from('half'));

    expect((await store.list('e1/', 10)).names).toEqual(['e1/a']);
  });

  it('lists nothing in a folder not made yet', async () => {
    expect(await folderWriteOnceStore(join(folder, 'not-made')).list('e1/', 10)).toEqual({
      names: [],
      foreign: 0,
      next: undefined,
    });
  });

  it('fails on anything else a name can meet, as itself', async () => {
    const store = folderWriteOnceStore(folder);
    await store.put('e1/a', Buffer.from('first'));

    // A name beneath a file: the folder it needs can't be made.
    await expect(store.put('e1/a/b', Buffer.from('second'))).rejects.toThrow(/ENOTDIR|EEXIST/);
    // A folder where a file was asked for.
    await expect(store.get('e1')).rejects.toThrow(/EISDIR/);
  });
});
