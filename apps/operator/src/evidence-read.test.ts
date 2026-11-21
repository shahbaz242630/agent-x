// A record read back from the evidence store (AT13f): what the store's answers mean to the operator's commands.
import { BlobStoreFailed } from '@agentx/platform/storage';
import { describe, expect, it } from 'vitest';

import { READ_DENIED_PROBLEM, summaryIn } from './evidence-read.ts';

const NAME = '0199a0f0-0000-7000-8000-000000000001/chain-restore-0199a0f0-0000-7000-8000-0000000000f1-outcome.ndjson';

/** A reader answering every read with `answer`, or throwing it. */
const answering = (answer: Buffer | Error) => ({
  get: (): Promise<Buffer> => (answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer)),
});

describe('a record read back from the evidence store (AT13f)', () => {
  it('gives its first line as an object', async () => {
    const read = await summaryIn(answering(Buffer.from('{"k":"restore","ok":true}\n{"row":1}\n')), NAME);
    expect(read).toEqual({ k: 'restore', ok: true });
    expect(await summaryIn(answering(Buffer.from('{"k":"restore"}')), NAME)).toEqual({ k: 'restore' });
    expect(await summaryIn(answering(Buffer.from('[1]\n')), NAME)).toEqual([1]);
    expect(await summaryIn(answering(Buffer.from('7\n')), NAME)).toEqual({});
  });

  it('reads none there, or a first line not JSON, as missing', async () => {
    const notThere = new BlobStoreFailed('evidence store', 'the blob service answered 404 (BlobNotFound)');
    expect(await summaryIn(answering(notThere), NAME)).toBe('missing');
    const folder = new BlobStoreFailed('evidence store', 'no file of that name');
    expect(await summaryIn(answering(folder), NAME)).toBe('missing');
    expect(await summaryIn(answering(Buffer.from('not json\n')), NAME)).toBe('missing');
  });

  it('reads a refusal of this identity as denied, its own plain words, never as missing', async () => {
    const refused = new BlobStoreFailed(
      'evidence store',
      'the blob service answered 403 (AuthorizationPermissionMismatch)',
    );
    expect(await summaryIn(answering(refused), NAME)).toBe('denied');
    expect(READ_DENIED_PROBLEM).toMatch(/read role on audit-exports and that foundation has run/);
  });

  it('throws anything else that stops the read: the network, a timeout, another answer', async () => {
    const busy = new BlobStoreFailed('evidence store', 'the blob service answered 503 (ServerBusy)');
    await expect(summaryIn(answering(busy), NAME)).rejects.toBe(busy);
    const network = new Error('connect ETIMEDOUT');
    await expect(summaryIn(answering(network), NAME)).rejects.toBe(network);
  });
});
