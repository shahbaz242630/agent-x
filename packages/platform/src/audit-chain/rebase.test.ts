// A rebase's line (4D2e E11): signed with the operator's `audit-rebase` key alone, checked with its public half, and
// refused for anything else. How the anchors' store takes one in is anchor-log.test.ts.
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { gzipSync } from 'node:zlib';

import { writeTestKeys } from '@agentx/testing';
import { afterAll, describe, expect, it } from 'vitest';

import { createKeyProvider, KeyError, type KeyProvider } from '../keys/key-provider.ts';
import { loadKeys } from '../keys/load.ts';
import { API_PURPOSES, byPurpose, OPERATOR_ONLY, PURPOSES } from '../keys/purposes.ts';
import { rebaseFile, rebaseFileName, rebaseMessage, readRebaseFile, signRebase } from './rebase.ts';

const allKeys = (fill: number): KeyProvider =>
  createKeyProvider(
    byPurpose((purpose) => ({
      current: 1,
      versions: new Map([[1, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]),
    })),
  );
/** The operator's keys, `audit-rebase` among them. */
const keys = allKeys(1);
/** Someone else's: the same purposes, other keys. */
const otherKeys = allKeys(40);

const ID = '0199a0f0-0000-7000-8000-0000000000aa';
const UNSIGNED = {
  id: ID,
  chain: 'organisation:0199a0f0-0000-7000-8000-000000000001',
  seq: 812n,
  hash: Buffer.alloc(32, 7),
  macKeyVersion: 3,
  at: new Date('2026-11-05T10:00:00.000Z'),
  reason: 'repaired' as const,
  evidence: 'INC-2026-11-05',
};
const NAME = rebaseFileName(1, ID);

/** A rebase file's one line, as given, gzipped as the store holds it. */
const fileOfLine = (line: Record<string, unknown>): Buffer => gzipSync(`${JSON.stringify(line)}\n`);
const LINE = (signing = keys, epoch = 1): Record<string, unknown> => {
  const signed = signRebase(signing, epoch, UNSIGNED);
  return {
    k: 'r',
    id: ID,
    chain: UNSIGNED.chain,
    seq: '812',
    hash: UNSIGNED.hash.toString('hex'),
    mk: 3,
    at: UNSIGNED.at.toISOString(),
    why: 'repaired',
    ev: UNSIGNED.evidence,
    kv: signed.keyVersion,
    sig: signed.signature.toString('base64'),
  };
};

describe('a rebase line (4D2e E11)', () => {
  it('reads back as written: one line, signed over its epoch, ID, chain, place, time, reason and evidence', async () => {
    const rebase = signRebase(keys, 1, UNSIGNED);
    const read = await readRebaseFile(keys, { bytes: rebaseFile(rebase), name: NAME, epoch: 1 });

    expect(read).toEqual({ rebase });
    expect(NAME).toBe(`e1/rebases/${ID}`);
    expect(rebaseMessage(1, UNSIGNED)).toEqual([
      'audit-rebase',
      '1',
      ID,
      UNSIGNED.chain,
      '812',
      UNSIGNED.hash,
      '3',
      '2026-11-05T10:00:00.000Z',
      'repaired',
      'INC-2026-11-05',
    ]);
  });

  it('SEC-DB-11 refuses one signed with another key, with the anchor key, unsigned, or for another epoch', async () => {
    const anchorSigned = keys.sign('audit-anchor', rebaseMessage(1, UNSIGNED));
    const lines = [
      LINE(otherKeys),
      // The API's own key, over the very same message: only `audit-rebase` signs a rebase.
      { ...LINE(), sig: anchorSigned.signature.toString('base64') },
      { ...LINE(), sig: '' },
      LINE(keys, 2),
      // A key version no one holds a half for: a KeyError, read as a bad signature.
      { ...LINE(), kv: 9 },
      // Any field changed after signing.
      { ...LINE(), seq: '813' },
      { ...LINE(), why: 'recovered' },
      { ...LINE(), ev: 'INC-other' },
    ];
    for (const line of lines) {
      expect(await readRebaseFile(keys, { bytes: fileOfLine(line), name: NAME, epoch: 1 })).toEqual({
        problem: 'signature',
      });
    }
  });

  it('refuses a file that is not one rebase line, or is named for another', async () => {
    const good = LINE();
    const files = [
      gzipSync(`${JSON.stringify(good)}\n${JSON.stringify(good)}\n`),
      gzipSync(JSON.stringify(good)),
      gzipSync('not json\n'),
      gzipSync('[1]\n'),
      Buffer.from(`${JSON.stringify(good)}\n`),
      gzipSync(`${JSON.stringify({ ...good, pad: 'x'.repeat(5000) })}\n`),
      Buffer.alloc(5000),
      ...[
        { k: 'a' },
        { id: 'not-an-id' },
        { chain: 'organisation:nope' },
        { seq: '01' },
        { hash: 'ab' },
        { mk: -1 },
        { kv: 1.5 },
        { sig: 5 },
        { why: 'because' },
        { ev: 'a b' },
        { at: '2026-11-05T10:00:00Z' },
      ].map((change) => fileOfLine({ ...good, ...change })),
    ];
    for (const bytes of files) {
      expect(await readRebaseFile(keys, { bytes, name: NAME, epoch: 1 })).toEqual({ problem: 'file' });
    }
    const otherName = rebaseFileName(1, '0199a0f0-0000-7000-8000-0000000000bb');
    expect(await readRebaseFile(keys, { bytes: fileOfLine(good), name: otherName, epoch: 1 })).toEqual({
      problem: 'file',
    });
    // Its epoch's folder alone: the same file read for epoch 2 names another file.
    expect(await readRebaseFile(keys, { bytes: fileOfLine(good), name: NAME, epoch: 2 })).toEqual({ problem: 'file' });
  });

  it('lets an error other than a missing key end the read, never taking it for a bad signature', async () => {
    const broken: KeyProvider = {
      ...keys,
      verifySignature: () => {
        throw new Error('a bug');
      },
    };
    await expect(readRebaseFile(broken, { bytes: fileOfLine(LINE()), name: NAME, epoch: 1 })).rejects.toThrow('a bug');
  });
});

describe("the API holds the rebase key's public half alone (4D2e E11)", () => {
  const mounted = writeTestKeys(API_PURPOSES);
  afterAll(() => {
    mounted.remove();
  });
  const operatorHalf = keys.describe().find((entry) => entry.purpose === 'audit-rebase')?.versions[0]?.publicKey;

  it("checks a rebase with it, and can't sign one: no key to sign with", async () => {
    writeFileSync(path.join(mounted.directory, 'public-audit-rebase-v1'), `${String(operatorHalf)}\n`);
    const api = loadKeys({ directory: mounted.directory, current: {} }, API_PURPOSES, OPERATOR_ONLY);

    expect(API_PURPOSES).not.toContain('audit-rebase');
    expect(OPERATOR_ONLY).toContain('audit-rebase');
    expect(
      await readRebaseFile(api, { bytes: rebaseFile(signRebase(keys, 1, UNSIGNED)), name: NAME, epoch: 1 }),
    ).toEqual({
      rebase: expect.objectContaining({ id: ID, seq: 812n }) as unknown,
    });
    expect(() => signRebase(api, 1, UNSIGNED)).toThrow(KeyError);
    expect(() => api.sign('audit-rebase', ['anything'])).toThrow(KeyError);
  });
});
