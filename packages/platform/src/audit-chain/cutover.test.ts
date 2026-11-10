import { gunzipSync, gzipSync } from 'node:zlib';

import { describe, expect, it } from 'vitest';

import { createKeyProvider, KeyError, type KeyProvider } from '../keys/key-provider.ts';
import { byPurpose, PURPOSES } from '../keys/purposes.ts';
import { cutoverFile, cutoverName, readCutoverFile, SHARDED_LAYOUT } from './cutover.ts';

const keysFilled = (fill: number, version = 1): KeyProvider =>
  createKeyProvider(
    byPurpose((purpose) => {
      // Only the anchors' key moves on: some others may never be rotated.
      const held = purpose === 'audit-anchor' ? version : 1;
      return { current: held, versions: new Map([[held, Buffer.alloc(32, PURPOSES.indexOf(purpose) + fill)]]) };
    }),
  );
const keys = keysFilled(3);
const AT = new Date('2026-11-10T08:00:00.000Z');

const made = (signing = keys, epoch = 1) => cutoverFile(signing, { epoch, at: AT });
/** A marker's one line, changed by `change`, gzipped again. */
const changed = (change: (fields: Record<string, unknown>) => Record<string, unknown>): Buffer => {
  const fields = JSON.parse(gunzipSync(made().bytes).toString('utf8')) as Record<string, unknown>;
  return gzipSync(`${JSON.stringify(change(fields))}\n`);
};
const read = (bytes: Buffer, name = made().name, epoch = 1, holding = keys) =>
  readCutoverFile(holding, { bytes, name, epoch });

describe('the cutover marker (PL-65)', () => {
  it('is at the one name for its epoch and layout, and reads back as a marker of the sharded layout', async () => {
    const { name, bytes } = made();
    expect(name).toBe('e1/cutover/shards-v1');
    expect(cutoverName(2)).toBe('e2/cutover/shards-v1');
    expect(JSON.parse(gunzipSync(bytes).toString('utf8'))).toMatchObject({ k: 'cutover', layout: SHARDED_LAYOUT });
    expect(await read(bytes, name)).toEqual({ marker: true });
  });

  it.each([
    ['not gzip', Buffer.from('not gzip')],
    ['no line', gzipSync('')],
    ['two lines', gzipSync(`{}\n{}\n`)],
    ['not JSON', gzipSync('nope\n')],
    ['JSON but no object', gzipSync('3\n')],
    ['another kind', changed((fields) => ({ ...fields, k: 'r' }))],
    ['another name', changed((fields) => ({ ...fields, name: 'e1/cutover/other' }))],
    ['no time', changed((fields) => ({ ...fields, at: 'soon' }))],
    ['no key version', changed((fields) => ({ ...fields, kv: -1 }))],
    ['no signature', changed((fields) => ({ ...fields, sig: 7 }))],
    ['no layout', changed((fields) => ({ ...fields, layout: 1 }))],
  ])('%s is no marker: `file`', async (_, bytes) => {
    expect(await read(bytes)).toEqual({ problem: 'file' });
  });

  it("another epoch's, under this one's name, is `epoch`", async () => {
    expect(await read(changed((fields) => ({ ...fields, epoch: 2 })))).toEqual({ problem: 'epoch' });
  });

  it('another layout, read under its own name, is `layout`, even signed', async () => {
    const other = cutoverFile(keys, { epoch: 1, at: AT, layout: 'shards-v2' });
    expect(await read(other.bytes, other.name)).toEqual({ problem: 'layout' });
  });

  it('signed by another key, by a version not held, or with a word changed, is `signature`', async () => {
    expect(await read(made(keysFilled(40)).bytes)).toEqual({ problem: 'signature' });
    expect(await read(made(keysFilled(3, 2)).bytes)).toEqual({ problem: 'signature' });
    expect(await read(changed((fields) => ({ ...fields, at: '2026-11-10T08:00:00.001Z' })))).toEqual({
      problem: 'signature',
    });
  });

  it('a key provider failing otherwise is thrown, never taken for a bad signature', async () => {
    const failing: KeyProvider = {
      ...keys,
      verifySignature: () => {
        throw new Error('the key store is away');
      },
    };
    await expect(read(made().bytes, made().name, 1, failing)).rejects.toThrow('the key store is away');
    const lacking: KeyProvider = {
      ...keys,
      verifySignature: () => {
        throw new KeyError('no such version');
      },
    };
    expect(await read(made().bytes, made().name, 1, lacking)).toEqual({ problem: 'signature' });
  });
});
