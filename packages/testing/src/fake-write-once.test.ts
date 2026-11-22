// The fake write-once store's own calls: the anchor log reads through
// `getAtMost` since the shards (PR2), so `get` is proven here, as the real
// stores' are in packages/platform/src/storage/write-once.test.ts.
import { OverwriteRefused } from '@agentx/platform/storage';
import { describe, expect, it } from 'vitest';

import { createFakeWriteOnceStore } from './fake-write-once.ts';

describe('the fake write-once store', () => {
  it('gets a written file by name, counts the call, and refuses a name never written', async () => {
    const fake = createFakeWriteOnceStore();
    await fake.store.put('a', Buffer.from('one'));
    expect(await fake.store.get('a')).toEqual(Buffer.from('one'));
    await expect(fake.store.get('b')).rejects.toThrow('no file of that name');
    expect(fake.calls).toEqual({ puts: 1, lists: 0, gets: 2, smallGets: 0 });
  });

  it('refuses a second write of a name, as the real stores do', async () => {
    const fake = createFakeWriteOnceStore();
    await fake.store.put('a', Buffer.from('one'));
    await expect(fake.store.put('a', Buffer.from('two'))).rejects.toBeInstanceOf(OverwriteRefused);
    expect(fake.files.get('a')).toEqual(Buffer.from('one'));
  });

  it('lists a page at a time after a name, and fetches at most so many bytes', async () => {
    const fake = createFakeWriteOnceStore();
    for (const name of ['p/1', 'p/2', 'p/3', 'q/1']) await fake.store.put(name, Buffer.from(name));
    expect(await fake.store.list('p/', 2)).toEqual({ names: ['p/1', 'p/2'], foreign: 0, next: 'p/2' });
    expect(await fake.store.list('p/', 2, 'p/2')).toEqual({ names: ['p/3'], foreign: 0, next: undefined });
    expect(await fake.store.getAtMost('p/1', 3)).toEqual(Buffer.from('p/1'));
    expect(await fake.store.getAtMost('p/1', 2)).toBe('too-large');
    expect(await fake.store.getAtMost('none', 9)).toBe('missing');
  });

  it('lists when each file landed by its own clock where given one, and those a test set (TR-12); none, nothing', async () => {
    const fake = createFakeWriteOnceStore({ now: () => 7 });
    await fake.store.put('p/1', Buffer.from('one'));
    fake.files.set('p/2', Buffer.from('planted'));
    expect((await fake.store.list('p/', 5)).created).toEqual(new Map([['p/1', 7]]));
    expect(fake.store.serverTime?.()).toBe(7);
    fake.created.set('p/2', 3);
    expect((await fake.store.list('p/', 5)).created).toEqual(
      new Map([
        ['p/1', 7],
        ['p/2', 3],
      ]),
    );
    const plain = createFakeWriteOnceStore();
    await plain.store.put('p/1', Buffer.from('one'));
    expect(await plain.store.list('p/', 5)).toEqual({ names: ['p/1'], foreign: 0, next: undefined });
    expect(plain.store.serverTime).toBeUndefined();
  });

  it('hands a call to `instead` when one is set, and the real store stays reachable', async () => {
    const fake = createFakeWriteOnceStore();
    await fake.real.put('a', Buffer.from('one'));
    fake.instead.get = () => Promise.reject(new Error('store down'));
    await expect(fake.store.get('a')).rejects.toThrow('store down');
    expect(await fake.real.get('a')).toEqual(Buffer.from('one'));
  });
});
