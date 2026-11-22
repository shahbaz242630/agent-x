// A write-once store in this process, for tests that need one to fail or hang on
// cue: a second write of a name refused, as the real ones refuse it
// (packages/platform/src/storage/write-once.test.ts proves those). `instead`
// takes a call's place, and may hand on to `real`.
import { OverwriteRefused, type WriteOnceStore } from '@agentx/platform/storage';

export interface FakeWriteOnceStore {
  /** What the tests give the code. */
  readonly store: WriteOnceStore;
  /** The store itself, whatever `instead` says. */
  readonly real: WriteOnceStore;
  readonly files: Map<string, Buffer>;
  /**
   * When each file landed by the store's clock, as Azure's list gives it (TR-12): set by a Put where the store was given
   * a clock (`now`, which its serverTime gives too, as Azure's Date), or by a test for a file it planted. A list gives
   * those of its page, where any.
   */
  readonly created: Map<string, number>;
  /** How many of each call reached `store`. */
  readonly calls: { puts: number; lists: number; gets: number; smallGets: number };
  /** Set to make a call do something else. */
  readonly instead: Partial<WriteOnceStore>;
}

export function createFakeWriteOnceStore({ now }: { readonly now?: () => number } = {}): FakeWriteOnceStore {
  const files = new Map<string, Buffer>();
  const created = new Map<string, number>();
  const calls = { puts: 0, lists: 0, gets: 0, smallGets: 0 };
  const instead: Partial<WriteOnceStore> = {};

  const real: WriteOnceStore = {
    put(name, bytes) {
      if (files.has(name)) return Promise.reject(new OverwriteRefused());
      files.set(name, bytes);
      if (now !== undefined) created.set(name, now());
      return Promise.resolve();
    },
    list(start, most, after) {
      const names = [...files.keys()]
        .filter((name) => name.startsWith(start) && (after === undefined || name > after))
        .toSorted();
      const page = names.slice(0, most);
      const landed = new Map(
        page.flatMap((name) => {
          const at = created.get(name);
          return at === undefined ? [] : [[name, at] as const];
        }),
      );
      return Promise.resolve({
        names: page,
        foreign: 0,
        next: names.length > most ? page.at(-1) : undefined,
        ...(landed.size > 0 ? { created: landed } : {}),
      });
    },
    get(name) {
      const bytes = files.get(name);
      return bytes === undefined ? Promise.reject(new Error('no file of that name')) : Promise.resolve(bytes);
    },
    getAtMost(name, mostBytes) {
      const bytes = files.get(name);
      if (bytes === undefined) return Promise.resolve('missing');
      return Promise.resolve(bytes.length > mostBytes ? 'too-large' : bytes);
    },
  };

  const store: WriteOnceStore = {
    // The store's clock as Azure's Date gives it (TR-12), where it was given one.
    ...(now === undefined ? {} : { serverTime: now }),
    put(name, bytes) {
      calls.puts += 1;
      return (instead.put ?? real.put)(name, bytes);
    },
    list(start, most, after) {
      calls.lists += 1;
      return (instead.list ?? real.list)(start, most, after);
    },
    get(name) {
      calls.gets += 1;
      return (instead.get ?? real.get)(name);
    },
    getAtMost(name, mostBytes) {
      calls.smallGets += 1;
      return (instead.getAtMost ?? real.getAtMost)(name, mostBytes);
    },
  };

  return { store, real, files, created, calls, instead };
}
