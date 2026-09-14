import { describe, expect, it } from 'vitest';

import { LOGGABLE_LIMITS, toLoggable, UNREADABLE } from './loggable.ts';

/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';

describe('SEC-DATA-02 an error is logged the same safe way under any name, at any depth', () => {
  const driverError = (): Error =>
    Object.assign(new Error('duplicate key'), { code: '23505', detail: PLANTED, table: 'payees' });

  it.each([
    ['as err', () => ({ err: driverError() })],
    ['under another name', () => ({ error: driverError() })],
    ['nested in an object', () => ({ context: { cause: driverError() } })],
    ['in a list', () => ({ errors: [driverError()] })],
  ])('%s', (_where, fields) => {
    const text = JSON.stringify(toLoggable(fields()));
    expect(text).toContain('"type":"Error"');
    expect(text).toContain('"code":"23505"');
    expect(text).not.toContain(PLANTED);
    expect(text).not.toContain('payees');
  });
});

describe('values pino would write badly become plain data', () => {
  it('writes binary data as its size, never its bytes (SEC-DATA-01)', () => {
    const body = Buffer.from(`email=someone@example.com&note=${PLANTED}`);
    expect(
      toLoggable({
        buffer: body,
        bytes: new Uint8Array(body),
        view: new DataView(new ArrayBuffer(8)),
        raw: new ArrayBuffer(4),
        shared: new SharedArrayBuffer(2),
      }),
    ).toEqual({
      buffer: { binaryBytes: body.length },
      bytes: { binaryBytes: body.length },
      view: { binaryBytes: 8 },
      raw: { binaryBytes: 4 },
      shared: { binaryBytes: 2 },
    });
  });

  it('writes a bigint as text, keeping every digit of an amount', () => {
    expect(toLoggable({ amountMinor: 12_345_678_901_234_567_891n })).toEqual({ amountMinor: '12345678901234567891' });
  });

  it('writes a date as ISO text, and an invalid date as null', () => {
    expect(toLoggable({ at: new Date(Date.UTC(2026, 8, 14)), bad: new Date(Number.NaN) })).toEqual({
      at: '2026-09-14T00:00:00.000Z',
      bad: null,
    });
  });

  it('writes a Map as its entries and a Set as its values', () => {
    expect(toLoggable({ map: new Map([['a', 1]]), set: new Set(['x']) })).toEqual({ map: [['a', 1]], set: ['x'] });
  });

  it('uses toJSON where an object has one, such as a URL', () => {
    expect(toLoggable({ url: new URL('https://api.partner.example/v1') })).toEqual({
      url: 'https://api.partner.example/v1',
    });
  });

  it('leaves out fields with no JSON form, and writes such list items as null', () => {
    expect(toLoggable({ gone: undefined, fn: () => 1, sym: Symbol('s'), list: [undefined, () => 1, 1] })).toEqual({
      list: [null, null, 1],
    });
  });

  it('writes infinities and NaN as null, and keeps null', () => {
    expect(toLoggable({ a: Number.POSITIVE_INFINITY, b: Number.NaN, c: 2, d: null })).toEqual({
      a: null,
      b: null,
      c: 2,
      d: null,
    });
  });

  it('keeps a field named __proto__ as a plain field', () => {
    const fields = JSON.parse('{"__proto__":{"x":1}}') as object;
    const result = toLoggable(fields) as Record<string, unknown>;
    expect(Object.hasOwn(result, '__proto__')).toBe(true);
  });
});

describe('logging can never break the caller', () => {
  it('writes a field whose getter throws as unreadable, and keeps the others', () => {
    const fields = {
      kept: 1,
      get broken(): string {
        throw new Error('trap');
      },
    };
    expect(toLoggable(fields)).toEqual({ kept: 1, broken: UNREADABLE });
  });

  it('writes an object that throws when inspected as unreadable', () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('trap');
        },
      },
    );
    expect(toLoggable({ hostile })).toEqual({ hostile: UNREADABLE });
  });

  it('writes a revoked proxy as unreadable', () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();
    expect(toLoggable({ err: proxy })).toEqual({ err: UNREADABLE });
  });

  it('writes a value that contains itself once, then marks the loop', () => {
    const loop: Record<string, unknown> = { name: 'loop' };
    loop.self = loop;
    expect(toLoggable(loop)).toEqual({ name: 'loop', self: '[circular]' });
  });

  it('writes a value shared by two fields in both places, as it is not a loop', () => {
    const shared = { id: 1 };
    expect(toLoggable({ a: shared, b: shared })).toEqual({ a: { id: 1 }, b: { id: 1 } });
  });
});

describe('the work for one log call is bounded', () => {
  it('stops at the depth limit', () => {
    const deep = Array.from({ length: LOGGABLE_LIMITS.depth + 2 }).reduce<unknown>((inner) => ({ next: inner }), 1);
    expect(JSON.stringify(toLoggable(deep))).toContain('[too deep]');
  });

  it('keeps the first fields and items, and counts the rest', () => {
    const wide = Object.fromEntries(
      Array.from({ length: LOGGABLE_LIMITS.fieldsPerObject + 3 }, (_, i) => [`f${i}`, i]),
    );
    const long = Array.from({ length: LOGGABLE_LIMITS.itemsPerArray + 4 }, (_, i) => i);
    const result = toLoggable({ wide, long }) as { wide: Record<string, unknown>; long: unknown[] };
    expect(result.wide['[fields cut]']).toBe(3);
    expect(result.long.at(-1)).toBe('[4 more items cut]');
  });

  it('stops after a fixed number of values in all', () => {
    const lists = Array.from({ length: 40 }, () => Array.from({ length: 40 }, (_, i) => i));
    expect(JSON.stringify(toLoggable({ lists }))).toContain('[too large]');
  });
});
