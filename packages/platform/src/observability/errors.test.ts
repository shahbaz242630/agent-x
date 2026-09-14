import { describe, expect, it } from 'vitest';

import { serializeError } from './errors.ts';

describe('SEC-DATA-02 errors are logged as a fixed set of facts', () => {
  it('keeps the type, message and stack positions, and drops the header line that repeats the message', () => {
    const logged = serializeError(new TypeError('bad input'));
    expect(logged.type).toBe('TypeError');
    expect(logged.message).toBe('bad input');
    expect(logged.stack?.length).toBeGreaterThan(0);
    expect(logged.stack?.every((frame) => frame.startsWith('at '))).toBe(true);
    expect(logged.stack?.join('\n')).not.toContain('bad input');
  });

  it('leaves out every other property an error carries, such as a driver’s row values', () => {
    const error = Object.assign(new Error('duplicate key'), {
      detail: 'Key (email)=(someone@example.com) already exists.',
      table: 'suppliers',
      query: 'SELECT secret FROM keys',
    });
    expect(Object.keys(serializeError(error)).sort()).toEqual(['message', 'stack', 'type']);
  });

  it.each([
    ['a Node error code', 'ECONNREFUSED'],
    ['a Node internal code', 'ERR_INVALID_URL'],
    ['an SQL state', '23505'],
    ['an SQL state with a letter', '42P01'],
  ])('keeps %s', (_what, code) => {
    expect(serializeError(Object.assign(new Error('x'), { code })).code).toBe(code);
  });

  it.each([
    ['text that could be data', 'user someone@example.com'],
    ['a number', 404],
    ['a code that is too long', 'A'.repeat(65)],
    ['a long run of digits, which could be an account number', '1234567890123456'],
    ['a single character', 'E'],
  ])('drops a code that is %s', (_what, code) => {
    expect(serializeError(Object.assign(new Error('x'), { code }))).not.toHaveProperty('code');
  });

  it('keeps at most 20 stack positions', () => {
    const error = new Error('deep');
    error.stack = ['Error: deep', ...Array.from({ length: 30 }, (_, i) => `    at f${i} (file.ts:${i}:1)`)].join('\n');
    expect(serializeError(error).stack).toHaveLength(20);
  });

  it('leaves out a stack that has no positions, or is not text', () => {
    const noFrames = Object.assign(new Error('x'), { stack: 'Error: x' });
    const notText = Object.assign(new Error('x'), { stack: 42 });
    expect(serializeError(noFrames)).not.toHaveProperty('stack');
    expect(serializeError(notText)).not.toHaveProperty('stack');
  });

  it('keeps the whole message: the redaction step cleans it, then cuts it safely', () => {
    expect(serializeError(new Error('m'.repeat(5000))).message).toHaveLength(5000);
  });

  it('names an error with no usable name as Error', () => {
    const unnamed = Object.assign(new Error('x'), { name: '' });
    expect(serializeError(unnamed).type).toBe('Error');
  });
});

describe('SEC-DATA-02 causes and grouped errors', () => {
  it('follows the cause chain, three deep, and marks where it was cut', () => {
    const chain = new Error('top', {
      cause: new Error('one', { cause: new Error('two', { cause: new Error('three', { cause: new Error('four') }) }) }),
    });
    const logged = serializeError(chain);
    expect(logged.cause?.message).toBe('one');
    expect(logged.cause?.cause?.message).toBe('two');
    expect(logged.cause?.cause?.cause?.message).toBe('three');
    expect(logged.cause?.cause?.cause?.cause).toBeUndefined();
    expect(logged.cause?.cause?.cause?.cut).toBe(true);
    expect(logged.cut).toBeUndefined();
  });

  it('survives an error that is its own cause', () => {
    const loop = new Error('loop');
    loop.cause = loop;
    expect(serializeError(loop).cause?.cause?.cause?.cut).toBe(true);
  });

  it('describes the errors inside an AggregateError, at most ten', () => {
    const many = new AggregateError(
      Array.from({ length: 12 }, (_, i) => new RangeError(`e${i}`)),
      'many failed',
    );
    const logged = serializeError(many);
    expect(logged.type).toBe('AggregateError');
    expect(logged.errors).toHaveLength(10);
    expect(logged.errors?.[0]).toMatchObject({ type: 'RangeError', message: 'e0' });
    expect(logged.cut).toBe(true);
  });

  it('marks an AggregateError below the depth limit as cut, leaving its errors out', () => {
    const inner = new AggregateError([new Error('deepest')], 'grouped');
    const chain = new Error('top', { cause: new Error('one', { cause: new Error('two', { cause: inner }) }) });
    const bottom = serializeError(chain).cause?.cause?.cause;
    expect(bottom).toMatchObject({ type: 'AggregateError', message: 'grouped', cut: true });
    expect(bottom).not.toHaveProperty('errors');
  });

  it('describes a cause that is not an Error', () => {
    expect(serializeError(new Error('top', { cause: 'plain text' })).cause).toEqual({
      type: 'NonError',
      message: 'plain text',
    });
  });
});

describe('SEC-DATA-02 anything thrown can be logged, never crashing the logger', () => {
  it.each([
    ['a string', 'went wrong', 'went wrong'],
    ['a number', 7, '7'],
    ['a bigint', 7n, '7'],
    ['a boolean', false, 'false'],
    ['undefined', undefined, '(undefined)'],
    ['null', null, '(object)'],
    ['a plain object with a message', { message: 'from an object' }, 'from an object'],
    ['a plain object without one', { other: 1 }, '(undefined)'],
    ['a symbol', Symbol('s'), '(symbol)'],
  ])('%s', (_what, thrown, message) => {
    expect(serializeError(thrown)).toEqual({ type: 'NonError', message });
  });

  it('an error whose properties throw when read', () => {
    const hostile = new Error('x');
    for (const property of ['name', 'message', 'stack', 'code', 'cause']) {
      Object.defineProperty(hostile, property, {
        get() {
          throw new Error('trap');
        },
      });
    }
    expect(serializeError(hostile)).toEqual({ type: 'Error', message: '(undefined)' });
  });
});
