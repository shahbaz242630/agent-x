import { findLeaks, SENSITIVE_SAMPLES as SAMPLES } from '@agentx/testing';
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import { hidesField, LIMITS, REDACTED, redactJson, redactLine } from './redact.ts';

/** A marker value that must never come out. Plain words, so secret scanners ignore it. */
const PLANTED = 'planted value that must not appear';
const RUNS = { numRuns: 300, seed: 20_260_914 };
const LINE_SEPARATOR = String.fromCharCode(0x2028);

/** Redacts `value` as one log line and returns what would be written, parsed. */
function redacted(value: unknown): unknown {
  const written = redactLine(JSON.stringify(value));
  expect(written.endsWith('\n')).toBe(true);
  expect(written.slice(0, -1)).not.toContain('\n');
  return JSON.parse(written);
}

const bytes = (text: string): number => Buffer.byteLength(text, 'utf8');

describe('SEC-DATA-05 redaction by field name, at any depth (names.ts has the full list)', () => {
  it('hides the value of a sensitive name, whatever its value: text, an object, a list, a number', () => {
    expect(redacted({ password: PLANTED, token: { nested: PLANTED }, iban: [PLANTED], pin: 1234 })).toEqual({
      password: REDACTED,
      token: REDACTED,
      iban: REDACTED,
      pin: REDACTED,
    });
  });

  it('keeps a code or state that is plainly a constant, and hides one that could be a secret', () => {
    expect(
      redacted({
        err: { code: 'ECONNRESET' },
        reasonCode: 'ORG_FROZEN',
        state: 'UNKNOWN',
        statusCode: 404,
        code: 'c0dexxxxxxxx',
        oauthState: 's7yyyyyyyyyy',
        transactionState: { raw: 'x' },
      }),
    ).toEqual({
      err: { code: 'ECONNRESET' },
      reasonCode: 'ORG_FROZEN',
      state: 'UNKNOWN',
      statusCode: 404,
      code: REDACTED,
      oauthState: REDACTED,
      transactionState: REDACTED,
    });
  });

  const sensitiveName = fc.constantFrom('password', 'apiKey', 'authorization', 'email', 'iban', 'sessionToken');
  const plainName = fc.constantFrom('a', 'b', 'items', 'detail', 'context', 'meta');
  /** A path of plain field names and list positions leading to where the value is planted. */
  const path = fc.array(fc.oneof(plainName, fc.nat({ max: 3 })), { maxLength: LIMITS.depth - 2 });

  function plant(steps: readonly (string | number)[], name: string): unknown {
    return steps.reduceRight<unknown>(
      (inner, step) => (typeof step === 'number' ? [...Array<null>(step).fill(null), inner] : { [step]: inner }),
      { [name]: PLANTED, kept: 'ordinary' },
    );
  }

  it('hides a sensitive field at any depth, inside objects and lists', () => {
    fc.assert(
      fc.property(path, sensitiveName, (steps, name) => {
        const text = JSON.stringify(redacted(plant(steps, name)));
        expect(text).not.toContain(PLANTED);
        expect(text).toContain('ordinary');
      }),
      RUNS,
    );
  });
});

describe('hidesField: the same rule, for code that must refuse such fields', () => {
  it.each([
    ['password', 'x', true],
    ['contactEmail', 'x', true],
    ['reasonCode', 'DUPLICATE_ORDER_REFERENCE', false],
    ['toState', 'ACTIVE', false],
    ['reasonCode', 'k3Jx9-random.Mixed', true],
    ['state', { nested: true }, true],
    ['plan', 'pilot', false],
  ])('%s = %j: hidden %s', (name, value, hidden) => {
    expect(hidesField(name, value)).toBe(hidden);
    expect(redacted({ [name]: value })).toEqual({ [name]: hidden ? REDACTED : value });
  });
});

describe('SEC-DATA-01 every string is scrubbed, in values, lists and field names', () => {
  it('scrubs text in any field', () => {
    const line = {
      event: 'test.event',
      note: `from ${SAMPLES.email} at ${SAMPLES.ipv4}`,
      list: [SAMPLES.uaeIban, { deeper: SAMPLES.bearer }],
    };
    expect(redacted(line)).toEqual({
      event: 'test.event',
      note: 'from [email] at [ip]',
      list: ['[iban]', { deeper: 'Bearer [redacted]' }],
    });
  });

  it('scrubs a field name that carries personal data, such as an email used as a key', () => {
    expect(redacted({ byUser: { [SAMPLES.email]: 3 } })).toEqual({ byUser: { '[email]': 3 } });
  });

  it('keeps numbers, booleans and null as they are', () => {
    expect(redacted({ count: 3, ratio: 0.5, ok: true, none: null })).toEqual({
      count: 3,
      ratio: 0.5,
      ok: true,
      none: null,
    });
  });

  it('keeps a field named __proto__ as a plain field, without touching any prototype', () => {
    const written = redactLine(`{"__proto__":{"note":"${SAMPLES.email}"},"event":"test.event"}`);
    const parsed = JSON.parse(written) as Record<string, unknown>;
    expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
    expect(written).toContain('[email]');
    expect(({} as Record<string, unknown>).note).toBeUndefined();
  });
});

describe('the logger’s own fields', () => {
  it('writes the fields checked where they are set exactly as they are, even if they look like data', () => {
    const line = { time: '2026-09-14T10:00:00.000Z', level: 'info', service: 'api', env: 'test', release: '1.0.0.123' };
    expect(redacted(line)).toEqual(line);
  });

  it('scrubs the same names anywhere but the top of the line', () => {
    expect(redacted({ detail: { release: '1.0.0.123' } })).toEqual({ detail: { release: '[ip]' } });
  });

  it('never cuts them when a line has too many fields: the caller’s fields are cut instead', () => {
    const many = Object.fromEntries(Array.from({ length: LIMITS.fieldsPerObject + 10 }, (_, i) => [`f${i}`, i]));
    const result = redacted({ ...many, correlationId: 'c-1', err: { type: 'Error' }, event: 'test.event' }) as Record<
      string,
      unknown
    >;
    expect(result.event).toBe('test.event');
    expect(result.correlationId).toBe('c-1');
    expect(result.err).toEqual({ type: 'Error' });
    expect(result['[fields cut]']).toBe(10);
  });
});

describe('AV-8 one line is capped in size, so a huge value cannot flood the log store', () => {
  it('stops at the depth limit', () => {
    const deep = Array.from({ length: LIMITS.depth + 3 }).reduce<unknown>((inner) => ({ next: inner }), 'bottom');
    const text = JSON.stringify(redacted(deep));
    expect(text).toContain('[too deep]');
    expect(text).not.toContain('bottom');
  });

  it('keeps the first fields of a nested object and counts the rest', () => {
    const wide = Object.fromEntries(Array.from({ length: LIMITS.fieldsPerObject + 7 }, (_, i) => [`f${i}`, i]));
    const result = redacted({ wide }) as { wide: Record<string, unknown> };
    expect(Object.keys(result.wide)).toHaveLength(LIMITS.fieldsPerObject + 1);
    expect(result.wide['[fields cut]']).toBe(7);
  });

  it('keeps the first items of a huge list and counts the rest', () => {
    const long = Array.from({ length: LIMITS.itemsPerArray + 5 }, (_, i) => i);
    const result = redacted({ long }) as { long: unknown[] };
    expect(result.long).toHaveLength(LIMITS.itemsPerArray + 1);
    expect(result.long.at(-1)).toBe('[5 more items cut]');
  });

  it('stops after a fixed number of values in all', () => {
    const lists = Array.from({ length: 40 }, () => Array.from({ length: 40 }, (_, i) => i));
    expect(JSON.stringify(redactJson({ lists }))).toContain('[too large]');
  });

  it('cuts a long string, marking where', () => {
    const result = redacted({ text: 'x '.repeat(LIMITS.stringLength) }) as { text: string };
    expect(result.text.length).toBeLessThan(LIMITS.stringLength);
    expect(result.text).toMatch(/…\[cut from \d+ characters\]$/);
  });

  it('never leaves a fragment of a secret that the cut split, wherever the secret falls', () => {
    // The window's edge is at LIMITS.stringLength and the kept text ends 256 characters before it;
    // slide every sample across both.
    const offset = fc.integer({ min: LIMITS.stringLength - 400, max: LIMITS.stringLength + 20 });
    const sample = fc.constantFrom(...Object.values(SAMPLES));
    fc.assert(
      fc.property(offset, sample, (at, secret) => {
        // The secret starts at `at`, after a space, so only the cut can split it.
        const text = `${'x '.repeat(Math.floor(at / 2))}${at % 2 === 1 ? ' ' : ''}${secret}${' y'.repeat(300)}`;
        const written = redactLine(JSON.stringify({ text }));
        expect(findLeaks(written)).toEqual([]);
        expect(written).not.toContain(secret);
      }),
      RUNS,
    );
  });

  it('never leaves even an eight-character piece of a secret, at any position around either cut', () => {
    // A piece like `someone.name+tag@example.c` matches no detector, so check the pieces themselves,
    // at every position where the kept text ends (stringLength - 256) and where the window ends.
    const secrets = [
      SAMPLES.email,
      SAMPLES.uaeIban,
      SAMPLES.spacedUaeIban,
      SAMPLES.lowercaseIban,
      SAMPLES.card,
      SAMPLES.emiratesId,
      SAMPLES.phone,
      SAMPLES.jwt,
    ];
    const keptEnd = LIMITS.stringLength - 256;
    const offsets = [
      ...Array.from({ length: 40 }, (_, i) => keptEnd - 35 + i),
      ...Array.from({ length: 40 }, (_, i) => LIMITS.stringLength - 35 + i),
    ];
    for (const secret of secrets) {
      const pieces = Array.from({ length: secret.length - 7 }, (_, i) => secret.slice(i, i + 8));
      for (const at of offsets) {
        const text = `${'x '.repeat(Math.floor(at / 2))}${at % 2 === 1 ? ' ' : ''}${secret}${' y'.repeat(300)}`;
        const written = redactLine(JSON.stringify({ text }));
        expect(
          pieces.filter((piece) => written.includes(piece)),
          `${secret} at ${at}`,
        ).toEqual([]);
      }
    }
  });
});

describe('AV-8 a line over the byte limit is shortened in steps, always keeping the error’s key facts', () => {
  const bigError = {
    type: 'AggregateError',
    message: `payment failed for ${'m'.repeat(1500)}`,
    code: 'ECONNRESET',
    stack: Array.from({ length: 20 }, (_, i) => `at frame${i} (/app/${'p'.repeat(900)}/file.ts:${i}:1)`),
    cause: { type: 'TypeError', message: 'inner', stack: ['at x'], cause: { type: 'RangeError', message: 'deepest' } },
  };

  it('first shortens the error, keeping the other fields', () => {
    const result = redacted({
      event: 'payment.failed',
      correlationId: 'c-1',
      outcome: 'failed',
      err: bigError,
    }) as Record<string, unknown>;
    expect(result).toMatchObject({ event: 'payment.failed', correlationId: 'c-1', outcome: 'failed', lineCut: true });
    expect(result.err).toMatchObject({
      type: 'AggregateError',
      code: 'ECONNRESET',
      causes: ['TypeError: inner', 'RangeError: deepest'],
    });
    expect((result.err as { stack: unknown[] }).stack).toHaveLength(5);
    expect(bytes(JSON.stringify(result))).toBeLessThanOrEqual(LIMITS.lineBytes);
  });

  it('then drops the caller’s fields, keeping the logger’s own and the error', () => {
    const bulky = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`f${i}`, 'z '.repeat(1000)]));
    const result = redacted({ event: 'payment.failed', orgId: 'o-1', ...bulky, err: bigError }) as Record<
      string,
      unknown
    >;
    expect(Object.keys(result).sort()).toEqual(['err', 'event', 'lineCut', 'orgId']);
    expect(result.err).toMatchObject({ type: 'AggregateError', code: 'ECONNRESET' });
  });

  it('last shortens the logger’s own fields too, so even a line of Arabic text always fits', () => {
    // Arabic letters take two bytes each, so ten own fields of 1,024 letters are over the limit.
    const long = 'ع '.repeat(1000);
    const own = {
      event: long,
      correlationId: long,
      orgId: long,
      actor: long,
      module: long,
      service: long,
      env: long,
      release: long,
      level: long,
      time: long,
    };
    const result = redacted({ ...own, err: bigError }) as Record<string, unknown>;
    expect(bytes(JSON.stringify(result))).toBeLessThanOrEqual(LIMITS.lineBytes);
    expect(result).toMatchObject({ err: { type: 'AggregateError', code: 'ECONNRESET' }, lineCut: true });
    expect((result.event as string).length).toBeLessThanOrEqual(257);
    expect(result.err).not.toHaveProperty('stack');
  });

  it.each([
    ['as plain text', `rejected ${'r '.repeat(400)}`, (err: unknown) => typeof err === 'string' && err.length <= 257],
    [
      'with no code, stack or causes',
      { type: 'Error', message: 'short' },
      (err: unknown) => JSON.stringify(err) === '{"type":"Error","message":"short"}',
    ],
    [
      'with no type or message',
      { stack: ['at x'] },
      (err: unknown) => JSON.stringify(err) === '{"type":null,"message":null,"stack":["at x"]}',
    ],
    [
      'with a cause whose type is not text and whose message is long',
      { type: 'Error', message: 'm', cause: { type: 5, message: 'z'.repeat(300) } },
      (err: unknown) => JSON.stringify(err).includes(`"causes":[": ${'z'.repeat(128)}…"]`),
    ],
  ])('shortens an error %s', (_what, err, check) => {
    const bulky = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`f${i}`, 'z '.repeat(1000)]));
    const result = redacted({ event: 'test.event', err, ...bulky }) as Record<string, unknown>;
    expect(result.lineCut).toBe(true);
    expect(check(result.err)).toBe(true);
  });

  it('shortens a line of Arabic text with no error at all', () => {
    const long = 'ع '.repeat(1000);
    const own = Object.fromEntries(
      ['event', 'correlationId', 'orgId', 'actor', 'module', 'service', 'env', 'release', 'level', 'time'].map(
        (name) => [name, long],
      ),
    );
    const result = redacted(own) as Record<string, unknown>;
    expect(bytes(JSON.stringify(result))).toBeLessThanOrEqual(LIMITS.lineBytes);
    expect(result).not.toHaveProperty('err');
    expect(result.lineCut).toBe(true);
  });

  it('shortens with the cleaned values, never the raw ones', () => {
    const bulky = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`f${i}`, 'z '.repeat(1000)]));
    const written = redactLine(JSON.stringify({ correlationId: `c-1 ${SAMPLES.email}`, ...bulky }));
    expect(written).toContain('"correlationId":"c-1 [email]"');
    expect(findLeaks(written)).toEqual([]);
  });

  it('measures in bytes, as the container runtime does, not in characters', () => {
    // Arabic letters take two bytes each: under the limit in characters, over it in bytes.
    const arabic = 'ع'.repeat(LIMITS.lineBytes / 2 - 100);
    const line = {
      event: 'test.event',
      a: arabic.slice(0, 2000),
      b: arabic.slice(0, 2000),
      c: arabic.slice(0, 2000),
      d: arabic.slice(0, 2000),
    };
    expect(JSON.stringify(line).length).toBeLessThan(LIMITS.lineBytes);
    expect(bytes(JSON.stringify(line))).toBeGreaterThan(LIMITS.lineBytes);
    expect(redacted(line)).toMatchObject({ lineCut: true });
  });
});

describe('redactLine never fails, and never writes its input unredacted', () => {
  it('turns a line it cannot read into a fixed error line', () => {
    const written = redactLine(`not json ${SAMPLES.email}`, () => Date.UTC(2026, 8, 14, 10, 0, 0));
    expect(written).toBe('{"time":"2026-09-14T10:00:00.000Z","level":"error","event":"log.unreadable_line"}\n');
  });

  it('refuses to parse a line far too long to be ours', () => {
    const written = redactLine(`"${'x'.repeat(LIMITS.rawLineLength)}"`, () => Date.UTC(2026, 8, 14, 10, 0, 0));
    expect(written).toBe('{"time":"2026-09-14T10:00:00.000Z","level":"error","event":"log.line_too_large"}\n');
  });

  it.each([
    ['a string', `"${SAMPLES.email}"`, '"[email]"\n'],
    ['a number', '42', '42\n'],
    ['a list', `["${SAMPLES.ipv4}"]`, '["[ip]"]\n'],
  ])('handles a line that is %s rather than an object', (_what, line, expected) => {
    expect(redactLine(line)).toBe(expected);
  });

  it('escapes characters that some tools read as line breaks, so a value cannot start a forged line', () => {
    const written = redactLine(JSON.stringify({ note: `a${LINE_SEPARATOR}{"level":"error"}` }));
    expect(written).not.toContain(LINE_SEPARATOR);
    expect(written).toContain('\\u2028');
    expect(JSON.parse(written)).toEqual({ note: `a${LINE_SEPARATOR}{"level":"error"}` });
  });
});
