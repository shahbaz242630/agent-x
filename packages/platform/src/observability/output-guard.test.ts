import { findLeaks, SENSITIVE_SAMPLES as SAMPLES } from '@agentx/testing';
import { describe, expect, it } from 'vitest';

import { cleanOutput, guardOutputs, type Output } from './output-guard.ts';

const NOW = (): number => Date.UTC(2026, 8, 14, 10, 0, 0);

/** A stand-in for process.stdout or process.stderr that records what reaches it. */
function fakeOutput(): Output & { written: string[]; callbacks: number } {
  const output = {
    written: [] as string[],
    callbacks: 0,
    write(
      chunk: string | Uint8Array,
      encoding?: BufferEncoding | ((error?: Error | null) => void),
      callback?: () => void,
    ) {
      output.written.push(typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8'));
      const done = typeof encoding === 'function' ? encoding : callback;
      if (done !== undefined) {
        output.callbacks += 1;
        done();
      }
      return true;
    },
  };
  return output;
}

describe('ADR-013 the output guard cleans whatever else reaches stdout and stderr', () => {
  it('redacts a JSON line as a log line, and scrubs any other text', () => {
    const text = `{"password":"plain words","note":"${SAMPLES.email}"}\nwarning: retry ${SAMPLES.relativeCallback} from ${SAMPLES.ipv4}\n`;
    expect(cleanOutput(text, NOW)).toBe(
      '{"password":"[redacted]","note":"[email]"}\nwarning: retry /oauth/callback from [ip]\n',
    );
  });

  it('scrubs a line that only looks like JSON', () => {
    expect(cleanOutput(`{ not json ${SAMPLES.email}`, NOW)).toBe('{ not json [email]');
  });

  it('guards both streams: strings and bytes, with or without an encoding, keeping the callback', () => {
    const stdout = fakeOutput();
    const stderr = fakeOutput();
    guardOutputs({ stdout, stderr }, NOW);

    stdout.write(`token=${'t'.repeat(20)}\n`);
    stdout.write(Buffer.from(`mail ${SAMPLES.email}\n`), () => undefined);
    stderr.write(`card ${SAMPLES.card}\n`, 'utf8', () => undefined);

    expect(stdout.written).toEqual(['token=[redacted]\n', 'mail [email]\n']);
    expect(stderr.written).toEqual(['card [card]\n']);
    expect(stdout.callbacks + stderr.callbacks).toBe(2);
  });

  it('guards each stream only once, so cleaning never runs twice on the same write', () => {
    const stdout = fakeOutput();
    const stderr = fakeOutput();
    guardOutputs({ stdout, stderr }, NOW);
    const guardedWrite: unknown = Reflect.get(stdout, 'write');
    guardOutputs({ stdout, stderr }, NOW);
    expect(Reflect.get(stdout, 'write')).toBe(guardedWrite);
  });

  it('uses the real clock when none is given', () => {
    const stdout = fakeOutput();
    guardOutputs({ stdout, stderr: fakeOutput() });
    stdout.write('not json {\n');
    expect(findLeaks(stdout.written.join(''))).toEqual([]);
  });
});
