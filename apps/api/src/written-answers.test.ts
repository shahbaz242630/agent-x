import type { FastifyReply } from 'fastify';
import { describe, expect, it } from 'vitest';

import { aboutToWrite, markWritten, recordingWrites, writtenText } from './written-answers.ts';

/** Stands in for a reply: the module only keys by it. */
const reply = (): FastifyReply => ({}) as FastifyReply;
const serialize = recordingWrites((data) => JSON.stringify(data));

describe('SEC-WEB-06 the text the contract wrote, recorded against its reply', () => {
  it('records what the serializer writes for the object the contract named, and for that reply alone', () => {
    const [named, other] = [reply(), reply()];
    const answer = { ok: true };
    aboutToWrite(named, answer);
    expect(serialize(answer)).toBe('{"ok":true}');
    expect(writtenText(named)).toBe('{"ok":true}');
    expect(writtenText(other)).toBeUndefined();
  });

  it('never takes text written for another object as the answer, and names the reply only once', () => {
    const named = reply();
    const answer = { ok: true };
    aboutToWrite(named, answer);
    serialize({ ok: true, secret: 'planted' });
    expect(writtenText(named)).toBeUndefined();
    serialize(answer);
    expect(writtenText(named)).toBeUndefined();
  });

  it('forgets the named reply when the serializer throws', () => {
    const named = reply();
    const answer = { ok: true };
    const failing = recordingWrites(() => {
      throw new Error('refused');
    });
    aboutToWrite(named, answer);
    expect(() => failing(answer)).toThrow('refused');
    serialize(answer);
    expect(writtenText(named)).toBeUndefined();
  });

  it('records the error body the contract wrote itself', () => {
    const errored = reply();
    markWritten(errored, '{"error":{}}');
    expect(writtenText(errored)).toBe('{"error":{}}');
  });
});
